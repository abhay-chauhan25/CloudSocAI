"""Read-only access to incidents: the investigations an analyst works through."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.api.deps import get_session
from app.api.routes.events import MAX_PAGE_SIZE
from app.api.schemas import (
    EventSummary,
    FindingSummary,
    IncidentDetail,
    IncidentSummary,
    Page,
    TimelineItem,
)
from app.correlation.timeline import build_timeline, timeline_range
from app.repositories.events import get_events, list_actor_events
from app.repositories.findings import get_findings
from app.repositories.incidents import IncidentSort, get_incident, search_incidents
from app.schemas.finding import Severity
from app.schemas.incident import IncidentStatus

router = APIRouter(prefix="/incidents", tags=["incidents"])


@router.get("")
def list_incidents(
    session: Annotated[Session, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=MAX_PAGE_SIZE)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
    status_: Annotated[IncidentStatus | None, Query(alias="status")] = None,
    severity: Severity | None = None,
    principal: Annotated[str | None, Query(max_length=256)] = None,
    sort: IncidentSort = "newest",
) -> Page[IncidentSummary]:
    """Incidents, most recent activity first or highest risk first (``sort=risk``)."""
    incidents, total = search_incidents(
        session,
        limit=limit,
        offset=offset,
        status=status_,
        severity=severity,
        principal=principal,
        sort=sort,
    )
    return Page(
        items=[IncidentSummary.from_stored(i) for i in incidents],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/{incident_id}")
def read_incident(
    incident_id: str, session: Annotated[Session, Depends(get_session)]
) -> IncidentDetail:
    """One incident with its risk breakdown, findings, and the actor's timeline."""
    stored = get_incident(session, incident_id)
    if stored is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Incident not found")

    incident = stored.incident
    findings = get_findings(session, incident.finding_ids)
    start, end = timeline_range(incident)
    actor_events = list_actor_events(
        session,
        principal_arn=incident.principal_arn,
        principal=incident.principal,
        start=start,
        end=end,
    )
    # Evidence is always on the timeline, even if it falls outside the actor query.
    known = {event.event_id for event in actor_events}
    evidence_ids = [i for f in findings for i in f.finding.event_ids if i not in known]
    timeline = build_timeline(findings, actor_events + get_events(session, evidence_ids))

    return IncidentDetail(
        incident_id=incident.incident_id,
        pattern_id=incident.pattern_id,
        title=incident.title,
        summary=incident.summary,
        severity=incident.severity,
        status=stored.status,
        first_seen=incident.first_seen,
        last_seen=incident.last_seen,
        created_at=stored.created_at,
        updated_at=stored.updated_at,
        account_id=incident.account_id,
        principal=incident.principal,
        principal_arn=incident.principal_arn,
        risk=incident.risk,
        findings=[FindingSummary.from_stored(f) for f in findings],
        timeline=[
            TimelineItem(
                event=EventSummary.from_event(entry.event),
                flagged=bool(entry.detector_ids),
                detector_ids=list(entry.detector_ids),
            )
            for entry in timeline
        ],
    )
