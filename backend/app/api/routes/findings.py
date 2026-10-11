"""Read-only access to findings, with their risk breakdown and evidence."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.api.deps import get_session
from app.api.routes.events import MAX_PAGE_SIZE
from app.api.schemas import DetectorInfo, EventSummary, FindingDetail, FindingSummary, Page
from app.detection.registry import DEFAULT_DETECTORS
from app.repositories.events import get_events
from app.repositories.findings import FindingSort, get_finding, search_findings
from app.schemas.finding import FindingStatus, Severity

router = APIRouter(prefix="/findings", tags=["findings"])

DETECTORS_BY_ID = {detector.detector_id: detector for detector in DEFAULT_DETECTORS}


@router.get("")
def list_findings(
    session: Annotated[Session, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=MAX_PAGE_SIZE)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
    severity: Severity | None = None,
    status_: Annotated[FindingStatus | None, Query(alias="status")] = None,
    detector_id: Annotated[str | None, Query(max_length=128)] = None,
    principal: Annotated[str | None, Query(max_length=256)] = None,
    sort: FindingSort = "newest",
) -> Page[FindingSummary]:
    """Findings, newest first or highest risk first (``sort=risk``)."""
    findings, total = search_findings(
        session,
        limit=limit,
        offset=offset,
        severity=severity,
        status=status_,
        detector_id=detector_id,
        principal=principal,
        sort=sort,
    )
    return Page(
        items=[FindingSummary.from_stored(f) for f in findings],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/{finding_id}")
def read_finding(
    finding_id: str, session: Annotated[Session, Depends(get_session)]
) -> FindingDetail:
    """One finding with its risk breakdown, the rule behind it, and its evidence events."""
    stored = get_finding(session, finding_id)
    if stored is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Finding not found")

    finding = stored.finding
    detector = DETECTORS_BY_ID.get(finding.detector_id)
    return FindingDetail(
        finding_id=finding.finding_id,
        detector_id=finding.detector_id,
        title=finding.title,
        severity=finding.severity,
        reason=finding.reason,
        status=stored.status,
        first_seen=finding.first_seen,
        last_seen=finding.last_seen,
        created_at=stored.created_at,
        account_id=finding.account_id,
        principal=finding.principal,
        principal_arn=finding.principal_arn,
        resource=finding.resource,
        risk=stored.risk,
        detector=DetectorInfo.from_detector(detector) if detector is not None else None,
        evidence=[EventSummary.from_event(e) for e in get_events(session, finding.event_ids)],
    )
