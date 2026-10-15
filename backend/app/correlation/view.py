"""Everything known about one incident, assembled once.

Used by the API's incident detail and by the AI analyst's context builder,
so the dashboard and the LLM always see the same evidence.
"""

from dataclasses import dataclass

from sqlalchemy.orm import Session

from app.correlation.timeline import TimelineEntry, build_timeline, timeline_range
from app.detection.registry import DETECTORS_BY_ID
from app.mitre.catalog import TECHNIQUES, Technique, tactic_rank
from app.repositories.events import get_events, list_actor_events
from app.repositories.findings import get_findings
from app.repositories.incidents import get_incident
from app.schemas.finding import StoredFinding
from app.schemas.incident import StoredIncident


@dataclass(frozen=True)
class IncidentTechnique:
    technique: Technique
    detector_ids: tuple[str, ...]


@dataclass(frozen=True)
class IncidentView:
    stored: StoredIncident
    findings: list[StoredFinding]
    techniques: list[IncidentTechnique]
    timeline: list[TimelineEntry]


def load_incident_view(session: Session, incident_id: str) -> IncidentView | None:
    stored = get_incident(session, incident_id)
    if stored is None:
        return None
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

    return IncidentView(
        stored=stored,
        findings=findings,
        techniques=incident_techniques(findings),
        timeline=timeline,
    )


def incident_techniques(findings: list[StoredFinding]) -> list[IncidentTechnique]:
    """The curated techniques of the incident's rules, earliest tactic first."""
    rules_by_technique: dict[str, set[str]] = {}
    for stored in findings:
        detector = DETECTORS_BY_ID.get(stored.finding.detector_id)
        for mapping in detector.mitre if detector is not None else ():
            rules_by_technique.setdefault(mapping.technique_id, set()).add(detector.detector_id)

    techniques = sorted(
        (TECHNIQUES[technique_id] for technique_id in rules_by_technique),
        key=lambda t: (min(tactic_rank(tactic) for tactic in t.tactics), t.technique_id),
    )
    return [
        IncidentTechnique(t, tuple(sorted(rules_by_technique[t.technique_id]))) for t in techniques
    ]
