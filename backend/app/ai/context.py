"""Build the evidence package the AI analyst receives for one incident.

Data minimisation: only fields the analysis needs are included, and every
caller-controlled string is length-capped. The context is the only thing the
model sees, so it is also what its answers are checked against.
"""

import hashlib
import json

from app.ai.schemas import (
    ContextEvent,
    ContextFinding,
    ContextIncident,
    ContextRiskFactor,
    ContextTechnique,
    IncidentContext,
)
from app.correlation.timeline import TimelineEntry
from app.correlation.view import IncidentView

# Bounds on how much is sent: they cap cost and limit how much
# attacker-controlled text can reach the model.
MAX_TIMELINE_EVENTS = 60
MAX_TEXT = 200


def truncate(value: str | None, limit: int = MAX_TEXT) -> str | None:
    if value is None or len(value) <= limit:
        return value
    return value[: limit - 1] + "…"


def build_context(view: IncidentView) -> IncidentContext:
    incident = view.stored.incident
    timeline, truncated = _select_timeline(view.timeline)
    return IncidentContext(
        incident=ContextIncident(
            incident_id=incident.incident_id,
            title=truncate(incident.title) or "",
            pattern=incident.pattern_id,
            severity=incident.severity.value,
            risk_score=incident.risk.score,
            risk_factors=[
                ContextRiskFactor(name=truncate(f.name) or "", points=f.points)
                for f in incident.risk.factors
            ],
            actor=truncate(incident.principal),
            actor_arn=truncate(incident.principal_arn),
            account_id=incident.account_id,
            first_seen=incident.first_seen,
            last_seen=incident.last_seen,
        ),
        findings=[
            ContextFinding(
                finding_id=f.finding.finding_id,
                rule=f.finding.detector_id,
                title=f.finding.title,
                severity=f.finding.severity.value,
                risk_score=f.risk.score,
                reason=truncate(f.finding.reason, 400) or "",
                event_ids=list(f.finding.event_ids),
            )
            for f in view.findings
        ],
        techniques=[
            ContextTechnique(
                technique_id=t.technique.technique_id,
                name=t.technique.name,
                tactics=[tactic.name for tactic in t.technique.tactics],
            )
            for t in view.techniques
        ],
        timeline=[_context_event(entry) for entry in timeline],
        timeline_truncated=truncated,
    )


def _select_timeline(entries: list[TimelineEntry]) -> tuple[list[TimelineEntry], bool]:
    """Keep every flagged event, then the earliest context events, up to the limit."""
    if len(entries) <= MAX_TIMELINE_EVENTS:
        return entries, False
    flagged = [e for e in entries if e.detector_ids]
    context = [e for e in entries if not e.detector_ids]
    keep = flagged + context[: max(0, MAX_TIMELINE_EVENTS - len(flagged))]
    keep_ids = {e.event.event_id for e in keep}
    return [e for e in entries if e.event.event_id in keep_ids], True


def _context_event(entry: TimelineEntry) -> ContextEvent:
    event = entry.event
    return ContextEvent(
        event_id=event.event_id,
        time=event.timestamp,
        service=event.service,
        action=event.event_name,
        succeeded=event.success,
        error_code=truncate(event.error_code, 100),
        source=truncate(event.source_address, 100),
        user_agent=truncate(event.user_agent),
        flagged_by=list(entry.detector_ids),
    )


def context_json(context: IncidentContext) -> str:
    """Canonical JSON: the same context always serialises identically."""
    return json.dumps(context.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))


def context_hash(context: IncidentContext) -> str:
    """Cache key: an analysis is current only while its context is unchanged."""
    return hashlib.sha256(context_json(context).encode()).hexdigest()
