"""The incident timeline: everything the actor did around the incident, in order.

Flagged events (evidence for a finding) are shown alongside unflagged
context events. The unflagged ones often complete the story, for example
an attacker's reconnaissance calls just before the first finding.
"""

from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta

from app.correlation.engine import CORRELATION_WINDOW
from app.schemas.event import Event
from app.schemas.finding import StoredFinding
from app.schemas.incident import Incident

# How far before the first finding and after the last one to show context.
TIMELINE_CONTEXT = CORRELATION_WINDOW


@dataclass(frozen=True)
class TimelineEntry:
    event: Event
    detector_ids: tuple[str, ...]  # empty for context events no rule flagged


def timeline_range(
    incident: Incident, context: timedelta = TIMELINE_CONTEXT
) -> tuple[datetime, datetime]:
    return incident.first_seen - context, incident.last_seen + context


def build_timeline(
    findings: Sequence[StoredFinding], actor_events: Sequence[Event]
) -> list[TimelineEntry]:
    """Merge the actor's events with the findings that flagged them, oldest first."""
    flagged_by: defaultdict[str, set[str]] = defaultdict(set)
    for stored in findings:
        for event_id in stored.finding.event_ids:
            flagged_by[event_id].add(stored.finding.detector_id)

    ordered = sorted(actor_events, key=lambda e: (e.timestamp, e.event_id))
    return [
        TimelineEntry(event=event, detector_ids=tuple(sorted(flagged_by.get(event.event_id, ()))))
        for event in ordered
    ]
