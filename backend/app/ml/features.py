"""Behaviour features: what one identity did in one clock hour, as numbers.

The unit of analysis is an activity window: one principal, one clock hour.
The same function turns events into features for the synthetic baseline and
for real events, so the model is always scored on exactly what it was
trained on.

Every feature is a count. Ratios were rejected because they are unstable on
small windows: one failed call out of one is a 100% failure rate, which
would make single, ordinary mistakes look extreme.
"""

from collections import defaultdict
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta

from app.schemas.event import Event

WINDOW = timedelta(hours=1)

# Services that control identity, logging, keys, and security tooling.
# Writes to them change who can do what, or what gets recorded.
SECURITY_SERVICES = frozenset({"iam", "cloudtrail", "organizations", "kms", "guardduty", "config"})

FEATURE_NAMES = (
    "event_count",
    "distinct_actions",
    "distinct_services",
    "failed_calls",
    "write_calls",
    "security_writes",
    "distinct_source_ips",
)

FEATURE_DESCRIPTIONS = {
    "event_count": "API calls",
    "distinct_actions": "different API actions",
    "distinct_services": "different AWS services",
    "failed_calls": "failed calls",
    "write_calls": "write (non-read-only) calls",
    "security_writes": "writes to IAM, CloudTrail, KMS, or other security services",
    "distinct_source_ips": "different source IP addresses",
}


@dataclass(frozen=True)
class ActivityWindow:
    principal: str
    start: datetime
    event_ids: tuple[str, ...]
    features: dict[str, int]

    @property
    def end(self) -> datetime:
        return self.start + WINDOW

    def vector(self) -> list[int]:
        return [self.features[name] for name in FEATURE_NAMES]


def principal_key(event: Event) -> str | None:
    """The stable identity used to group activity: the ARN when present."""
    return event.principal_arn or event.principal


def window_start(timestamp: datetime) -> datetime:
    return timestamp.replace(minute=0, second=0, microsecond=0)


def extract_features(events: Sequence[Event]) -> dict[str, int]:
    # read_only=None means the record did not say; unknown is not counted as a write.
    writes = [event for event in events if event.read_only is False]
    return {
        "event_count": len(events),
        "distinct_actions": len({(event.service, event.event_name) for event in events}),
        "distinct_services": len({event.service for event in events}),
        "failed_calls": sum(1 for event in events if not event.success),
        "write_calls": len(writes),
        "security_writes": sum(1 for event in writes if event.service in SECURITY_SERVICES),
        "distinct_source_ips": len({event.source_ip for event in events if event.source_ip}),
    }


def build_windows(events: Iterable[Event]) -> list[ActivityWindow]:
    """Group events into principal-hour windows, oldest first.

    Events with no identifiable principal are left out: they cannot be
    compared with anyone's normal behaviour.
    """
    grouped: dict[tuple[str, datetime], list[Event]] = defaultdict(list)
    for event in events:
        principal = principal_key(event)
        if principal is not None:
            grouped[(principal, window_start(event.timestamp))].append(event)

    windows = [
        ActivityWindow(
            principal=principal,
            start=start,
            event_ids=tuple(event.event_id for event in window_events),
            features=extract_features(window_events),
        )
        for (principal, start), window_events in grouped.items()
    ]
    return sorted(windows, key=lambda window: (window.start, window.principal))
