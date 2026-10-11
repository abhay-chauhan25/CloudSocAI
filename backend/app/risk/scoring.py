"""Explainable risk scoring for findings.

Risk = base points for the finding's severity + points for context factors,
capped to 0-100. Every factor that contributes is recorded with the evidence
behind it, so an analyst can rebuild the score by hand.

Severity is the rule's judgement of the behaviour; context factors describe
this particular occurrence. A factor is only added when the rule's severity
does not already account for it — counting the same evidence twice would
inflate the score without adding information.
"""

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta
from ipaddress import IPv4Address, IPv6Address

from app.schemas.event import Event
from app.schemas.finding import Finding, Severity
from app.schemas.risk import RiskAssessment, RiskFactor

BASE_SEVERITY_POINTS = {
    Severity.INFORMATIONAL: 5,
    Severity.LOW: 20,
    Severity.MEDIUM: 40,
    Severity.HIGH: 60,
    Severity.CRITICAL: 80,
}
NEW_SOURCE_IP_POINTS = 15
LONG_TERM_KEY_POINTS = 5

# An address counts as "new" for this long after a principal first uses it.
NEW_SOURCE_IP_PERIOD = timedelta(hours=24)

IpAddress = IPv4Address | IPv6Address


@dataclass(frozen=True)
class RiskContext:
    """What scoring knows beyond the finding itself: the events it can look up.

    The baseline is only as good as the stored history. With little history,
    fewer "new source IP" factors apply — absence of a baseline is treated as
    unknown, never as suspicious.
    """

    events_by_id: dict[str, Event]
    first_activity: dict[str, datetime]  # principal -> earliest event
    first_use_of_ip: dict[tuple[str, IpAddress], datetime]  # (principal, ip) -> earliest event

    @classmethod
    def from_events(cls, events: Iterable[Event]) -> "RiskContext":
        events_by_id: dict[str, Event] = {}
        first_activity: dict[str, datetime] = {}
        first_use_of_ip: dict[tuple[str, IpAddress], datetime] = {}
        for event in events:
            events_by_id[event.event_id] = event
            principal = _principal_key(event)
            if principal is None:
                continue
            first_activity[principal] = min(
                event.timestamp, first_activity.get(principal, event.timestamp)
            )
            if event.source_ip is not None:
                key = (principal, event.source_ip)
                earliest = first_use_of_ip.get(key, event.timestamp)
                first_use_of_ip[key] = min(event.timestamp, earliest)
        return cls(events_by_id, first_activity, first_use_of_ip)

    def evidence(self, finding: Finding) -> list[Event]:
        return [self.events_by_id[i] for i in finding.event_ids if i in self.events_by_id]


def score_finding(finding: Finding, context: RiskContext) -> RiskAssessment:
    evidence = context.evidence(finding)
    factors = [
        RiskFactor(
            name=f"Base severity: {finding.severity}",
            points=BASE_SEVERITY_POINTS[finding.severity],
            explanation=f"The {finding.detector_id} rule rates this behaviour {finding.severity}.",
        )
    ]
    for factor in (_new_source_ip(evidence, context), _long_term_key(evidence)):
        if factor is not None:
            factors.append(factor)
    return RiskAssessment.from_factors(factors)


def _new_source_ip(evidence: list[Event], context: RiskContext) -> RiskFactor | None:
    """The actor used an IP address they had not used before, recently.

    Requires a baseline: the principal must have activity from before the
    address first appeared. Otherwise "new" cannot be distinguished from
    "first time we have seen this principal at all".
    """
    for event in evidence:
        principal = _principal_key(event)
        if principal is None or event.source_ip is None:
            continue
        first_use = context.first_use_of_ip.get((principal, event.source_ip))
        if first_use is None:
            continue
        has_baseline = context.first_activity[principal] < first_use
        is_recent = event.timestamp - first_use <= NEW_SOURCE_IP_PERIOD
        if has_baseline and is_recent:
            return RiskFactor(
                name="New source IP",
                points=NEW_SOURCE_IP_POINTS,
                explanation=(
                    f"{event.principal!r} first used {event.source_ip} at "
                    f"{first_use:%Y-%m-%d %H:%M:%S}Z; their earlier activity came from "
                    "other addresses."
                ),
            )
    return None


def _long_term_key(evidence: list[Event]) -> RiskFactor | None:
    """The actions used a long-term access key (AKIA...).

    Long-term keys never expire on their own and are the credential most
    often leaked (in code, CI logs, laptops). Console and role sessions use
    temporary ASIA... keys instead.
    """
    for event in evidence:
        if event.access_key_id and event.access_key_id.startswith("AKIA"):
            return RiskFactor(
                name="Long-term access key",
                points=LONG_TERM_KEY_POINTS,
                explanation=(
                    f"{event.principal!r} acted with long-term access key "
                    f"{_mask(event.access_key_id)}, which does not expire on its own."
                ),
            )
    return None


def _principal_key(event: Event) -> str | None:
    return event.principal_arn or event.principal


def _mask(access_key_id: str) -> str:
    """Show only the prefix and last four characters, as the AWS console does."""
    return f"{access_key_id[:4]}...{access_key_id[-4:]}"
