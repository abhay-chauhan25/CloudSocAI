"""The detector interface shared by every detection rule.

A detector is deterministic: the same events always produce the same
findings. Detectors only read Events; they never modify them and never keep
state between runs.
"""

from abc import ABC, abstractmethod
from collections.abc import Sequence
from typing import ClassVar

from app.schemas.event import Event
from app.schemas.finding import Finding, Severity, make_finding_id


class Detector(ABC):
    """A rule that turns Events into Findings.

    Subclasses describe themselves with the class attributes below, so every
    detector carries the metadata an analyst needs to judge its output.
    """

    detector_id: ClassVar[str]  # stable and unique, e.g. "root-account-use"
    name: ClassVar[str]
    description: ClassVar[str]  # what triggers it
    rationale: ClassVar[str]  # why it matters, and its known false positives
    severity: ClassVar[Severity]  # default; a rule may adjust it per finding
    mitre_techniques: ClassVar[tuple[str, ...]]  # ATT&CK IDs, empty when none is justified

    @abstractmethod
    def detect(self, events: Sequence[Event]) -> list[Finding]:
        """Return findings for ``events``, which are sorted by timestamp."""

    def build_finding(
        self,
        evidence: Sequence[Event],
        *,
        reason: str,
        severity: Severity | None = None,
        resource: str | None = None,
    ) -> Finding:
        """Create a finding whose actor and time range come from its evidence."""
        first = evidence[0]
        return Finding(
            finding_id=make_finding_id(self.detector_id, (e.event_id for e in evidence)),
            detector_id=self.detector_id,
            title=self.name,
            severity=severity or self.severity,
            reason=reason,
            first_seen=min(e.timestamp for e in evidence),
            last_seen=max(e.timestamp for e in evidence),
            account_id=first.account_id,
            principal=first.principal,
            principal_arn=first.principal_arn,
            resource=resource,
            event_ids=tuple(e.event_id for e in evidence),
        )


class SingleEventDetector(Detector):
    """A detector that judges each event on its own: one match, one finding."""

    def detect(self, events: Sequence[Event]) -> list[Finding]:
        return [
            self.build_finding(
                [event],
                reason=self.explain(event),
                severity=self.severity_for(event),
                resource=self.resource_for(event),
            )
            for event in events
            if self.matches(event)
        ]

    @abstractmethod
    def matches(self, event: Event) -> bool:
        """The trigger logic."""

    @abstractmethod
    def explain(self, event: Event) -> str:
        """Why this event matched, in terms an analyst can verify against the evidence."""

    def severity_for(self, event: Event) -> Severity:
        return self.severity

    def resource_for(self, event: Event) -> str | None:
        return None


def request_param(event: Event, key: str) -> str | None:
    """Read a string from ``request_parameters``, whose shape differs per API.

    Returns None when the parameters, the key, or a string value is missing,
    so rules never crash on an unexpected shape.
    """
    value = (event.request_parameters or {}).get(key)
    return value if isinstance(value, str) else None


def outcome_suffix(event: Event) -> str:
    """Text appended to a reason when the call itself failed."""
    return "" if event.success else f" (the call failed: {event.error_code or 'failure'})"
