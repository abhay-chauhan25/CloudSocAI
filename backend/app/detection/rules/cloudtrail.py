"""Detections for tampering with CloudTrail, the account's audit log."""

from typing import ClassVar

from app.detection.base import SingleEventDetector, outcome_suffix, request_param
from app.schemas.event import Event
from app.schemas.finding import Severity


class _TrailTamperingDetector(SingleEventDetector):
    """Shared logic: one CloudTrail API call that weakens logging.

    A successful call is critical. A failed attempt is still high: someone
    tried to blind the defenders, and only lacked permission.
    """

    trail_event_name: ClassVar[str]
    severity = Severity.CRITICAL
    mitre_techniques = ("T1562.008",)  # Impair Defenses: Disable or Modify Cloud Logs

    def matches(self, event: Event) -> bool:
        return event.service == "cloudtrail" and event.event_name == self.trail_event_name

    def explain(self, event: Event) -> str:
        return (
            f"{event.principal!r} called {event.event_name} on trail "
            f"{self.resource_for(event)!r}{outcome_suffix(event)}."
        )

    def severity_for(self, event: Event) -> Severity:
        return self.severity if event.success else Severity.HIGH

    def resource_for(self, event: Event) -> str | None:
        return request_param(event, "name")  # the trail's name or ARN


class CloudTrailLoggingStopped(_TrailTamperingDetector):
    detector_id = "cloudtrail-logging-stopped"
    name = "CloudTrail logging stopped"
    trail_event_name = "StopLogging"
    description = "Logging was stopped (or an attempt was made) on a CloudTrail trail."
    rationale = (
        "Attackers stop logging so their next actions leave no audit trail. The "
        "StopLogging call itself is still recorded. False positives: a planned trail "
        "migration or teardown of a test environment, which should be announced."
    )


class CloudTrailTrailDeleted(_TrailTamperingDetector):
    detector_id = "cloudtrail-trail-deleted"
    name = "CloudTrail trail deleted"
    trail_event_name = "DeleteTrail"
    description = "A CloudTrail trail was deleted (or an attempt was made)."
    rationale = (
        "Deleting a trail stops logging and removes its configuration, making the gap "
        "harder to undo than StopLogging. False positives: planned decommissioning, "
        "for example tearing down a lab environment."
    )
