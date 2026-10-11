"""Detection of bursts of failed API calls by one principal."""

from collections import defaultdict
from collections.abc import Sequence
from datetime import timedelta

from app.detection.base import Detector
from app.schemas.event import Event
from app.schemas.finding import Finding, Severity

DEFAULT_THRESHOLD = 5
DEFAULT_WINDOW = timedelta(minutes=5)


class FailedCallBurst(Detector):
    detector_id = "failed-call-burst"
    name = "Burst of failed API calls"
    description = (
        f"One principal made {DEFAULT_THRESHOLD} or more failed API calls within "
        f"{int(DEFAULT_WINDOW.total_seconds() // 60)} minutes."
    )
    rationale = (
        "Someone using stolen credentials usually does not know what they are allowed "
        "to do, so they probe many services and get denied repeatedly. A single denied "
        "call is normal. False positives: misconfigured scripts or deployments retrying "
        "a call they lack permission for (usually the same API over and over)."
    )
    severity = Severity.MEDIUM
    # Denials have many causes (discovery, brute force, broken automation), so no
    # single ATT&CK technique is justified for the burst itself.
    mitre_techniques = ()

    def __init__(
        self, threshold: int = DEFAULT_THRESHOLD, window: timedelta = DEFAULT_WINDOW
    ) -> None:
        if threshold < 2:
            raise ValueError("threshold must be at least 2")
        self.threshold = threshold
        self.window = window

    def detect(self, events: Sequence[Event]) -> list[Finding]:
        failures_by_principal: defaultdict[str, list[Event]] = defaultdict(list)
        for event in events:
            principal = event.principal_arn or event.principal
            # A failure with no identifiable actor cannot be attributed to a burst.
            if not event.success and principal is not None:
                failures_by_principal[principal].append(event)

        return [
            self._finding(burst)
            for failures in failures_by_principal.values()
            for burst in self._bursts(failures)
        ]

    def _bursts(self, failures: list[Event]) -> list[list[Event]]:
        """Merge every qualifying sliding window into maximal bursts.

        A window is any run of failures spanning at most ``self.window``. If it
        holds at least ``self.threshold`` failures it qualifies; overlapping
        qualifying windows belong to the same burst, so one continuous attack
        produces one finding rather than one per extra failure.
        """
        bursts: list[list[Event]] = []
        burst_start = burst_end = None
        left = 0
        for right, event in enumerate(failures):
            while event.timestamp - failures[left].timestamp > self.window:
                left += 1
            if right - left + 1 < self.threshold:
                continue
            if burst_end is not None and left <= burst_end:
                burst_end = right  # overlaps the current burst: extend it
            else:
                if burst_start is not None:
                    bursts.append(failures[burst_start : burst_end + 1])
                burst_start, burst_end = left, right
        if burst_start is not None:
            bursts.append(failures[burst_start : burst_end + 1])
        return bursts

    def _finding(self, burst: list[Event]) -> Finding:
        duration = burst[-1].timestamp - burst[0].timestamp
        services = sorted({e.service for e in burst})
        error_codes = sorted({e.error_code or "failure" for e in burst})
        reason = (
            f"{burst[0].principal!r} made {len(burst)} failed API calls in "
            f"{int(duration.total_seconds())} seconds (threshold: {self.threshold} within "
            f"{int(self.window.total_seconds())} seconds) across {len(services)} "
            f"service(s): {', '.join(services)}. Errors: {', '.join(error_codes)}."
        )
        return self.build_finding(burst, reason=reason)
