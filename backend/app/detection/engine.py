"""Run detectors over a batch of events."""

import logging
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from app.detection.base import Detector
from app.detection.registry import DEFAULT_DETECTORS
from app.schemas.event import Event
from app.schemas.finding import Finding

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class DetectorFailure:
    detector_id: str
    error: str  # the exception type only; messages may contain event data


@dataclass(frozen=True)
class DetectionResult:
    findings: list[Finding]
    failures: list[DetectorFailure]


def run_detectors(
    events: Iterable[Event], detectors: Sequence[Detector] = DEFAULT_DETECTORS
) -> DetectionResult:
    """Run every detector over the same time-ordered events.

    Findings come back sorted by time. A detector that raises is recorded in
    ``failures`` and logged, and the remaining detectors still run: one broken
    rule must not blind all the others, but its failure is never hidden.
    """
    # A tuple, so a detector cannot reorder or modify the list others receive.
    ordered = tuple(sorted(events, key=lambda e: (e.timestamp, e.event_id)))
    findings: list[Finding] = []
    failures: list[DetectorFailure] = []

    for detector in detectors:
        try:
            findings.extend(detector.detect(ordered))
        except Exception as exc:
            logger.exception("detector %r failed", detector.detector_id)
            failures.append(DetectorFailure(detector.detector_id, type(exc).__name__))

    findings.sort(key=lambda f: (f.first_seen, f.detector_id, f.finding_id))
    return DetectionResult(findings=findings, failures=failures)
