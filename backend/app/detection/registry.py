"""The list of detectors that run by default.

Adding a rule means writing the detector and listing it here; the engine
and the command line pick it up automatically.
"""

from collections.abc import Sequence

from app.detection.base import Detector
from app.detection.rules.account import ConsoleLoginWithoutMfa, RootAccountUse
from app.detection.rules.cloudtrail import CloudTrailLoggingStopped, CloudTrailTrailDeleted
from app.detection.rules.failed_calls import FailedCallBurst
from app.detection.rules.iam import AccessKeyCreated, AdministratorAccessAttached, IamUserCreated


def check_unique_ids(detectors: Sequence[Detector]) -> tuple[Detector, ...]:
    """Reject duplicate detector IDs: findings are attributed to rules by ID."""
    seen: set[str] = set()
    for detector in detectors:
        if detector.detector_id in seen:
            raise ValueError(f"duplicate detector ID: {detector.detector_id}")
        seen.add(detector.detector_id)
    return tuple(detectors)


DEFAULT_DETECTORS: tuple[Detector, ...] = check_unique_ids(
    [
        RootAccountUse(),
        ConsoleLoginWithoutMfa(),
        IamUserCreated(),
        AccessKeyCreated(),
        AdministratorAccessAttached(),
        CloudTrailLoggingStopped(),
        CloudTrailTrailDeleted(),
        FailedCallBurst(),
    ]
)
