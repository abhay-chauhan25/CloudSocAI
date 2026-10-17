"""The posture checks that run by default."""

from app.detection.registry import DETECTORS_BY_ID
from app.posture.base import PostureCheck
from app.posture.checks.cloudtrail import LogFileValidationDisabled, NoMultiRegionTrailLogging
from app.posture.checks.ec2 import AdminPortOpenToInternet
from app.posture.checks.iam import (
    AccessKeyNotRotated,
    ConsoleUserWithoutMfa,
    RootAccessKeysPresent,
    RootMfaDisabled,
)
from app.posture.checks.s3 import BucketPolicyPublic, PublicAccessNotBlocked


def check_unique_ids(checks: list[PostureCheck]) -> tuple[PostureCheck, ...]:
    """Reject duplicate IDs, including clashes with detection rules: both kinds
    of finding are attributed by the same ``detector_id`` column."""
    seen = set(DETECTORS_BY_ID)
    for check in checks:
        if check.check_id in seen:
            raise ValueError(f"duplicate check ID: {check.check_id}")
        seen.add(check.check_id)
    return tuple(checks)


DEFAULT_CHECKS: tuple[PostureCheck, ...] = check_unique_ids(
    [
        RootMfaDisabled(),
        RootAccessKeysPresent(),
        ConsoleUserWithoutMfa(),
        AccessKeyNotRotated(),
        PublicAccessNotBlocked(),
        BucketPolicyPublic(),
        AdminPortOpenToInternet(),
        NoMultiRegionTrailLogging(),
        LogFileValidationDisabled(),
    ]
)

CHECKS_BY_ID: dict[str, PostureCheck] = {c.check_id: c for c in DEFAULT_CHECKS}
