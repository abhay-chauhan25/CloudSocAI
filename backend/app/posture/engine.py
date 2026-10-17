"""Run posture checks over one snapshot."""

import logging
from collections.abc import Sequence
from dataclasses import dataclass

from app.posture.base import PostureCheck
from app.posture.registry import DEFAULT_CHECKS
from app.posture.snapshot import PostureSnapshot
from app.schemas.finding import Finding

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class CheckFailure:
    check_id: str
    error: str  # the exception type only; messages may contain configuration data


@dataclass(frozen=True)
class PostureResult:
    findings: list[Finding]
    passed: list[str]  # check IDs that ran and found nothing
    not_evaluated: list[str]  # check IDs whose snapshot section is missing
    failures: list[CheckFailure]


def run_posture_checks(
    snapshot: PostureSnapshot, checks: Sequence[PostureCheck] = DEFAULT_CHECKS
) -> PostureResult:
    """Run every check whose data is present.

    A check without data is reported as not evaluated, never as passed: a
    collector that lacked permission to read S3 must not make S3 look secure.
    A check that raises is recorded and logged; the others still run.
    """
    findings: list[Finding] = []
    passed: list[str] = []
    not_evaluated: list[str] = []
    failures: list[CheckFailure] = []

    for check in checks:
        if snapshot.section(check.service) is None:
            not_evaluated.append(check.check_id)
            continue
        try:
            results = check.evaluate(snapshot)
        except Exception as exc:
            logger.exception("posture check %r failed", check.check_id)
            failures.append(CheckFailure(check.check_id, type(exc).__name__))
            continue
        findings.extend(results)
        if not results:
            passed.append(check.check_id)

    findings.sort(key=lambda f: (-f.severity.rank, f.detector_id, f.resource or ""))
    return PostureResult(findings, passed, not_evaluated, failures)
