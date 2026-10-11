"""The Finding model: validation, immutability, and deterministic IDs."""

from datetime import UTC, datetime, timedelta, timezone
from typing import Any

import pytest
from pydantic import ValidationError

from app.schemas.finding import Finding, Severity, make_finding_id

SEEN = datetime(2026, 10, 6, 3, 5, tzinfo=UTC)


def make_finding(**overrides: Any) -> Finding:
    fields: dict[str, Any] = {
        "finding_id": make_finding_id("access-key-created", ["event-1"]),
        "detector_id": "access-key-created",
        "title": "Access key created",
        "severity": Severity.MEDIUM,
        "reason": "'developer' created an access key for a different user, 'svc-backup'.",
        "first_seen": SEEN,
        "last_seen": SEEN,
        "account_id": "123456789012",
        "principal": "developer",
        "principal_arn": "arn:aws:iam::123456789012:user/developer",
        "resource": "svc-backup",
        "event_ids": ("event-1",),
    }
    fields.update(overrides)
    return Finding(**fields)


def test_finding_id_is_deterministic_and_ignores_evidence_order() -> None:
    assert make_finding_id("d", ["a", "b"]) == make_finding_id("d", ["b", "a"])


def test_finding_id_differs_by_detector_and_by_evidence() -> None:
    ids = {
        make_finding_id("detector-a", ["e1"]),
        make_finding_id("detector-b", ["e1"]),
        make_finding_id("detector-a", ["e2"]),
        make_finding_id("detector-a", ["e1", "e2"]),
    }

    assert len(ids) == 4


def test_times_are_converted_to_utc() -> None:
    plus_two = timezone(timedelta(hours=2))
    finding = make_finding(
        first_seen=datetime(2026, 10, 6, 5, 5, tzinfo=plus_two),
        last_seen=datetime(2026, 10, 6, 5, 5, tzinfo=plus_two),
    )

    assert finding.first_seen == SEEN
    assert finding.first_seen.tzinfo == UTC


def test_naive_times_are_rejected() -> None:
    with pytest.raises(ValidationError, match="timezone"):
        make_finding(first_seen=datetime(2026, 10, 6, 3, 5))


def test_last_seen_before_first_seen_is_rejected() -> None:
    with pytest.raises(ValidationError, match="last_seen"):
        make_finding(last_seen=SEEN - timedelta(seconds=1))


def test_posture_findings_may_have_no_evidence_events() -> None:
    assert make_finding(event_ids=()).event_ids == ()


def test_unknown_severity_and_extra_fields_are_rejected() -> None:
    with pytest.raises(ValidationError):
        make_finding(severity="severe")
    with pytest.raises(ValidationError):
        make_finding(risk_score=90)


def test_findings_are_immutable() -> None:
    finding = make_finding()

    with pytest.raises(ValidationError):
        finding.severity = Severity.LOW  # type: ignore[misc]
