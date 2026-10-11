"""Explainable risk: the score always equals its factors, and each factor is justified."""

from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from app.collectors.cloudtrail_file import load_cloudtrail_file
from app.detection.engine import run_detectors
from app.normalization.cloudtrail import normalize_cloudtrail_records
from app.risk.scoring import (
    BASE_SEVERITY_POINTS,
    LONG_TERM_KEY_POINTS,
    NEW_SOURCE_IP_POINTS,
    RiskContext,
    score_finding,
)
from app.schemas.event import Event
from app.schemas.finding import Finding, Severity, make_finding_id
from app.schemas.risk import RiskAssessment, RiskFactor

START = datetime(2026, 10, 7, 9, 0, tzinfo=UTC)
TEMPORARY_KEY = "ASIADEVCONSOLEXAMPLE"
LONG_TERM_KEY = "AKIAIOSFODNN7EXAMPLE"


def factor(points: int, name: str = "factor") -> RiskFactor:
    return RiskFactor(name=name, points=points, explanation="test")


_counter = 0


def make_event(
    *, at: datetime, ip: str = "198.51.100.23", key: str = TEMPORARY_KEY, principal: str = "dev"
) -> Event:
    global _counter
    _counter += 1
    fields: dict[str, Any] = {
        "event_id": f"risk-event-{_counter}",
        "source": "cloudtrail",
        "timestamp": at,
        "account_id": "123456789012",
        "service": "iam",
        "event_name": "CreateAccessKey",
        "event_type": "AwsApiCall",
        "read_only": False,
        "region": "us-east-1",
        "principal_type": "IAMUser",
        "principal": principal,
        "principal_arn": f"arn:aws:iam::123456789012:user/{principal}",
        "session_name": None,
        "access_key_id": key,
        "mfa_authenticated": None,
        "source_address": ip,
        "source_ip": ip_address(ip),
        "user_agent": "aws-cli/2.17.0",
        "success": True,
        "error_code": None,
        "error_message": None,
        "request_parameters": None,
        "raw_event": {},
    }
    return Event(**fields)


def finding_for(event: Event, severity: Severity = Severity.MEDIUM) -> Finding:
    return Finding(
        finding_id=make_finding_id("test-rule", [event.event_id]),
        detector_id="test-rule",
        title="Test",
        severity=severity,
        reason="test",
        first_seen=event.timestamp,
        last_seen=event.timestamp,
        account_id=event.account_id,
        principal=event.principal,
        principal_arn=event.principal_arn,
        resource=None,
        event_ids=(event.event_id,),
    )


def score(target: Event, *history: Event, severity: Severity = Severity.MEDIUM) -> RiskAssessment:
    return score_finding(finding_for(target, severity), RiskContext.from_events([*history, target]))


def factor_names(assessment: RiskAssessment) -> list[str]:
    return [f.name for f in assessment.factors]


# --- the RiskAssessment structure ----------------------------------------------


def test_score_is_the_sum_of_its_factors() -> None:
    assert RiskAssessment.from_factors([factor(40), factor(15), factor(5)]).score == 60


def test_score_is_capped_to_0_100() -> None:
    assert RiskAssessment.from_factors([factor(80), factor(30)]).score == 100
    assert RiskAssessment.from_factors([factor(5), factor(-20)]).score == 0


def test_a_score_that_disagrees_with_its_factors_is_rejected() -> None:
    with pytest.raises(ValidationError, match="sum of its factors"):
        RiskAssessment(score=92, factors=(factor(40),))


def test_a_score_without_factors_is_rejected() -> None:
    with pytest.raises(ValidationError):
        RiskAssessment(score=0, factors=())


# --- severity ------------------------------------------------------------------


def test_severities_are_ordered_and_base_points_increase_with_them() -> None:
    ordered = sorted(Severity, key=lambda s: s.rank)

    assert ordered == [
        Severity.INFORMATIONAL,
        Severity.LOW,
        Severity.MEDIUM,
        Severity.HIGH,
        Severity.CRITICAL,
    ]
    points = [BASE_SEVERITY_POINTS[s] for s in ordered]
    assert points == sorted(points)
    assert len(set(points)) == len(points)


@pytest.mark.parametrize("severity", list(Severity))
def test_base_severity_is_always_the_first_factor(severity: Severity) -> None:
    assessment = score(make_event(at=START), severity=severity)

    assert assessment.factors[0].points == BASE_SEVERITY_POINTS[severity]
    assert assessment.score == BASE_SEVERITY_POINTS[severity]


# --- new source IP -------------------------------------------------------------


def test_ip_first_used_after_earlier_activity_is_new() -> None:
    usual = make_event(at=START - timedelta(hours=10))
    unusual = make_event(at=START, ip="203.0.113.50")

    assessment = score(unusual, usual)

    assert factor_names(assessment) == ["Base severity: medium", "New source IP"]
    assert assessment.score == BASE_SEVERITY_POINTS[Severity.MEDIUM] + NEW_SOURCE_IP_POINTS
    assert "first used 203.0.113.50" in assessment.factors[1].explanation


def test_the_usual_ip_is_not_new() -> None:
    earlier = make_event(at=START - timedelta(hours=10))

    assert "New source IP" not in factor_names(score(make_event(at=START), earlier))


def test_no_history_means_no_baseline_not_a_new_ip() -> None:
    assert "New source IP" not in factor_names(score(make_event(at=START, ip="203.0.113.50")))


def test_an_ip_in_use_for_more_than_a_day_is_no_longer_new() -> None:
    usual = make_event(at=START - timedelta(days=5))
    second_ip_first_use = make_event(at=START - timedelta(days=2), ip="203.0.113.50")
    today = make_event(at=START, ip="203.0.113.50")

    assert "New source IP" not in factor_names(score(today, usual, second_ip_first_use))


def test_another_principals_history_is_not_a_baseline() -> None:
    someone_else = make_event(at=START - timedelta(hours=10), principal="other")

    target = make_event(at=START, ip="203.0.113.50")
    assert "New source IP" not in factor_names(score(target, someone_else))


# --- long-term access key ------------------------------------------------------


def test_long_term_key_adds_points_and_masks_the_key() -> None:
    assessment = score(make_event(at=START, key=LONG_TERM_KEY))

    [_, long_term] = assessment.factors
    assert long_term.points == LONG_TERM_KEY_POINTS
    assert "AKIA...MPLE" in long_term.explanation
    assert LONG_TERM_KEY not in long_term.explanation


def test_temporary_or_missing_keys_add_nothing() -> None:
    assert len(score(make_event(at=START, key=TEMPORARY_KEY)).factors) == 1
    assert len(score(make_event(at=START, key="")).factors) == 1


# --- over the fixtures ---------------------------------------------------------


def test_fixture_scores(cloudtrail_samples_dir: Path) -> None:
    events: list[Event] = []
    for path in sorted(cloudtrail_samples_dir.glob("*.json")):
        events += normalize_cloudtrail_records(load_cloudtrail_file(path)).events
    context = RiskContext.from_events(events)

    scores = {
        (f.detector_id, f.resource): score_finding(f, context).score
        for f in run_detectors(events).findings
    }

    # developer's stolen key, from a new IP: base + 15 (new IP) + 5 (long-term key)
    assert scores[("iam-user-created", "svc-backup")] == 20 + 15 + 5
    assert scores[("access-key-created", "svc-backup")] == 40 + 15 + 5
    assert scores[("admin-policy-attached", "user 'svc-backup'")] == 60 + 15 + 5
    # root has no earlier activity (no baseline) and used a console session key
    assert scores[("cloudtrail-trail-deleted", "management-trail")] == 80
    assert scores[("failed-call-burst", None)] == 40 + 15 + 5
