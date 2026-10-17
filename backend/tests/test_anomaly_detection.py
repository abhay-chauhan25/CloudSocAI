"""Behaviour anomaly detection: features, reproducibility, evaluation, and false positives."""

from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from typing import Any

import pytest
from pydantic import ValidationError

from app.ml.baseline import generate_baseline
from app.ml.evaluate import evaluate
from app.ml.features import FEATURE_NAMES, build_windows, extract_features
from app.ml.model import default_model, score_windows, train
from app.schemas.anomaly import AnomalyScore
from app.schemas.event import Event

HOUR = datetime(2026, 10, 8, 14, 0, tzinfo=UTC)
_counter = 0


def call(
    service: str,
    name: str,
    *,
    read_only: bool | None = True,
    success: bool = True,
    principal: str | None = "dev",
    at: datetime = HOUR,
    ip: str = "198.51.100.23",
) -> Event:
    global _counter
    _counter += 1
    fields: dict[str, Any] = {
        "event_id": f"ml-event-{_counter}",
        "source": "cloudtrail",
        "timestamp": at,
        "account_id": "123456789012",
        "service": service,
        "event_name": name,
        "event_type": "AwsApiCall",
        "read_only": read_only,
        "region": "us-east-1",
        "principal_type": "IAMUser",
        "principal": principal,
        "principal_arn": f"arn:aws:iam::123456789012:user/{principal}" if principal else None,
        "session_name": None,
        "access_key_id": None,
        "mfa_authenticated": None,
        "source_address": ip,
        "source_ip": ip_address(ip),
        "user_agent": "aws-cli/2.17.0",
        "success": success,
        "error_code": None if success else "AccessDenied",
        "error_message": None,
        "request_parameters": None,
        "raw_event": {},
    }
    return Event(**fields)


def score_of(events: list[Event]) -> AnomalyScore:
    [score] = score_windows(default_model(), build_windows(events))
    return score


# --- features ------------------------------------------------------------------


def test_features_count_what_happened_in_the_window() -> None:
    events = [
        call("s3", "ListBuckets"),
        call("s3", "ListBuckets", ip="203.0.113.9"),
        call("iam", "CreateUser", read_only=False),
        call("iam", "AttachUserPolicy", read_only=False, success=False),
        call("ec2", "StartInstances", read_only=False),
    ]

    assert extract_features(events) == {
        "event_count": 5,
        "distinct_actions": 4,
        "distinct_services": 3,
        "failed_calls": 1,
        "write_calls": 3,
        "security_writes": 2,
        "distinct_source_ips": 2,
    }


def test_unknown_read_only_is_not_counted_as_a_write() -> None:
    features = extract_features([call("iam", "Mystery", read_only=None)])

    assert (features["write_calls"], features["security_writes"]) == (0, 0)


def test_windows_group_by_principal_and_clock_hour() -> None:
    events = [
        call("s3", "GetObject", at=HOUR + timedelta(minutes=59)),
        call("s3", "GetObject", at=HOUR + timedelta(minutes=5)),
        call("s3", "GetObject", at=HOUR + timedelta(hours=1)),  # next hour
        call("s3", "GetObject", principal="ops"),
        call("s3", "GetObject", principal=None),  # cannot be attributed: left out
    ]

    windows = build_windows(events)

    assert [
        (w.principal.rsplit("/", 1)[-1], w.start, w.features["event_count"]) for w in windows
    ] == [
        ("dev", HOUR, 2),
        ("ops", HOUR, 1),
        ("dev", HOUR + timedelta(hours=1), 1),
    ]
    assert windows[0].end == HOUR + timedelta(hours=1)
    assert len(windows[0].vector()) == len(FEATURE_NAMES)


def test_features_are_identical_for_identical_events() -> None:
    events = [call("s3", "GetObject"), call("iam", "CreateUser", read_only=False)]

    assert build_windows(events) == build_windows(list(events))


# --- reproducibility -----------------------------------------------------------


def test_the_baseline_is_reproducible_from_its_seed() -> None:
    assert generate_baseline(50, seed=1) == generate_baseline(50, seed=1)
    assert generate_baseline(50, seed=1) != generate_baseline(50, seed=2)


def test_training_twice_with_the_same_seed_gives_identical_scores() -> None:
    windows = build_windows(generate_baseline(100, seed=99))

    first, second = train(windows=500, seed=3), train(windows=500, seed=3)

    assert first.threshold == second.threshold
    assert score_windows(first, windows) == score_windows(second, windows)


def test_scores_are_probabilities_of_isolation_between_zero_and_one() -> None:
    windows = build_windows(generate_baseline(200, seed=5))

    scores = score_windows(default_model(), windows)

    assert all(0 < s.score <= 1 for s in scores)
    assert all(s.is_anomalous == (s.score > s.threshold) for s in scores)


# --- evaluation ----------------------------------------------------------------


def test_the_threshold_flags_about_five_percent_of_fresh_normal_hours() -> None:
    evaluation = evaluate(default_model())

    assert 0.03 <= evaluation.holdout_false_positive_rate <= 0.08


def test_every_scenario_attack_hour_is_flagged_and_no_ordinary_hour_is() -> None:
    evaluation = evaluate(default_model())

    assert [s.is_anomalous for s in evaluation.attacks()] == [True, True, True]
    assert not any(s.is_anomalous for s in evaluation.ordinary())


def test_explanations_name_the_features_that_stood_out() -> None:
    evaluation = evaluate(default_model())
    by_principal = {s.principal.rsplit(":", 1)[-1]: s for s in evaluation.attacks()}

    burst = by_principal["user/ci-deploy"]
    assert [f.name for f in burst.unusual_features] == ["failed_calls"]
    assert "failed_calls 7 (normally at most 3)" in burst.describe()
    # The root hour is unusual only as a combination; the explanation says so.
    root = by_principal["root"]
    assert root.unusual_features == ()
    assert "unusual combination of features" in root.describe()


# --- false positives and negatives ---------------------------------------------


def test_a_routine_pipeline_hour_is_not_flagged() -> None:
    events = [call("s3", "PutObject", read_only=False) for _ in range(30)]
    events += [call("ecr", "BatchGetImage") for _ in range(30)]

    assert not score_of(events).is_anomalous


def test_a_deploy_surge_is_flagged_a_known_false_positive() -> None:
    # Far more writes than any baseline hour: unusual, though not malicious.
    events = [call("s3", "PutObject", read_only=False) for _ in range(150)]

    score = score_of(events)

    assert score.is_anomalous
    assert "write_calls" in [f.name for f in score.unusual_features]


def test_a_single_admin_change_is_not_flagged() -> None:
    assert not score_of([call("iam", "AttachUserPolicy", read_only=False)]).is_anomalous


def test_a_developer_retrying_a_denied_call_is_flagged_a_known_false_positive() -> None:
    # Benign, but behaviourally identical to probing: this is why the anomaly
    # signal only adds risk to rule findings and never alerts on its own.
    events = [call("s3", "ListBuckets")] + [
        call("ec2", "StartInstances", read_only=False, success=False) for _ in range(6)
    ]

    assert score_of(events).is_anomalous


def test_a_quiet_attacker_hour_is_not_flagged_a_known_false_negative() -> None:
    # One read with a stolen key looks like any ordinary hour.
    assert not score_of([call("sts", "GetCallerIdentity", principal="svc-backup")]).is_anomalous


# --- schema --------------------------------------------------------------------


def test_scores_outside_zero_to_one_are_rejected() -> None:
    valid = score_of([call("s3", "GetObject")])

    with pytest.raises(ValidationError):
        AnomalyScore(**(valid.model_dump() | {"score": 1.5}))
