"""Each detection rule: positive and negative cases, plus the edge cases it documents."""

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from app.collectors.cloudtrail_file import load_cloudtrail_file
from app.detection.base import Detector
from app.detection.rules.account import ConsoleLoginWithoutMfa, RootAccountUse
from app.detection.rules.cloudtrail import CloudTrailLoggingStopped, CloudTrailTrailDeleted
from app.detection.rules.failed_calls import FailedCallBurst
from app.detection.rules.iam import (
    AccessKeyCreated,
    AdministratorAccessAttached,
    IamUserCreated,
    is_aws_managed_administrator_access,
)
from app.normalization.cloudtrail import normalize_cloudtrail_record, normalize_cloudtrail_records
from app.schemas.event import Event
from app.schemas.finding import Severity

ACCOUNT = "123456789012"
START = datetime(2026, 10, 7, 14, 0, tzinfo=UTC)
ADMIN_POLICY = "arn:aws:iam::aws:policy/AdministratorAccess"

IAM_USER = {
    "type": "IAMUser",
    "principalId": "AIDAEXAMPLEDEVELOPER1",
    "arn": f"arn:aws:iam::{ACCOUNT}:user/developer",
    "accountId": ACCOUNT,
    "accessKeyId": "AKIAIOSFODNN7EXAMPLE",
    "userName": "developer",
}
ROOT = {
    "type": "Root",
    "principalId": ACCOUNT,
    "arn": f"arn:aws:iam::{ACCOUNT}:root",
    "accountId": ACCOUNT,
    "accessKeyId": "",
}
SSO_ROLE = {
    "type": "AssumedRole",
    "principalId": "AROAEXAMPLESSOADMIN01:alice@example.com",
    "arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/AWSReservedSSO_Admin/alice@example.com",
    "accountId": ACCOUNT,
    "sessionContext": {
        "sessionIssuer": {
            "type": "Role",
            "principalId": "AROAEXAMPLESSOADMIN01",
            "arn": f"arn:aws:iam::{ACCOUNT}:role/AWSReservedSSO_Admin",
            "accountId": ACCOUNT,
            "userName": "AWSReservedSSO_Admin",
        },
        "attributes": {"creationDate": "2026-10-07T14:00:00Z", "mfaAuthenticated": "false"},
    },
}

_counter = 0


def make_event(
    event_name: str = "ListUsers",
    *,
    service: str = "iam",
    identity: dict[str, Any] | None = None,
    params: dict[str, Any] | None = None,
    at: datetime = START,
    error_code: str | None = None,
    **overrides: Any,
) -> Event:
    """Build an Event the way production does: a raw record through the normalizer."""
    global _counter
    _counter += 1
    record: dict[str, Any] = {
        "eventVersion": "1.10",
        "userIdentity": identity or IAM_USER,
        "eventTime": at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "eventSource": f"{service}.amazonaws.com",
        "eventName": event_name,
        "awsRegion": "us-east-1",
        "sourceIPAddress": "203.0.113.50",
        "userAgent": "aws-cli/2.17.0",
        "requestParameters": params,
        "responseElements": None,
        "eventID": f"test-event-{_counter:04d}",
        "readOnly": False,
        "eventType": "AwsApiCall",
        "recipientAccountId": ACCOUNT,
    }
    if error_code is not None:
        record["errorCode"] = error_code
        record["errorMessage"] = "denied"
    record.update(overrides)
    return normalize_cloudtrail_record(record)


def console_login(identity: dict[str, Any], mfa_used: str, *, success: bool = True) -> Event:
    return make_event(
        "ConsoleLogin",
        service="signin",
        identity=identity,
        eventType="AwsConsoleSignIn",
        additionalEventData={"MFAUsed": mfa_used},
        responseElements={"ConsoleLogin": "Success" if success else "Failure"},
    )


def fixture_events(samples_dir: Path, filename: str) -> list[Event]:
    return normalize_cloudtrail_records(load_cloudtrail_file(samples_dir / filename)).events


def detect(detector: Detector, *events: Event) -> list:
    return detector.detect(sorted(events, key=lambda e: e.timestamp))


# --- root-account-use ----------------------------------------------------------


def test_root_api_call_is_detected() -> None:
    [finding] = detect(RootAccountUse(), make_event("DescribeTrails", identity=ROOT))

    assert finding.detector_id == "root-account-use"
    assert finding.severity is Severity.HIGH
    assert finding.principal == "root"
    assert "root user called DescribeTrails" in finding.reason


def test_iam_user_call_is_not_root_use() -> None:
    assert detect(RootAccountUse(), make_event("DescribeTrails")) == []


def test_service_acting_on_roots_behalf_is_not_root_use() -> None:
    on_behalf = {**ROOT, "invokedBy": "support.amazonaws.com"}

    assert detect(RootAccountUse(), make_event("DescribeCases", identity=on_behalf)) == []


def test_failed_root_call_is_still_detected_and_says_so() -> None:
    event = make_event("DeleteTrail", identity=ROOT, error_code="AccessDenied")

    [finding] = detect(RootAccountUse(), event)

    assert "the call failed: AccessDenied" in finding.reason


# --- console-login-without-mfa -------------------------------------------------


def test_iam_user_console_login_without_mfa_is_medium() -> None:
    [finding] = detect(ConsoleLoginWithoutMfa(), console_login(IAM_USER, "No"))

    assert finding.severity is Severity.MEDIUM
    assert finding.principal == "developer"


def test_root_console_login_without_mfa_is_high() -> None:
    [finding] = detect(ConsoleLoginWithoutMfa(), console_login(ROOT, "No"))

    assert finding.severity is Severity.HIGH


def test_console_login_with_mfa_is_not_detected() -> None:
    assert detect(ConsoleLoginWithoutMfa(), console_login(IAM_USER, "Yes")) == []


def test_failed_console_login_without_mfa_is_not_detected() -> None:
    assert detect(ConsoleLoginWithoutMfa(), console_login(IAM_USER, "No", success=False)) == []


def test_federated_sso_login_is_not_detected() -> None:
    # SSO sign-ins report MFAUsed=No even when the identity provider enforced MFA.
    assert detect(ConsoleLoginWithoutMfa(), console_login(SSO_ROLE, "No")) == []


# --- iam-user-created ----------------------------------------------------------


def test_create_user_is_detected_as_low() -> None:
    event = make_event("CreateUser", params={"userName": "svc-backup"})

    [finding] = detect(IamUserCreated(), event)

    assert finding.severity is Severity.LOW
    assert finding.resource == "svc-backup"
    assert finding.reason == "'developer' created the IAM user 'svc-backup'."


def test_failed_or_unrelated_user_calls_are_not_detected() -> None:
    failed = make_event("CreateUser", params={"userName": "x"}, error_code="AccessDenied")
    other = make_event("DeleteUser", params={"userName": "x"})

    assert detect(IamUserCreated(), failed, other) == []


# --- access-key-created --------------------------------------------------------


def test_access_key_for_another_user_is_detected() -> None:
    event = make_event("CreateAccessKey", params={"userName": "svc-backup"})

    [finding] = detect(AccessKeyCreated(), event)

    assert finding.severity is Severity.MEDIUM
    assert finding.resource == "svc-backup"
    assert "for a different user, 'svc-backup'" in finding.reason


def test_access_key_for_self_is_detected_and_described() -> None:
    [finding] = detect(AccessKeyCreated(), make_event("CreateAccessKey"))

    assert finding.resource == "developer"
    assert "for themselves" in finding.reason


def test_root_access_key_is_high() -> None:
    [finding] = detect(AccessKeyCreated(), make_event("CreateAccessKey", identity=ROOT))

    assert finding.severity is Severity.HIGH
    assert "for the root user" in finding.reason


def test_failed_or_other_key_calls_are_not_detected() -> None:
    failed = make_event("CreateAccessKey", error_code="AccessDenied")
    listing = make_event("ListAccessKeys")

    assert detect(AccessKeyCreated(), failed, listing) == []


# --- admin-policy-attached -----------------------------------------------------


@pytest.mark.parametrize(
    ("event_name", "target_key", "expected_resource"),
    [
        ("AttachUserPolicy", "userName", "user 'target'"),
        ("AttachGroupPolicy", "groupName", "group 'target'"),
        ("AttachRolePolicy", "roleName", "role 'target'"),
    ],
)
def test_admin_policy_attached_to_any_identity_is_detected(
    event_name: str, target_key: str, expected_resource: str
) -> None:
    event = make_event(event_name, params={target_key: "target", "policyArn": ADMIN_POLICY})

    [finding] = detect(AdministratorAccessAttached(), event)

    assert finding.severity is Severity.HIGH
    assert finding.resource == expected_resource


def test_other_policies_and_failed_attaches_are_not_detected() -> None:
    read_only = make_event(
        "AttachUserPolicy",
        params={"userName": "intern-bob", "policyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"},
    )
    failed = make_event(
        "AttachUserPolicy",
        params={"userName": "x", "policyArn": ADMIN_POLICY},
        error_code="AccessDenied",
    )
    detached = make_event("DetachUserPolicy", params={"userName": "x", "policyArn": ADMIN_POLICY})

    assert detect(AdministratorAccessAttached(), read_only, failed, detached) == []


def test_attach_without_parameters_does_not_crash() -> None:
    assert detect(AdministratorAccessAttached(), make_event("AttachUserPolicy")) == []


@pytest.mark.parametrize(
    ("arn", "expected"),
    [
        ("arn:aws:iam::aws:policy/AdministratorAccess", True),
        ("arn:aws-us-gov:iam::aws:policy/AdministratorAccess", True),
        # A customer-managed policy that merely has the same name.
        (f"arn:aws:iam::{ACCOUNT}:policy/AdministratorAccess", False),
        ("arn:aws:iam::aws:policy/AdministratorAccess-Amplify", False),
        ("AdministratorAccess", False),
    ],
)
def test_administrator_access_arn_matching(arn: str, expected: bool) -> None:
    assert is_aws_managed_administrator_access(arn) is expected


# --- cloudtrail-logging-stopped / cloudtrail-trail-deleted ---------------------


@pytest.mark.parametrize(
    ("detector", "event_name"),
    [(CloudTrailLoggingStopped(), "StopLogging"), (CloudTrailTrailDeleted(), "DeleteTrail")],
)
def test_trail_tampering_is_critical(detector: Detector, event_name: str) -> None:
    event = make_event(event_name, service="cloudtrail", params={"name": "management-trail"})

    [finding] = detect(detector, event)

    assert finding.severity is Severity.CRITICAL
    assert finding.resource == "management-trail"
    assert detector.mitre_techniques == ("T1562.008",)


@pytest.mark.parametrize(
    ("detector", "event_name"),
    [(CloudTrailLoggingStopped(), "StopLogging"), (CloudTrailTrailDeleted(), "DeleteTrail")],
)
def test_failed_trail_tampering_attempt_is_high(detector: Detector, event_name: str) -> None:
    event = make_event(
        event_name, service="cloudtrail", params={"name": "t"}, error_code="AccessDenied"
    )

    [finding] = detect(detector, event)

    assert finding.severity is Severity.HIGH
    assert "the call failed: AccessDenied" in finding.reason


@pytest.mark.parametrize("detector", [CloudTrailLoggingStopped(), CloudTrailTrailDeleted()])
def test_reading_or_starting_trails_is_not_tampering(detector: Detector) -> None:
    events = [
        make_event(name, service="cloudtrail", params={"name": "t"})
        for name in ("DescribeTrails", "StartLogging", "CreateTrail")
    ]

    assert detect(detector, *events) == []


# --- failed-call-burst ---------------------------------------------------------


def failures(count: int, *, every: timedelta, identity: dict[str, Any] = IAM_USER) -> list[Event]:
    return [
        make_event("ListUsers", identity=identity, at=START + i * every, error_code="AccessDenied")
        for i in range(count)
    ]


def test_five_failures_within_five_minutes_is_a_burst() -> None:
    events = failures(5, every=timedelta(minutes=1))  # spans exactly 4 minutes

    [finding] = detect(FailedCallBurst(), *events)

    assert finding.severity is Severity.MEDIUM
    assert finding.event_ids == tuple(e.event_id for e in events)
    assert (finding.first_seen, finding.last_seen) == (START, START + timedelta(minutes=4))
    assert "made 5 failed API calls in 240 seconds" in finding.reason


def test_four_failures_is_below_the_threshold() -> None:
    assert detect(FailedCallBurst(), *failures(4, every=timedelta(seconds=1))) == []


def test_failures_spread_beyond_the_window_are_not_a_burst() -> None:
    assert detect(FailedCallBurst(), *failures(5, every=timedelta(minutes=2))) == []


def test_successful_calls_do_not_count() -> None:
    events = failures(4, every=timedelta(seconds=1)) + [
        make_event("ListUsers", at=START + timedelta(seconds=10))
    ]

    assert detect(FailedCallBurst(), *events) == []


def test_failures_by_different_principals_are_not_combined() -> None:
    other_user = {**IAM_USER, "arn": f"arn:aws:iam::{ACCOUNT}:user/other", "userName": "other"}
    events = failures(3, every=timedelta(seconds=1)) + failures(
        3, every=timedelta(seconds=1), identity=other_user
    )

    assert detect(FailedCallBurst(), *events) == []


def test_one_continuous_burst_is_one_finding() -> None:
    # 20 failures, one every 30 seconds: every 5-minute window qualifies and they
    # all overlap, so this is a single burst, not 16 overlapping findings.
    [finding] = detect(FailedCallBurst(), *failures(20, every=timedelta(seconds=30)))

    assert len(finding.event_ids) == 20


def test_separate_bursts_are_separate_findings() -> None:
    first = failures(5, every=timedelta(seconds=1))
    later = [
        make_event("ListUsers", at=START + timedelta(hours=1, seconds=i), error_code="Denied")
        for i in range(5)
    ]

    findings = detect(FailedCallBurst(), *first, *later)

    assert [len(f.event_ids) for f in findings] == [5, 5]


def test_threshold_and_window_are_configurable() -> None:
    detector = FailedCallBurst(threshold=3, window=timedelta(seconds=10))

    assert len(detect(detector, *failures(3, every=timedelta(seconds=5)))) == 1
    assert detect(detector, *failures(3, every=timedelta(seconds=6))) == []


def test_threshold_below_two_is_rejected() -> None:
    with pytest.raises(ValueError, match="at least 2"):
        FailedCallBurst(threshold=1)


def test_fixture_burst_is_detected(cloudtrail_samples_dir: Path) -> None:
    events = fixture_events(cloudtrail_samples_dir, "failed-api-burst.json")

    [finding] = FailedCallBurst().detect(events)

    assert finding.principal == "ci-deploy"
    assert len(finding.event_ids) == 7
    assert "across 6 service(s)" in finding.reason


@pytest.mark.parametrize("filename", ["normal-user-activity.json", "iam-privilege-change.json"])
def test_single_benign_failures_are_not_a_burst(
    cloudtrail_samples_dir: Path, filename: str
) -> None:
    assert FailedCallBurst().detect(fixture_events(cloudtrail_samples_dir, filename)) == []
