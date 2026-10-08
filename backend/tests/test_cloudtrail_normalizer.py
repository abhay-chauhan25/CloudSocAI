"""CloudTrail -> Event normalization: fixtures, identities, sources, outcomes, bad input."""

import copy
from datetime import UTC, datetime
from ipaddress import IPv4Address, IPv6Address
from pathlib import Path
from typing import Any

import pytest

from app.collectors.cloudtrail_file import load_cloudtrail_file
from app.normalization.cloudtrail import (
    NormalizationError,
    normalize_cloudtrail_record,
    normalize_cloudtrail_records,
)
from app.schemas.event import Event, PrincipalType

ACCOUNT = "123456789012"


def make_record(**overrides: Any) -> dict[str, Any]:
    """A minimal valid CloudTrail record; tests override only what they exercise."""
    record: dict[str, Any] = {
        "eventVersion": "1.10",
        "userIdentity": {
            "type": "IAMUser",
            "principalId": "AIDAEXAMPLEDEVELOPER1",
            "arn": f"arn:aws:iam::{ACCOUNT}:user/developer",
            "accountId": ACCOUNT,
            "accessKeyId": "AKIAIOSFODNN7EXAMPLE",
            "userName": "developer",
        },
        "eventTime": "2026-10-05T09:00:00Z",
        "eventSource": "iam.amazonaws.com",
        "eventName": "ListUsers",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "198.51.100.23",
        "userAgent": "aws-cli/2.17.0",
        "requestParameters": None,
        "responseElements": None,
        "eventID": "11111111-1111-4111-8111-111111111111",
        "readOnly": True,
        "eventType": "AwsApiCall",
        "recipientAccountId": ACCOUNT,
    }
    record.update(overrides)
    return record


def normalize(**overrides: Any) -> Event:
    return normalize_cloudtrail_record(make_record(**overrides))


def load_events(samples_dir: Path, filename: str) -> list[Event]:
    result = normalize_cloudtrail_records(load_cloudtrail_file(samples_dir / filename))
    assert result.errors == []
    return result.events


# --- fixtures normalize end to end ---------------------------------------------


@pytest.mark.parametrize(
    "filename",
    ["normal-user-activity.json", "iam-privilege-change.json", "cloudtrail-disabled.json"],
)
def test_every_fixture_record_normalizes(cloudtrail_samples_dir: Path, filename: str) -> None:
    records = load_cloudtrail_file(cloudtrail_samples_dir / filename)

    result = normalize_cloudtrail_records(records)

    assert result.errors == []
    assert [e.event_id for e in result.events] == [r["eventID"] for r in records]


def test_iam_attack_is_normalized_for_detection(cloudtrail_samples_dir: Path) -> None:
    events = load_events(cloudtrail_samples_dir, "iam-privilege-change.json")
    [attach] = [e for e in events if e.event_name == "AttachUserPolicy"]

    assert attach.service == "iam"
    assert attach.principal_type is PrincipalType.IAM_USER
    assert attach.principal == "developer"
    assert attach.source_ip == IPv4Address("203.0.113.50")
    assert attach.access_key_id == "AKIAIOSFODNN7EXAMPLE"
    assert attach.request_parameters == {
        "userName": "svc-backup",
        "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
    }


def test_tampering_events_are_root_without_mfa(cloudtrail_samples_dir: Path) -> None:
    events = load_events(cloudtrail_samples_dir, "cloudtrail-disabled.json")

    assert {(e.principal_type, e.principal, e.mfa_authenticated) for e in events} == {
        (PrincipalType.ROOT, "root", False)
    }
    assert [e.event_name for e in events if e.service == "cloudtrail" and not e.read_only] == [
        "StopLogging",
        "DeleteTrail",
    ]


def test_raw_record_is_preserved_unchanged() -> None:
    record = make_record()
    original = copy.deepcopy(record)

    event = normalize_cloudtrail_record(record)

    assert event.raw_event == original
    assert record == original


# --- identity (Task 17) --------------------------------------------------------


def test_root_identity() -> None:
    event = normalize(
        userIdentity={
            "type": "Root",
            "principalId": ACCOUNT,
            "arn": f"arn:aws:iam::{ACCOUNT}:root",
            "accountId": ACCOUNT,
            "accessKeyId": "",
        }
    )

    assert event.principal_type is PrincipalType.ROOT
    assert event.principal == "root"
    assert event.principal_arn == f"arn:aws:iam::{ACCOUNT}:root"
    assert event.access_key_id is None  # "" means no key, not a key called ""


def test_iam_user_identity() -> None:
    event = normalize()

    assert event.principal_type is PrincipalType.IAM_USER
    assert event.principal == "developer"
    assert event.principal_arn == f"arn:aws:iam::{ACCOUNT}:user/developer"
    assert event.session_name is None


def test_assumed_role_uses_stable_role_identity() -> None:
    event = normalize(
        userIdentity={
            "type": "AssumedRole",
            "principalId": "AROAEXAMPLEREPORTGEN1:report-generator",
            "arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/report-generator-role/report-generator",
            "accountId": ACCOUNT,
            "accessKeyId": "ASIAEXAMPLEREPORTGEN",
            "sessionContext": {
                "sessionIssuer": {
                    "type": "Role",
                    "arn": f"arn:aws:iam::{ACCOUNT}:role/report-generator-role",
                    "userName": "report-generator-role",
                },
                "attributes": {"mfaAuthenticated": "false"},
            },
        }
    )

    assert event.principal_type is PrincipalType.ASSUMED_ROLE
    assert event.principal == "report-generator-role"
    assert event.principal_arn == f"arn:aws:iam::{ACCOUNT}:role/report-generator-role"
    assert event.session_name == "report-generator"
    assert event.mfa_authenticated is False


def test_federated_user_identity() -> None:
    event = normalize(
        userIdentity={
            "type": "FederatedUser",
            "arn": f"arn:aws:sts::{ACCOUNT}:federated-user/contractor-dana",
            "accountId": ACCOUNT,
        }
    )

    assert event.principal_type is PrincipalType.FEDERATED_USER
    assert event.principal == "contractor-dana"


def test_aws_service_identity() -> None:
    event = normalize(userIdentity={"type": "AWSService", "invokedBy": "lambda.amazonaws.com"})

    assert event.principal_type is PrincipalType.AWS_SERVICE
    assert event.principal == "lambda.amazonaws.com"
    assert event.principal_arn is None


def test_cross_account_identity() -> None:
    event = normalize(
        userIdentity={
            "type": "AWSAccount",
            "principalId": "AIDAEXAMPLEOTHER",
            "accountId": "111122223333",
        }
    )

    assert event.principal_type is PrincipalType.AWS_ACCOUNT
    assert event.principal == "111122223333"


@pytest.mark.parametrize("raw_type", ["IdentityCenterUser", None, 42])
def test_unrecognized_identity_type_is_kept_as_unknown(raw_type: Any) -> None:
    identity = {"type": raw_type, "arn": f"arn:aws:iam::{ACCOUNT}:user/someone"}

    event = normalize(userIdentity=identity)

    assert event.principal_type is PrincipalType.UNKNOWN
    assert event.principal == f"arn:aws:iam::{ACCOUNT}:user/someone"
    assert event.raw_event["userIdentity"]["type"] == raw_type


@pytest.mark.parametrize(
    ("mfa_used", "expected"),
    [("Yes", True), ("No", False)],
)
def test_console_login_mfa(mfa_used: str, expected: bool) -> None:
    event = normalize(
        eventName="ConsoleLogin",
        eventSource="signin.amazonaws.com",
        additionalEventData={"MFAUsed": mfa_used},
        responseElements={"ConsoleLogin": "Success"},
    )

    assert event.mfa_authenticated is expected


def test_mfa_is_unknown_when_not_recorded() -> None:
    # Long-term access key calls carry no session context: MFA is unknown, not "no".
    assert normalize().mfa_authenticated is None


def test_unexpected_mfa_value_is_an_error() -> None:
    with pytest.raises(NormalizationError, match="unexpected MFA value 'maybe'"):
        normalize(
            eventName="ConsoleLogin",
            additionalEventData={"MFAUsed": "maybe"},
            responseElements={"ConsoleLogin": "Success"},
        )


# --- source IP / region / service (Task 18) ------------------------------------


@pytest.mark.parametrize(
    ("source", "expected_ip"),
    [
        ("203.0.113.50", IPv4Address("203.0.113.50")),
        ("2001:db8::1", IPv6Address("2001:db8::1")),
        ("lambda.amazonaws.com", None),
        ("AWS Internal", None),
    ],
)
def test_source_address_is_parsed_only_when_it_is_an_ip(source: str, expected_ip: Any) -> None:
    event = normalize(sourceIPAddress=source)

    assert event.source_address == source
    assert event.source_ip == expected_ip


def test_missing_source_address() -> None:
    record = make_record()
    del record["sourceIPAddress"]

    event = normalize_cloudtrail_record(record)

    assert event.source_address is None
    assert event.source_ip is None


@pytest.mark.parametrize(
    ("event_source", "service"),
    [
        ("iam.amazonaws.com", "iam"),
        ("cloudtrail.amazonaws.com", "cloudtrail"),
        ("signin.amazonaws.com", "signin"),
        ("custom.example.internal", "custom.example.internal"),
    ],
)
def test_service_name_is_derived_from_event_source(event_source: str, service: str) -> None:
    assert normalize(eventSource=event_source).service == service


def test_region_account_and_time_are_mapped() -> None:
    event = normalize(awsRegion="eu-west-1", eventTime="2026-10-05T11:00:00+02:00")

    assert event.region == "eu-west-1"
    assert event.account_id == ACCOUNT
    assert event.timestamp == datetime(2026, 10, 5, 9, 0, tzinfo=UTC)


# --- failed API calls (Task 19) ------------------------------------------------


@pytest.mark.parametrize("error_code", ["AccessDenied", "Client.UnauthorizedOperation"])
def test_failed_api_call(error_code: str) -> None:
    event = normalize(errorCode=error_code, errorMessage="not authorized")

    assert event.success is False
    assert event.error_code == error_code
    assert event.error_message == "not authorized"


def test_successful_api_call() -> None:
    event = normalize()

    assert event.success is True
    assert event.error_code is None


def test_failed_console_login_has_no_error_code_but_is_a_failure() -> None:
    event = normalize(
        eventName="ConsoleLogin",
        eventSource="signin.amazonaws.com",
        eventType="AwsConsoleSignIn",
        responseElements={"ConsoleLogin": "Failure"},
        errorMessage="Failed authentication",
        additionalEventData={"MFAUsed": "No"},
    )

    assert event.success is False
    assert event.error_code is None
    assert event.error_message == "Failed authentication"


# --- malformed input -----------------------------------------------------------


@pytest.mark.parametrize(
    "field", ["eventID", "eventTime", "eventSource", "eventName", "awsRegion", "userIdentity"]
)
def test_missing_required_field_is_rejected(field: str) -> None:
    record = make_record()
    del record[field]

    with pytest.raises(NormalizationError, match=f"missing required field '{field}'"):
        normalize_cloudtrail_record(record)


@pytest.mark.parametrize(
    ("overrides", "expected_message"),
    [
        ({"eventID": ""}, "missing required field 'eventID'"),
        ({"eventName": 123}, "'eventName' must be a string, got int"),
        ({"userIdentity": "developer"}, "'userIdentity' must be an object, got str"),
        ({"readOnly": "true"}, "'readOnly' must be a boolean, got str"),
        ({"requestParameters": ["a"]}, "'requestParameters' must be an object, got list"),
        ({"sourceIPAddress": 3405803826}, "'sourceIPAddress' must be a string, got int"),
        ({"eventTime": "yesterday"}, "timestamp:"),
        ({"eventTime": "2026-10-05T09:00:00"}, "timestamp:"),
    ],
)
def test_malformed_fields_are_rejected(overrides: dict[str, Any], expected_message: str) -> None:
    with pytest.raises(NormalizationError, match=expected_message):
        normalize(**overrides)


def test_bad_record_is_reported_not_dropped_and_batch_continues() -> None:
    bad = make_record(eventID="bad-1", eventTime="not-a-time")
    records = [
        make_record(eventID="ok-1"),
        bad,
        make_record(eventID="ok-2"),
    ]

    result = normalize_cloudtrail_records(records)

    assert [e.event_id for e in result.events] == ["ok-1", "ok-2"]
    [error] = result.errors
    assert error.index == 1
    assert error.event_id == "bad-1"
    assert "timestamp" in error.reason


def test_error_report_does_not_echo_untrusted_input() -> None:
    hostile = "<script>alert(1)</script>" * 1000

    with pytest.raises(NormalizationError) as excinfo:
        normalize(eventTime=hostile)

    assert "<script>" not in str(excinfo.value)
