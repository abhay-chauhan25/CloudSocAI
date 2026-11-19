"""Lab scenario runner: guards, call order, and self-cleanup, against stubbed AWS."""

from datetime import UTC, datetime

import pytest
from botocore.stub import ANY

from app.lab import scenarios
from app.lab.scenarios import (
    ADMIN_POLICY_ARN,
    BURST_CALLS,
    LabGuardError,
    check_account,
    check_denied_role,
    check_lab_trail,
    failed_call_burst,
    iam_persistence,
    logging_tampering,
)
from tests.aws_stubs import StubbedSession

ACCOUNT = "123456789012"
USER = "cloudsoc-lab-scenario-user"
TRAIL = "cloudsoc-lab-trail"
TRAIL_ARN = f"arn:aws:cloudtrail:us-east-1:{ACCOUNT}:trail/{TRAIL}"
DENIED_ROLE = f"arn:aws:iam::{ACCOUNT}:role/cloudsoc-lab-denied"
# Stands in for the secret key AWS returns; it must never reach the logs.
LEAK_CANARY = "canary-value-that-must-not-be-logged"
NOW = datetime(2026, 11, 19, tzinfo=UTC)


# --- guards ---------------------------------------------------------------------


def identity(account: str) -> dict:
    return {
        "Account": account,
        "Arn": f"arn:aws:iam::{account}:user/admin",
        "UserId": "AIDAEXAMPLEEXAMPLE01",
    }


def test_refuses_credentials_from_another_account() -> None:
    session = StubbedSession("sts")
    session.stubs["sts"].add_response("get_caller_identity", identity("210987654321"))

    with session.active(), pytest.raises(LabGuardError, match="not 123456789012"):
        check_account(session.clients["sts"], ACCOUNT)


@pytest.mark.parametrize(
    ("tags", "allowed"),
    [
        (
            [
                {"Key": "Project", "Value": "cloudsoc-lab"},
                {"Key": "ManagedBy", "Value": "terraform"},
            ],
            True,
        ),
        ([{"Key": "Project", "Value": "production"}], False),
        ([], False),
    ],
)
def test_only_a_lab_tagged_trail_is_accepted(tags: list[dict], allowed: bool) -> None:
    session = StubbedSession("cloudtrail")
    stub = session.stubs["cloudtrail"]
    stub.add_response(
        "describe_trails",
        {"trailList": [{"Name": TRAIL, "TrailARN": TRAIL_ARN}]},
        {"trailNameList": [TRAIL], "includeShadowTrails": False},
    )
    stub.add_response(
        "list_tags", {"ResourceTagList": [{"ResourceId": TRAIL_ARN, "TagsList": tags}]}
    )

    with session.active():
        if allowed:
            check_lab_trail(session.clients["cloudtrail"], TRAIL)
        else:
            with pytest.raises(LabGuardError, match="not tagged"):
                check_lab_trail(session.clients["cloudtrail"], TRAIL)


def test_only_the_lab_denied_role_is_accepted() -> None:
    check_denied_role(DENIED_ROLE, ACCOUNT, "cloudsoc-lab")
    with pytest.raises(LabGuardError):
        check_denied_role(
            f"arn:aws:iam::{ACCOUNT}:role/OrganizationAccountAccessRole", ACCOUNT, "cloudsoc-lab"
        )


def test_command_refuses_before_changing_anything(monkeypatch: pytest.MonkeyPatch) -> None:
    session = StubbedSession("sts", "cloudtrail")
    session.stubs["sts"].add_response("get_caller_identity", identity("210987654321"))
    monkeypatch.setattr(scenarios, "create_session", lambda profile, region: session)
    args = ["--region", "us-east-1", "--account-id", ACCOUNT, "--trail-name", TRAIL]

    with session.active():  # no other call is stubbed, so any change would fail the test
        exit_code = scenarios.main([*args, "--denied-role-arn", DENIED_ROLE])

    assert exit_code == scenarios.EXIT_REFUSED


# --- iam-persistence --------------------------------------------------------------


def stub_cleanup(stub, keys: list[str]) -> None:
    stub.add_client_error("detach_user_policy", "NoSuchEntity", http_status_code=404)
    stub.add_response(
        "list_access_keys",
        {"AccessKeyMetadata": [{"UserName": USER, "AccessKeyId": k} for k in keys]},
    )
    for key in keys:
        stub.add_response("delete_access_key", {}, {"UserName": USER, "AccessKeyId": key})
    stub.add_response("delete_user", {}, {"UserName": USER})


def test_iam_persistence_runs_in_order_and_never_logs_the_secret(
    caplog: pytest.LogCaptureFixture,
) -> None:
    session = StubbedSession("iam")
    stub = session.stubs["iam"]
    admin = {"UserName": USER, "PolicyArn": ADMIN_POLICY_ARN}
    stub.add_response(
        "create_user",
        {
            "User": {
                "Path": "/",
                "UserName": USER,
                "UserId": "AIDAEXAMPLEEXAMPLE01",
                "Arn": "arn:aws:iam::123456789012:user/x",
                "CreateDate": NOW,
            }
        },
        {"UserName": USER, "Tags": ANY},
    )
    stub.add_response("attach_user_policy", {}, admin)
    stub.add_response("detach_user_policy", {}, admin)
    stub.add_response(
        "create_access_key",
        {
            "AccessKey": {
                "UserName": USER,
                "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
                "Status": "Active",
                "SecretAccessKey": LEAK_CANARY,
            }
        },
    )
    stub.add_response(
        "delete_access_key", {}, {"UserName": USER, "AccessKeyId": "AKIAIOSFODNN7EXAMPLE"}
    )
    stub_cleanup(stub, keys=[])

    with session.active(), caplog.at_level("INFO"):
        iam_persistence(session.clients["iam"], "cloudsoc-lab")

    assert LEAK_CANARY not in caplog.text
    assert "deleted user cloudsoc-lab-scenario-user" in caplog.text


def test_iam_persistence_cleans_up_when_a_step_fails() -> None:
    session = StubbedSession("iam")
    stub = session.stubs["iam"]
    stub.add_response(
        "create_user",
        {
            "User": {
                "Path": "/",
                "UserName": USER,
                "UserId": "AIDAEXAMPLEEXAMPLE01",
                "Arn": "arn:aws:iam::123456789012:user/x",
                "CreateDate": NOW,
            }
        },
    )
    stub.add_client_error("attach_user_policy", "AccessDenied")
    stub_cleanup(stub, keys=[])

    with session.active(), pytest.raises(Exception, match="AccessDenied"):
        iam_persistence(session.clients["iam"], "cloudsoc-lab")
    # assert_no_pending_responses on exit proves delete_user was called


# --- logging-tampering ------------------------------------------------------------


def test_logging_is_restarted_and_only_a_nonexistent_trail_is_deleted() -> None:
    session = StubbedSession("cloudtrail")
    stub = session.stubs["cloudtrail"]
    stub.add_response("stop_logging", {}, {"Name": TRAIL})
    stub.add_response("start_logging", {}, {"Name": TRAIL})
    stub.add_client_error(
        "delete_trail",
        "TrailNotFoundException",
        expected_params={"Name": "cloudsoc-lab-decoy-trail"},
    )

    with session.active():
        logging_tampering(session.clients["cloudtrail"], TRAIL, "cloudsoc-lab")


def test_failure_to_restart_logging_is_loud(caplog: pytest.LogCaptureFixture) -> None:
    session = StubbedSession("cloudtrail")
    stub = session.stubs["cloudtrail"]
    stub.add_response("stop_logging", {})
    stub.add_client_error("start_logging", "AccessDeniedException")

    with session.active(), pytest.raises(Exception, match="AccessDeniedException"):
        logging_tampering(session.clients["cloudtrail"], TRAIL, "cloudsoc-lab")
    assert "could not restart logging" in caplog.text


# --- failed-call-burst ------------------------------------------------------------

DENIED_ERROR = {
    "iam": "AccessDenied",
    "s3": "AccessDenied",
    "ec2": "UnauthorizedOperation",
    "lambda": "AccessDeniedException",
    "dynamodb": "AccessDeniedException",
    "kms": "AccessDeniedException",
}


def stub_assume_role(session: StubbedSession) -> None:
    session.stubs["sts"].add_response(
        "assume_role",
        {
            "Credentials": {
                "AccessKeyId": "ASIAIOSFODNN7EXAMPLE",
                "SecretAccessKey": LEAK_CANARY,
                "SessionToken": "EXAMPLE-SESSION-TOKEN",
                "Expiration": NOW,
            }
        },
        {"RoleArn": DENIED_ROLE, "RoleSessionName": "cloudsoc-lab-burst", "DurationSeconds": 900},
    )


def test_burst_counts_six_denied_calls() -> None:
    caller = StubbedSession("sts")
    stub_assume_role(caller)
    denied = StubbedSession(*(service for service, _ in BURST_CALLS))
    for service, operation in BURST_CALLS:
        denied.stubs[service].add_client_error(operation, DENIED_ERROR[service])

    with caller.active(), denied.active():
        count = failed_call_burst(
            caller.clients["sts"], DENIED_ROLE, "us-east-1", make_session=lambda **_: denied
        )

    assert count == len(BURST_CALLS) == 6


def test_burst_stops_if_the_role_turns_out_to_have_permissions() -> None:
    caller = StubbedSession("sts")
    stub_assume_role(caller)
    denied = StubbedSession("iam")
    denied.stubs["iam"].add_response("list_users", {"Users": []})

    with caller.active(), denied.active(), pytest.raises(RuntimeError, match="succeeded"):
        failed_call_burst(
            caller.clients["sts"], DENIED_ROLE, "us-east-1", make_session=lambda **_: denied
        )
