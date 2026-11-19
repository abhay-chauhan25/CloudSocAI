"""Collecting a posture snapshot from (stubbed) live AWS calls."""

import json
import stat
from datetime import UTC, datetime
from pathlib import Path

import pytest

from app import posture_collect
from app.collectors.aws import AwsAccessError
from app.posture.collect import REPORT_POLL_ATTEMPTS, collect_snapshot
from app.posture.engine import run_posture_checks
from app.posture.snapshot import parse_snapshot
from tests.aws_stubs import StubbedSession

ACCOUNT = "123456789012"
SERVICES = ("sts", "iam", "s3", "s3control", "ec2", "cloudtrail")
TRAIL_ARN = f"arn:aws:cloudtrail:us-east-1:{ACCOUNT}:trail/cloudsoc-lab-trail"
BUCKET = f"cloudsoc-lab-unblocked-{ACCOUNT}-us-east-1"

# A real report has more columns; the snapshot model ignores the ones it does not use.
CREDENTIAL_REPORT = (
    "user,arn,user_creation_time,password_enabled,mfa_active,"
    "access_key_1_active,access_key_1_last_rotated,access_key_2_active,access_key_2_last_rotated\n"
    f"<root_account>,arn:aws:iam::{ACCOUNT}:root,2026-01-01T00:00:00+00:00,not_supported,true,"
    "false,N/A,false,N/A\n"
)

NOW = datetime(2026, 11, 19, tzinfo=UTC)


def no_sleep(seconds: float) -> None:
    pass


def stub_identity(session: StubbedSession) -> None:
    session.stubs["sts"].add_response(
        "get_caller_identity",
        {
            "Account": ACCOUNT,
            "Arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/cloudsoc-lab-reader/test",
            "UserId": "AROAEXAMPLEEXAMPLE01:test",
        },
    )


def stub_iam(session: StubbedSession) -> None:
    iam = session.stubs["iam"]
    iam.add_response(
        "get_account_summary",
        {"SummaryMap": {"AccountMFAEnabled": 1, "AccountAccessKeysPresent": 0}},
    )
    iam.add_response("generate_credential_report", {"State": "STARTED"})
    iam.add_response("generate_credential_report", {"State": "COMPLETE"})
    iam.add_response(
        "get_credential_report",
        {"Content": CREDENTIAL_REPORT.encode(), "ReportFormat": "text/csv", "GeneratedTime": NOW},
    )


def stub_s3(session: StubbedSession) -> None:
    session.stubs["s3control"].add_client_error(
        "get_public_access_block", "NoSuchPublicAccessBlockConfiguration", http_status_code=404
    )
    s3 = session.stubs["s3"]
    s3.add_response("list_buckets", {"Buckets": [{"Name": BUCKET, "CreationDate": NOW}]})
    s3.add_response(
        "get_public_access_block",
        {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": False,
                "IgnorePublicAcls": False,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": False,
            }
        },
        {"Bucket": BUCKET},
    )
    s3.add_client_error("get_bucket_policy_status", "NoSuchBucketPolicy", http_status_code=404)


def stub_ec2(session: StubbedSession) -> None:
    session.stubs["ec2"].add_response(
        "describe_security_groups",
        {
            "SecurityGroups": [
                {
                    "GroupId": "sg-0a1b2c3d4e5f60099",
                    "GroupName": "cloudsoc-lab-open-ssh",
                    "VpcId": "vpc-0a1b2c3d4e5f60099",
                    "Description": "lab",
                    "OwnerId": ACCOUNT,
                    "IpPermissions": [
                        {
                            "IpProtocol": "tcp",
                            "FromPort": 22,
                            "ToPort": 22,
                            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                        }
                    ],
                }
            ]
        },
    )


def stub_cloudtrail(session: StubbedSession) -> None:
    cloudtrail = session.stubs["cloudtrail"]
    cloudtrail.add_response(
        "describe_trails",
        {
            "trailList": [
                {
                    "Name": "cloudsoc-lab-trail",
                    "TrailARN": TRAIL_ARN,
                    "HomeRegion": "us-east-1",
                    "IsMultiRegionTrail": True,
                    "LogFileValidationEnabled": True,
                }
            ]
        },
    )
    cloudtrail.add_response("get_trail_status", {"IsLogging": True}, {"Name": TRAIL_ARN})


def stub_everything(session: StubbedSession) -> None:
    stub_identity(session)
    stub_iam(session)
    stub_s3(session)
    stub_ec2(session)
    stub_cloudtrail(session)


def test_collects_every_section_into_a_valid_snapshot() -> None:
    session = StubbedSession(*SERVICES)
    stub_everything(session)

    with session.active():
        collection = collect_snapshot(session, "us-east-1", sleep=no_sleep)

    assert collection.missing == {}
    snapshot = parse_snapshot(collection.snapshot)
    assert snapshot.account_id == ACCOUNT
    assert snapshot.iam is not None and snapshot.iam.credential_report[0].is_root
    assert snapshot.s3 is not None and snapshot.s3.account_public_access_block is None
    assert snapshot.s3.buckets[0].policy_status is None  # "no policy" is not an error


def test_collected_lab_snapshot_fails_the_expected_checks() -> None:
    session = StubbedSession(*SERVICES)
    stub_everything(session)

    with session.active():
        snapshot = parse_snapshot(collect_snapshot(session, "us-east-1", sleep=no_sleep).snapshot)
    result = run_posture_checks(snapshot)

    assert {f.detector_id for f in result.findings} == {
        "sg-admin-port-open-to-internet",
        "s3-public-access-not-blocked",
    }
    assert result.not_evaluated == []


def test_denied_section_is_left_out_not_passed() -> None:
    session = StubbedSession(*SERVICES)
    stub_identity(session)
    stub_iam(session)
    stub_s3(session)
    session.stubs["ec2"].add_client_error(
        "describe_security_groups", "UnauthorizedOperation", http_status_code=403
    )
    stub_cloudtrail(session)

    with session.active():
        collection = collect_snapshot(session, "us-east-1", sleep=no_sleep)
    result = run_posture_checks(parse_snapshot(collection.snapshot))

    assert list(collection.missing) == ["ec2"]
    assert "DescribeSecurityGroups failed with UnauthorizedOperation" in collection.missing["ec2"]
    assert result.not_evaluated == ["sg-admin-port-open-to-internet"]


def test_credential_report_that_never_completes_leaves_iam_out() -> None:
    session = StubbedSession(*SERVICES)
    stub_identity(session)
    iam = session.stubs["iam"]
    iam.add_response("get_account_summary", {"SummaryMap": {"AccountMFAEnabled": 1}})
    for _ in range(REPORT_POLL_ATTEMPTS):
        iam.add_response("generate_credential_report", {"State": "INPROGRESS"})
    session.stubs["s3control"].add_client_error("get_public_access_block", "AccessDenied")
    session.stubs["ec2"].add_client_error("describe_security_groups", "UnauthorizedOperation")
    session.stubs["cloudtrail"].add_client_error("describe_trails", "AccessDeniedException")

    with session.active():
        collection = collect_snapshot(session, "us-east-1", sleep=no_sleep)

    assert set(collection.missing) == {"iam", "s3", "ec2", "cloudtrail"}
    assert "not ready in time" in collection.missing["iam"]


def test_unusable_credentials_stop_collection() -> None:
    session = StubbedSession("sts")
    session.stubs["sts"].add_client_error("get_caller_identity", "ExpiredToken")

    with session.active(), pytest.raises(AwsAccessError, match="ExpiredToken"):
        collect_snapshot(session, "us-east-1", sleep=no_sleep)


def test_command_writes_an_owner_only_snapshot_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    session = StubbedSession(*SERVICES)
    stub_everything(session)
    monkeypatch.setattr(posture_collect, "create_session", lambda profile, region: session)
    monkeypatch.setattr("app.posture.collect.time.sleep", no_sleep)
    output = tmp_path / "out" / "snapshot.json"

    with session.active():
        exit_code = posture_collect.main(["--region", "us-east-1", "--output", str(output)])

    assert exit_code == posture_collect.EXIT_OK
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    assert parse_snapshot(json.loads(output.read_text())).account_id == ACCOUNT
