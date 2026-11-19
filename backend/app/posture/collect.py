"""Build a posture snapshot from a live AWS account with read-only calls.

Each section (IAM, S3, EC2, CloudTrail) is collected independently. If the
credentials cannot read a section, it is left out and the reason recorded,
so its checks are reported as "not evaluated" instead of passing. The
calls and the IAM actions they need (all read-only):

    sts.get_caller_identity               none
    iam.get_account_summary               iam:GetAccountSummary
    iam.generate_credential_report        iam:GenerateCredentialReport
    iam.get_credential_report             iam:GetCredentialReport
    s3control.get_public_access_block     s3:GetAccountPublicAccessBlock
    s3.list_buckets                       s3:ListAllMyBuckets
    s3.get_public_access_block            s3:GetBucketPublicAccessBlock (per bucket)
    s3.get_bucket_policy_status           s3:GetBucketPolicyStatus (per bucket)
    ec2.describe_security_groups          ec2:DescribeSecurityGroups
    cloudtrail.describe_trails            cloudtrail:DescribeTrails
    cloudtrail.get_trail_status           cloudtrail:GetTrailStatus
"""

import csv
import io
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from functools import partial
from typing import Any

import boto3
from botocore.exceptions import ClientError

from app.collectors.aws import AWS_ERRORS, AwsAccessError, describe_aws_error

# Credential report generation usually takes a few seconds.
REPORT_POLL_SECONDS = 2.0
REPORT_POLL_ATTEMPTS = 15

SECTIONS = ("iam", "s3", "ec2", "cloudtrail")

# "This setting does not exist" answers, which mean None rather than an error.
NO_PUBLIC_ACCESS_BLOCK = "NoSuchPublicAccessBlockConfiguration"
NO_BUCKET_POLICY = "NoSuchBucketPolicy"


class CollectionError(RuntimeError):
    """A section could not be collected for a reason other than an AWS error."""


@dataclass
class Collection:
    snapshot: dict[str, Any]  # parse with app.posture.snapshot.parse_snapshot
    missing: dict[str, str] = field(default_factory=dict)  # section -> reason


def collect_snapshot(
    session: boto3.Session, region: str, sleep: Callable[[float], None] | None = None
) -> Collection:
    """Read the account's configuration into the snapshot format.

    ``sleep`` waits between credential-report polls (tests pass a no-op).

    Raises:
        AwsAccessError: the credentials do not work at all (identity lookup failed).
    """
    try:
        account_id = session.client("sts", region_name=region).get_caller_identity()["Account"]
    except AWS_ERRORS as exc:
        raise AwsAccessError(describe_aws_error(exc)) from exc

    wait = sleep or time.sleep
    collectors: dict[str, Callable[[], dict[str, Any]]] = {
        "iam": lambda: _collect_iam(session.client("iam", region_name=region), wait),
        "s3": lambda: _collect_s3(
            session.client("s3", region_name=region),
            session.client("s3control", region_name=region),
            account_id,
        ),
        "ec2": lambda: _collect_ec2(session.client("ec2", region_name=region)),
        "cloudtrail": lambda: _collect_cloudtrail(session.client("cloudtrail", region_name=region)),
    }

    collection = Collection(
        snapshot={
            "account_id": account_id,
            "region": region,
            "captured_at": datetime.now(UTC).isoformat(),
        }
    )
    for section in SECTIONS:
        try:
            collection.snapshot[section] = collectors[section]()
        except CollectionError as exc:
            collection.missing[section] = str(exc)
        except AWS_ERRORS as exc:
            collection.missing[section] = describe_aws_error(exc)
    return collection


def _collect_iam(iam: Any, sleep: Callable[[float], None]) -> dict[str, Any]:
    summary = iam.get_account_summary()["SummaryMap"]
    return {"account_summary": summary, "credential_report": _credential_report(iam, sleep)}


def _credential_report(iam: Any, sleep: Callable[[float], None]) -> list[dict[str, str]]:
    # Generating is asynchronous: ask until AWS reports it complete. A report
    # generated in the last four hours is reused by AWS, so this is cheap.
    for _ in range(REPORT_POLL_ATTEMPTS):
        if iam.generate_credential_report()["State"] == "COMPLETE":
            break
        sleep(REPORT_POLL_SECONDS)
    else:
        raise CollectionError("credential report was not ready in time; try again")

    content = iam.get_credential_report()["Content"].decode("utf-8")
    return list(csv.DictReader(io.StringIO(content)))


def _collect_s3(s3: Any, s3control: Any, account_id: str) -> dict[str, Any]:
    account_block = _absent_as_none(
        lambda: s3control.get_public_access_block(AccountId=account_id),
        NO_PUBLIC_ACCESS_BLOCK,
    )
    buckets = []
    for bucket in s3.list_buckets().get("Buckets", []):
        name = bucket["Name"]
        block = _absent_as_none(
            partial(s3.get_public_access_block, Bucket=name), NO_PUBLIC_ACCESS_BLOCK
        )
        status = _absent_as_none(
            partial(s3.get_bucket_policy_status, Bucket=name), NO_BUCKET_POLICY
        )
        buckets.append(
            {
                "Name": name,
                "PublicAccessBlockConfiguration": (
                    block["PublicAccessBlockConfiguration"] if block else None
                ),
                "PolicyStatus": status["PolicyStatus"] if status else None,
            }
        )
    return {
        "account_public_access_block": (
            account_block["PublicAccessBlockConfiguration"] if account_block else None
        ),
        "buckets": buckets,
    }


def _collect_ec2(ec2: Any) -> dict[str, Any]:
    groups = []
    for page in ec2.get_paginator("describe_security_groups").paginate():
        groups.extend(page["SecurityGroups"])
    return {"security_groups": groups}


def _collect_cloudtrail(cloudtrail: Any) -> dict[str, Any]:
    # includeShadowTrails (the default) lists multi-region trails created in
    # another region too: they log this region as well.
    trails = cloudtrail.describe_trails()["trailList"]
    status = {}
    for trail in trails:
        arn = trail["TrailARN"]
        result = cloudtrail.get_trail_status(Name=arn)
        status[arn] = {"IsLogging": result["IsLogging"]}
    return {"trails": trails, "status": status}


def _absent_as_none(call: Callable[[], dict[str, Any]], absent_code: str) -> dict[str, Any] | None:
    try:
        return call()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == absent_code:
            return None
        raise
