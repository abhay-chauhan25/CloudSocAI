"""Generate real CloudTrail activity in the lab so CloudSOC's rules have something to find.

Usage (from backend/, after `terraform apply`, with the admin profile you
applied Terraform with):

    python -m app.lab.scenarios --profile <admin-profile> --region us-east-1 \\
        --account-id <account-id> --trail-name cloudsoc-lab-trail \\
        --denied-role-arn arn:aws:iam::<account-id>:role/cloudsoc-lab-denied

Every scenario undoes itself, and every change it makes is reversible and
confined to lab resources:

    iam-persistence    create a user, attach then detach AdministratorAccess,
                       create then delete an access key, delete the user.
                       The user never holds admin rights and a key at once.
    logging-tampering  stop the lab trail and immediately restart it, then
                       try to delete a trail that does not exist.
    failed-call-burst  assume the no-permission role and make six calls that
                       are all denied.

Guards: the credentials must belong to --account-id, the trail must carry
the lab's Project tag, and the role must be the lab's denied role, so a
typo cannot point this at a real account's trail.
"""

import argparse
import logging
import sys
from collections.abc import Callable

import boto3
from botocore.client import BaseClient
from botocore.exceptions import ClientError

from app.collectors.aws import AWS_ERRORS, AwsAccessError, create_session, describe_aws_error

logger = logging.getLogger(__name__)

LAB_TAG = ("Project", "cloudsoc-lab")
ADMIN_POLICY_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"
DENIED_CODES = {"AccessDenied", "AccessDeniedException", "UnauthorizedOperation"}

EXIT_OK = 0
EXIT_SCENARIO_FAILED = 1
EXIT_AWS_UNAVAILABLE = 3
EXIT_REFUSED = 5  # a guard failed: wrong account, or not a lab resource


class LabGuardError(RuntimeError):
    """The target is not (provably) part of the lab."""


def check_account(sts: BaseClient, expected_account_id: str) -> None:
    actual = sts.get_caller_identity()["Account"]
    if actual != expected_account_id:
        raise LabGuardError(
            f"credentials belong to account {actual}, not {expected_account_id}; refusing"
        )


def check_lab_trail(cloudtrail: BaseClient, trail_name: str) -> None:
    trails = cloudtrail.describe_trails(trailNameList=[trail_name], includeShadowTrails=False)
    if not trails["trailList"]:
        raise LabGuardError(f"trail {trail_name!r} not found in this region")
    arn = trails["trailList"][0]["TrailARN"]
    tags = cloudtrail.list_tags(ResourceIdList=[arn])["ResourceTagList"][0].get("TagsList", [])
    if {"Key": LAB_TAG[0], "Value": LAB_TAG[1]} not in tags:
        raise LabGuardError(f"trail {trail_name!r} is not tagged {LAB_TAG[0]}={LAB_TAG[1]}")


def check_denied_role(denied_role_arn: str, account_id: str, prefix: str) -> None:
    expected = f"arn:aws:iam::{account_id}:role/{prefix}-denied"
    if denied_role_arn != expected:
        raise LabGuardError(f"expected the lab's denied role {expected}, got {denied_role_arn}")


def iam_persistence(iam: BaseClient, prefix: str) -> None:
    user = f"{prefix}-scenario-user"
    iam.create_user(UserName=user, Tags=[{"Key": LAB_TAG[0], "Value": LAB_TAG[1]}])
    logger.info("created user %s", user)
    try:
        iam.attach_user_policy(UserName=user, PolicyArn=ADMIN_POLICY_ARN)
        iam.detach_user_policy(UserName=user, PolicyArn=ADMIN_POLICY_ARN)
        logger.info("attached and detached AdministratorAccess")
        # The response contains the secret key; it is never read or logged,
        # and the key is deleted straight away.
        key_id = iam.create_access_key(UserName=user)["AccessKey"]["AccessKeyId"]
        iam.delete_access_key(UserName=user, AccessKeyId=key_id)
        logger.info("created and deleted an access key")
    finally:
        _delete_user(iam, user)


def _delete_user(iam: BaseClient, user: str) -> None:
    """Remove the scenario user and anything attached to it, whatever state it is in."""
    try:
        iam.detach_user_policy(UserName=user, PolicyArn=ADMIN_POLICY_ARN)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    for key in iam.list_access_keys(UserName=user)["AccessKeyMetadata"]:
        iam.delete_access_key(UserName=user, AccessKeyId=key["AccessKeyId"])
    iam.delete_user(UserName=user)
    logger.info("deleted user %s", user)


def logging_tampering(cloudtrail: BaseClient, trail_name: str, prefix: str) -> None:
    cloudtrail.stop_logging(Name=trail_name)
    logger.info("stopped logging on %s", trail_name)
    try:
        cloudtrail.start_logging(Name=trail_name)
    except AWS_ERRORS:
        logger.critical("could not restart logging: run `aws cloudtrail start-logging`")
        raise
    logger.info("restarted logging on %s", trail_name)

    decoy = f"{prefix}-decoy-trail"
    try:
        cloudtrail.delete_trail(Name=decoy)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "TrailNotFoundException":
            raise
        logger.info("DeleteTrail on nonexistent %s failed, as intended", decoy)
    else:
        raise RuntimeError(f"{decoy} existed and was deleted; it should not exist")


# Six read-only calls across services: none can succeed with the denied role.
BURST_CALLS: tuple[tuple[str, str], ...] = (
    ("iam", "list_users"),
    ("s3", "list_buckets"),
    ("ec2", "describe_instances"),
    ("lambda", "list_functions"),
    ("dynamodb", "list_tables"),
    ("kms", "list_keys"),
)


def failed_call_burst(
    sts: BaseClient,
    denied_role_arn: str,
    region: str,
    make_session: Callable[..., boto3.Session] = boto3.Session,
) -> int:
    credentials = sts.assume_role(
        RoleArn=denied_role_arn, RoleSessionName="cloudsoc-lab-burst", DurationSeconds=900
    )["Credentials"]
    # Temporary credentials stay in memory for these calls only.
    denied = make_session(
        aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"],
        aws_session_token=credentials["SessionToken"],
        region_name=region,
    )
    denied_calls = 0
    for service, operation in BURST_CALLS:
        try:
            getattr(denied.client(service), operation)()
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in DENIED_CODES:
                raise
            denied_calls += 1
        else:
            raise RuntimeError(f"{service}.{operation} succeeded; the denied role has permissions")
    logger.info("%d calls denied as the no-permission role", denied_calls)
    return denied_calls


SCENARIOS = ("iam-persistence", "logging-tampering", "failed-call-burst")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run CloudSOC lab scenarios.")
    parser.add_argument("--profile", help="admin profile used for terraform apply")
    parser.add_argument("--region", required=True)
    parser.add_argument("--account-id", required=True, help="the lab account (safety check)")
    parser.add_argument("--trail-name", required=True, help="the lab trail (must be tagged)")
    parser.add_argument("--denied-role-arn", required=True)
    parser.add_argument("--prefix", default="cloudsoc-lab", help="Terraform's name_prefix")
    parser.add_argument("--scenario", choices=SCENARIOS, action="append", help="default: all")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    try:
        session = create_session(args.profile, args.region)
        sts = session.client("sts")
        cloudtrail = session.client("cloudtrail")
        check_account(sts, args.account_id)
        check_lab_trail(cloudtrail, args.trail_name)
        check_denied_role(args.denied_role_arn, args.account_id, args.prefix)
    except LabGuardError as exc:
        logger.error("%s", exc)
        return EXIT_REFUSED
    except AwsAccessError as exc:
        logger.error("%s", exc)
        return EXIT_AWS_UNAVAILABLE
    except AWS_ERRORS as exc:
        logger.error("%s", describe_aws_error(exc))
        return EXIT_AWS_UNAVAILABLE

    runs: dict[str, Callable[[], object]] = {
        "iam-persistence": lambda: iam_persistence(session.client("iam"), args.prefix),
        "logging-tampering": lambda: logging_tampering(cloudtrail, args.trail_name, args.prefix),
        "failed-call-burst": lambda: failed_call_burst(sts, args.denied_role_arn, args.region),
    }
    failed = False
    for name in args.scenario or SCENARIOS:
        logger.info("scenario %s", name)
        try:
            runs[name]()
        except AWS_ERRORS as exc:
            logger.error("scenario %s failed: %s", name, describe_aws_error(exc))
            failed = True
        except RuntimeError as exc:
            logger.error("scenario %s failed: %s", name, exc)
            failed = True

    logger.info("done; CloudTrail delivers these events to S3 within about 5-15 minutes")
    return EXIT_SCENARIO_FAILED if failed else EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
