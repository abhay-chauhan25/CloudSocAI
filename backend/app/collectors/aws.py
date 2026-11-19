"""AWS sessions and error reporting shared by every collector that calls AWS.

Credentials are never passed in or stored by CloudSOC. boto3 finds them
through its standard credential chain: environment variables, then the
shared ``~/.aws`` files (a named profile, SSO, or an assumed role), then
the instance or container role when running inside AWS. Code that needs
AWS asks for a session and receives clients from it, so tests can hand in
stubbed clients instead.
"""

import boto3
from botocore.exceptions import (
    BotoCoreError,
    ClientError,
    NoCredentialsError,
    NoRegionError,
    ProfileNotFound,
)

# Errors raised by AWS calls that collectors translate into AwsAccessError.
AWS_ERRORS: tuple[type[Exception], ...] = (BotoCoreError, ClientError)


class AwsAccessError(RuntimeError):
    """An AWS call failed: missing credentials, permission denied, unreachable, ..."""


def create_session(profile: str | None = None, region: str | None = None) -> boto3.Session:
    """A boto3 session using the standard credential chain.

    Raises:
        AwsAccessError: the named profile does not exist.
    """
    try:
        return boto3.Session(profile_name=profile, region_name=region)
    except ProfileNotFound as exc:
        raise AwsAccessError(describe_aws_error(exc)) from exc


def describe_aws_error(exc: Exception) -> str:
    """A short, actionable message for an AWS failure.

    botocore messages name the operation and error code (and sometimes a
    resource ARN) but never credential values, so they are safe to log.
    """
    if isinstance(exc, NoCredentialsError):
        return (
            "no AWS credentials found: configure a profile with `aws configure` "
            "or `aws sso login`, then pass --profile"
        )
    if isinstance(exc, NoRegionError):
        return "no AWS region configured: pass --region"
    if isinstance(exc, ClientError):
        code = exc.response.get("Error", {}).get("Code", "Unknown")
        operation = exc.operation_name
        if code in {"AccessDenied", "AccessDeniedException", "403"}:
            return (
                f"access denied calling {operation}: check the reader policy "
                "(and kms:Decrypt if the logs are KMS-encrypted)"
            )
        if code in {"NoSuchBucket", "404"}:
            return f"{operation}: bucket or object not found"
        return f"{operation} failed with {code}"
    return str(exc)
