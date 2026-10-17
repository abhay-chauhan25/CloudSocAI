"""Storage posture: S3 buckets that are, or could become, public."""

from app.posture.base import PostureCheck, require
from app.posture.snapshot import Bucket, PostureSnapshot, PublicAccessBlock
from app.schemas.finding import Finding, Severity

SETTINGS = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")


def effective_disabled_settings(account: PublicAccessBlock | None, bucket: Bucket) -> list[str]:
    """Block Public Access settings off at both levels.

    A setting protects a bucket if it is on for the account *or* the bucket,
    so only settings off in both places leave a gap.
    """
    off_for_account = set(account.disabled_settings()) if account else set(SETTINGS)
    off_for_bucket = (
        set(bucket.public_access_block.disabled_settings())
        if bucket.public_access_block
        else set(SETTINGS)
    )
    return [name for name in SETTINGS if name in off_for_account & off_for_bucket]


def _bucket_arn(bucket: Bucket) -> str:
    return f"arn:aws:s3:::{bucket.name}"


class PublicAccessNotBlocked(PostureCheck):
    check_id = "s3-public-access-not-blocked"
    name = "S3 bucket can be made public"
    description = (
        "At least one Block Public Access setting is off for both the account and the bucket."
    )
    rationale = (
        "Block Public Access is the safety net that stops a mistaken ACL or bucket policy "
        "from exposing data. With it off, one wrong policy edit publishes the bucket. "
        "Buckets that host public websites are a deliberate exception."
    )
    remediation = "Turn on all four Block Public Access settings, ideally at the account level."
    reference = "CIS AWS Foundations Benchmark: S3 Block Public Access enabled"
    severity = Severity.MEDIUM
    service = "s3"

    def evaluate(self, snapshot: PostureSnapshot) -> list[Finding]:
        s3 = require(snapshot.s3)
        findings = []
        for bucket in s3.buckets:
            disabled = effective_disabled_settings(s3.account_public_access_block, bucket)
            if disabled:
                findings.append(
                    self.build_finding(
                        snapshot,
                        resource=_bucket_arn(bucket),
                        reason=(
                            f"Bucket {bucket.name!r}: {', '.join(disabled)} off for both the "
                            "account and the bucket."
                        ),
                    )
                )
        return findings


class BucketPolicyPublic(PostureCheck):
    check_id = "s3-bucket-public"
    name = "S3 bucket is public"
    description = (
        "The bucket policy is public (PolicyStatus.IsPublic) and RestrictPublicBuckets "
        "does not neutralise it."
    )
    rationale = (
        "Anyone on the internet can use whatever the policy grants, usually reading every "
        "object. Public data buckets are among the most common causes of cloud data leaks. "
        "Intentionally public content is better served through CloudFront."
    )
    remediation = (
        "Remove the public statement from the bucket policy and enable Block Public Access."
    )
    reference = "CIS AWS Foundations Benchmark: S3 Block Public Access enabled"
    severity = Severity.CRITICAL
    service = "s3"

    def evaluate(self, snapshot: PostureSnapshot) -> list[Finding]:
        s3 = require(snapshot.s3)
        account = s3.account_public_access_block
        return [
            self.build_finding(
                snapshot,
                resource=_bucket_arn(bucket),
                reason=(
                    f"Bucket {bucket.name!r}: the bucket policy is public and "
                    "RestrictPublicBuckets is off for both the account and the bucket."
                ),
            )
            for bucket in s3.buckets
            if bucket.policy_status is not None
            and bucket.policy_status.is_public
            and "RestrictPublicBuckets" in effective_disabled_settings(account, bucket)
        ]
