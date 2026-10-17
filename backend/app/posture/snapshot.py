"""A point-in-time snapshot of AWS configuration, as posture checks read it.

Wrapper keys (``iam``, ``s3``, ``buckets`` ...) are CloudSOC's own. The
objects inside them keep the exact field names AWS API responses use
(``SummaryMap``, ``IpPermissions``, ``TrailARN`` ...), so a collector can
fill a snapshot straight from boto3 calls and the checks never change:

    iam.account_summary        iam.get_account_summary()["SummaryMap"]
    iam.credential_report      iam.get_credential_report(), CSV decoded into rows
    s3.account_public_access_block
                               s3control.get_public_access_block()["PublicAccessBlockConfiguration"]
    s3.buckets[]               s3.list_buckets() names, each merged with
                               s3.get_public_access_block() and s3.get_bucket_policy_status()
    ec2.security_groups        ec2.describe_security_groups()["SecurityGroups"]
    cloudtrail.trails          cloudtrail.describe_trails()["trailList"]
    cloudtrail.status          cloudtrail.get_trail_status() per trail ARN

Only the fields the checks use are modelled; AWS returns many more and adds
new ones over time, so unknown fields are ignored. A missing section means
the collector could not read it — checks for it are reported as not
evaluated, never as passing.
"""

import json
from pathlib import Path
from typing import Annotated, Any

from pydantic import AwareDatetime, BaseModel, BeforeValidator, ConfigDict, Field, ValidationError


class SnapshotError(Exception):
    """The snapshot file could not be read or does not have the expected shape."""


def _csv_bool(value: Any) -> Any:
    # Credential report cells are text: "true", "false", "N/A", "not_supported".
    return value == "true" if isinstance(value, str) else value


def _csv_time(value: Any) -> Any:
    return None if value in ("N/A", "not_supported", "no_information") else value


CsvBool = Annotated[bool, BeforeValidator(_csv_bool)]
CsvTime = Annotated[AwareDatetime | None, BeforeValidator(_csv_time)]


class AwsShape(BaseModel):
    model_config = ConfigDict(frozen=True, extra="ignore")


# --- IAM -----------------------------------------------------------------------


class AccountSummary(AwsShape):
    account_mfa_enabled: int = Field(alias="AccountMFAEnabled")
    account_access_keys_present: int = Field(alias="AccountAccessKeysPresent")


ROOT_REPORT_USER = "<root_account>"


class CredentialReportRow(AwsShape):
    user: str
    arn: str
    password_enabled: CsvBool
    mfa_active: CsvBool
    access_key_1_active: CsvBool
    access_key_1_last_rotated: CsvTime
    access_key_2_active: CsvBool
    access_key_2_last_rotated: CsvTime

    @property
    def is_root(self) -> bool:
        return self.user == ROOT_REPORT_USER


class IamSnapshot(AwsShape):
    account_summary: AccountSummary
    credential_report: tuple[CredentialReportRow, ...]


# --- S3 ------------------------------------------------------------------------


class PublicAccessBlock(AwsShape):
    block_public_acls: bool = Field(alias="BlockPublicAcls")
    ignore_public_acls: bool = Field(alias="IgnorePublicAcls")
    block_public_policy: bool = Field(alias="BlockPublicPolicy")
    restrict_public_buckets: bool = Field(alias="RestrictPublicBuckets")

    def disabled_settings(self) -> list[str]:
        return [
            name
            for name, enabled in (
                ("BlockPublicAcls", self.block_public_acls),
                ("IgnorePublicAcls", self.ignore_public_acls),
                ("BlockPublicPolicy", self.block_public_policy),
                ("RestrictPublicBuckets", self.restrict_public_buckets),
            )
            if not enabled
        ]


class PolicyStatus(AwsShape):
    is_public: bool = Field(alias="IsPublic")


class Bucket(AwsShape):
    name: str = Field(alias="Name")
    # None: the bucket has no Block Public Access configuration at all.
    public_access_block: PublicAccessBlock | None = Field(alias="PublicAccessBlockConfiguration")
    # None: the bucket has no bucket policy.
    policy_status: PolicyStatus | None = Field(alias="PolicyStatus")


class S3Snapshot(AwsShape):
    # The account-wide setting applies on top of every bucket's own setting.
    account_public_access_block: PublicAccessBlock | None
    buckets: tuple[Bucket, ...]


# --- EC2 -----------------------------------------------------------------------


class IpRange(AwsShape):
    cidr_ip: str = Field(alias="CidrIp")


class Ipv6Range(AwsShape):
    cidr_ipv6: str = Field(alias="CidrIpv6")


class IpPermission(AwsShape):
    ip_protocol: str = Field(alias="IpProtocol")  # "tcp", "udp", "icmp", or "-1" for all
    from_port: int | None = Field(default=None, alias="FromPort")
    to_port: int | None = Field(default=None, alias="ToPort")
    ip_ranges: tuple[IpRange, ...] = Field(default=(), alias="IpRanges")
    ipv6_ranges: tuple[Ipv6Range, ...] = Field(default=(), alias="Ipv6Ranges")


class SecurityGroup(AwsShape):
    group_id: str = Field(alias="GroupId")
    group_name: str = Field(alias="GroupName")
    vpc_id: str | None = Field(default=None, alias="VpcId")
    ip_permissions: tuple[IpPermission, ...] = Field(default=(), alias="IpPermissions")


class Ec2Snapshot(AwsShape):
    security_groups: tuple[SecurityGroup, ...]


# --- CloudTrail ----------------------------------------------------------------


class Trail(AwsShape):
    name: str = Field(alias="Name")
    trail_arn: str = Field(alias="TrailARN")
    is_multi_region: bool = Field(alias="IsMultiRegionTrail")
    log_file_validation: bool = Field(alias="LogFileValidationEnabled")


class TrailStatus(AwsShape):
    is_logging: bool = Field(alias="IsLogging")


class CloudTrailSnapshot(AwsShape):
    trails: tuple[Trail, ...]
    status: dict[str, TrailStatus]  # by TrailARN


# --- the snapshot --------------------------------------------------------------


class PostureSnapshot(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    account_id: str = Field(pattern=r"^\d{12}$")
    region: str = Field(min_length=1, description="Region the regional sections were read from")
    captured_at: AwareDatetime
    iam: IamSnapshot | None = None
    s3: S3Snapshot | None = None
    ec2: Ec2Snapshot | None = None
    cloudtrail: CloudTrailSnapshot | None = None

    def section(self, service: str) -> AwsShape | None:
        return getattr(self, service)


def parse_snapshot(data: Any) -> PostureSnapshot:
    try:
        return PostureSnapshot.model_validate(data)
    except ValidationError as exc:
        fields = sorted({".".join(str(p) for p in error["loc"]) for error in exc.errors()})
        raise SnapshotError(f"invalid snapshot ({', '.join(fields[:5])})") from exc


def load_snapshot(path: Path) -> PostureSnapshot:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise SnapshotError(f"cannot read {path}: {exc.strerror}") from exc
    except ValueError as exc:
        raise SnapshotError(f"{path} is not valid JSON") from exc
    return parse_snapshot(data)
