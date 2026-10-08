"""The normalized security Event.

An Event is one immutable fact: "this principal called this API, from here,
at this time, with this outcome". Detectors only ever see Events, never raw
provider JSON, so supporting a new log source means writing a new normalizer,
not changing every detector.
"""

from datetime import UTC, datetime
from enum import StrEnum
from ipaddress import IPv4Address, IPv6Address
from typing import Any, Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_validator


class PrincipalType(StrEnum):
    """Kinds of AWS identity, mirroring CloudTrail's ``userIdentity.type``."""

    ROOT = "Root"
    IAM_USER = "IAMUser"
    ASSUMED_ROLE = "AssumedRole"
    FEDERATED_USER = "FederatedUser"
    AWS_SERVICE = "AWSService"
    AWS_ACCOUNT = "AWSAccount"
    # AWS adds identity types over time. An unrecognised type is kept as
    # UNKNOWN (the original stays in raw_event) rather than dropping the event.
    UNKNOWN = "Unknown"


class Event(BaseModel):
    """A normalized, immutable security event."""

    # frozen: events are evidence and must not change after normalization.
    # extra="forbid": a misspelled field name is an error, not silently ignored.
    model_config = ConfigDict(frozen=True, extra="forbid")

    # --- record identity -----------------------------------------------------
    event_id: str = Field(min_length=1, description="Provider event ID; deduplication key")
    source: Literal["cloudtrail"] = Field(description="Telemetry source that produced the event")
    timestamp: AwareDatetime = Field(description="When the action happened, in UTC")
    account_id: str | None = Field(description="AWS account that recorded the event")

    # --- what happened -------------------------------------------------------
    service: str = Field(min_length=1, description='Short service name, e.g. "iam"')
    event_name: str = Field(min_length=1, description='API name, e.g. "AttachUserPolicy"')
    event_type: str | None = Field(description='e.g. "AwsApiCall", "AwsConsoleSignIn"')
    read_only: bool | None = Field(description="True for read/list/describe calls")
    region: str = Field(min_length=1)

    # --- who did it ----------------------------------------------------------
    principal_type: PrincipalType
    principal: str | None = Field(description="Human-readable actor: user, role, or service")
    principal_arn: str | None = Field(description="Stable ARN of the actor (role ARN for roles)")
    session_name: str | None = Field(description="Role session name, for assumed roles")
    access_key_id: str | None
    mfa_authenticated: bool | None = Field(description="None when the record does not say")

    # --- from where, and how -------------------------------------------------
    source_address: str | None = Field(
        description='sourceIPAddress as recorded: an IP, a service name, or "AWS Internal"'
    )
    source_ip: IPv4Address | IPv6Address | None = Field(
        description="source_address parsed as an IP, or None when it is not an IP"
    )
    user_agent: str | None = Field(description="Caller-controlled; treat as untrusted text")

    # --- outcome -------------------------------------------------------------
    success: bool
    error_code: str | None
    error_message: str | None

    # --- evidence ------------------------------------------------------------
    request_parameters: dict[str, Any] | None = Field(
        description="API-specific inputs; unvalidated, shape differs per API"
    )
    raw_event: dict[str, Any] = Field(description="The original record, kept as evidence")

    @field_validator("timestamp")
    @classmethod
    def _convert_to_utc(cls, value: datetime) -> datetime:
        return value.astimezone(UTC)
