"""The Finding: security-relevant evidence identified by a detector.

An Event says "something happened"; a Finding says "a detector judged this
worth a defender's attention, and here is why". Findings point to their
evidence events by ID and never modify them.
"""

import uuid
from collections.abc import Iterable
from datetime import UTC, datetime
from enum import StrEnum
from typing import Self

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_validator, model_validator

# Fixed namespace for deterministic finding IDs. Changing it would change
# every finding ID, so it must stay constant.
FINDING_ID_NAMESPACE = uuid.UUID("6f9d1c2e-3b4a-5d6e-8f70-91a2b3c4d5e6")


class Severity(StrEnum):
    """How strongly a finding suggests malicious or dangerous activity."""

    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


def make_finding_id(detector_id: str, event_ids: Iterable[str]) -> str:
    """Derive a finding's ID from its detector and evidence.

    Running detection again over the same events produces the same ID, so a
    finding can be stored idempotently, the same way events are.
    """
    key = "\n".join([detector_id, *sorted(event_ids)])
    return str(uuid.uuid5(FINDING_ID_NAMESPACE, key))


class Finding(BaseModel):
    """A detector's judgement about one or more events."""

    # Frozen: analyst decisions (triage status, notes) are added in storage,
    # not by mutating what the detector produced.
    model_config = ConfigDict(frozen=True, extra="forbid")

    finding_id: str = Field(min_length=1, description="Deterministic; see make_finding_id()")
    detector_id: str = Field(min_length=1, description="Which detector produced the finding")
    title: str = Field(min_length=1)
    severity: Severity
    reason: str = Field(min_length=1, description="Plain-English explanation of why it fired")

    first_seen: AwareDatetime = Field(description="Time of the earliest evidence event, UTC")
    last_seen: AwareDatetime = Field(description="Time of the latest evidence event, UTC")

    account_id: str | None
    principal: str | None = Field(description="The actor, as in Event.principal")
    principal_arn: str | None
    resource: str | None = Field(description="What was acted on, when the detector knows it")

    event_ids: tuple[str, ...] = Field(
        description="Evidence events; empty for findings not based on events (posture checks)"
    )

    @field_validator("first_seen", "last_seen")
    @classmethod
    def _convert_to_utc(cls, value: datetime) -> datetime:
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def _check_time_range(self) -> Self:
        if self.last_seen < self.first_seen:
            raise ValueError("last_seen must not be earlier than first_seen")
        return self
