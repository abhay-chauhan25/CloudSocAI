"""The Incident: related findings grouped into one investigation.

Unlike Events and Findings, an incident evolves: when a new related finding
arrives it joins the incident, and the title, time range, and risk are
recalculated. Each Incident object is a snapshot of that state.
"""

import uuid
from enum import StrEnum
from typing import Self

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator

from app.schemas.finding import Severity
from app.schemas.risk import RiskAssessment

INCIDENT_ID_NAMESPACE = uuid.UUID("0b8e6f3a-91d2-5c47-a3e8-5d2f7c1b9e40")


class IncidentStatus(StrEnum):
    """Analyst workflow state. Only open and investigating incidents gain new findings."""

    OPEN = "open"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"

    @property
    def accepts_new_findings(self) -> bool:
        return self in (IncidentStatus.OPEN, IncidentStatus.INVESTIGATING)


def make_incident_id(seed_finding_id: str) -> str:
    """Derive an incident's ID from the earliest finding it was created from.

    A finding belongs to at most one incident, so this is unique, and
    re-running correlation from scratch reproduces the same IDs.
    """
    return str(uuid.uuid5(INCIDENT_ID_NAMESPACE, seed_finding_id))


class Incident(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    incident_id: str = Field(min_length=1)
    pattern_id: str = Field(description="Which correlation pattern describes the incident")
    title: str = Field(min_length=1)
    summary: str = Field(min_length=1, description="Why these findings were grouped")
    severity: Severity = Field(description="The highest severity among its findings")
    risk: RiskAssessment

    first_seen: AwareDatetime
    last_seen: AwareDatetime

    account_id: str | None
    principal: str | None
    principal_arn: str | None

    finding_ids: tuple[str, ...] = Field(min_length=1, description="Ordered by first_seen")

    @model_validator(mode="after")
    def _check_time_range(self) -> Self:
        if self.last_seen < self.first_seen:
            raise ValueError("last_seen must not be earlier than first_seen")
        return self


class StoredIncident(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    incident: Incident
    status: IncidentStatus
    created_at: AwareDatetime
    updated_at: AwareDatetime
