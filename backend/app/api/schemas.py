"""Response models: exactly what the API sends, separate from storage models.

List endpoints return small summaries; detail endpoints return everything.
Keeping these separate means a new database column never leaks into the API
by accident.
"""

from datetime import datetime

from pydantic import BaseModel, ConfigDict

from app.detection.base import Detector
from app.schemas.event import Event, PrincipalType
from app.schemas.finding import FindingStatus, Severity, StoredFinding
from app.schemas.risk import RiskAssessment


class Page[T](BaseModel):
    """One page of a list, with enough information to fetch the next."""

    items: list[T]
    total: int  # how many items match, across all pages
    limit: int
    offset: int


class EventSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    event_id: str
    timestamp: datetime
    service: str
    event_name: str
    region: str
    principal_type: PrincipalType
    principal: str | None
    source_address: str | None
    success: bool
    error_code: str | None

    @classmethod
    def from_event(cls, event: Event) -> "EventSummary":
        return cls.model_validate(event)


class FindingSummary(BaseModel):
    finding_id: str
    detector_id: str
    title: str
    severity: Severity
    risk_score: int
    status: FindingStatus
    first_seen: datetime
    last_seen: datetime
    principal: str | None
    resource: str | None
    event_count: int

    @classmethod
    def from_stored(cls, stored: StoredFinding) -> "FindingSummary":
        finding = stored.finding
        return cls(
            finding_id=finding.finding_id,
            detector_id=finding.detector_id,
            title=finding.title,
            severity=finding.severity,
            risk_score=stored.risk.score,
            status=stored.status,
            first_seen=finding.first_seen,
            last_seen=finding.last_seen,
            principal=finding.principal,
            resource=finding.resource,
            event_count=len(finding.event_ids),
        )


class DetectorInfo(BaseModel):
    """The rule behind a finding, so an analyst can judge it without reading code."""

    detector_id: str
    name: str
    description: str
    rationale: str
    mitre_techniques: list[str]

    @classmethod
    def from_detector(cls, detector: Detector) -> "DetectorInfo":
        return cls(
            detector_id=detector.detector_id,
            name=detector.name,
            description=detector.description,
            rationale=detector.rationale,
            mitre_techniques=list(detector.mitre_techniques),
        )


class FindingDetail(BaseModel):
    finding_id: str
    detector_id: str
    title: str
    severity: Severity
    reason: str
    status: FindingStatus
    first_seen: datetime
    last_seen: datetime
    created_at: datetime
    account_id: str | None
    principal: str | None
    principal_arn: str | None
    resource: str | None
    risk: RiskAssessment
    # None if the rule that produced the finding no longer exists.
    detector: DetectorInfo | None
    evidence: list[EventSummary]


class HealthStatus(BaseModel):
    status: str
    database: str
