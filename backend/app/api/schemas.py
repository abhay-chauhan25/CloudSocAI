"""Response models: exactly what the API sends, separate from storage models.

List endpoints return small summaries; detail endpoints return everything.
Keeping these separate means a new database column never leaks into the API
by accident.
"""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict

from app.detection.base import Detector, MitreMapping
from app.mitre.catalog import TECHNIQUES, Tactic, Technique
from app.posture.base import PostureCheck
from app.posture.registry import CHECKS_BY_ID
from app.schemas.event import Event, PrincipalType
from app.schemas.finding import FindingStatus, Severity, StoredFinding
from app.schemas.incident import IncidentStatus, StoredIncident
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


# "rule": a detection rule judged events. "posture": a posture check judged configuration.
FindingKind = Literal["rule", "posture"]


def finding_kind(detector_id: str) -> FindingKind:
    return "posture" if detector_id in CHECKS_BY_ID else "rule"


class FindingSummary(BaseModel):
    finding_id: str
    detector_id: str
    kind: FindingKind
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
            kind=finding_kind(finding.detector_id),
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


class TacticInfo(BaseModel):
    tactic_id: str
    name: str
    url: str

    @classmethod
    def from_tactic(cls, tactic: Tactic) -> "TacticInfo":
        return cls(tactic_id=tactic.tactic_id, name=tactic.name, url=tactic.url)


class TechniqueInfo(BaseModel):
    technique_id: str
    name: str
    tactics: list[TacticInfo]
    url: str

    @classmethod
    def from_technique(cls, technique: Technique) -> "TechniqueInfo":
        return cls(
            technique_id=technique.technique_id,
            name=technique.name,
            tactics=[TacticInfo.from_tactic(t) for t in technique.tactics],
            url=technique.url,
        )


class MitreMappingInfo(TechniqueInfo):
    """A technique together with the curated reason a rule maps to it."""

    rationale: str

    @classmethod
    def from_mapping(cls, mapping: MitreMapping) -> "MitreMappingInfo":
        technique = TECHNIQUES[mapping.technique_id]
        return cls(
            **TechniqueInfo.from_technique(technique).model_dump(), rationale=mapping.rationale
        )


class DetectorInfo(BaseModel):
    """The rule behind a finding, so an analyst can judge it without reading code."""

    detector_id: str
    name: str
    description: str
    rationale: str
    severity: Severity
    mitre: list[MitreMappingInfo]

    @classmethod
    def from_detector(cls, detector: Detector) -> "DetectorInfo":
        return cls(
            detector_id=detector.detector_id,
            name=detector.name,
            description=detector.description,
            rationale=detector.rationale,
            severity=detector.severity,
            mitre=[MitreMappingInfo.from_mapping(m) for m in detector.mitre],
        )


class PostureCheckInfo(BaseModel):
    """The posture check behind a finding: what it tests, why, and how to fix it."""

    check_id: str
    name: str
    service: str
    description: str
    rationale: str
    remediation: str
    reference: str
    severity: Severity

    @classmethod
    def from_check(cls, check: PostureCheck) -> "PostureCheckInfo":
        return cls(
            check_id=check.check_id,
            name=check.name,
            service=check.service,
            description=check.description,
            rationale=check.rationale,
            remediation=check.remediation,
            reference=check.reference,
            severity=check.severity,
        )


class DetectorCatalog(BaseModel):
    attack_version: str
    tactics: list[TacticInfo]  # every Enterprise tactic in matrix order, for coverage views
    detectors: list[DetectorInfo]
    # Posture checks describe configuration weaknesses, not adversary behaviour,
    # so they are not mapped to ATT&CK techniques.
    posture_checks: list[PostureCheckInfo]


class IncidentTechnique(TechniqueInfo):
    """An ATT&CK technique observed in an incident, and which of its rules mapped to it."""

    detector_ids: list[str]


class FindingDetail(BaseModel):
    finding_id: str
    detector_id: str
    kind: FindingKind
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
    # The rule or posture check behind the finding; both None if it no longer exists.
    detector: DetectorInfo | None
    posture_check: PostureCheckInfo | None
    evidence: list[EventSummary]  # empty for posture findings


class IncidentSummary(BaseModel):
    incident_id: str
    pattern_id: str
    title: str
    severity: Severity
    risk_score: int
    status: IncidentStatus
    first_seen: datetime
    last_seen: datetime
    principal: str | None
    finding_count: int

    @classmethod
    def from_stored(cls, stored: StoredIncident) -> "IncidentSummary":
        incident = stored.incident
        return cls(
            incident_id=incident.incident_id,
            pattern_id=incident.pattern_id,
            title=incident.title,
            severity=incident.severity,
            risk_score=incident.risk.score,
            status=stored.status,
            first_seen=incident.first_seen,
            last_seen=incident.last_seen,
            principal=incident.principal,
            finding_count=len(incident.finding_ids),
        )


class TimelineItem(BaseModel):
    """One event in an incident's timeline; ``detector_ids`` is empty for context events."""

    event: EventSummary
    flagged: bool
    detector_ids: list[str]


class IncidentDetail(BaseModel):
    incident_id: str
    pattern_id: str
    title: str
    summary: str
    severity: Severity
    status: IncidentStatus
    first_seen: datetime
    last_seen: datetime
    created_at: datetime
    updated_at: datetime
    account_id: str | None
    principal: str | None
    principal_arn: str | None
    risk: RiskAssessment
    findings: list[FindingSummary]
    # Curated mappings of the incident's rules, ordered by tactic (matrix order).
    mitre: list[IncidentTechnique]
    timeline: list[TimelineItem]


class HealthStatus(BaseModel):
    status: str
    database: str
