"""Save and load Incidents and their member findings.

Functions take a Session and do not commit: the caller owns the transaction.
"""

from typing import Literal

from sqlalchemy import delete, func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.models.finding import FindingRecord
from app.models.incident import IncidentFinding, IncidentRecord
from app.repositories.findings import get_findings
from app.schemas.finding import FindingStatus, Severity, StoredFinding
from app.schemas.incident import Incident, IncidentStatus, StoredIncident
from app.schemas.risk import RiskAssessment

IncidentSort = Literal["newest", "risk"]

# Columns recalculated whenever an incident changes. Status and created_at
# are deliberately absent: an update never undoes an analyst's decision.
RECALCULATED_COLUMNS = (
    "pattern_id",
    "title",
    "summary",
    "severity",
    "risk_score",
    "risk_factors",
    "first_seen",
    "last_seen",
)


def save_incident(session: Session, incident: Incident) -> None:
    """Insert a new incident, or update an existing one, and set its members.

    A finding that already belongs to a different incident is rejected by
    the database (its finding_id is the membership table's primary key).
    """
    row = _to_row(incident)
    statement = insert(IncidentRecord).values(row)
    statement = statement.on_conflict_do_update(
        index_elements=[IncidentRecord.incident_id],
        set_={
            **{column: statement.excluded[column] for column in RECALCULATED_COLUMNS},
            "updated_at": func.now(),
        },
    )
    session.execute(statement)

    session.execute(
        delete(IncidentFinding).where(IncidentFinding.incident_id == incident.incident_id)
    )
    session.execute(
        insert(IncidentFinding),
        [
            {"incident_id": incident.incident_id, "finding_id": finding_id, "position": position}
            for position, finding_id in enumerate(incident.finding_ids)
        ],
    )
    # These statements bypass the ORM, so incident rows already loaded in this
    # session would otherwise keep showing their old values and members.
    session.expire_all()


def list_open_incidents(session: Session) -> list[tuple[Incident, list[StoredFinding]]]:
    """Incidents that can still gain findings, each with its current findings."""
    open_statuses = [s.value for s in IncidentStatus if s.accepts_new_findings]
    records = session.scalars(
        select(IncidentRecord)
        .where(IncidentRecord.status.in_(open_statuses))
        .order_by(IncidentRecord.first_seen, IncidentRecord.incident_id)
    )
    result = []
    for record in records:
        stored = _to_stored_incident(record)
        result.append((stored.incident, get_findings(session, stored.incident.finding_ids)))
    return result


def list_unassigned_findings(session: Session) -> list[StoredFinding]:
    """Findings in no incident yet, except those an analyst marked false positive."""
    assigned = select(IncidentFinding.finding_id)
    finding_ids = session.scalars(
        select(FindingRecord.finding_id)
        .where(FindingRecord.finding_id.not_in(assigned))
        .where(FindingRecord.status != FindingStatus.FALSE_POSITIVE.value)
        .order_by(FindingRecord.first_seen, FindingRecord.finding_id)
    ).all()
    return get_findings(session, finding_ids)


def get_incident(session: Session, incident_id: str) -> StoredIncident | None:
    record = session.scalar(select(IncidentRecord).where(IncidentRecord.incident_id == incident_id))
    return _to_stored_incident(record) if record is not None else None


def search_incidents(
    session: Session,
    *,
    limit: int,
    offset: int = 0,
    status: IncidentStatus | None = None,
    severity: Severity | None = None,
    principal: str | None = None,
    sort: IncidentSort = "newest",
) -> tuple[list[StoredIncident], int]:
    """One page of incidents plus the total number that match.

    ``sort="newest"`` orders by most recent activity; ``sort="risk"`` puts
    the highest risk first.
    """
    query = select(IncidentRecord)
    if status is not None:
        query = query.where(IncidentRecord.status == status.value)
    if severity is not None:
        query = query.where(IncidentRecord.severity == severity.value)
    if principal is not None:
        query = query.where(IncidentRecord.principal == principal)

    total = session.scalar(select(func.count()).select_from(query.subquery())) or 0
    if sort == "risk":
        order = (IncidentRecord.risk_score.desc(), IncidentRecord.last_seen.desc())
    else:
        order = (IncidentRecord.last_seen.desc(),)
    records = session.scalars(
        query.order_by(*order, IncidentRecord.incident_id).limit(limit).offset(offset)
    )
    return [_to_stored_incident(record) for record in records], total


def count_incidents(session: Session) -> int:
    return session.scalar(select(func.count()).select_from(IncidentRecord)) or 0


def _to_row(incident: Incident) -> dict:
    row = incident.model_dump(mode="python", exclude={"risk", "finding_ids"})
    row["severity"] = incident.severity.value
    row["risk_score"] = incident.risk.score
    row["risk_factors"] = [factor.model_dump(mode="json") for factor in incident.risk.factors]
    return row


def _to_stored_incident(record: IncidentRecord) -> StoredIncident:
    skip = {"risk", "finding_ids"}
    fields = {name: getattr(record, name) for name in Incident.model_fields if name not in skip}
    incident = Incident(
        **fields,
        risk=RiskAssessment(score=record.risk_score, factors=tuple(record.risk_factors)),
        finding_ids=tuple(member.finding_id for member in record.members),
    )
    return StoredIncident(
        incident=incident,
        status=IncidentStatus(record.status),
        created_at=record.created_at,
        updated_at=record.updated_at,
    )
