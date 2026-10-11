"""Save and load Findings with their risk assessment and evidence links.

Like the events repository, functions take a Session and do not commit:
the caller owns the transaction.
"""

from collections.abc import Sequence
from dataclasses import dataclass

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.models.finding import FindingEvidence, FindingRecord
from app.schemas.finding import Finding, FindingStatus, StoredFinding
from app.schemas.risk import RiskAssessment

INSERT_BATCH_SIZE = 1000  # well under PostgreSQL's 65,535 bind-parameter limit


@dataclass(frozen=True)
class ScoredFinding:
    """A detector's finding together with the risk calculated for it."""

    finding: Finding
    risk: RiskAssessment


def save_findings(session: Session, scored: Sequence[ScoredFinding]) -> int:
    """Insert findings and their evidence links, skipping findings already stored.

    Returns how many were newly inserted. A finding that already exists is
    left untouched, so re-running detection never resets an analyst's triage
    status. Evidence links must reference stored events: the foreign key
    rejects a finding that cites an unknown event.
    """
    inserted = 0
    for start in range(0, len(scored), INSERT_BATCH_SIZE):
        batch = scored[start : start + INSERT_BATCH_SIZE]
        new_ids = set(
            session.scalars(
                insert(FindingRecord)
                .values([_to_row(item) for item in batch])
                .on_conflict_do_nothing(index_elements=[FindingRecord.finding_id])
                .returning(FindingRecord.finding_id)
            ).all()
        )
        links = [
            {"finding_id": item.finding.finding_id, "event_id": event_id, "position": position}
            for item in batch
            if item.finding.finding_id in new_ids
            for position, event_id in enumerate(item.finding.event_ids)
        ]
        if links:
            session.execute(insert(FindingEvidence), links)
        inserted += len(new_ids)
    return inserted


def get_finding(session: Session, finding_id: str) -> StoredFinding | None:
    record = session.scalar(select(FindingRecord).where(FindingRecord.finding_id == finding_id))
    return _to_stored_finding(record) if record is not None else None


def list_findings(session: Session) -> list[StoredFinding]:
    """All stored findings, oldest first."""
    records = session.scalars(
        select(FindingRecord).order_by(FindingRecord.first_seen, FindingRecord.finding_id)
    )
    return [_to_stored_finding(record) for record in records]


def count_findings(session: Session) -> int:
    return session.scalar(select(func.count()).select_from(FindingRecord)) or 0


def _to_row(item: ScoredFinding) -> dict:
    row = item.finding.model_dump(mode="python", exclude={"event_ids"})
    row["severity"] = item.finding.severity.value
    row["risk_score"] = item.risk.score
    row["risk_factors"] = [factor.model_dump(mode="json") for factor in item.risk.factors]
    return row


def _to_stored_finding(record: FindingRecord) -> StoredFinding:
    fields = {name: getattr(record, name) for name in Finding.model_fields if name != "event_ids"}
    finding = Finding(**fields, event_ids=tuple(link.event_id for link in record.evidence))
    return StoredFinding(
        finding=finding,
        risk=RiskAssessment(score=record.risk_score, factors=tuple(record.risk_factors)),
        status=FindingStatus(record.status),
        created_at=record.created_at,
    )
