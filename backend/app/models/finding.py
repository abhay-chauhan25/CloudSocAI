"""The ``findings`` table and its links to evidence events."""

from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Identity,
    Integer,
    SmallInteger,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base
from app.schemas.finding import FindingStatus, Severity


def _one_of(column: str, values: list[str]) -> str:
    allowed = ", ".join(f"'{value}'" for value in values)
    return f"{column} IN ({allowed})"


class FindingRecord(Base):
    """One stored finding, with its risk breakdown and triage status."""

    __tablename__ = "findings"
    __table_args__ = (
        # Enforced by the database too, so no writer can store an unknown value.
        CheckConstraint(_one_of("severity", [s.value for s in Severity]), name="severity"),
        CheckConstraint(_one_of("status", [s.value for s in FindingStatus]), name="status"),
        CheckConstraint("risk_score BETWEEN 0 AND 100", name="risk_score"),
        CheckConstraint("last_seen >= first_seen", name="time_range"),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    # Deterministic ID from the detector and evidence; UNIQUE makes storing
    # the same finding twice impossible.
    finding_id: Mapped[str] = mapped_column(Text, unique=True)

    detector_id: Mapped[str] = mapped_column(Text, index=True)
    title: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(16))
    reason: Mapped[str] = mapped_column(Text)

    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))

    account_id: Mapped[str | None] = mapped_column(Text)
    principal: Mapped[str | None] = mapped_column(Text)
    principal_arn: Mapped[str | None] = mapped_column(Text, index=True)
    resource: Mapped[str | None] = mapped_column(Text)

    risk_score: Mapped[int] = mapped_column(SmallInteger, index=True)
    risk_factors: Mapped[list[dict[str, Any]]] = mapped_column(JSONB)

    status: Mapped[str] = mapped_column(String(16), server_default=FindingStatus.OPEN.value)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    evidence: Mapped[list["FindingEvidence"]] = relationship(
        order_by="FindingEvidence.position", lazy="selectin"
    )


class FindingEvidence(Base):
    """Links a finding to one evidence event (many-to-many: an event can be
    evidence for several findings, and a finding can cite several events)."""

    __tablename__ = "finding_events"

    finding_id: Mapped[str] = mapped_column(
        Text, ForeignKey("findings.finding_id", ondelete="CASCADE"), primary_key=True
    )
    # RESTRICT: an event cannot be deleted while a finding cites it as evidence.
    event_id: Mapped[str] = mapped_column(
        Text, ForeignKey("events.event_id", ondelete="RESTRICT"), primary_key=True, index=True
    )
    # Keeps the evidence in the order the detector listed it.
    position: Mapped[int] = mapped_column(Integer)
