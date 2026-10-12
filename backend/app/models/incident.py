"""The ``incidents`` table and the findings each incident groups."""

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
from app.models.finding import one_of
from app.schemas.finding import Severity
from app.schemas.incident import IncidentStatus


class IncidentRecord(Base):
    """One incident. Unlike events and findings, its row is updated as it evolves."""

    __tablename__ = "incidents"
    __table_args__ = (
        CheckConstraint(one_of("severity", [s.value for s in Severity]), name="severity"),
        CheckConstraint(one_of("status", [s.value for s in IncidentStatus]), name="status"),
        CheckConstraint("risk_score BETWEEN 0 AND 100", name="risk_score"),
        CheckConstraint("last_seen >= first_seen", name="time_range"),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    incident_id: Mapped[str] = mapped_column(Text, unique=True)

    pattern_id: Mapped[str] = mapped_column(Text)
    title: Mapped[str] = mapped_column(Text)
    summary: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(16))
    risk_score: Mapped[int] = mapped_column(SmallInteger, index=True)
    risk_factors: Mapped[list[dict[str, Any]]] = mapped_column(JSONB)

    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)

    account_id: Mapped[str | None] = mapped_column(Text)
    principal: Mapped[str | None] = mapped_column(Text)
    principal_arn: Mapped[str | None] = mapped_column(Text, index=True)

    status: Mapped[str] = mapped_column(String(16), server_default=IncidentStatus.OPEN.value)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    members: Mapped[list["IncidentFinding"]] = relationship(
        order_by="IncidentFinding.position", lazy="selectin"
    )


class IncidentFinding(Base):
    """Membership of a finding in an incident."""

    __tablename__ = "incident_findings"

    # finding_id alone is the primary key: the database itself guarantees a
    # finding belongs to at most one incident.
    finding_id: Mapped[str] = mapped_column(
        Text, ForeignKey("findings.finding_id", ondelete="RESTRICT"), primary_key=True
    )
    incident_id: Mapped[str] = mapped_column(
        Text, ForeignKey("incidents.incident_id", ondelete="CASCADE"), index=True
    )
    position: Mapped[int] = mapped_column(Integer)
