"""The ``incident_analyses`` table: every AI analysis attempt, successful or not.

Doubles as an audit log of what was sent to an external AI provider, when,
for which incident, and at what token cost.
"""

from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Identity,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base


class AnalysisRecord(Base):
    __tablename__ = "incident_analyses"
    __table_args__ = (
        CheckConstraint("status IN ('succeeded', 'failed')", name="status"),
        # A success has a result and no error; a failure the opposite.
        CheckConstraint(
            "(status = 'succeeded' AND result IS NOT NULL AND error_kind IS NULL) OR "
            "(status = 'failed' AND result IS NULL AND error_kind IS NOT NULL)",
            name="outcome",
        ),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    incident_id: Mapped[str] = mapped_column(
        Text, ForeignKey("incidents.incident_id", ondelete="CASCADE"), index=True
    )
    status: Mapped[str] = mapped_column(String(16))
    provider: Mapped[str] = mapped_column(Text)
    model: Mapped[str] = mapped_column(Text)
    prompt_version: Mapped[str] = mapped_column(Text)
    # SHA-256 of the exact context sent; the analysis is current while it matches.
    context_hash: Mapped[str] = mapped_column(String(64))

    result: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    error_kind: Mapped[str | None] = mapped_column(String(32))
    error_message: Mapped[str | None] = mapped_column(Text)

    input_tokens: Mapped[int | None] = mapped_column(Integer)
    output_tokens: Mapped[int | None] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )
