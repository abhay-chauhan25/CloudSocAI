"""The ``anomaly_scores`` table: the anomaly model's score for each principal-hour.

Scores are derived data, not evidence: they are recalculated when a window
gains events, and a new model version stores its own rows alongside the old.
"""

from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    Identity,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base


class AnomalyScoreRecord(Base):
    __tablename__ = "anomaly_scores"
    __table_args__ = (
        UniqueConstraint("principal", "window_start", "model_version"),
        CheckConstraint("score > 0 AND score <= 1", name="score"),
        CheckConstraint("window_end > window_start", name="time_range"),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    principal: Mapped[str] = mapped_column(Text)
    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    window_end: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    model_version: Mapped[str] = mapped_column(Text)

    score: Mapped[float] = mapped_column(Float)
    threshold: Mapped[float] = mapped_column(Float)
    is_anomalous: Mapped[bool] = mapped_column(Boolean, index=True)
    features: Mapped[dict[str, int]] = mapped_column(JSONB)
    unusual_features: Mapped[list[dict[str, Any]]] = mapped_column(JSONB)

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
