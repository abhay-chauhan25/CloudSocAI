"""The ``events`` table: durable storage for normalized Events."""

from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, DateTime, Identity, String, Text, func
from sqlalchemy.dialects.postgresql import INET, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base


class EventRecord(Base):
    """One stored event. Mirrors ``app.schemas.event.Event`` column for column."""

    __tablename__ = "events"

    # Surrogate key. Findings reference events by the stable event_id instead.
    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    # Provider event ID. UNIQUE makes duplicate ingestion impossible at the
    # database level, not just unlikely in application code.
    event_id: Mapped[str] = mapped_column(Text, unique=True)

    source: Mapped[str] = mapped_column(String(32))
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    account_id: Mapped[str | None] = mapped_column(Text)

    service: Mapped[str] = mapped_column(Text)
    event_name: Mapped[str] = mapped_column(Text, index=True)
    event_type: Mapped[str | None] = mapped_column(Text)
    read_only: Mapped[bool | None]
    region: Mapped[str] = mapped_column(Text)

    principal_type: Mapped[str] = mapped_column(String(32))
    principal: Mapped[str | None] = mapped_column(Text)
    principal_arn: Mapped[str | None] = mapped_column(Text, index=True)
    session_name: Mapped[str | None] = mapped_column(Text)
    access_key_id: Mapped[str | None] = mapped_column(Text)
    mfa_authenticated: Mapped[bool | None]

    source_address: Mapped[str | None] = mapped_column(Text)
    source_ip: Mapped[str | None] = mapped_column(INET)
    user_agent: Mapped[str | None] = mapped_column(Text)

    success: Mapped[bool]
    error_code: Mapped[str | None] = mapped_column(Text)
    error_message: Mapped[str | None] = mapped_column(Text)

    request_parameters: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    raw_event: Mapped[dict[str, Any]] = mapped_column(JSONB)

    # When CloudSOC stored the event, as opposed to when it happened. The gap
    # between the two is the ingestion delay.
    ingested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
