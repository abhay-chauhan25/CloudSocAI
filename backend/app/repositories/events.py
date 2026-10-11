"""Save and load Events.

Converts between the validated Pydantic ``Event`` and the ``EventRecord`` row,
so the rest of the application never deals with database types. Functions
take a Session and do not commit: the caller owns the transaction.
"""

from collections.abc import Sequence
from ipaddress import ip_address

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.models.event import EventRecord
from app.schemas.event import Event

# PostgreSQL allows at most 65,535 bind parameters per statement. At ~23
# columns per row, 1,000 rows (~23,000 parameters) stays well under the limit.
INSERT_BATCH_SIZE = 1000


def save_events(session: Session, events: Sequence[Event]) -> int:
    """Insert events, skipping any whose event_id is already stored.

    Returns how many were newly inserted. Re-ingesting the same log file is
    therefore safe (idempotent): duplicates are detected by the database's
    UNIQUE constraint, which also holds under concurrent ingestion.
    """
    inserted = 0
    for start in range(0, len(events), INSERT_BATCH_SIZE):
        batch = events[start : start + INSERT_BATCH_SIZE]
        statement = (
            insert(EventRecord)
            .values([_to_row(event) for event in batch])
            .on_conflict_do_nothing(index_elements=[EventRecord.event_id])
            .returning(EventRecord.event_id)
        )
        inserted += len(session.scalars(statement).all())
    return inserted


def get_event(session: Session, event_id: str) -> Event | None:
    record = session.scalar(select(EventRecord).where(EventRecord.event_id == event_id))
    return _to_event(record) if record is not None else None


def list_events(session: Session) -> list[Event]:
    """All stored events, oldest first.

    Loads everything into memory, which is fine for a lab-sized dataset. At
    scale, detection would run over time windows instead (e.g. the last hour).
    """
    records = session.scalars(
        select(EventRecord).order_by(EventRecord.timestamp, EventRecord.event_id)
    )
    return [_to_event(record) for record in records]


def search_events(
    session: Session,
    *,
    limit: int,
    offset: int = 0,
    principal: str | None = None,
    event_name: str | None = None,
) -> tuple[list[Event], int]:
    """One page of events, newest first, plus the total number that match."""
    query = select(EventRecord)
    if principal is not None:
        query = query.where(EventRecord.principal == principal)
    if event_name is not None:
        query = query.where(EventRecord.event_name == event_name)

    total = session.scalar(select(func.count()).select_from(query.subquery())) or 0
    records = session.scalars(
        query.order_by(EventRecord.timestamp.desc(), EventRecord.event_id.desc())
        .limit(limit)
        .offset(offset)
    )
    return [_to_event(record) for record in records], total


def get_events(session: Session, event_ids: Sequence[str]) -> list[Event]:
    """The events with these IDs, in the order given; unknown IDs are skipped."""
    records = session.scalars(select(EventRecord).where(EventRecord.event_id.in_(event_ids)))
    by_id = {record.event_id: _to_event(record) for record in records}
    return [by_id[event_id] for event_id in event_ids if event_id in by_id]


def count_events(session: Session) -> int:
    return session.scalar(select(func.count()).select_from(EventRecord)) or 0


def _to_row(event: Event) -> dict:
    row = event.model_dump(mode="python")
    row["principal_type"] = event.principal_type.value
    row["source_ip"] = str(event.source_ip) if event.source_ip is not None else None
    return row


def _to_event(record: EventRecord) -> Event:
    fields = {name: getattr(record, name) for name in Event.model_fields}
    if record.source_ip is not None:
        # Depending on driver settings INET may come back as a string or an
        # ipaddress object; normalise to a plain address either way.
        fields["source_ip"] = ip_address(str(record.source_ip).split("/")[0])
    return Event(**fields)
