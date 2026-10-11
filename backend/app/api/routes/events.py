"""Read-only access to normalized events."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.api.deps import get_session
from app.api.schemas import EventSummary, Page
from app.repositories.events import get_event, search_events
from app.schemas.event import Event

router = APIRouter(prefix="/events", tags=["events"])

# Bounded page size: a client can never ask for the whole table at once.
MAX_PAGE_SIZE = 200


@router.get("")
def list_events(
    session: Annotated[Session, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=MAX_PAGE_SIZE)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
    principal: Annotated[str | None, Query(max_length=256)] = None,
    event_name: Annotated[str | None, Query(max_length=128)] = None,
) -> Page[EventSummary]:
    """Events, newest first. Filter by actor or API name."""
    events, total = search_events(
        session, limit=limit, offset=offset, principal=principal, event_name=event_name
    )
    return Page(
        items=[EventSummary.from_event(e) for e in events],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/{event_id}")
def read_event(event_id: str, session: Annotated[Session, Depends(get_session)]) -> Event:
    """One event in full, including the original CloudTrail record."""
    event = get_event(session, event_id)
    if event is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Event not found")
    return event
