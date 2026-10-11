"""Dependencies injected into route functions."""

from collections.abc import Iterator

from fastapi import Request
from sqlalchemy.orm import Session


def get_session(request: Request) -> Iterator[Session]:
    """One database session per request, closed when the response is sent.

    The API only reads, so nothing is committed. Tests replace this
    dependency to run against the test database.
    """
    with request.app.state.sessions() as session:
        yield session
