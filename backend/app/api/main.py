"""The FastAPI application.

Run locally (from backend/, with the database running):

    uvicorn app.api.main:app --reload

Interactive docs: http://127.0.0.1:8000/docs

The API has no authentication yet, so it must only listen on 127.0.0.1
(uvicorn's default), like the database.
"""

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from sqlalchemy.exc import OperationalError

from app.api.routes import events, findings, health
from app.db import create_db_engine, create_session_factory

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Create the connection pool at startup and close it at shutdown."""
    engine = create_db_engine()
    app.state.sessions = create_session_factory(engine)
    yield
    engine.dispose()


async def database_unavailable(request: Request, exc: Exception) -> JSONResponse:
    # Logged for operators; the client gets a generic message, never driver details.
    logger.error("database unavailable while serving %s %s", request.method, request.url.path)
    return JSONResponse(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        content={"detail": "Database unavailable"},
    )


def create_app() -> FastAPI:
    app = FastAPI(
        title="CloudSOC AI",
        summary="Read-only API for CloudSOC events and findings (portfolio prototype).",
        version="0.1.0",
        lifespan=lifespan,
    )
    app.add_exception_handler(OperationalError, database_unavailable)
    app.include_router(health.router)
    app.include_router(events.router)
    app.include_router(findings.router)
    return app


app = create_app()
