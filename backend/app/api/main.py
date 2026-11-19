"""The FastAPI application.

Run locally (from backend/, with the database running):

    uvicorn app.api.main:app --reload

Interactive docs: http://127.0.0.1:8000/docs

Every route except /health requires the API key from API_KEY (see
app/api/security.py). Locally it still listens on 127.0.0.1 only
(uvicorn's default); in Docker it is reachable only through nginx.
"""

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Request, status
from fastapi.responses import JSONResponse
from sqlalchemy.exc import OperationalError

from app.ai.service import build_analyst_config
from app.api.routes import analysis, detectors, events, findings, health, incidents
from app.api.security import DEFAULT_ALLOWED_HOSTS, browser_protection, require_api_key
from app.config import get_settings
from app.db import create_db_engine, create_session_factory

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Check configuration, create the connection pool at startup, close it at shutdown."""
    settings = get_settings()
    if settings.api_key is None:
        raise RuntimeError(
            "API_KEY is not set. Generate one with: "
            'python -c "import secrets; print(secrets.token_urlsafe(32))"'
        )
    app.state.api_key = settings.api_key
    engine = create_db_engine()
    app.state.sessions = create_session_factory(engine)
    app.state.analyst = build_analyst_config(settings)
    yield
    engine.dispose()


async def database_unavailable(request: Request, exc: Exception) -> JSONResponse:
    # Logged for operators; the client gets a generic message, never driver details.
    logger.error("database unavailable while serving %s %s", request.method, request.url.path)
    return JSONResponse(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        content={"detail": "Database unavailable"},
    )


def create_app(allowed_hosts: tuple[str, ...] = DEFAULT_ALLOWED_HOSTS) -> FastAPI:
    app = FastAPI(
        title="CloudSOC AI",
        summary="Read-only API for CloudSOC events, findings, and incidents (portfolio prototype).",
        version="0.1.0",
        lifespan=lifespan,
    )
    app.add_exception_handler(OperationalError, database_unavailable)
    app.middleware("http")(browser_protection(allowed_hosts))
    # /health stays open: container health checks and load balancers call it,
    # and it reveals nothing beyond "up" or "degraded".
    app.include_router(health.router)
    authenticated = [Depends(require_api_key)]
    for module in (events, findings, incidents, analysis, detectors):
        app.include_router(module.router, dependencies=authenticated)
    return app


app = create_app()
