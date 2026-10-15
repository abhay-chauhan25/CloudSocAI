"""Shared pytest fixtures."""

from collections.abc import Callable, Iterator
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy import URL, Connection, Engine, text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from app.api.deps import get_session
from app.api.main import create_app
from app.collectors.cloudtrail_file import load_cloudtrail_file
from app.config import Settings, get_settings
from app.correlation.service import run_correlation
from app.db import create_db_engine
from app.detection.engine import run_detectors
from app.normalization.cloudtrail import normalize_cloudtrail_records
from app.repositories.events import save_events
from app.repositories.findings import ScoredFinding, save_findings
from app.risk.scoring import RiskContext, score_finding
from app.schemas.event import Event

BACKEND_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = BACKEND_DIR.parent
CLOUDTRAIL_SAMPLES_DIR = REPO_ROOT / "sample-data" / "cloudtrail"


@pytest.fixture
def cloudtrail_samples_dir() -> Path:
    return CLOUDTRAIL_SAMPLES_DIR


# --- database ------------------------------------------------------------------
# Tests use a separate "<POSTGRES_DB>_test" database so they never touch
# development data. It is created on demand and migrated from scratch.


def _alembic_config(connection: Connection) -> Config:
    config = Config(str(BACKEND_DIR / "alembic.ini"))
    config.attributes["connection"] = connection
    config.attributes["configure_logger"] = False  # keep pytest's log capture intact
    return config


def _ensure_database_exists(settings: Settings, name: str) -> None:
    admin_engine = create_db_engine(settings.database_url())
    try:
        with admin_engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
            exists = conn.scalar(
                text("SELECT 1 FROM pg_database WHERE datname = :name"), {"name": name}
            )
            if not exists:
                quoted = admin_engine.dialect.identifier_preparer.quote(name)
                conn.execute(text(f"CREATE DATABASE {quoted}"))
    finally:
        admin_engine.dispose()


@pytest.fixture(scope="session")
def test_database_url() -> URL:
    """URL of the test database, created if needed; skips if PostgreSQL is unavailable."""
    try:
        settings = get_settings()
        name = f"{settings.postgres_db}_test"
        _ensure_database_exists(settings, name)
    except ValidationError:
        pytest.skip("database settings missing: copy .env.example to .env")
    except OperationalError:
        pytest.skip("PostgreSQL is not reachable: run `docker compose up -d`")
    return settings.database_url(name)


@pytest.fixture(scope="session")
def alembic_config() -> Callable[[Connection], Config]:
    """Build an Alembic config that migrates over a given connection."""
    return _alembic_config


@pytest.fixture(scope="session")
def db_engine(test_database_url: URL) -> Iterator[Engine]:
    """Engine for the test database, migrated from scratch once per test run."""
    engine = create_db_engine(test_database_url)
    with engine.begin() as connection:
        config = _alembic_config(connection)
        command.downgrade(config, "base")
        command.upgrade(config, "head")
    yield engine
    engine.dispose()


@pytest.fixture
def db_session(db_engine: Engine) -> Iterator[Session]:
    """A session whose changes are rolled back after each test, even if it commits."""
    connection = db_engine.connect()
    transaction = connection.begin()
    session = Session(
        bind=connection, join_transaction_mode="create_savepoint", expire_on_commit=False
    )
    yield session
    session.close()
    transaction.rollback()
    connection.close()


# --- API -----------------------------------------------------------------------


@pytest.fixture
def client(db_session: Session) -> Iterator[TestClient]:
    """An API client whose requests use the rolled-back test session."""
    app = create_app()
    app.dependency_overrides[get_session] = lambda: db_session
    # Not used as a context manager, so the lifespan (which would connect to
    # the development database) never runs.
    yield TestClient(app)


@pytest.fixture
def seeded(db_session: Session, cloudtrail_samples_dir: Path) -> list[Event]:
    """All fixture events stored, with their scored findings and incidents."""
    events: list[Event] = []
    for path in sorted(cloudtrail_samples_dir.glob("*.json")):
        events += normalize_cloudtrail_records(load_cloudtrail_file(path)).events
    save_events(db_session, events)
    context = RiskContext.from_events(events)
    save_findings(
        db_session,
        [ScoredFinding(f, score_finding(f, context)) for f in run_detectors(events).findings],
    )
    run_correlation(db_session)
    return events
