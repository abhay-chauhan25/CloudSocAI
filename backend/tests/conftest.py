"""Shared pytest fixtures."""

from collections.abc import Callable, Iterator
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from pydantic import ValidationError
from sqlalchemy import URL, Connection, Engine, text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from app.config import Settings, get_settings
from app.db import create_db_engine

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
