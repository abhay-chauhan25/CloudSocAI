"""Migrations apply cleanly, reverse cleanly, and match the ORM models."""

from collections.abc import Callable

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from sqlalchemy import Connection, Engine, inspect

from app.db import Base

pytestmark = pytest.mark.db


def test_events_table_exists_with_expected_shape(db_engine: Engine) -> None:
    inspector = inspect(db_engine)

    columns = {column["name"]: column for column in inspector.get_columns("events")}
    assert {"event_id", "timestamp", "principal_arn", "source_ip", "raw_event"} <= set(columns)
    assert columns["event_id"]["nullable"] is False
    assert columns["raw_event"]["nullable"] is False
    assert [c["column_names"] for c in inspector.get_unique_constraints("events")] == [["event_id"]]


def test_models_and_migrations_are_in_sync(db_engine: Engine) -> None:
    # Fails if a model was changed without generating a migration for it.
    with db_engine.connect() as connection:
        differences = compare_metadata(MigrationContext.configure(connection), Base.metadata)

    assert differences == []


def test_migrations_downgrade_and_upgrade_cleanly(
    db_engine: Engine, alembic_config: Callable[[Connection], Config]
) -> None:
    with db_engine.begin() as connection:
        command.downgrade(alembic_config(connection), "base")
    assert "events" not in inspect(db_engine).get_table_names()

    with db_engine.begin() as connection:
        command.upgrade(alembic_config(connection), "head")
    assert "events" in inspect(db_engine).get_table_names()
