"""Alembic environment: how migrations connect to the database.

The connection comes from one of two places:
- a Connection passed in ``config.attributes["connection"]`` (used by tests to
  migrate their own test database), or
- the application settings (environment variables / .env) otherwise.
"""

from logging.config import fileConfig

from alembic import context
from sqlalchemy import Connection

import app.models  # noqa: F401  (registers every table on Base.metadata)
from app.db import Base, create_db_engine

config = context.config

if config.config_file_name is not None and config.attributes.get("configure_logger", True):
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def run_migrations(connection: Connection) -> None:
    context.configure(connection=connection, target_metadata=target_metadata)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connection = config.attributes.get("connection")
    if connection is not None:
        run_migrations(connection)
        return

    engine = create_db_engine()
    with engine.connect() as connection:
        run_migrations(connection)
    engine.dispose()


if context.is_offline_mode():
    raise SystemExit("Offline (SQL script) migrations are not supported; run against a database.")

run_migrations_online()
