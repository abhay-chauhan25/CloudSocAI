"""Database engine, session factory, and the declarative base for ORM models."""

from sqlalchemy import URL, Engine, MetaData, create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from app.config import get_settings

# Deterministic constraint names, so later migrations can reliably alter or
# drop constraints instead of guessing the names PostgreSQL would generate.
NAMING_CONVENTION = {
    "ix": "ix_%(table_name)s_%(column_0_name)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    """Base class for all ORM models; its metadata drives Alembic migrations."""

    metadata = MetaData(naming_convention=NAMING_CONVENTION)


def create_db_engine(url: URL | None = None) -> Engine:
    # pool_pre_ping checks a pooled connection is alive before using it, so a
    # restarted database produces a reconnect instead of a confusing error.
    return create_engine(url or get_settings().database_url(), pool_pre_ping=True)


def create_session_factory(engine: Engine) -> sessionmaker:
    # expire_on_commit=False keeps loaded attributes readable after commit,
    # which suits converting rows back into immutable Events.
    return sessionmaker(bind=engine, expire_on_commit=False)
