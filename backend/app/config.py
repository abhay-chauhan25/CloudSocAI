"""Application settings, read from environment variables or the repo-root .env file.

Environment variables take precedence over .env, so deployments can inject
real values without files. Secrets (the database password, the Gemini and
API keys) are SecretStr: hidden in repr() and logs, unwrapped only where used.
"""

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy import URL

ENV_FILE = Path(__file__).resolve().parents[2] / ".env"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=ENV_FILE, extra="ignore")

    postgres_user: str
    postgres_password: SecretStr
    postgres_db: str
    postgres_host: str = "localhost"
    postgres_port: int = 5432

    # AI analyst. Without an explicit choice, Gemini is used when a key is
    # configured and the offline mock otherwise; "disabled" turns it off.
    ai_provider: Literal["gemini", "mock", "disabled"] | None = None
    gemini_api_key: SecretStr | None = None
    gemini_model: str = "gemini-3.5-flash-lite"
    ai_daily_limit: int = 50  # analysis attempts per 24 hours, across all incidents
    ai_cooldown_seconds: int = 60  # minimum time between attempts for one incident

    # Shared secret for the HTTP API (X-API-Key). Required to start the API;
    # the command-line tools do not use it.
    api_key: SecretStr | None = None

    @field_validator("api_key", mode="before")
    @classmethod
    def _blank_is_unset(cls, value: object) -> object:
        # `API_KEY=` copied from .env.example means "not set", not "empty key".
        return None if value == "" else value

    @field_validator("api_key")
    @classmethod
    def _long_enough(cls, value: SecretStr | None) -> SecretStr | None:
        if value is not None and len(value.get_secret_value()) < 32:
            raise ValueError(
                "API_KEY must be at least 32 characters (use secrets.token_urlsafe(32))"
            )
        return value

    def resolved_ai_provider(self) -> Literal["gemini", "mock", "disabled"]:
        if self.ai_provider is not None:
            return self.ai_provider
        return "gemini" if self.gemini_api_key else "mock"

    def database_url(self, database: str | None = None) -> URL:
        """Build the connection URL; ``database`` overrides the default DB name."""
        # URL.create escapes special characters in the password safely,
        # unlike building the URL with string formatting.
        return URL.create(
            drivername="postgresql+psycopg",
            username=self.postgres_user,
            password=self.postgres_password.get_secret_value(),
            host=self.postgres_host,
            port=self.postgres_port,
            database=database or self.postgres_db,
        )


@lru_cache
def get_settings() -> Settings:
    return Settings()  # values come from the environment
