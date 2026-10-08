"""Application settings, read from environment variables or the repo-root .env file.

Environment variables take precedence over .env, so deployments can inject
real values without files. The database password is a SecretStr: it is
hidden in repr() and logs and must be unwrapped explicitly to be used.
"""

from functools import lru_cache
from pathlib import Path

from pydantic import SecretStr
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
    return Settings()  # type: ignore[call-arg]  # values come from the environment
