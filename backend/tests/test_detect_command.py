"""The `python -m app.detect` command against a real database."""

from pathlib import Path

import pytest
from sqlalchemy import URL, Engine, text

from app import detect, ingest
from app.config import get_settings
from app.db import create_db_engine

pytestmark = pytest.mark.db


def test_detect_command_prints_findings_for_stored_events(
    db_engine: Engine,
    test_database_url: URL,
    cloudtrail_samples_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def connect() -> Engine:
        return create_db_engine(test_database_url)

    monkeypatch.setattr(ingest, "create_db_engine", connect)
    monkeypatch.setattr(detect, "create_db_engine", connect)

    try:
        assert ingest.main([str(cloudtrail_samples_dir / "cloudtrail-disabled.json")]) == 0
        capsys.readouterr()

        assert detect.main([]) == detect.EXIT_OK
    finally:
        # The commands commit for real, so clean up what they stored.
        with db_engine.begin() as connection:
            connection.execute(text("TRUNCATE events"))

    output = capsys.readouterr().out
    assert output.startswith("4 events analysed, 7 findings")
    assert "[CRITICAL] CloudTrail logging stopped (cloudtrail-logging-stopped)" in output
    assert "[HIGH] Console sign-in without MFA" in output


def test_detect_command_reports_unreachable_database(monkeypatch: pytest.MonkeyPatch) -> None:
    unreachable = get_settings().model_copy(update={"postgres_port": 1})
    monkeypatch.setattr(
        detect, "create_db_engine", lambda: create_db_engine(unreachable.database_url())
    )

    assert detect.main([]) == detect.EXIT_DATABASE_UNAVAILABLE
