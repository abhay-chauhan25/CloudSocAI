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
        first_run = capsys.readouterr().out
        assert detect.main([]) == detect.EXIT_OK
        second_run = capsys.readouterr().out
        with db_engine.connect() as connection:
            stored = connection.scalar(text("SELECT count(*) FROM findings"))
    finally:
        # The commands commit for real, so clean up what they stored.
        with db_engine.begin() as connection:
            # CASCADE also clears every table that references these.
            connection.execute(text("TRUNCATE events, findings, incidents, anomaly_scores CASCADE"))

    assert stored == 7
    assert first_run.startswith("4 events analysed, 7 findings (7 new, 0 already stored)")
    assert second_run.startswith("4 events analysed, 7 findings (0 new, 7 already stored)")
    assert "1 activity hours scored, 1 unusual" in first_run
    assert "[CRITICAL] risk  90  CloudTrail logging stopped" in first_run
    assert "+80  Base severity: critical" in first_run
    assert "+10  Behaviour anomaly: 'root': Activity 2026-10-06 22:00-23:00Z" in first_run
    assert "Incidents: 1 created, 0 updated" in first_run
    assert "NEW [CRITICAL] risk 100  Audit logging tampered: root  (7 findings)" in first_run
    assert "Incidents: 0 created, 0 updated" in second_run


def test_detect_command_reports_unreachable_database(monkeypatch: pytest.MonkeyPatch) -> None:
    unreachable = get_settings().model_copy(update={"postgres_port": 1})
    monkeypatch.setattr(
        detect, "create_db_engine", lambda: create_db_engine(unreachable.database_url())
    )

    assert detect.main([]) == detect.EXIT_DATABASE_UNAVAILABLE
