"""Storing events: round-trips, deduplication, and the ingest pipeline."""

import json
import logging
from pathlib import Path

import pytest
from sqlalchemy import URL, Engine, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app import ingest
from app.collectors.cloudtrail_file import load_cloudtrail_file
from app.config import get_settings
from app.db import create_db_engine
from app.models.event import EventRecord
from app.normalization.cloudtrail import normalize_cloudtrail_records
from app.repositories.events import count_events, get_event, save_events
from app.schemas.event import Event

pytestmark = pytest.mark.db

FIXTURE_FILES = [
    "normal-user-activity.json",
    "iam-privilege-change.json",
    "cloudtrail-disabled.json",
]


def fixture_events(samples_dir: Path) -> list[Event]:
    events: list[Event] = []
    for name in FIXTURE_FILES:
        events += normalize_cloudtrail_records(load_cloudtrail_file(samples_dir / name)).events
    return events


# --- repository ----------------------------------------------------------------


def test_saved_events_round_trip_unchanged(
    db_session: Session, cloudtrail_samples_dir: Path
) -> None:
    events = fixture_events(cloudtrail_samples_dir)

    assert save_events(db_session, events) == 18
    assert count_events(db_session) == 18
    for event in events:
        assert get_event(db_session, event.event_id) == event


def test_saving_the_same_events_twice_stores_them_once(
    db_session: Session, cloudtrail_samples_dir: Path
) -> None:
    events = fixture_events(cloudtrail_samples_dir)

    save_events(db_session, events)
    assert save_events(db_session, events) == 0
    assert count_events(db_session) == 18


def test_duplicates_within_one_batch_are_stored_once(
    db_session: Session, cloudtrail_samples_dir: Path
) -> None:
    event = fixture_events(cloudtrail_samples_dir)[0]

    assert save_events(db_session, [event, event]) == 1


def test_database_itself_rejects_duplicate_event_ids(
    db_session: Session, cloudtrail_samples_dir: Path
) -> None:
    # Bypass the repository: uniqueness is enforced by PostgreSQL, not just our code.
    event = fixture_events(cloudtrail_samples_dir)[0]
    save_events(db_session, [event])
    duplicate = EventRecord(**{**event.model_dump(), "source_ip": str(event.source_ip)})

    with pytest.raises(IntegrityError, match="uq_events_event_id"), db_session.begin_nested():
        db_session.add(duplicate)
        db_session.flush()


def test_saving_nothing_is_a_no_op(db_session: Session) -> None:
    assert save_events(db_session, []) == 0


def test_unknown_event_id_returns_none(db_session: Session) -> None:
    assert get_event(db_session, "no-such-event") is None


def test_raw_event_is_stored_as_queryable_json(
    db_session: Session, cloudtrail_samples_dir: Path
) -> None:
    save_events(db_session, fixture_events(cloudtrail_samples_dir))

    policy_arns = db_session.scalars(
        text(
            "SELECT raw_event -> 'requestParameters' ->> 'policyArn' FROM events "
            "WHERE event_name = 'AttachUserPolicy' ORDER BY timestamp"
        )
    ).all()

    assert policy_arns == [
        "arn:aws:iam::aws:policy/ReadOnlyAccess",
        "arn:aws:iam::aws:policy/AdministratorAccess",
    ]


# --- ingest pipeline -------------------------------------------------------------


def test_ingest_file_reports_counts(db_session: Session, cloudtrail_samples_dir: Path) -> None:
    path = cloudtrail_samples_dir / "iam-privilege-change.json"

    first = ingest.ingest_cloudtrail_file(db_session, path)
    second = ingest.ingest_cloudtrail_file(db_session, path)

    assert (first.records, first.inserted, first.duplicates, first.errors) == (7, 7, 0, [])
    assert (second.inserted, second.duplicates) == (0, 7)


def test_ingest_stores_good_records_and_logs_rejected_ones(
    db_session: Session,
    cloudtrail_samples_dir: Path,
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    good = load_cloudtrail_file(cloudtrail_samples_dir / "normal-user-activity.json")[0]
    bad = {**good, "eventID": "evil\nINFO forged log line", "eventTime": "not-a-time"}
    path = tmp_path / "mixed.json"
    path.write_text(json.dumps({"Records": [good, bad]}), encoding="utf-8")

    with caplog.at_level(logging.WARNING):
        report = ingest.ingest_cloudtrail_file(db_session, path)

    assert (report.records, report.inserted, len(report.errors)) == (2, 1, 1)
    assert get_event(db_session, good["eventID"]) is not None
    [message] = caplog.messages
    assert "record 1" in message
    assert "\n" not in message  # the newline in the hostile eventID was escaped


def test_ingest_command_exit_codes(
    db_engine: Engine,
    test_database_url: URL,
    cloudtrail_samples_dir: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(ingest, "create_db_engine", lambda: create_db_engine(test_database_url))
    good = str(cloudtrail_samples_dir / "cloudtrail-disabled.json")
    broken = tmp_path / "broken.json"
    broken.write_text("{not json", encoding="utf-8")

    try:
        assert ingest.main([good]) == ingest.EXIT_OK
        assert ingest.main([str(broken), good]) == ingest.EXIT_PROBLEMS
    finally:
        # main() commits for real, so clean up what it stored.
        with db_engine.begin() as connection:
            connection.execute(text("TRUNCATE events"))


def test_ingest_command_reports_unreachable_database(
    cloudtrail_samples_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    unreachable = get_settings().model_copy(update={"postgres_port": 1})
    monkeypatch.setattr(
        ingest, "create_db_engine", lambda: create_db_engine(unreachable.database_url())
    )

    exit_code = ingest.main([str(cloudtrail_samples_dir / "cloudtrail-disabled.json")])

    assert exit_code == ingest.EXIT_DATABASE_UNAVAILABLE
