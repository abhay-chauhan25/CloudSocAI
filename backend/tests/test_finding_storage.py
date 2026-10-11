"""Storing findings: round-trips, idempotency, evidence integrity, and constraints."""

from pathlib import Path

import pytest
from sqlalchemy import text, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.collectors.cloudtrail_file import load_cloudtrail_file
from app.detection.engine import run_detectors
from app.models.finding import FindingRecord
from app.normalization.cloudtrail import normalize_cloudtrail_records
from app.repositories.events import save_events
from app.repositories.findings import (
    ScoredFinding,
    count_findings,
    get_finding,
    list_findings,
    save_findings,
)
from app.risk.scoring import RiskContext, score_finding
from app.schemas.event import Event
from app.schemas.finding import FindingStatus

pytestmark = pytest.mark.db


def all_fixture_events(samples_dir: Path) -> list[Event]:
    events: list[Event] = []
    for path in sorted(samples_dir.glob("*.json")):
        events += normalize_cloudtrail_records(load_cloudtrail_file(path)).events
    return events


def scored_findings(events: list[Event]) -> list[ScoredFinding]:
    context = RiskContext.from_events(events)
    return [ScoredFinding(f, score_finding(f, context)) for f in run_detectors(events).findings]


@pytest.fixture
def stored_events(db_session: Session, cloudtrail_samples_dir: Path) -> list[Event]:
    events = all_fixture_events(cloudtrail_samples_dir)
    save_events(db_session, events)
    return events


def test_findings_round_trip_with_risk_and_open_status(
    db_session: Session, stored_events: list[Event]
) -> None:
    scored = scored_findings(stored_events)

    assert save_findings(db_session, scored) == 11
    assert count_findings(db_session) == 11
    for item in scored:
        stored = get_finding(db_session, item.finding.finding_id)
        assert stored is not None
        assert stored.finding == item.finding
        assert stored.risk == item.risk
        assert stored.status is FindingStatus.OPEN


def test_multi_event_evidence_keeps_its_order(
    db_session: Session, stored_events: list[Event]
) -> None:
    scored = scored_findings(stored_events)
    [burst] = [s for s in scored if s.finding.detector_id == "failed-call-burst"]
    save_findings(db_session, scored)

    stored = get_finding(db_session, burst.finding.finding_id)

    assert stored is not None
    assert stored.finding.event_ids == burst.finding.event_ids
    assert len(stored.finding.event_ids) == 7


def test_saving_again_stores_nothing_and_keeps_triage_status(
    db_session: Session, stored_events: list[Event]
) -> None:
    scored = scored_findings(stored_events)
    save_findings(db_session, scored)
    first_id = scored[0].finding.finding_id
    db_session.execute(
        update(FindingRecord)
        .where(FindingRecord.finding_id == first_id)
        .values(status=FindingStatus.FALSE_POSITIVE.value)
    )

    assert save_findings(db_session, scored) == 0
    stored = get_finding(db_session, first_id)
    assert stored is not None
    assert stored.status is FindingStatus.FALSE_POSITIVE


def test_list_findings_is_oldest_first(db_session: Session, stored_events: list[Event]) -> None:
    save_findings(db_session, list(reversed(scored_findings(stored_events))))

    times = [s.finding.first_seen for s in list_findings(db_session)]

    assert len(times) == 11
    assert times == sorted(times)


def test_unknown_finding_id_returns_none(db_session: Session) -> None:
    assert get_finding(db_session, "no-such-finding") is None


def test_saving_nothing_is_a_no_op(db_session: Session) -> None:
    assert save_findings(db_session, []) == 0


# --- integrity enforced by PostgreSQL ------------------------------------------


def test_finding_citing_an_unstored_event_is_rejected(
    db_session: Session, cloudtrail_samples_dir: Path
) -> None:
    # Detect over events that were never saved: the evidence links must fail.
    scored = scored_findings(all_fixture_events(cloudtrail_samples_dir))

    with pytest.raises(IntegrityError, match="fk_finding_events_event_id_events"):
        with db_session.begin_nested():
            save_findings(db_session, scored[:1])


def test_evidence_events_cannot_be_deleted(db_session: Session, stored_events: list[Event]) -> None:
    scored = scored_findings(stored_events)
    save_findings(db_session, scored)
    evidence_id = scored[0].finding.event_ids[0]

    with pytest.raises(IntegrityError, match="fk_finding_events_event_id_events"):
        with db_session.begin_nested():
            db_session.execute(text("DELETE FROM events WHERE event_id = :id"), {"id": evidence_id})


@pytest.mark.parametrize(
    ("column", "value", "constraint"),
    [
        ("severity", "'severe'", "ck_findings_severity"),
        ("status", "'closed'", "ck_findings_status"),
        ("risk_score", "101", "ck_findings_risk_score"),
    ],
)
def test_database_rejects_invalid_values(
    db_session: Session, stored_events: list[Event], column: str, value: str, constraint: str
) -> None:
    save_findings(db_session, scored_findings(stored_events)[:1])

    with pytest.raises(IntegrityError, match=constraint):
        with db_session.begin_nested():
            db_session.execute(text(f"UPDATE findings SET {column} = {value}"))  # noqa: S608
