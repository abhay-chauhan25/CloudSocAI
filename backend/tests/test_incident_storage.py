"""Correlation against the database: creating, updating, and protecting incidents."""

from pathlib import Path

import pytest
from sqlalchemy import text, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.collectors.cloudtrail_file import load_cloudtrail_file
from app.correlation.service import run_correlation
from app.detection.engine import run_detectors
from app.models.finding import FindingRecord
from app.models.incident import IncidentFinding, IncidentRecord
from app.normalization.cloudtrail import normalize_cloudtrail_records
from app.repositories.events import save_events
from app.repositories.findings import ScoredFinding, get_finding, save_findings
from app.repositories.incidents import (
    count_incidents,
    get_incident,
    list_unassigned_findings,
    search_incidents,
)
from app.risk.scoring import RiskContext, score_finding
from app.schemas.event import Event
from app.schemas.finding import Finding, FindingStatus
from app.schemas.incident import IncidentStatus

pytestmark = pytest.mark.db


def load_events(samples_dir: Path, *names: str) -> list[Event]:
    events: list[Event] = []
    for name in names or [p.name for p in sorted(samples_dir.glob("*.json"))]:
        events += normalize_cloudtrail_records(load_cloudtrail_file(samples_dir / name)).events
    return events


def store_findings(session: Session, events: list[Event]) -> list[Finding]:
    """Store events and the findings detected in them; return the findings."""
    save_events(session, events)
    context = RiskContext.from_events(events)
    findings = run_detectors(events).findings
    save_findings(session, [ScoredFinding(f, score_finding(f, context)) for f in findings])
    return findings


def incident_of(session: Session, finding_id: str) -> str | None:
    return session.scalar(
        text("SELECT incident_id FROM incident_findings WHERE finding_id = :id"), {"id": finding_id}
    )


def test_correlation_creates_the_expected_incidents(
    db_session: Session, cloudtrail_samples_dir: Path
) -> None:
    store_findings(db_session, load_events(cloudtrail_samples_dir))

    report = run_correlation(db_session)

    assert (len(report.created), len(report.updated)) == (3, 0)
    incidents, total = search_incidents(db_session, limit=10, sort="risk")
    assert total == 3
    assert [(i.incident.pattern_id, i.incident.risk.score) for i in incidents] == [
        ("audit-logging-tampered", 95),
        ("iam-persistence", 90),
        ("credential-probing", 60),
    ]
    assert all(i.status is IncidentStatus.OPEN for i in incidents)
    assert list_unassigned_findings(db_session) == []


def test_stored_incident_round_trips(db_session: Session, cloudtrail_samples_dir: Path) -> None:
    store_findings(db_session, load_events(cloudtrail_samples_dir))
    [created, *_] = run_correlation(db_session).created

    stored = get_incident(db_session, created.incident_id)

    assert stored is not None
    assert stored.incident == created


def test_running_again_changes_nothing(db_session: Session, cloudtrail_samples_dir: Path) -> None:
    store_findings(db_session, load_events(cloudtrail_samples_dir))
    run_correlation(db_session)

    report = run_correlation(db_session)

    assert (report.created, report.updated) == ([], [])
    assert count_incidents(db_session) == 3


def test_new_finding_updates_the_open_incident_and_keeps_its_status(
    db_session: Session, cloudtrail_samples_dir: Path
) -> None:
    # First only the user creation and key creation arrive. The normal-activity
    # file gives developer a baseline, so the attacker's IP counts as new.
    events = load_events(
        cloudtrail_samples_dir, "normal-user-activity.json", "iam-privilege-change.json"
    )
    findings = store_findings(db_session, events)
    admin = next(f for f in findings if f.detector_id == "admin-policy-attached")
    db_session.execute(
        text("DELETE FROM finding_events WHERE finding_id = :id"), {"id": admin.finding_id}
    )
    db_session.execute(
        text("DELETE FROM findings WHERE finding_id = :id"), {"id": admin.finding_id}
    )
    [incident] = run_correlation(db_session).created
    assert incident.risk.score == 65  # access key (60) + user created (5)
    db_session.execute(
        update(IncidentRecord)
        .where(IncidentRecord.incident_id == incident.incident_id)
        .values(status=IncidentStatus.INVESTIGATING.value)
    )

    # ...then the AdministratorAccess finding arrives and joins it.
    context = RiskContext.from_events(events)
    save_findings(db_session, [ScoredFinding(admin, score_finding(admin, context))])
    report = run_correlation(db_session)

    assert report.created == []
    [updated] = report.updated
    assert updated.incident_id == incident.incident_id
    assert updated.risk.score == 90
    stored = get_incident(db_session, incident.incident_id)
    assert stored is not None
    assert stored.status is IncidentStatus.INVESTIGATING  # analyst decision kept
    assert len(stored.incident.finding_ids) == 3
    assert stored.updated_at >= stored.created_at


def test_resolved_incidents_do_not_gain_findings(
    db_session: Session, cloudtrail_samples_dir: Path
) -> None:
    events = load_events(cloudtrail_samples_dir, "cloudtrail-disabled.json")
    findings = store_findings(db_session, events)
    delete_trail = next(f for f in findings if f.detector_id == "cloudtrail-trail-deleted")
    db_session.execute(
        text("DELETE FROM finding_events WHERE finding_id = :id"), {"id": delete_trail.finding_id}
    )
    db_session.execute(
        text("DELETE FROM findings WHERE finding_id = :id"), {"id": delete_trail.finding_id}
    )
    [first] = run_correlation(db_session).created
    db_session.execute(update(IncidentRecord).values(status=IncidentStatus.RESOLVED.value))

    context = RiskContext.from_events(events)
    save_findings(db_session, [ScoredFinding(delete_trail, score_finding(delete_trail, context))])
    report = run_correlation(db_session)

    [second] = report.created
    assert second.incident_id != first.incident_id
    assert second.finding_ids == (delete_trail.finding_id,)


def test_false_positive_findings_are_not_correlated(
    db_session: Session, cloudtrail_samples_dir: Path
) -> None:
    findings = store_findings(
        db_session, load_events(cloudtrail_samples_dir, "failed-api-burst.json")
    )
    [burst] = findings
    db_session.execute(
        update(FindingRecord)
        .where(FindingRecord.finding_id == burst.finding_id)
        .values(status=FindingStatus.FALSE_POSITIVE.value)
    )

    assert run_correlation(db_session).created == []
    assert incident_of(db_session, burst.finding_id) is None


def test_a_lone_low_finding_waits_for_a_partner(
    db_session: Session, cloudtrail_samples_dir: Path
) -> None:
    events = load_events(cloudtrail_samples_dir, "iam-privilege-change.json")
    findings = store_findings(db_session, events)
    keep = {"iam-user-created"}
    for f in findings:
        if f.detector_id not in keep:
            db_session.execute(
                text("DELETE FROM finding_events WHERE finding_id = :id"), {"id": f.finding_id}
            )
            db_session.execute(
                text("DELETE FROM findings WHERE finding_id = :id"), {"id": f.finding_id}
            )

    assert run_correlation(db_session).created == []
    [waiting] = list_unassigned_findings(db_session)
    assert waiting.finding.detector_id == "iam-user-created"


def test_a_finding_cannot_belong_to_two_incidents(
    db_session: Session, cloudtrail_samples_dir: Path
) -> None:
    store_findings(db_session, load_events(cloudtrail_samples_dir))
    [incident, other, *_] = run_correlation(db_session).created

    with pytest.raises(IntegrityError, match="pk_incident_findings"):
        with db_session.begin_nested():
            db_session.add(
                IncidentFinding(
                    incident_id=other.incident_id,
                    finding_id=incident.finding_ids[0],
                    position=99,
                )
            )
            db_session.flush()


def test_findings_in_an_incident_cannot_be_deleted(
    db_session: Session, cloudtrail_samples_dir: Path
) -> None:
    store_findings(db_session, load_events(cloudtrail_samples_dir))
    [incident, *_] = run_correlation(db_session).created
    finding_id = incident.finding_ids[0]
    assert get_finding(db_session, finding_id) is not None

    with pytest.raises(IntegrityError, match="fk_incident_findings_finding_id_findings"):
        with db_session.begin_nested():
            db_session.execute(
                text("DELETE FROM finding_events WHERE finding_id = :id"), {"id": finding_id}
            )
            db_session.execute(
                text("DELETE FROM findings WHERE finding_id = :id"), {"id": finding_id}
            )
