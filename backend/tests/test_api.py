"""The HTTP API: responses, filtering, pagination, validation, and failures."""

from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.api.deps import get_session
from app.api.main import create_app
from app.collectors.cloudtrail_file import load_cloudtrail_file
from app.config import get_settings
from app.db import create_db_engine, create_session_factory
from app.detection.engine import run_detectors
from app.normalization.cloudtrail import normalize_cloudtrail_records
from app.repositories.events import save_events
from app.repositories.findings import ScoredFinding, save_findings
from app.risk.scoring import RiskContext, score_finding
from app.schemas.event import Event

pytestmark = pytest.mark.db

EVENT_COUNT = 27
FINDING_COUNT = 11
CREATE_USER_EVENT = "9b2f4e6a-1c3d-4e5f-8a7b-200000000004"


@pytest.fixture
def client(db_session: Session) -> Iterator[TestClient]:
    """An API client whose requests use the rolled-back test session."""
    app = create_app()
    app.dependency_overrides[get_session] = lambda: db_session
    # Not used as a context manager, so the lifespan (which would connect to
    # the development database) never runs.
    yield TestClient(app)


@pytest.fixture
def seeded(db_session: Session, cloudtrail_samples_dir: Path) -> list[Event]:
    """All fixture events stored, with their detected and scored findings."""
    events: list[Event] = []
    for path in sorted(cloudtrail_samples_dir.glob("*.json")):
        events += normalize_cloudtrail_records(load_cloudtrail_file(path)).events
    save_events(db_session, events)
    context = RiskContext.from_events(events)
    save_findings(
        db_session,
        [ScoredFinding(f, score_finding(f, context)) for f in run_detectors(events).findings],
    )
    return events


def finding_id_for(client: TestClient, detector_id: str) -> str:
    [item] = client.get("/findings", params={"detector_id": detector_id}).json()["items"]
    return item["finding_id"]


# --- health --------------------------------------------------------------------


def test_health_reports_ok(client: TestClient) -> None:
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "database": "ok"}


# --- events --------------------------------------------------------------------


@pytest.mark.usefixtures("seeded")
def test_events_list_is_newest_first_and_paginated(client: TestClient) -> None:
    first = client.get("/events", params={"limit": 10}).json()
    second = client.get("/events", params={"limit": 10, "offset": 10}).json()

    assert (first["total"], first["limit"], first["offset"]) == (EVENT_COUNT, 10, 0)
    assert len(first["items"]) == len(second["items"]) == 10
    times = [e["timestamp"] for e in first["items"] + second["items"]]
    assert times == sorted(times, reverse=True)
    ids = {e["event_id"] for e in first["items"]} | {e["event_id"] for e in second["items"]}
    assert len(ids) == 20  # no overlap between pages


@pytest.mark.usefixtures("seeded")
def test_event_summaries_leave_out_the_raw_record(client: TestClient) -> None:
    item = client.get("/events", params={"limit": 1}).json()["items"][0]

    assert "raw_event" not in item
    assert {"event_id", "timestamp", "event_name", "principal", "success"} <= set(item)


@pytest.mark.usefixtures("seeded")
def test_events_can_be_filtered(client: TestClient) -> None:
    by_principal = client.get("/events", params={"principal": "root"}).json()
    by_name = client.get("/events", params={"event_name": "AttachUserPolicy"}).json()
    both = client.get("/events", params={"principal": "root", "event_name": "CreateUser"}).json()

    assert by_principal["total"] == 4
    assert {e["principal"] for e in by_principal["items"]} == {"root"}
    assert by_name["total"] == 2
    assert both == {"items": [], "total": 0, "limit": 50, "offset": 0}


@pytest.mark.usefixtures("seeded")
def test_event_detail_includes_the_raw_record(client: TestClient) -> None:
    response = client.get(f"/events/{CREATE_USER_EVENT}")

    assert response.status_code == 200
    body = response.json()
    assert body["event_name"] == "CreateUser"
    assert body["source_ip"] == "203.0.113.50"
    assert body["raw_event"]["eventID"] == CREATE_USER_EVENT


def test_unknown_event_is_404(client: TestClient) -> None:
    response = client.get("/events/no-such-event")

    assert response.status_code == 404
    assert response.json() == {"detail": "Event not found"}


# --- findings ------------------------------------------------------------------


@pytest.mark.usefixtures("seeded")
def test_findings_list(client: TestClient) -> None:
    body = client.get("/findings").json()

    assert body["total"] == FINDING_COUNT
    first_seen = [f["first_seen"] for f in body["items"]]
    assert first_seen == sorted(first_seen, reverse=True)
    burst = next(f for f in body["items"] if f["detector_id"] == "failed-call-burst")
    assert (burst["risk_score"], burst["status"], burst["event_count"]) == (60, "open", 7)


@pytest.mark.usefixtures("seeded")
def test_findings_sorted_by_risk(client: TestClient) -> None:
    items = client.get("/findings", params={"sort": "risk"}).json()["items"]

    scores = [f["risk_score"] for f in items]
    assert scores == sorted(scores, reverse=True)
    assert scores[0] == 80


@pytest.mark.usefixtures("seeded")
def test_findings_can_be_filtered(client: TestClient) -> None:
    critical = client.get("/findings", params={"severity": "critical"}).json()
    by_rule = client.get("/findings", params={"detector_id": "root-account-use"}).json()
    by_actor = client.get("/findings", params={"principal": "developer"}).json()
    resolved = client.get("/findings", params={"status": "resolved"}).json()

    assert {f["detector_id"] for f in critical["items"]} == {
        "cloudtrail-logging-stopped",
        "cloudtrail-trail-deleted",
    }
    assert by_rule["total"] == 4
    assert by_actor["total"] == 3
    assert resolved["total"] == 0


@pytest.mark.usefixtures("seeded")
def test_finding_detail_explains_itself(client: TestClient) -> None:
    finding_id = finding_id_for(client, "admin-policy-attached")

    body = client.get(f"/findings/{finding_id}").json()

    assert body["reason"] == "'developer' attached AdministratorAccess to user 'svc-backup'."
    assert body["risk"]["score"] == 80
    assert [f["points"] for f in body["risk"]["factors"]] == [60, 15, 5]
    assert body["detector"]["mitre_techniques"] == ["T1098.003"]
    assert "rationale" in body["detector"]
    [evidence] = body["evidence"]
    assert evidence["event_name"] == "AttachUserPolicy"


@pytest.mark.usefixtures("seeded")
def test_finding_detail_lists_all_evidence_in_order(client: TestClient) -> None:
    body = client.get(f"/findings/{finding_id_for(client, 'failed-call-burst')}").json()

    times = [e["timestamp"] for e in body["evidence"]]
    assert len(times) == 7
    assert times == sorted(times)
    assert all(not e["success"] for e in body["evidence"])


def test_unknown_finding_is_404(client: TestClient) -> None:
    response = client.get("/findings/no-such-finding")

    assert response.status_code == 404
    assert response.json() == {"detail": "Finding not found"}


# --- validation ----------------------------------------------------------------


@pytest.mark.parametrize(
    ("path", "params"),
    [
        ("/events", {"limit": 0}),
        ("/events", {"limit": 201}),
        ("/events", {"offset": -1}),
        ("/events", {"limit": "ten"}),
        ("/events", {"principal": "x" * 257}),
        ("/findings", {"severity": "severe"}),
        ("/findings", {"status": "closed"}),
        ("/findings", {"sort": "random"}),
        ("/findings", {"limit": 201}),
    ],
)
def test_invalid_parameters_are_rejected_with_422(
    client: TestClient, path: str, params: dict
) -> None:
    response = client.get(path, params=params)

    assert response.status_code == 422
    assert response.json()["detail"][0]["loc"][0] == "query"


def test_api_is_read_only(client: TestClient) -> None:
    assert client.post("/findings", json={}).status_code == 405
    assert client.delete(f"/events/{CREATE_USER_EVENT}").status_code == 405


# --- database failures ---------------------------------------------------------


@pytest.fixture
def unreachable_client() -> Iterator[TestClient]:
    unreachable = get_settings().model_copy(update={"postgres_port": 1})
    engine = create_db_engine(unreachable.database_url())
    sessions = create_session_factory(engine)

    def broken_session() -> Iterator[Session]:
        with sessions() as session:
            yield session

    app = create_app()
    app.dependency_overrides[get_session] = broken_session
    yield TestClient(app)
    engine.dispose()


def test_health_reports_database_outage_as_503(unreachable_client: TestClient) -> None:
    response = unreachable_client.get("/health")

    assert response.status_code == 503
    assert response.json() == {"status": "degraded", "database": "unavailable"}


def test_database_outage_is_503_without_internal_details(unreachable_client: TestClient) -> None:
    response = unreachable_client.get("/findings")

    assert response.status_code == 503
    assert response.json() == {"detail": "Database unavailable"}
    assert "psycopg" not in response.text
    assert "5432" not in response.text and ":1" not in response.text
