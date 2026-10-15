"""The analysis endpoints: generation, caching, staleness, limits, and failures."""

from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.ai.providers import MockProvider, ProviderResponse
from app.ai.schemas import IncidentContext
from app.ai.service import AnalystConfig
from app.api.routes.analysis import get_analyst_config

pytestmark = [pytest.mark.db, pytest.mark.usefixtures("seeded")]


class CountingProvider(MockProvider):
    """The mock analyst, counting how often it is actually called."""

    def __init__(self) -> None:
        self.calls = 0

    def generate(self, context: IncidentContext) -> ProviderResponse:
        self.calls += 1
        return super().generate(context)


class HallucinatingProvider(MockProvider):
    """Returns a well-formed answer that cites an event that does not exist."""

    def generate(self, context: IncidentContext) -> ProviderResponse:
        text = super().generate(context).text.replace(context.timeline[-1].event_id, "invented")
        return ProviderResponse(text=text, input_tokens=900, output_tokens=150)


def use_analyst(client: TestClient, provider, *, daily_limit=50, cooldown_seconds=0) -> None:
    config = AnalystConfig(provider, daily_limit, timedelta(seconds=cooldown_seconds))
    client.app.dependency_overrides[get_analyst_config] = lambda: config  # type: ignore[attr-defined]


def incident_id(client: TestClient, pattern_id: str = "iam-persistence") -> str:
    items = client.get("/incidents").json()["items"]
    return next(i["incident_id"] for i in items if i["pattern_id"] == pattern_id)


def change_incident(session: Session, incident: str) -> None:
    session.execute(
        text("UPDATE incidents SET title = title || ' (updated)' WHERE incident_id = :id"),
        {"id": incident},
    )


def analysis_rows(session: Session) -> list[tuple]:
    return session.execute(
        text("SELECT status, error_kind, input_tokens FROM incident_analyses ORDER BY id")
    ).all()


def test_generate_then_read_an_analysis(client: TestClient) -> None:
    use_analyst(client, MockProvider())
    target = incident_id(client)

    created = client.post(f"/incidents/{target}/analysis")
    read = client.get(f"/incidents/{target}/analysis")

    assert created.status_code == 201
    body = created.json()
    assert (body["provider"], body["cached"], body["is_current"]) == ("mock", False, True)
    assert body["result"]["summary"].startswith("[Mock analysis")
    assert len(body["result"]["attack_narrative"]) == 3
    assert read.status_code == 200
    assert read.json()["result"] == body["result"]


def test_an_unchanged_incident_is_served_from_cache(client: TestClient) -> None:
    provider = CountingProvider()
    use_analyst(client, provider)
    target = incident_id(client)

    first = client.post(f"/incidents/{target}/analysis")
    second = client.post(f"/incidents/{target}/analysis")

    assert (first.status_code, second.status_code) == (201, 200)
    assert second.json()["cached"] is True
    assert provider.calls == 1


def test_analysis_becomes_stale_when_the_incident_changes(
    client: TestClient, db_session: Session
) -> None:
    provider = CountingProvider()
    use_analyst(client, provider)
    target = incident_id(client)
    client.post(f"/incidents/{target}/analysis")

    change_incident(db_session, target)

    assert client.get(f"/incidents/{target}/analysis").json()["is_current"] is False
    regenerated = client.post(f"/incidents/{target}/analysis")
    assert regenerated.status_code == 201
    assert provider.calls == 2


def test_cooldown_blocks_rapid_regeneration(client: TestClient, db_session: Session) -> None:
    use_analyst(client, MockProvider(), cooldown_seconds=60)
    target = incident_id(client)
    client.post(f"/incidents/{target}/analysis")
    change_incident(db_session, target)

    response = client.post(f"/incidents/{target}/analysis")

    assert response.status_code == 429
    assert 0 < int(response.headers["Retry-After"]) <= 61
    assert "retry in" in response.json()["detail"]


def test_daily_limit_caps_calls_across_incidents(client: TestClient) -> None:
    use_analyst(client, MockProvider(), daily_limit=1)

    first = client.post(f"/incidents/{incident_id(client, 'iam-persistence')}/analysis")
    second = client.post(f"/incidents/{incident_id(client, 'credential-probing')}/analysis")

    assert first.status_code == 201
    assert second.status_code == 429
    assert "daily limit of 1" in second.json()["detail"]


def test_rejected_answers_are_recorded_and_never_shown(
    client: TestClient, db_session: Session
) -> None:
    use_analyst(client, HallucinatingProvider())
    target = incident_id(client)

    response = client.post(f"/incidents/{target}/analysis")

    assert response.status_code == 502
    assert response.json()["kind"] == "ungrounded"
    assert client.get(f"/incidents/{target}/analysis").json() == {"detail": "No analysis yet"}
    assert analysis_rows(db_session) == [("failed", "ungrounded", 900)]


def test_failed_attempts_count_toward_the_cooldown(client: TestClient) -> None:
    use_analyst(client, HallucinatingProvider(), cooldown_seconds=60)
    target = incident_id(client)
    client.post(f"/incidents/{target}/analysis")

    assert client.post(f"/incidents/{target}/analysis").status_code == 429


def test_disabled_analyst_returns_503(client: TestClient) -> None:
    use_analyst(client, None)

    response = client.post(f"/incidents/{incident_id(client)}/analysis")

    assert response.status_code == 503
    assert response.json()["kind"] == "not_configured"


def test_unknown_incident_is_404(client: TestClient) -> None:
    use_analyst(client, MockProvider())

    assert client.post("/incidents/nope/analysis").status_code == 404
    assert client.get("/incidents/nope/analysis").json() == {"detail": "Incident not found"}


def test_analysis_never_changes_the_incident(client: TestClient) -> None:
    use_analyst(client, MockProvider())
    target = incident_id(client)
    before = client.get(f"/incidents/{target}").json()

    client.post(f"/incidents/{target}/analysis")

    after = client.get(f"/incidents/{target}").json()
    for field in ("severity", "risk", "status", "mitre", "findings"):
        assert after[field] == before[field], field
