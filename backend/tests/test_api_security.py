"""API key authentication, Host allowlist, Fetch Metadata CSRF check, and headers."""

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr, ValidationError

from app.api import main
from app.api.main import create_app
from app.api.security import API_KEY_HEADER, host_allowed
from app.config import Settings
from tests.api_client import TEST_API_KEY, authenticated_client

# Database settings are required fields; these tests never connect.
DB_SETTINGS = {"postgres_user": "u", "postgres_password": "p", "postgres_db": "d"}

# /detectors reads only the in-code catalog, so these tests need no database.
PROTECTED = "/detectors"


@pytest.fixture
def anonymous() -> TestClient:
    app = create_app()
    app.state.api_key = SecretStr(TEST_API_KEY)
    return TestClient(app, base_url="http://localhost")


def test_valid_key_is_accepted() -> None:
    assert authenticated_client(create_app()).get(PROTECTED).status_code == 200


@pytest.mark.parametrize("headers", [{}, {API_KEY_HEADER: "wrong"}, {API_KEY_HEADER: ""}])
def test_missing_or_wrong_key_is_401(anonymous: TestClient, headers: dict[str, str]) -> None:
    response = anonymous.get(PROTECTED, headers=headers)

    assert response.status_code == 401
    assert response.json() == {"detail": "Missing or invalid API key"}


def test_unconfigured_key_fails_closed() -> None:
    client = TestClient(create_app(), base_url="http://localhost")  # app.state.api_key never set

    response = client.get(PROTECTED, headers={API_KEY_HEADER: "anything"})

    assert response.status_code == 503


@pytest.mark.db
def test_health_needs_no_key(client: TestClient) -> None:
    assert client.get("/health", headers={API_KEY_HEADER: ""}).status_code == 200


def test_docs_list_the_key_requirement() -> None:
    schema = authenticated_client(create_app()).get("/openapi.json").json()

    assert API_KEY_HEADER in str(schema["components"]["securitySchemes"])


@pytest.mark.parametrize(
    ("host", "allowed"),
    [
        ("localhost:8080", True),
        ("127.0.0.1", True),
        ("[::1]:8080", True),
        ("api:8000", True),
        ("attacker.example", False),
        ("localhost.attacker.example", False),
        ("", False),
    ],
)
def test_host_allowlist(host: str, allowed: bool) -> None:
    assert host_allowed(host, ("localhost", "127.0.0.1", "[::1]", "api")) is allowed


def test_rebound_host_is_refused_even_with_the_key() -> None:
    client = authenticated_client(create_app())

    response = client.get(PROTECTED, headers={"Host": "attacker.example:8080"})

    assert response.status_code == 400


@pytest.mark.parametrize("site", ["cross-site", "same-site"])
def test_cross_site_post_is_refused_before_any_work(site: str) -> None:
    client = authenticated_client(create_app())

    response = client.post("/incidents/any/analysis", headers={"Sec-Fetch-Site": site})

    assert response.status_code == 403


def test_cross_site_get_is_still_allowed() -> None:
    # Reads change nothing, and the browser will not let another site read the response.
    client = authenticated_client(create_app())

    assert client.get(PROTECTED, headers={"Sec-Fetch-Site": "cross-site"}).status_code == 200


def test_responses_carry_security_headers() -> None:
    response = authenticated_client(create_app()).get(PROTECTED)

    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Referrer-Policy"] == "no-referrer"


def test_api_refuses_to_start_without_a_key(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = Settings(**DB_SETTINGS, api_key=None)
    monkeypatch.setattr(main, "get_settings", lambda: settings)

    with pytest.raises(RuntimeError, match="API_KEY is not set"), TestClient(create_app()):
        pass


def test_short_keys_are_rejected_and_blank_means_unset() -> None:
    with pytest.raises(ValidationError, match="at least 32 characters"):
        Settings(**DB_SETTINGS, api_key="short")
    assert Settings(**DB_SETTINGS, api_key="").api_key is None
