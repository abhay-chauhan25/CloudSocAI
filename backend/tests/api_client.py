"""Building API test clients the way the dashboard proxy calls the API."""

from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import SecretStr

from app.api.security import API_KEY_HEADER

TEST_API_KEY = "test-api-key-0123456789-abcdefghijklmnop"


def authenticated_client(app: FastAPI) -> TestClient:
    """A client that sends the API key, to a local host name, like the dashboard proxy.

    Not used as a context manager, so the lifespan (which would connect to the
    development database) never runs; the key it would load is set here instead.
    """
    app.state.api_key = SecretStr(TEST_API_KEY)
    return TestClient(app, base_url="http://localhost", headers={API_KEY_HEADER: TEST_API_KEY})
