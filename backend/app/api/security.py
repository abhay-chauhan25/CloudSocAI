"""Request authentication and browser-facing protections for the API.

API key. Every route except /health requires the X-API-Key header. The
dashboard never holds the key: the Vite dev server and nginx add it when
they forward /api/... requests, so it is never shipped to the browser.

Because the proxy adds the key automatically, it behaves like a cookie:
any page open in the browser could make the browser send a request to
http://127.0.0.1:8080/api/... and have it authenticated. Two checks close
that gap:

- Fetch Metadata (CSRF). Browsers label every request with Sec-Fetch-Site.
  State-changing requests (the AI analysis POST, which can spend money) are
  refused unless they come from the dashboard's own origin.
- Host allowlist (DNS rebinding). An attacker's domain can be made to
  resolve to 127.0.0.1, turning their page into "same origin" with the
  dashboard. The Host header still names their domain, so requests for
  any host other than the local ones are refused.
"""

import hmac
from collections.abc import Awaitable, Callable
from typing import Annotated

from fastapi import HTTPException, Request, Response, Security, status
from fastapi.responses import JSONResponse
from fastapi.security import APIKeyHeader
from pydantic import SecretStr

API_KEY_HEADER = "X-API-Key"

# Hosts the API answers to: the browser's view of the dashboard, and "api",
# the service name nginx and other containers use on the Compose network.
DEFAULT_ALLOWED_HOSTS = ("localhost", "127.0.0.1", "[::1]", "api")

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
# "same-origin": the dashboard itself. "none": typed into the address bar or
# sent by a non-browser client such as curl (which sends no header at all).
TRUSTED_FETCH_SITES = {"same-origin", "none"}

# auto_error=False: a missing header is reported by require_api_key with the
# same message as a wrong one, instead of FastAPI's generic 403.
api_key_header = APIKeyHeader(name=API_KEY_HEADER, auto_error=False)


def require_api_key(
    request: Request, provided: Annotated[str | None, Security(api_key_header)]
) -> None:
    expected: SecretStr | None = getattr(request.app.state, "api_key", None)
    if expected is None:
        # Fail closed: a missing configuration never means "no authentication".
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "API key not configured")
    # compare_digest takes the same time wherever the strings differ, so the
    # response time does not reveal how much of a guess was right.
    if provided is None or not hmac.compare_digest(
        provided.encode(), expected.get_secret_value().encode()
    ):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing or invalid API key")


Handler = Callable[[Request], Awaitable[Response]]


def host_allowed(host_header: str, allowed_hosts: tuple[str, ...]) -> bool:
    host = host_header.lower()
    if host.startswith("["):  # IPv6 literal: "[::1]:8080"
        host = host.split("]", 1)[0] + "]"
    else:
        host = host.split(":", 1)[0]
    return host in allowed_hosts


def browser_protection(
    allowed_hosts: tuple[str, ...],
) -> Callable[[Request, Handler], Awaitable[Response]]:
    """Middleware: Host allowlist, Fetch Metadata check, and security headers."""

    async def middleware(request: Request, call_next: Handler) -> Response:
        if not host_allowed(request.headers.get("host", ""), allowed_hosts):
            return JSONResponse({"detail": "Unknown host"}, status_code=status.HTTP_400_BAD_REQUEST)

        site = request.headers.get("sec-fetch-site")
        if (
            request.method not in SAFE_METHODS
            and site is not None
            and site not in TRUSTED_FETCH_SITES
        ):
            return JSONResponse(
                {"detail": "Cross-site request refused"}, status_code=status.HTTP_403_FORBIDDEN
            )

        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        # Security data should not linger in browser or proxy caches.
        response.headers.setdefault("Cache-Control", "no-store")
        return response

    return middleware
