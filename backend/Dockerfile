# CloudSOC backend: the FastAPI app plus the ingest, detect, and scan commands.
#
#   docker build -t cloudsoc-backend backend/
#
# Configuration comes only from environment variables (see docker-compose.yml);
# no .env file or secret is copied into the image.

FROM python:3.12.15-slim-trixie

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Dependencies first, in their own layer: rebuilding after a code change
# reuses this layer instead of reinstalling everything.
COPY requirements.lock .
RUN pip install --requirement requirements.lock

COPY pyproject.toml alembic.ini ./
COPY app ./app
COPY migrations ./migrations
RUN pip install --no-deps .

# Run as an unprivileged user: a compromise of the app does not get root
# inside the container. Owned by root, so the app cannot modify its own code.
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin cloudsoc
USER cloudsoc

EXPOSE 8000

HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2)"]

# 0.0.0.0 inside the container: the port is reachable only on the Compose
# network unless docker-compose.yml publishes it.
CMD ["uvicorn", "app.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
