# Containers and Local Deployment

The whole stack (database, migrations, API, dashboard) starts with one command, from images built from this repository:

```bash
cp .env.example .env              # set POSTGRES_PASSWORD (and optionally GEMINI_API_KEY)
docker compose up -d --build --wait
docker compose run --rm seed      # load the synthetic demo data
open http://127.0.0.1:8080
```

## Images

| Image | Built from | Contents | Runs as |
|---|---|---|---|
| `cloudsoc-backend` | `backend/Dockerfile`, `python:3.12.15-slim-trixie` | Exact dependencies from `requirements.lock`, then the `app` package and migrations. No tests, no `.venv`, no `.env` (see `.dockerignore`) | UID 10001, no shell login |
| `cloudsoc-frontend` | `frontend/Dockerfile`, two stages: `node:22.23.3-alpine3.24` builds, `nginx-unprivileged:1.31.7-alpine3.24` serves | Only the built static files and `nginx.conf`. No Node, no source, no `node_modules` | nginx's unprivileged user, port 8080 |

- **Images vs containers.** An *image* is a read-only template: a filesystem plus a start command. A *container* is a running instance of it. The same backend image runs as three containers (`migrate`, `api`, `seed`) with different commands.
- **Layer caching.** Each Dockerfile instruction is a cached layer. Dependencies are copied and installed *before* the code, so a code change rebuilds in seconds instead of reinstalling scikit-learn.
- **Multi-stage build.** The frontend needs Node and about 200 MB of dev dependencies to *build*, but only static files to *run*. The final image copies `dist/` out of the build stage, which makes it smaller with less attack surface.
- **Pinned versions.** Base images use exact tags. Python packages come from `requirements.lock` (resolved from what the test suite ran against) and npm packages from `package-lock.json` via `npm ci`. The same commit builds the same image.

## Services (`docker-compose.yml`)

```text
           browser
              │ 127.0.0.1:8080
        ┌─────▼─────┐   edge network
        │    web    │ nginx: static files, /api/* → api:8000
        └─────┬─────┘
              │
        ┌─────▼─────┐   edge + data networks
        │    api    │ FastAPI (not published to the host)
        └─────┬─────┘
              │         data network
        ┌─────▼─────┐   127.0.0.1:5432 (for local development only)
        │ postgres  │──── volume: cloudsoc-pgdata
        └───────────┘
  migrate: alembic upgrade head, then exits; the API waits for it
  seed:    demo data loader (profile "demo"), run on demand
```

| Concept | How it's used here |
|---|---|
| **Ports** | `host:container` mappings. Only the dashboard (8080) and the database (5432, for running tests and uvicorn on the host) are published, both bound to **127.0.0.1**, so nothing is reachable from other machines. The API has no published port: the browser reaches it only through nginx |
| **Networks** | Containers on the same network reach each other by **service name** through Docker's internal DNS (`postgres`, `api`). Two networks separate tiers: `web` is only on `edge` and can't even resolve `postgres` |
| **Volumes** | `cloudsoc-pgdata` stores the database outside the container, so it survives `docker compose down` and image rebuilds. `docker compose down -v` deletes it. `sample-data/` is bind-mounted read-only into `seed` |
| **Environment** | Configuration comes from `.env` through `env_file`, and nothing is baked into images. `POSTGRES_HOST` is overridden to `postgres`, because inside the network the database isn't on `localhost` |
| **Start order** | `depends_on` with conditions: postgres must be *healthy* (`pg_isready`), migrate must *complete successfully*, and the API must be *healthy* (its `HEALTHCHECK` calls `/health`) before nginx starts |
| **Restart** | `unless-stopped` for long-running services; one-off jobs don't restart |

## Hardening

- **Non-root users** in both images.
- **Read-only root filesystem** (`read_only: true`), with a `tmpfs` for `/tmp`. A compromised process can't modify the app's code or plant files.
- **`cap_drop: [ALL]`.** Neither service needs any Linux capability: nginx binds 8080, which needs no privilege.
- **`no-new-privileges`.** setuid binaries can't regain privileges.
- **`server_tokens off`.** nginx doesn't reveal its version.
- **Secrets stay out.** `.env` is excluded from both build contexts, and `docker history` shows no secret.

## Local development without containers

The original workflow still works. `docker compose up -d --wait postgres` starts only the database, and you run `uvicorn` and `npm run dev` on the host (see the README). The test suite always uses the published database port.

## Limitations

- **One host.** Compose is for a single machine. A production deployment would use managed PostgreSQL (RDS) and a container service (ECS/Fargate or Kubernetes) behind a TLS load balancer.
- **No TLS.** It's only exposed on 127.0.0.1. Anything beyond localhost needs HTTPS in front of nginx.
- **Image scanning.** Scanning images for vulnerable OS packages (for example with Trivy or Docker Scout) belongs in CI.
