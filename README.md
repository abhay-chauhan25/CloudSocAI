# CloudSOC AI

An AWS-focused security monitoring platform — a lightweight **cloud SIEM + CSPM** with AI-assisted investigation — built as a portfolio and learning project.

> **Status: early prototype.** Synthetic CloudTrail logs can be loaded, normalized, stored in PostgreSQL, and analysed by 8 deterministic detection rules. Storing findings, the API, and the dashboard do not exist yet. See [Roadmap](#roadmap).

## What it will do

```text
CloudTrail / VPC Flow Logs / AWS config
    ↓
Ingestion → Normalization → PostgreSQL
    ↓
Deterministic rules + CSPM checks + ML anomaly signals
    ↓
Findings → Correlation → Incidents (explainable risk score, MITRE ATT&CK)
    ↓
LLM-assisted investigation (advisory only) → React dashboard
```

Core design rule: **rules and ML detect; the LLM only explains.** The LLM never decides that activity is malicious and never changes AWS resources.

## Repository layout

```text
backend/
  app/
    collectors/     read raw log files
    normalization/  raw CloudTrail records -> Events
    schemas/        Pydantic data models (Event, Finding)
    detection/      detector interface, engine, and rules
    models/         SQLAlchemy database tables
    repositories/   save/load data
    ingest.py       command: file -> normalize -> database
    detect.py       command: stored events -> detection rules -> findings
  migrations/       Alembic database migrations
  tests/            pytest test suite
sample-data/        synthetic CloudTrail logs (fake identifiers only)
docs/               architecture, detection rules, and CloudTrail reference
docker-compose.yml  local PostgreSQL
.env.example        configuration template (copy to .env)
```

## Local setup

Requirements: **Python 3.12+** and **Docker**. No AWS account is needed — everything runs on synthetic data.

```bash
# 1. Configuration: copy the template and set your own password
cp .env.example .env

# 2. Start PostgreSQL (bound to localhost only)
docker compose up -d --wait

# 3. Backend environment
cd backend
python3.12 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# 4. Create the database tables
alembic upgrade head

# 5. Load the sample data (safe to re-run: duplicates are skipped)
python -m app.ingest ../sample-data/cloudtrail/*.json

# 6. Run the detection rules and print the findings
python -m app.detect
```

## Running checks

From `backend/` with the virtual environment activated:

```bash
pytest                  # run the test suite (database tests use a separate *_test database
                        # and are skipped with a message if PostgreSQL is not running)
ruff check .            # lint (includes security rules from flake8-bandit)
ruff format --check .   # verify formatting (use `ruff format .` to fix)
```

## Roadmap

The project is built one small task at a time, following the numbered roadmap in [`CLAUDE.md`](CLAUDE.md) §25 (Stages 0–19). The first milestone is a local pipeline: synthetic CloudTrail → normalization → PostgreSQL → detection rules → findings → FastAPI → dashboard.

## Security

- Never commit credentials. `.env`, AWS credential files, and Terraform state are gitignored.
- All security testing targets only synthetic data or infrastructure owned by the developer.
