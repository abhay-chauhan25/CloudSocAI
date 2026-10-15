# CloudSOC AI

An AWS-focused security monitoring platform — a lightweight **cloud SIEM + CSPM** with AI-assisted investigation — built as a portfolio and learning project.

> **Status: early prototype.** Synthetic CloudTrail logs can be loaded, normalized, stored in PostgreSQL, and analysed by 8 deterministic detection rules (mapped to MITRE ATT&CK) that produce stored findings with explainable risk scores, correlated into incidents with investigation timelines, explained on request by an advisory LLM analyst (Gemini, grounded and validated), and served by a REST API and a React dashboard. See [Roadmap](#roadmap).

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
    schemas/        Pydantic data models (Event, Finding, RiskAssessment)
    detection/      detector interface, engine, and rules
    risk/           explainable risk scoring
    correlation/    findings -> incidents, timelines
    api/            FastAPI app: /health, /events, /findings, /incidents, /detectors
    mitre/          curated MITRE ATT&CK catalog (v20)
    ai/             advisory AI analyst: context, prompt, providers, validation
    models/         SQLAlchemy database tables
    repositories/   save/load data
    ingest.py       command: file -> normalize -> database
    detect.py       command: stored events -> rules -> scored findings -> incidents
  migrations/       Alembic database migrations
  tests/            pytest test suite
frontend/           React + TypeScript dashboard (Vite)
sample-data/        synthetic CloudTrail logs (fake identifiers only)
docs/               architecture, detection rules, AI analyst threat model, CloudTrail reference
docker-compose.yml  local PostgreSQL
.env.example        configuration template (copy to .env)
```

## Local setup

Requirements: **Python 3.12+**, **Node.js 20.19+**, and **Docker**. No AWS account is needed — everything runs on synthetic data.

```bash
# 1. Configuration: copy the template and set your own password
#    (optional: add GEMINI_API_KEY for real AI analyses; without it a mock is used)
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

# 6. Detect, score, and store findings, then correlate them into incidents (safe to re-run)
python -m app.detect

# 7. Start the API (listens on 127.0.0.1 only), then open http://127.0.0.1:8000/docs
uvicorn app.api.main:app --reload
```

In a second terminal, start the dashboard:

```bash
cd frontend
npm install
npm run dev             # http://127.0.0.1:5173 (calls the API through Vite's /api proxy)
```

## Running checks

From `backend/` with the virtual environment activated:

```bash
pytest                  # run the test suite (database tests use a separate *_test database
                        # and are skipped with a message if PostgreSQL is not running)
ruff check .            # lint (includes security rules from flake8-bandit)
ruff format --check .   # verify formatting (use `ruff format .` to fix)
```

From `frontend/`:

```bash
npm run typecheck       # TypeScript, strict mode
npm test                # component and API-client tests (Vitest + Testing Library)
npm run build           # production build into dist/
```

## Roadmap

The project is built one small task at a time, following the numbered roadmap in [`CLAUDE.md`](CLAUDE.md) §25 (Stages 0–19). The first milestone is a local pipeline: synthetic CloudTrail → normalization → PostgreSQL → detection rules → findings → FastAPI → dashboard.

## Security

- Never commit credentials. `.env`, AWS credential files, and Terraform state are gitignored.
- All security testing targets only synthetic data or infrastructure owned by the developer.
