# CloudSOC AI

An AWS-focused security monitoring platform — a lightweight **cloud SIEM + CSPM** with AI-assisted investigation — built as a portfolio and learning project.

> **Status: early prototype.** Synthetic CloudTrail logs (or real ones, read from a trail's S3 bucket) can be loaded, normalized, stored in PostgreSQL, and analysed by 8 deterministic detection rules (mapped to MITRE ATT&CK) and an Isolation Forest behaviour-anomaly model, producing stored findings with explainable risk scores; 9 CSPM posture checks find insecure configuration in AWS snapshots; correlated into incidents with investigation timelines, explained on request by an advisory LLM analyst (Gemini, grounded and validated), and served by a REST API and a React dashboard. See [Roadmap](#roadmap).

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
    collectors/     read raw CloudTrail logs from local files or S3 (boto3, read-only)
    normalization/  raw CloudTrail records -> Events
    schemas/        Pydantic data models (Event, Finding, RiskAssessment)
    detection/      detector interface, engine, and rules
    risk/           explainable risk scoring
    ml/             behaviour anomaly detection (Isolation Forest): features, baseline, model
    posture/        CSPM: configuration snapshot model and posture checks (IAM, S3, EC2, CloudTrail)
    correlation/    findings -> incidents, timelines
    api/            FastAPI app: /health, /events, /findings, /incidents, /detectors
    mitre/          curated MITRE ATT&CK catalog (v20)
    ai/             advisory AI analyst: context, prompt, providers, validation
    models/         SQLAlchemy database tables
    repositories/   save/load data
    ingest.py       command: file -> normalize -> database
    ingest_s3.py    command: S3 trail bucket -> normalize -> database
    detect.py       command: stored events -> anomaly scores + rules -> scored findings -> incidents
    posture_scan.py command: configuration snapshot -> posture checks -> findings
    posture_collect.py command: live AWS account -> configuration snapshot (read-only)
    lab/            Terraform-lab scenario generator (lab account only)
  migrations/       Alembic database migrations
  tests/            pytest test suite
frontend/           React + TypeScript dashboard (Vite)
infra/terraform/    disposable AWS lab: CloudTrail trail, read-only CloudSOC role, deliberately insecure targets
sample-data/        synthetic CloudTrail logs and AWS configuration snapshots (fake identifiers only)
docs/               architecture, detection rules, posture checks, anomaly detection, AI analyst threat model, AWS ingestion, AWS lab runbook, containers, CloudTrail reference
docker-compose.yml  full local stack: PostgreSQL, migrations, API, dashboard (+ demo seed job)
.env.example        configuration template (copy to .env)
```

## Quick start (Docker only)

Requirements: **Docker**. No AWS account is needed — everything runs on synthetic data.

```bash
cp .env.example .env                  # then set POSTGRES_PASSWORD
docker compose up -d --build --wait   # database, migrations, API, dashboard
docker compose run --rm seed          # load the synthetic samples, detect, scan posture
open http://127.0.0.1:8080
```

See [docs/containers.md](docs/containers.md) for the images, networks, and hardening.

## Local development setup

Requirements: **Python 3.12+**, **Node.js 20.19+**, and **Docker** (for PostgreSQL).

```bash
# 1. Configuration: copy the template and set your own password
#    (optional: add GEMINI_API_KEY for real AI analyses; without it a mock is used)
cp .env.example .env

# 2. Start only PostgreSQL (bound to localhost only)
docker compose up -d --wait postgres

# 3. Backend environment
cd backend
python3.12 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# 4. Create the database tables
alembic upgrade head

# 5. Load the sample data (safe to re-run: duplicates are skipped)
python -m app.ingest ../sample-data/cloudtrail/*.json

# 6. Score behaviour, detect, score, and store findings, then correlate them into incidents (safe to re-run)
python -m app.detect

# Optional: see how the anomaly model performs (no database needed)
python -m app.ml.evaluate

# Optional, needs AWS: ingest real logs from a trail's bucket (docs/aws-ingestion.md);
# docs/aws-lab.md builds a disposable lab with Terraform and generates activity to detect
# python -m app.ingest_s3 --bucket <bucket> --account-id <id> --region us-east-1 --profile <profile>

# Check an AWS configuration snapshot for insecure settings (safe to re-run)
python -m app.posture_scan ../sample-data/aws-config/insecure-account.json

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
