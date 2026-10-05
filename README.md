# CloudSOC AI

An AWS-focused security monitoring platform — a lightweight **cloud SIEM + CSPM** with AI-assisted investigation — built as a portfolio and learning project.

> **Status: early prototype (Stage 0 — foundation).** The repository currently contains project tooling and design documents only. No ingestion, detection, or API functionality exists yet. See [Roadmap](#roadmap).

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
  app/            Python package for the backend (ingestion, detection, API, ...)
  tests/          pytest test suite
  pyproject.toml  Project metadata, dependencies, and pytest/Ruff configuration
docs/             Architecture and design notes
information.md    Project blueprint (what and why)
CLAUDE.md         Development contract and numbered task roadmap
```

Further directories (`sample-data/`, `frontend/`, `infrastructure/`) are added when the tasks that need them are implemented.

## Local setup

Requirements: **Python 3.12+**. No AWS account is needed — early stages run entirely on synthetic data.

```bash
cd backend
python3.12 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Running checks

From `backend/` with the virtual environment activated:

```bash
pytest                  # run the test suite
ruff check .            # lint (includes security rules from flake8-bandit)
ruff format --check .   # verify formatting (use `ruff format .` to fix)
```

## Roadmap

The project is built one small task at a time, following the numbered roadmap in [`CLAUDE.md`](CLAUDE.md) §25 (Stages 0–19). The first milestone is a local pipeline: synthetic CloudTrail → normalization → PostgreSQL → detection rules → findings → FastAPI → dashboard.

## Security

- Never commit credentials. `.env`, AWS credential files, and Terraform state are gitignored.
- All security testing targets only synthetic data or infrastructure owned by the developer.
