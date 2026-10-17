# CloudSOC AI — Architecture Notes

This document records architectural concepts and decisions as they are introduced. The high-level blueprint lives in [`information.md`](../information.md).

## Core data model: Event, Finding, Incident

CloudSOC is built around three distinct objects. Keeping them separate is a hard rule of the project (`CLAUDE.md` §14).

| | **Event** | **Finding** | **Incident** |
|---|---|---|---|
| Meaning | Something happened | A detector judged something security-relevant | Related findings form one investigation |
| Example | `developer` called `CreateAccessKey` | "Access key created for privileged user" | "Possible IAM account compromise" |
| Produced by | Ingestion + normalization | Detection rules, CSPM checks, ML | Correlation engine |
| Volume | Very high (every API call) | Lower | Lowest |
| Mutability | Immutable fact | Has a triage status | Evolves as new findings correlate |
| Malicious? | Not by itself | Possibly — it is *evidence* | A *hypothesis* an analyst investigates |
| Risk score | No | Yes (explainable) | Yes (recalculated from its findings) |

### Event — "something happened"

A normalized record of one action, regardless of whether it is good or bad. Almost all events are benign. Events are **immutable**: they are the evidence trail, and changing them would destroy their value in an investigation.

### Finding — "a detector says this matters"

A finding is created when a detector (rule, posture check, or ML model) identifies security-relevant evidence. It records *which* detector fired, *why*, its severity, and an explainable risk score.

A finding points to its evidence:

- **Rule findings** usually reference one event (e.g. `CreateAccessKey`).
- **Correlation-style or ML findings** may reference several events.
- **CSPM findings** reference *no* event — their evidence is a resource's configuration (e.g. a security group open to `0.0.0.0/0`).

Findings have a triage lifecycle (for example: open → acknowledged → resolved / false positive). Marking a finding as a false positive changes the finding, never the underlying event.

### Incident — "these things belong together"

An incident groups related findings into one story that an analyst investigates, using correlation keys such as principal, source IP, resource, account, region, and time window.

```text
03:04  ConsoleLogin from new IP   ─┐
03:05  CreateAccessKey             ├─ findings ─→  Incident: Possible IAM Account Compromise
03:06  AttachUserPolicy (Admin)    │                Risk 94 — Critical
03:08  AssumeRole                 ─┘
```

Incidents are updated as new related findings arrive, and their risk is recalculated. The AI analyst operates **only on incidents** — it receives structured incident context, never raw event streams.

### The detection funnel

```text
Events      ██████████████████████████  thousands — every API call
Findings    ████                        dozens — what detectors flagged
Incidents   █                           a few — what an analyst should investigate
```

Each layer reduces noise. Collapsing them into one object would either bury analysts in raw activity or lose the evidence needed to justify an alert.

### Why keep them separate?

1. **Different questions.** "What happened?" (events), "what is suspicious?" (findings), "what is the attack story?" (incidents).
2. **Evidence integrity.** Events stay unchanged; analyst decisions live on findings and incidents.
3. **False-positive handling.** A noisy detector can be tuned or its findings dismissed without touching telemetry.
4. **Explainability.** Every incident traces back through findings to the exact events that caused it.
5. **Independent evolution.** New log sources add events; new detectors add findings; new correlation rules add incidents.

### Terminology

Many SIEMs use **alert** for what CloudSOC calls a **finding**. CloudSOC uses "finding" (as AWS Security Hub does) because not every finding should page someone — informational findings still exist.

## Normalized Event schema

Defined in `backend/app/schemas/event.py` (Pydantic) and produced by `backend/app/normalization/cloudtrail.py`.

```text
raw CloudTrail record (untrusted dict)
    ↓  normalize_cloudtrail_record()   — checks every field's presence and type
Event (frozen Pydantic model)          — or NormalizationError with a specific reason
```

| Group | Fields | Notes |
|---|---|---|
| Record identity | `event_id`, `source`, `timestamp`, `account_id` | `event_id` is CloudTrail's `eventID` (dedup key); `timestamp` is always timezone-aware UTC |
| What happened | `service`, `event_name`, `event_type`, `read_only`, `region` | `service` is `"iam"` from `"iam.amazonaws.com"` |
| Who | `principal_type`, `principal`, `principal_arn`, `session_name`, `access_key_id`, `mfa_authenticated` | One consistent shape for every `userIdentity` variant |
| From where | `source_address`, `source_ip`, `user_agent` | `source_ip` is set only when `source_address` really is an IP |
| Outcome | `success`, `error_code`, `error_message` | |
| Evidence | `request_parameters`, `raw_event` | `raw_event` keeps the original record unchanged |

Key decisions:

- **Immutable** (`frozen=True`): an Event is evidence. Analyst decisions belong on Findings and Incidents.
- **Strict field names** (`extra="forbid"`): a typo fails loudly.
- **Identity mapping:** `principal` is the human-readable actor (`"root"`, the user name, the *role* name, or the invoking service). For assumed roles, `principal_arn` is the stable **role ARN**, not the per-session ARN, so baselines and correlation group all sessions of a role together; the session is kept in `session_name`.
- **Unknown is not false:** `mfa_authenticated` is `None` when the record does not say (e.g. long-term access key calls). An unrecognised identity type becomes `UNKNOWN` instead of being rejected.
- **Failures:** `success` is false when `errorCode` is present, *or* when a `ConsoleLogin` has `responseElements.ConsoleLogin == "Failure"` (console failures carry no `errorCode`).
- **Bad records are reported, never dropped:** `normalize_cloudtrail_records()` returns both `events` and `errors` (index, event ID, reason). Error reasons name fields, never echo the offending input.
- **`request_parameters` is passed through unvalidated.** Its shape differs per API; each detector reads only the keys it needs and must handle their absence. Per-API resource extraction is added only when a detector needs it.

## Storage

Events are stored in PostgreSQL (`docker-compose.yml`, bound to `127.0.0.1` only).

```text
python -m app.ingest <files>
    → load_cloudtrail_file()          collectors/cloudtrail_file.py
    → normalize_cloudtrail_records()  normalization/cloudtrail.py
    → save_events()                   repositories/events.py
    → events table                    models/event.py, created by migrations/
```

- **Two models on purpose.** The Pydantic `Event` is the validated in-memory shape; the SQLAlchemy `EventRecord` is the storage shape. Only `repositories/` converts between them.
- **Idempotent ingestion.** `event_id` has a `UNIQUE` constraint and inserts use `ON CONFLICT DO NOTHING`, so re-ingesting a file stores nothing twice — enforced by the database even under concurrent writers.
- **One transaction per file.** A file is stored completely or not at all; one unreadable file does not stop the others.
- **Column types:** `timestamp with time zone`, `INET` for `source_ip`, `JSONB` for `raw_event` and `request_parameters` (queryable, e.g. `raw_event -> 'requestParameters' ->> 'policyArn'`). `ingested_at` records when CloudSOC stored the event, separate from when it happened.
- **Indexes** on `timestamp`, `principal_arn`, and `event_name` — the fields detection and correlation filter by.
- **Schema changes only through Alembic migrations.** Constraint names follow a fixed naming convention. A test fails if the models and migrations drift apart.
- **Configuration** comes from environment variables or the gitignored `.env`; the password is a `SecretStr` and is never written to committed files.

## Finding schema and detection

Defined in `backend/app/schemas/finding.py`; produced by the detectors in `backend/app/detection/` (rules documented in [`detections.md`](detections.md)).

```text
Events (sorted by time)
    ↓  run_detectors()        detection/engine.py — every registered detector, failures isolated
    ↓  Detector.detect()      detection/rules/*.py
Findings (frozen Pydantic models), sorted by first_seen
```

| Field | Meaning |
|---|---|
| `finding_id` | UUIDv5 of the detector ID + sorted evidence event IDs — deterministic |
| `detector_id`, `title` | Which rule fired |
| `severity` | `informational` / `low` / `medium` / `high` / `critical` |
| `reason` | Plain-English explanation an analyst can verify against the evidence |
| `first_seen`, `last_seen` | Time range of the evidence (UTC) |
| `account_id`, `principal`, `principal_arn` | The actor — the correlation keys for incidents |
| `resource` | What was acted on, when the rule knows it (e.g. `svc-backup`, a trail name) |
| `event_ids` | Evidence: one event for most rules, many for the burst rule, none for future posture checks |

Severity levels, lowest to highest (`Severity.rank` 0–4):

| Severity | Meaning |
|---|---|
| informational | Worth recording, not worth reviewing on its own |
| low | Routine activity that attackers also use (e.g. creating a user) |
| medium | Unusual or risky; review when time allows |
| high | Likely dangerous; review promptly |
| critical | Almost never legitimate; act now (e.g. audit logging stopped) |

## Risk scoring

Defined in `backend/app/risk/scoring.py`. **Severity** is the rule's judgement of the behaviour; **risk** is this occurrence's priority in context.

```text
risk = base points for severity + context factors, capped to 0–100
```

| Factor | Points | Applies when |
|---|---|---|
| Base severity | 5 / 20 / 40 / 60 / 80 | Always (informational → critical) |
| New source IP | +15 | The actor first used this IP within the last 24 hours **and** has earlier activity from other addresses |
| Long-term access key | +5 | The evidence used an `AKIA…` key (never expires; the most commonly leaked credential) |
| Behaviour anomaly | +10 | The actor's activity in the evidence's clock hour was flagged by the anomaly model (see [anomaly-detection.md](anomaly-detection.md)) |

Worked example — the stolen developer key attaching `AdministratorAccess`:

```text
+60  Base severity: high
+15  New source IP: 'developer' first used 203.0.113.50 at 2026-10-06 03:04:12Z
 +5  Long-term access key: AKIA...MPLE
+10  Behaviour anomaly: 'developer': Activity 2026-10-06 03:00-04:00Z scored 0.593 against a
     threshold of 0.588: security_writes 3 (normally at most 2).
 --
 90
```

Design rules:

- **Always explainable.** `RiskAssessment` rejects any score that is not exactly the capped sum of its factors, and each factor carries a sentence citing its evidence.
- **No double counting.** There is deliberately no "root identity" bonus: the rules already raise severity for root, so adding points again would count the same evidence twice.
- **No baseline, no penalty.** A principal with no earlier history gets no "new IP" points — unknown is not suspicious. The baseline is only as good as the stored history.
- **Key IDs are masked** in explanations (`AKIA...MPLE`), as the AWS console does.

## Posture checks (CSPM)

Posture checks (`backend/app/posture/`) judge **configuration state** from a snapshot shaped like boto3 responses, not activity. They produce ordinary `Finding`s with `event_ids=()`, no actor, the resource ARN in `resource`, and the observed values quoted in `reason`; their ID is `uuid5(check_id, resource)`, so a recurring misconfiguration stays one finding. The API marks each finding `kind: "rule"` or `"posture"`, and `GET /detectors` lists posture checks separately from rules (they have no ATT&CK mapping). Missing snapshot sections are reported as *not evaluated*, never as passing. Details: [posture-checks.md](posture-checks.md).

## Finding storage

```text
python -m app.detect
    → list_events()              all stored events
    → run_detectors()            findings
    → score_finding()            RiskAssessment per finding
    → save_findings()            findings + finding_events tables
```

- **`findings`** stores the detector output plus `risk_score`, `risk_factors` (JSONB breakdown), `status` (triage: `open`, `acknowledged`, `resolved`, `false_positive`), and `created_at`. Check constraints reject unknown severities/statuses and scores outside 0–100 at the database level.
- **`finding_events`** is a join table (many-to-many): a finding cites several events, and an event can be evidence for several findings. `position` keeps the detector's evidence order.
- **Evidence integrity through foreign keys.** A finding cannot cite an event that is not stored, and an event cannot be deleted while a finding cites it (`ON DELETE RESTRICT`).
- **Idempotent and triage-safe.** Finding IDs are deterministic and inserts use `ON CONFLICT DO NOTHING`, so re-running detection stores nothing new and never resets an analyst's status. Known limitation: a burst that grows between runs gets a new ID (its evidence changed), so it is stored again as a new, larger finding.
- **One transaction per run.** All findings from a run are stored together or not at all.

## Correlation and incidents

Code in `backend/app/correlation/`; run as the last step of `python -m app.detect`.

```text
open incidents + findings in no incident (excluding false positives)
    ↓ group_findings()        same actor, each finding ≤ 1 hour from the group
    ↓ qualifies_as_incident() ≥ 2 findings, or 1 finding that is High+ or risk ≥ 60
    ↓ build_incident()        pattern → title, highest severity, incident risk
    ↓ save_incident()         insert or update; status is never overwritten
incidents + incident_findings tables
```

**Correlation key and window.** Findings are grouped by actor (`principal_arn`) when each is within **1 hour** of the group. A shorter window misses slow attacks; a longer one merges unrelated activity. Chains are followed: findings 50 minutes apart keep extending the same incident.

**Patterns** (`correlation/patterns.py`) name a group by which rules fired in it, checked in order:

| Pattern | Matches when | Example |
|---|---|---|
| Audit logging tampered | `cloudtrail-logging-stopped` or `cloudtrail-trail-deleted` | root stops then deletes the trail |
| Possible IAM persistence | ≥ 2 of `iam-user-created`, `access-key-created`, `admin-policy-attached` | developer creates `svc-backup`, gives it a key and admin |
| Root account activity | `root-account-use` | |
| Possible stolen credential probing | `failed-call-burst` | ci-deploy's key probing 6 services |
| Related suspicious activity | anything else (catch-all) | |

**Incident risk** = the highest finding risk + **5 for each additional distinct rule**, capped at 100, stored with its breakdown. Summing finding scores would hit 100 almost immediately; repeated findings from the same rule add nothing because they are not independent corroboration.

```text
Possible IAM persistence: developer           Audit logging tampered: root
 +80  admin-policy-attached scored 80          +80  cloudtrail-logging-stopped scored 80
  +5  access-key-created                        +5  cloudtrail-trail-deleted
  +5  iam-user-created                          +5  console-login-without-mfa
  --                                            +5  root-account-use (4 findings)
  90                                            --
                                                95
```

**Lifecycle rules:**

- A finding belongs to **at most one incident**: `incident_findings.finding_id` is the primary key, so PostgreSQL enforces it.
- New findings join **open** or **investigating** incidents; the title, time range, and risk are recalculated and `updated_at` changes. **Resolved** and **false-positive** incidents never reopen — new activity starts a new incident.
- Findings an analyst marked **false positive** are never correlated.
- A lone low-risk finding stays unassigned and is reconsidered on the next run, when a related finding may have arrived.
- Incident IDs are derived from the earliest finding, so correlating from scratch reproduces the same IDs.
- Known limitation: a new finding that falls between two existing incidents joins one of them; the two are not merged.

**Timeline.** `GET /incidents/{id}` returns every event by the actor from 1 hour before the first finding to 1 hour after the last, with the flagged ones marked. For the developer incident it shows the unflagged reconnaissance (`GetCallerIdentity`, `ListAttachedUserPolicies`, the denied `ListSecrets`) before the three flagged IAM changes.

## HTTP API

FastAPI app in `backend/app/api/` (run with `uvicorn app.api.main:app --reload`; docs at `http://127.0.0.1:8000/docs`). The API is **read-only** except for requesting an AI analysis.

| Endpoint | Returns |
|---|---|
| `GET /health` | `{"status": "ok", "database": "ok"}`, or **503** with `"unavailable"` when PostgreSQL is unreachable |
| `GET /events` | Page of event summaries, newest first. Filters: `principal`, `event_name` |
| `GET /events/{event_id}` | The full Event, including `raw_event` |
| `GET /findings` | Page of finding summaries (with `risk_score`, `status`, `event_count`). Filters: `severity`, `status`, `detector_id`, `principal`; `sort=newest` (default) or `sort=risk` |
| `GET /findings/{finding_id}` | Reason, risk breakdown, the rule's description/rationale/MITRE IDs, and evidence event summaries in order |
| `GET /incidents` | Page of incident summaries (title, severity, `risk_score`, `status`, `finding_count`). Filters: `status`, `severity`, `principal`; `sort=newest` (by latest activity) or `sort=risk` |
| `GET /incidents/{incident_id}` | Summary, risk breakdown, member findings, ATT&CK techniques (ordered by tactic), and the actor's timeline |
| `GET /incidents/{incident_id}/analysis` | Latest successful AI analysis and whether it is still current (see [ai-analyst.md](ai-analyst.md)) |
| `POST /incidents/{incident_id}/analysis` | Generate an advisory AI analysis, or return the cached one; rate-limited. The API's only write endpoint, and it never changes the incident |
| `GET /detectors` | The rule catalog: each rule's description, rationale, default severity, and curated ATT&CK mappings, plus the ATT&CK version and all 15 tactics for coverage views |

Design notes:

- **Response models are separate from storage and domain models** (`api/schemas.py`), so a new database column never reaches clients by accident. Lists return summaries (no `raw_event`); detail endpoints return everything.
- **Pagination:** `limit` (1–200, default 50) and `offset`, with `total` for the matching rows. The cap bounds the work any one request can cause. Offset pagination gets slower deep into large tables and can skip or repeat rows while new data arrives; keyset ("after this timestamp") pagination is the scalable alternative if needed.
- **Validation:** invalid parameters (out-of-range `limit`, unknown `severity`/`status`/`sort`, over-long strings) are rejected with **422** before any database work. Unknown IDs return **404**.
- **Failures:** a database outage returns **503** `{"detail": "Database unavailable"}` — driver errors, hosts, and ports are logged, never sent to clients.
- **Sessions:** one read-only session per request through the `get_session` dependency; tests override it to use the rolled-back test database.
- **No authentication yet.** The server must only listen on `127.0.0.1` (uvicorn's default), like PostgreSQL. Authentication and API hardening are reviewed before anything is exposed.

## Dashboard (frontend)

React 19 + TypeScript + Vite in `frontend/`. It only displays data; every decision (detection, risk, correlation) is made by the backend.

```text
Browser ── http://127.0.0.1:5173/api/incidents ──▶ Vite dev server ── /incidents ──▶ FastAPI :8000
           (same origin as the page)               (proxy strips /api)
```

| Page | URL | Shows |
|---|---|---|
| Overview | `/` | API/database health, open incidents, findings per severity, event count, top 5 incidents by risk |
| Incidents | `/incidents?status=&severity=&sort=&offset=` | Filterable, paginated incident list |
| Incident detail | `/incidents/:id` | Summary, risk breakdown, facts, advisory AI analysis (generate/regenerate), member findings, ATT&CK techniques and tactics, timeline (flagged vs context events) |
| Findings | `/findings?severity=&status=&sort=&offset=` | Filterable, paginated finding list |
| Finding detail | `/findings/:id` | Reason, risk breakdown, the rule's description/rationale, ATT&CK mappings with rationale, evidence events |
| Rules | `/rules` | Every rule with its ATT&CK mappings, and tactic coverage (covered vs gaps) |

Design notes:

- **No CORS.** The dev server proxies `/api` to FastAPI, so the browser only talks to one origin and the backend sends no CORS headers. In a deployment, a reverse proxy plays the same role.
- **One API module.** `src/api/client.ts` is the only code that calls `fetch`. IDs placed in paths are URL-encoded, and failures become an `ApiError` with a user-safe message (404, 503 "database unavailable", status 0 "backend not reachable"); response bodies are never shown.
- **`useApi` hook.** Loading / error / success states, and an `AbortController` so a slow response for an old filter can never overwrite newer data.
- **Filters live in the URL**, so views can be bookmarked, shared, and navigated with the back button. URL values are validated against the known enums and fall back to defaults.
- **Untrusted text.** Titles, reasons, and timeline fields contain attacker-controlled values. React escapes all text, and the app never uses `dangerouslySetInnerHTML`; a test renders a title containing an `<img onerror>` payload and checks no element is created.
- **Types** in `src/api/types.ts` are hand-written mirrors of the API response models. Generating them from FastAPI's OpenAPI schema is the scalable alternative.
- **Dependencies are pinned to exact versions**, each published at least two weeks before it was added, and locked in `package-lock.json`.

### Open design points (resolved in later tasks)

These are noted now so the schemas are designed deliberately, not discovered late:

- ~~**Event schema (Task 15)**~~ — resolved above.
- ~~**Finding schema (Task 30)**~~ — resolved above (`event_ids` holds zero or more events).
- ~~**Risk (Tasks 43–44)**~~ — resolved above (score stored with its factor breakdown).
- ~~**Incident schema (Task 69)**~~ — resolved above (at most one incident per finding).
