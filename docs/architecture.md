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
| ML anomaly, correlation | — | Added in later stages |

Worked example — the stolen developer key attaching `AdministratorAccess`:

```text
+60  Base severity: high
+15  New source IP: 'developer' first used 203.0.113.50 at 2026-10-06 03:04:12Z
 +5  Long-term access key: AKIA...MPLE
 --
 80
```

Design rules:

- **Always explainable.** `RiskAssessment` rejects any score that is not exactly the capped sum of its factors, and each factor carries a sentence citing its evidence.
- **No double counting.** There is deliberately no "root identity" bonus: the rules already raise severity for root, so adding points again would count the same evidence twice.
- **No baseline, no penalty.** A principal with no earlier history gets no "new IP" points — unknown is not suspicious. The baseline is only as good as the stored history.
- **Key IDs are masked** in explanations (`AKIA...MPLE`), as the AWS console does.

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

### Open design points (resolved in later tasks)

These are noted now so the schemas are designed deliberately, not discovered late:

- ~~**Event schema (Task 15)**~~ — resolved above.
- ~~**Finding schema (Task 30)**~~ — resolved above (`event_ids` holds zero or more events).
- ~~**Risk (Tasks 43–44)**~~ — resolved above (score stored with its factor breakdown).
- **Incident schema (Task 69):** decide whether a finding can belong to more than one incident.
