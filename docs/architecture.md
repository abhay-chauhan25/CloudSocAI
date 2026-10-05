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

### Open design points (resolved in later tasks)

These are noted now so the schemas are designed deliberately, not discovered late:

- **Event schema (Task 15):** include the CloudTrail `eventID` (deduplication), AWS account ID (correlation), and error code (failed-call detections).
- **Finding schema (Task 30):** support zero, one, or many evidence events — not a single required `event_id`.
- **Risk (Tasks 43–44):** store the score *with* its breakdown so it stays explainable.
- **Incident schema (Task 69):** decide whether a finding can belong to more than one incident.
