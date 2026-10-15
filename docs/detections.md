# Detection Rules

CloudSOC's detections are deterministic rules over normalized [Events](architecture.md#normalized-event-schema). Each rule lives in `backend/app/detection/rules/`, is registered in `backend/app/detection/registry.py`, and has positive and negative tests in `backend/tests/test_detectors.py`.

Run them over the stored events (findings are scored and stored; see [risk scoring](architecture.md#risk-scoring)):

```bash
cd backend && python -m app.detect
```

## The rules

| ID | Severity | Fires when | MITRE ATT&CK |
|---|---|---|---|
| `root-account-use` | High | The root user signs in or makes an API call (not a service acting on root's behalf) | T1078.004 Valid Accounts: Cloud Accounts |
| `console-login-without-mfa` | Medium; **High for root** | A successful console sign-in by root or an IAM user records `MFAUsed: No` | T1078.004 |
| `iam-user-created` | Low | A successful `CreateUser` | T1136.003 Create Account: Cloud Account |
| `access-key-created` | Medium; **High for root's own key** | A successful `CreateAccessKey` | T1098.001 Additional Cloud Credentials |
| `admin-policy-attached` | High | A successful `Attach{User,Group,Role}Policy` with AWS's `AdministratorAccess` | T1098.003 Additional Cloud Roles |
| `cloudtrail-logging-stopped` | Critical; **High if the call failed** | `StopLogging` | T1685.002 Disable or Modify Tools: Disable or Modify Cloud Log |
| `cloudtrail-trail-deleted` | Critical; **High if the call failed** | `DeleteTrail` | T1685.002 |
| `failed-call-burst` | Medium | One principal makes **5 or more failed calls within 5 minutes** | none (see below) |

Severity reflects how strongly the evidence alone suggests danger: creating a user is routine (Low); stopping the audit log almost never is (Critical). Combining weak signals into a stronger story is the job of correlation, not of individual rules.

## MITRE ATT&CK mappings

Mappings use **ATT&CK Enterprise v20** (`backend/app/mitre/catalog.py`). Each rule declares its mappings as `MitreMapping(technique_id, rationale)`; tests check that every technique exists in the catalog and that every mapping explains itself. The mappings are curated by hand: an LLM may explain them but never adds or replaces one.

| Technique | Tactics (v20) | Rules | Why the mapping holds |
|---|---|---|---|
| T1078.004 Valid Accounts: Cloud Accounts | Initial Access, Persistence, Privilege Escalation, Stealth | `root-account-use`, `console-login-without-mfa` | Both observe a valid cloud account's credentials being used; the rule cannot tell an owner from an attacker, which is why the technique fits |
| T1136.003 Create Account: Cloud Account | Persistence | `iam-user-created` | `CreateUser` creates a new cloud account an attacker can keep using after losing the first identity |
| T1098.001 Account Manipulation: Additional Cloud Credentials | Persistence, Privilege Escalation | `access-key-created` | `CreateAccessKey` adds a credential to an existing account |
| T1098.003 Account Manipulation: Additional Cloud Roles | Persistence, Privilege Escalation | `admin-policy-attached` | Attaching a policy grants additional permissions; ATT&CK names `AttachUserPolicy` as an AWS example |
| T1685.002 Disable or Modify Tools: Disable or Modify Cloud Log | Defense Impairment | `cloudtrail-logging-stopped`, `cloudtrail-trail-deleted` | Stops or removes the cloud audit log; ATT&CK's analytic for it names `StopLogging` and `DeleteTrail` |

**ATT&CK changes between versions.** In v20, TA0005 was renamed from Defense Evasion to **Stealth**, a new **Defense Impairment** tactic (TA0112) was added, and cloud-log tampering moved from T1562.008 to **T1685.002**. Mappings are pinned to a version and must be re-checked against attack.mitre.org when upgrading.

**Coverage.** The rules cover 5 of 15 Enterprise tactics (Initial Access, Persistence, Privilege Escalation, Stealth, Defense Impairment). That gap is expected: CloudTrail management events say little about Execution, Collection, or Exfiltration, which need other telemetry (data events, VPC Flow Logs, endpoints). The dashboard's **Rules** page shows covered tactics and gaps.

## Design decisions

- **Interface.** Every detector receives the whole batch of events, sorted by time, and returns findings. Single-event rules extend `SingleEventDetector` and only define `matches()` and `explain()`; the burst rule needs the batch to count failures in a window.
- **Metadata on every rule.** ID, name, description, rationale (including known false positives), default severity, and MITRE technique IDs. A test fails if any of it is missing.
- **Successful calls only — with two exceptions.** A denied `CreateUser` or `AttachUserPolicy` changed nothing, so it is not reported by those rules (the burst rule covers repeated denials). A *failed* `StopLogging`/`DeleteTrail` is still reported (as High): an attempt to blind the defenders is significant even when it fails. Root activity is reported whether or not it succeeded.
- **Explainable reasons.** Each finding says what happened in terms an analyst can check against the evidence events. Caller-controlled values (user names, trail names) are quoted with `repr`, so newlines or control characters cannot forge extra output.
- **Deterministic finding IDs.** A finding's ID is a UUIDv5 of its detector ID and sorted evidence event IDs. Re-running detection produces identical findings, so storage can be idempotent.
- **Failure isolation.** If one detector raises, the engine logs it, records it in `failures`, and still runs the others. `python -m app.detect` exits non-zero when that happens.

## False positives and blind spots

| Rule | Known false positives | Known blind spots |
|---|---|---|
| `root-account-use` | The few tasks that require root (some billing/account settings) | — |
| `console-login-without-mfa` | — | SSO/federated sign-ins are **excluded on purpose**: CloudTrail records `MFAUsed: No` for them even when the identity provider enforced MFA |
| `iam-user-created` | Routine onboarding | — |
| `access-key-created` | Planned key rotation | — |
| `admin-policy-attached` | Deliberate admin onboarding | Inline policies (`PutUserPolicy`) or customer policies granting `*:*`; only the AWS-managed policy is recognised |
| `cloudtrail-logging-stopped` / `-trail-deleted` | Planned migrations, lab teardown | Other ways to weaken logging (`UpdateTrail`, event selectors, S3 bucket policy changes) |
| `failed-call-burst` | Misconfigured automation retrying a forbidden call | Slow probing below 5 failures per 5 minutes; failures with no identifiable principal |

**Why no MITRE mapping for `failed-call-burst`:** repeated denials have many causes — cloud discovery, credential testing, broken automation. Tagging one technique would claim more than the evidence shows. Correlation can attach a technique when the surrounding activity makes the intent clear.

## Overlapping findings

One event can produce several findings. Root's `StopLogging` call produces both `root-account-use` and `cloudtrail-logging-stopped`. This is intentional: each rule answers a different question. Grouping them into one investigation is the correlation engine's job — see [Correlation and incidents](architecture.md#correlation-and-incidents).
