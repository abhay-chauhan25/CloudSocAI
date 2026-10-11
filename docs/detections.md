# Detection Rules

CloudSOC's detections are deterministic rules over normalized [Events](architecture.md#normalized-event-schema). Each rule lives in `backend/app/detection/rules/`, is registered in `backend/app/detection/registry.py`, and has positive and negative tests in `backend/tests/test_detectors.py`.

Run them over the stored events:

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
| `cloudtrail-logging-stopped` | Critical; **High if the call failed** | `StopLogging` | T1562.008 Disable or Modify Cloud Logs |
| `cloudtrail-trail-deleted` | Critical; **High if the call failed** | `DeleteTrail` | T1562.008 |
| `failed-call-burst` | Medium | One principal makes **5 or more failed calls within 5 minutes** | none (see below) |

Severity reflects how strongly the evidence alone suggests danger: creating a user is routine (Low); stopping the audit log almost never is (Critical). Combining weak signals into a stronger story is the job of correlation, not of individual rules.

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

One event can produce several findings. Root's `StopLogging` call produces both `root-account-use` and `cloudtrail-logging-stopped`. This is intentional: each rule answers a different question. Grouping them into one investigation is the correlation engine's job (Incidents).
