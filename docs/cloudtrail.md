# CloudTrail Reference for CloudSOC

What CloudSOC needs to know about AWS CloudTrail records. Synthetic fixtures in `sample-data/cloudtrail/` follow this structure.

## What CloudTrail records

CloudTrail records **API activity** in an AWS account: who called which API, from where, when, and whether it succeeded.

| Category | Examples | Recorded by default? |
|---|---|---|
| **Management events** (control plane) | `CreateUser`, `AttachUserPolicy`, `StopLogging`, `ConsoleLogin`, `DescribeInstances` | Yes — the first copy is free |
| **Data events** (data plane) | S3 `GetObject`, Lambda `Invoke` | No — must be enabled; high volume, extra cost |

CloudSOC v1 uses **management events only**: they cover identity, privilege, and configuration changes, which is where most cloud attacks show up.

- **Event history** in the console keeps 90 days of management events per region.
- A **trail** delivers events to an S3 bucket for long-term retention. This is what CloudSOC ingests.
- Delivery is batched: AWS documents an average of about 5 minutes after the API call, with no guarantee. CloudSOC is therefore **near-real-time at best**, never real-time.

## How logs arrive in S3

```text
s3://<bucket>/AWSLogs/<account-id>/CloudTrail/<region>/<YYYY>/<MM>/<DD>/
    <account-id>_CloudTrail_<region>_<YYYYMMDDTHHmmZ>_<unique>.json.gz
```

Each file is gzip-compressed JSON with a single top-level key:

```json
{ "Records": [ { ...event... }, { ...event... } ] }
```

Things a parser must not assume:

- **Records are not guaranteed to be in time order**, within a file or across files. Sort by `eventTime` when order matters.
- **A trail may also write digest files** (`CloudTrail-Digest/...`) used for log integrity validation. They have a different shape and are not events.
- **Delivery can duplicate events**; `eventID` is the deduplication key.

## Anatomy of a record

| Field | Example | What CloudSOC uses it for |
|---|---|---|
| `eventVersion` | `"1.10"` | Record format version; newer versions add fields |
| `userIdentity` | object (see below) | **Who** made the call |
| `eventTime` | `"2026-10-06T03:04:12Z"` | **When** (UTC, ISO 8601) — timelines, correlation windows |
| `eventSource` | `"iam.amazonaws.com"` | **Which service** — `iam` after normalization |
| `eventName` | `"AttachUserPolicy"` | **Which API** — the main detection trigger |
| `awsRegion` | `"us-east-1"` | Region — new-region detections |
| `sourceIPAddress` | `"203.0.113.50"` | **From where** — new-IP detections |
| `userAgent` | `"aws-cli/2.17.0 ..."` | Which tool — CLI vs console vs SDK |
| `errorCode` / `errorMessage` | `"AccessDenied"` | Present **only when the call failed** |
| `requestParameters` | `{"userName": "...", "policyArn": "..."}` | API-specific inputs — e.g. *which* policy was attached |
| `responseElements` | `{"accessKey": {...}}` | API-specific outputs; `null` for many calls and for failures |
| `additionalEventData` | `{"MFAUsed": "No"}` | Extra context, e.g. MFA on console sign-in |
| `eventID` | UUID | Unique ID — deduplication, evidence references |
| `requestID` | UUID | AWS request ID (absent on some events, e.g. `ConsoleLogin`) |
| `readOnly` | `true` | `true` for read/list/describe calls |
| `eventType` | `"AwsApiCall"` | Also `AwsConsoleSignIn`, `AwsServiceEvent` |
| `managementEvent` | `true` | Management vs data event |
| `eventCategory` | `"Management"` | Same distinction, newer field |
| `recipientAccountId` | `"123456789012"` | The account that received the event — multi-account correlation |

`requestParameters` and `responseElements` have **no fixed schema**: their contents differ for every API. Detectors must read them defensively.

## `userIdentity` — who made the call

| `type` | Meaning | Key fields |
|---|---|---|
| `Root` | The account root user — should almost never be used | `arn` ends in `:root`, `principalId` = account ID |
| `IAMUser` | A long-lived IAM user | `userName`, `arn`, `accessKeyId` |
| `AssumedRole` | Temporary credentials from an assumed role (Lambda, EC2, SSO, cross-account) | `arn` is `arn:aws:sts::...:assumed-role/<role>/<session>`; real role in `sessionContext.sessionIssuer` |
| `FederatedUser` | Credentials from `GetFederationToken` | `sessionContext.sessionIssuer` |
| `AWSService` | An AWS service acting on your behalf | `invokedBy` (e.g. `lambda.amazonaws.com`) |
| `AWSAccount` | A principal in another account | `accountId` |

Access key ID prefixes are meaningful:

- `AKIA...` — long-term key belonging to an IAM user (or root).
- `ASIA...` — temporary STS credentials (assumed role, console session).

`sessionContext.attributes.mfaAuthenticated` records whether the session was MFA-backed.

## Gotchas that matter for detection

1. **`sourceIPAddress` is not always an IP.** When a service calls on your behalf it contains a service name (`lambda.amazonaws.com`) or `"AWS Internal"`. Treat it as a string and parse IPs explicitly.
2. **Global services log in `us-east-1`.** IAM and STS-global calls show `awsRegion: "us-east-1"` regardless of where the caller is.
3. **Failed calls are still events.** They carry `errorCode` (e.g. `AccessDenied` for IAM, `Client.UnauthorizedOperation` for EC2 — formats differ by service) and usually `responseElements: null`. Bursts of denials are a classic reconnaissance signal.
4. **Failed console logins are different.** A failed `ConsoleLogin` has `responseElements: {"ConsoleLogin": "Failure"}` and an `errorMessage`, not an `errorCode`.
5. **Secrets are not logged.** `CreateAccessKey` records the access key *ID*, never the secret key.
6. **The record of tampering is itself logged.** `StopLogging` is recorded before logging stops. Events *after* it may never reach that trail's bucket — they remain visible in Event history and in any other trail (e.g. an organization trail). This is why mature setups use an org trail that member accounts cannot disable.
7. **Some fields are attacker-controlled.** `userAgent`, `roleSessionName`, user names, and many `requestParameters` are chosen by the caller. They are untrusted input to CloudSOC — relevant to log injection and, later, to LLM prompt injection.

## Fields CloudSOC needs (preview of the Event schema)

| Need | Fields |
|---|---|
| Identity | `userIdentity.type`, `.arn`, `.userName`, `.accessKeyId`, `sessionContext.sessionIssuer.arn` |
| Action | `eventSource`, `eventName`, `readOnly`, `eventType` |
| Outcome | `errorCode`, `errorMessage`, `responseElements.ConsoleLogin` |
| Context | `eventTime`, `awsRegion`, `sourceIPAddress`, `userAgent`, `recipientAccountId` |
| Detection-specific | `requestParameters.policyArn`, `requestParameters.userName`, `additionalEventData.MFAUsed` |
| Traceability | `eventID`, and the full raw record kept as evidence |

The Event schema itself is designed in Task 15.

## Synthetic data conventions

Fixtures must never contain real identifiers. They use values reserved for documentation:

| Value | Convention |
|---|---|
| Account ID | `123456789012` (AWS documentation example account) |
| IP addresses | RFC 5737 documentation ranges: `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` |
| Access key IDs | Must contain `EXAMPLE` (e.g. AWS's own documentation key `AKIAIOSFODNN7EXAMPLE`), or be empty as on a root console sign-in |

These ranges are guaranteed never to be routed or assigned, so fixtures can never point at a real system or leak a real credential. `backend/tests/test_cloudtrail_fixtures.py` enforces this.

## Fixtures

All three describe the same fictional account. Times are UTC.

### `normal-user-activity.json` — a normal working day (2026-10-05)

| Time | Principal | Event | Notes |
|---|---|---|---|
| 09:02 | `developer` | `ConsoleLogin` (success, MFA) | from usual office IP `198.51.100.23` |
| 09:03 | `developer` | `DescribeInstances` | read-only console browsing |
| 09:05 | `developer` | `ListBuckets` | read-only |
| 10:15 | `developer` | `StartInstances` → `Client.UnauthorizedOperation` | benign failure: wrong team's instance |
| 11:30 | `admin-alice` | `AttachUserPolicy` **ReadOnlyAccess** → `intern-bob` | legitimate admin work |
| 12:00 | Lambda service | `AssumeRole` `report-generator-role` | `sourceIPAddress` is a service name |
| 12:00 | `report-generator-role` | `GetParameter` | assumed-role identity |

**Should not trigger high-severity detections.** It is the negative case for the AdministratorAccess detector (a *different* policy is attached) and shows that a failed call is not automatically suspicious.

### `iam-privilege-change.json` — stolen developer keys used for persistence (2026-10-06)

An attacker uses `developer`'s long-term access key (`AKIA...`) from an unfamiliar IP (`203.0.113.50`) at 03:04 with the AWS CLI. `developer` is over-privileged (legacy IAM permissions) — the realistic precondition.

| Time | Principal | Event | Attacker intent |
|---|---|---|---|
| 03:04:12 | `developer` | `GetCallerIdentity` | "whose keys are these?" |
| 03:04:40 | `developer` | `ListAttachedUserPolicies` | what can I do? |
| 03:05:02 | `developer` | `ListSecrets` → `AccessDenied` | probing for secrets |
| 03:05:31 | `developer` | `CreateUser` `svc-backup` | backdoor user with a boring name |
| 03:05:48 | `developer` | `CreateAccessKey` for `svc-backup` | credentials for the backdoor |
| 03:06:10 | `developer` | `AttachUserPolicy` **AdministratorAccess** → `svc-backup` | full privileges |
| 03:07:55 | `svc-backup` | `GetCallerIdentity` | testing the new key, same IP |

**Should trigger:** access-key-created, AdministratorAccess-attached, and later the IAM correlation rule (new credential + privilege change, same actor, within minutes).

### `cloudtrail-disabled.json` — root login and defense evasion (2026-10-06)

| Time | Principal | Event | Attacker intent |
|---|---|---|---|
| 22:41 | root | `ConsoleLogin` (success, **no MFA**) from `192.0.2.77` | root access |
| 22:43 | root | `DescribeTrails` | find the logging |
| 22:44 | root | `StopLogging` `management-trail` | blind the defenders |
| 22:45 | root | `DeleteTrail` `management-trail` | remove the trail entirely |

**Should trigger:** root-account-use, and CloudTrail stopped/deleted (defense evasion — MITRE ATT&CK T1562.008, *Impair Defenses: Disable or Modify Cloud Logs*).
