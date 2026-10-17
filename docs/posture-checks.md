# Posture Checks (CSPM)

A SIEM watches **activity**: "someone *did* something dangerous". Cloud Security Posture Management (CSPM) watches **configuration**: "something *is* dangerous right now". A public S3 bucket leaks data even if nobody has touched it today, and no CloudTrail event will tell you so.

The two work together:
- CSPM shrinks the attack surface before an attacker arrives.
- The SIEM catches them using what's left.

In CloudSOC, both produce the same `Finding` type, so risk scoring, storage, the API, and the dashboard treat them alike.

Code: `backend/app/posture/` (snapshot, base, checks, registry, engine) and the `python -m app.posture_scan` command.

## Snapshot → checks → findings

```text
AWS configuration snapshot (JSON, boto3 response shapes)
    ↓  parse_snapshot(): validate the fields the checks use, ignore the rest
PostureSnapshot
    ↓  run_posture_checks(): every check whose section is present
Findings (no actor, no events; resource ARN + observed values in the reason)
    ↓  score_finding(): base severity
findings table  →  API (`kind: "posture"`)  →  dashboard
```

### Snapshot format

The **wrapper keys** (`iam`, `s3`, `ec2`, `cloudtrail`, `buckets`, …) are CloudSOC's own. The **objects inside** keep the exact field names AWS returns, so a live collector can fill a snapshot directly from boto3 without changing any check:

| Snapshot path | AWS API call |
|---|---|
| `iam.account_summary` | `iam.get_account_summary()["SummaryMap"]` |
| `iam.credential_report` | `iam.get_credential_report()`, with the CSV decoded into rows |
| `s3.account_public_access_block` | `s3control.get_public_access_block()["PublicAccessBlockConfiguration"]` |
| `s3.buckets[]` | `s3.list_buckets()`, each merged with `get_public_access_block()` and `get_bucket_policy_status()` |
| `ec2.security_groups` | `ec2.describe_security_groups()["SecurityGroups"]` |
| `cloudtrail.trails` / `.status` | `cloudtrail.describe_trails()["trailList"]` / `get_trail_status()` per trail |

Parsing rules:
- **Only fields the checks use are modelled.** AWS returns many more and adds new ones over time, so unknown fields are **ignored**.
- **Missing or wrongly-typed used fields are an error.** The error names the field path, for example `iam.account_summary.AccountMFAEnabled`.
- **Credential report cells are text**, so `"true"`, `"N/A"` and `"not_supported"` are interpreted explicitly.

Fixtures: `sample-data/aws-config/insecure-account.json` (fails every check, 11 findings) and `secure-account.json` (passes every check).

## Checks

| Check | Severity | Fails when |
|---|---|---|
| `root-mfa-disabled` | critical | `AccountMFAEnabled = 0` |
| `root-access-keys-present` | critical | `AccountAccessKeysPresent > 0` |
| `iam-user-console-without-mfa` | high | A user has a console password and no MFA |
| `iam-access-key-not-rotated` | medium | An **active** key was last rotated more than 90 days before the snapshot (root excluded: its keys are already critical) |
| `s3-public-access-not-blocked` | medium | A Block Public Access setting is off for **both** the account and the bucket |
| `s3-bucket-public` | critical | The bucket policy is public **and** `RestrictPublicBuckets` is off at both levels |
| `sg-admin-port-open-to-internet` | high | Inbound SSH (22) or RDP (3389) from `0.0.0.0/0` or `::/0`, including all-protocol (`-1`) and port-range rules |
| `cloudtrail-no-multi-region-logging` | high | No trail is both multi-region and currently logging |
| `cloudtrail-log-validation-disabled` | medium | A trail has log file validation off |

Each check records:
- a description;
- a rationale, including when the configuration may be deliberate (for example, website buckets or break-glass users);
- a remediation;
- the CIS AWS Foundations Benchmark control it follows.

The reference is named by **topic**, not control number, because the numbering changes between benchmark versions.

### Nuances the checks get right

- **Effective settings.** S3 Block Public Access applies at the account *or* the bucket level, so a setting is a gap only if it's off at both. The secure fixture has a bucket with a public policy that the account's `RestrictPublicBuckets` neutralises, and it's correctly not flagged.
- **Port ranges.** A rule allowing TCP 0–65535, or all protocols, exposes SSH and RDP even though it never names port 22. UDP 22 doesn't.
- **"Logging" means logging.** A multi-region trail that has been *stopped* still fails, and so does a trail whose status couldn't be read.

## Design decisions

- **Not evaluated isn't passed.** If a snapshot lacks a section (say, the collector had no S3 permissions), its checks are reported as **not evaluated**. Treating missing data as compliant is a classic CSPM blind spot.
- **One finding per check and resource.** The ID is `uuid5(check_id, resource)`, so the same misconfiguration seen in every scan stays **one** finding instead of piling up a new one each day.
- **Failure isolation.** A check that raises is recorded by exception type only (messages can contain configuration data), and the other checks still run. The command exits non-zero.
- **No ATT&CK mapping.** ATT&CK describes adversary *behaviour*. A misconfiguration is a weakness that enables many techniques, not a technique itself, so posture checks map to CIS controls instead. The Rules page's tactic coverage counts only behavioural rules.
- **No correlation.** Posture findings have no actor, so the correlation engine skips them. Linking "public bucket" with "someone read from it" would need S3 data events, which are out of scope.
- **Risk is base severity only.** There's no activity context to add. A natural extension is resource context, such as "bucket tagged as holding customer data".

## Limitations

- **No auto-resolve.** Fixing a misconfiguration doesn't close its finding; a later clean scan simply produces nothing. A real CSPM marks such findings resolved (Security Hub's `RecordState: ARCHIVED`). An analyst resolves them by hand here.
- **One region per snapshot.** Security groups and trails are regional. Covering an account means one snapshot per region.
- **A small set of checks.** Commercial tools ship hundreds, and add attack-path analysis (public instance → instance role → admin permissions) that single-resource checks can't see.

## How real CSPM products compare

AWS Security Hub (CIS and Foundational Best Practices standards), AWS Config rules, Prowler, and products like Wiz or Prisma Cloud all follow the same loop:
1. collect configuration through read-only APIs;
2. evaluate controls;
3. emit findings with severity and remediation.

They differ in scale (hundreds of controls, many accounts and regions), continuous evaluation triggered by configuration changes, and graph-based risk prioritisation.
