# AWS Ingestion

CloudSOC reads real CloudTrail logs from the S3 bucket a trail delivers to and sends them through the **same** normalizer, storage, detection, and correlation pipeline as the synthetic samples. Nothing downstream knows whether an event came from a file or from AWS.

Code: `backend/app/collectors/aws.py` (sessions, errors), `backend/app/collectors/cloudtrail_s3.py` (listing, download, decompression), and the `python -m app.ingest_s3` command.

```text
S3: AWSLogs/<account>/CloudTrail/<region>/YYYY/MM/DD/*.json.gz
    ↓ list_log_keys()     one day = one prefix; paginated; capped at --max-objects
    ↓ read_log_object()   GetObject → size check → gunzip (capped) → UTF-8 → envelope parser
    ↓ ingest_records()    the same normalize → store path as local files
events table  →  python -m app.detect  →  findings, incidents
```

## Credentials: the boto3 credential chain

CloudSOC never accepts, stores, or logs AWS keys. boto3 looks for credentials in a fixed order and uses the first it finds:

1. **Environment variables** (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`)
2. **Shared files** in `~/.aws/`, selected with `--profile` or `AWS_PROFILE`. This includes IAM Identity Center (SSO) profiles and profiles that assume a role.
3. **The workload's role** when running inside AWS (an ECS task role or an EC2 instance profile), served by a local metadata endpoint

The recommended setup is a profile that **assumes a read-only role**. The credentials are then temporary (one hour by default) and nothing long-lived sits on disk with more than read access. Long-term access keys (`AKIA…`) are the credential type CloudSOC's own risk model treats as riskiest.

## Least-privilege policy

`ListObjectsV2` is authorised by the `s3:ListBucket` action, and `GetObject` by `s3:GetObject`. The reader needs nothing else, and both are limited to the CloudTrail prefix:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ListTrailLogs",
      "Effect": "Allow",
      "Action": "s3:ListBucket",
      "Resource": "arn:aws:s3:::<bucket>",
      "Condition": { "StringLike": { "s3:prefix": "AWSLogs/<account-id>/CloudTrail/*" } }
    },
    {
      "Sid": "ReadTrailLogs",
      "Effect": "Allow",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::<bucket>/AWSLogs/<account-id>/CloudTrail/*"
    }
  ]
}
```

- **No write, delete, or `s3:*`.** A compromised CloudSOC host can read logs but can't erase them, which is the attacker's goal behind the `cloudtrail-trail-deleted` rule.
- **No digest files.** `CloudTrail-Digest/` falls outside the prefix. Validating log integrity would need them, and it's a separate feature.
- **KMS.** If the trail encrypts logs with a customer-managed KMS key, add `kms:Decrypt` on that key, conditioned on `kms:ViaService = s3.<region>.amazonaws.com` so the key can only be used through S3.

The Terraform lab creates exactly this policy on a role; see [aws-lab.md](aws-lab.md).

## Running it

```bash
cd backend
python -m app.ingest_s3 --bucket <bucket> --account-id <account-id> --region us-east-1 \
    --profile cloudsoc-reader --date 2026-10-06
python -m app.detect
```

| Option | Meaning |
|---|---|
| `--date` | UTC day to read. Repeatable; defaults to today |
| `--prefix` | The trail's S3 key prefix, if one was configured |
| `--organization-id` | For organization trails, whose keys include `o-…` |
| `--max-objects` | Per-day cap (default 1000). Hitting it is reported, never silent |

Exit codes:

| Code | Meaning |
|---|---|
| 0 | Clean |
| 1 | Some objects or records couldn't be ingested |
| 2 | Database unavailable |
| 3 | AWS unavailable (credentials, access denied, bucket missing) |
| 4 | Invalid arguments |

The command is **idempotent**: event IDs are unique, so re-reading a day stores nothing twice.

## Failure handling

| Failure | Behaviour |
|---|---|
| No credentials, unknown profile, listing denied | Stops with exit 3 and an actionable message. Nothing can be read, so continuing would only hide the problem |
| One object denied, corrupt, not gzip, too large | That object is logged and skipped, the others continue, and the exit code is 1 |
| An object larger than 50 MB, or one that **decompresses** past 50 MB | Rejected. Output is capped *while* decompressing, so a few KB of crafted gzip (a decompression bomb) can't exhaust memory |
| Trailing bytes after the gzip stream, truncated gzip | Rejected rather than partially parsed |
| Objects under the prefix that aren't `.json.gz` | Listed in the output as skipped, never silently ignored |
| More log files than `--max-objects` | Warning and exit 1, so a partial day is never mistaken for a complete one |

## Testing strategy

- **Unit tests (always run, offline):** `tests/test_cloudtrail_s3.py` uses botocore's **Stubber**. Each test queues the exact AWS responses it expects, the client is unsigned, and any unexpected call fails. This covers pagination, truncation, access denied, corrupt and oversized objects, and decompression bombs.
- **Command tests (with the local database):** run the whole command against stubbed S3 and check that events are stored, and skipped on a re-run.
- **Live run:** the [lab runbook](aws-lab.md) generates known activity, then checks the expected findings appear.
- **Live test (opt-in):** `tests/test_aws_live.py` is marked `aws` and skipped unless `CLOUDSOC_LIVE_BUCKET`, `CLOUDSOC_LIVE_ACCOUNT_ID`, and `CLOUDSOC_LIVE_REGION` are set. It is read-only and database-free: it lists one day, downloads at most two files, and checks that every record normalizes. Point it only at the lab bucket. It never runs in CI.

## Cost

S3 charges about $0.005 per 1,000 list requests and $0.0004 per 1,000 GET requests in us-east-1. A day of lab logs is a few hundred small objects, so reading one costs a fraction of a cent. Data transfer out to the internet is free for the first 100 GB a month. The main cost of a trail is S3 storage, which the lab removes on teardown.

## Limitations

- **Polling, not streaming.** Real SIEMs subscribe to the bucket's event notifications (S3 → SQS) and read each file as it lands. This command reads whole days on demand.
- **One account and region per run.** Organization-wide collection would loop over accounts and regions.
- **Management events only.** S3 data events and other telemetry (VPC Flow Logs) are out of scope.
