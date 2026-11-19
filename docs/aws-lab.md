# AWS Lab (Terraform)

A small, disposable AWS environment that produces **real** CloudTrail telemetry and **real** misconfigurations, so CloudSOC can be shown working end to end on live data rather than synthetic samples. It is created with Terraform, exercised by a scenario script, checked, and destroyed the same day.

Code: `infra/terraform/` (the lab), `backend/app/lab/scenarios.py` (activity generator), `backend/app/posture_collect.py` (live posture snapshot).

## What Terraform creates

| File | Resources | Purpose |
|---|---|---|
| `logging.tf` | A multi-region CloudTrail trail; a private, encrypted S3 bucket with a policy allowing only this trail to write to it, TLS-only access, and logs expiring after 7 days | The telemetry source |
| `reader.tf` | `cloudsoc-lab-reader` role with two read-only inline policies | What CloudSOC runs as (see [aws-ingestion.md](aws-ingestion.md)) |
| `scenarios.tf` | `cloudsoc-lab-denied` role (no permissions); a VPC with no internet gateway; a security group allowing SSH from `0.0.0.0/0`; a bucket with Block Public Access off and no policy | Targets that should trigger detections and posture findings, but expose nothing |

Every resource is tagged `Project=cloudsoc-lab` and `ManagedBy=terraform`.

### Why Terraform (Infrastructure as Code)

- **Declarative.** The `.tf` files describe the *desired* end state. `terraform plan` diffs it against reality, and `apply` makes only the changes needed.
- **Reviewable and repeatable.** The lab lives in Git like code. Anyone can recreate exactly the same environment, and code review catches a public bucket before it exists.
- **Clean teardown.** Terraform records everything it created in its **state** file, so `terraform destroy` removes exactly that and nothing else. Hand-clicked resources get forgotten and keep billing.
- **Pinned.** The AWS provider is pinned to `6.72.0`, and its checksums are in `.terraform.lock.hcl` (committed). State is local and gitignored, because state files can contain sensitive values.
- **Alternatives.** CloudFormation and CDK are AWS-only, and Pulumi uses general-purpose languages. Terraform is the most widely used multi-cloud option.

## Runbook

### 0. Prerequisites (one-time)

- An AWS account you control, with MFA on the root user. Never use root for this.
- An IAM Identity Center (SSO) user or IAM user with admin rights, configured as a CLI profile, for example `aws configure sso --profile cloudsoc-admin`.
- `brew install awscli hashicorp/tap/terraform`, then check with `terraform -version`, which should report 1.17.x.

### 1. Create the lab (about 1 minute)

```bash
cd infra/terraform
export AWS_PROFILE=cloudsoc-admin
terraform init                  # downloads the pinned provider, verifies its checksums
terraform plan -out lab.tfplan  # review: 16 resources to add, 0 to change or destroy
terraform apply lab.tfplan
terraform output                # names and ARNs used below
```

Add the reader profile that `terraform output -raw reader_profile` prints to `~/.aws/config`, setting `source_profile` to your admin profile. CloudSOC then reads through a **temporary, read-only role session** instead of your admin credentials.

### 2. Generate activity

```bash
cd backend
python -m app.lab.scenarios --profile cloudsoc-admin --region us-east-1 \
    --account-id "$(terraform -chdir=../infra/terraform output -raw account_id)" \
    --trail-name cloudsoc-lab-trail \
    --denied-role-arn "$(terraform -chdir=../infra/terraform output -raw denied_role_arn)"
```

| Scenario | What it does | Undone by |
|---|---|---|
| `iam-persistence` | Creates `cloudsoc-lab-scenario-user`, attaches then detaches AdministratorAccess, creates then deletes an access key | Deleting the user (always, even on failure) |
| `logging-tampering` | `StopLogging` on the lab trail, then `StartLogging`; `DeleteTrail` on a trail name that doesn't exist | Restarting immediately; the delete can't succeed |
| `failed-call-burst` | Assumes the no-permission role and makes 6 calls across IAM, S3, EC2, Lambda, DynamoDB, and KMS | Nothing to undo: everything is denied |

**Guards.** The script refuses to run (exit 5) if:
- the credentials belong to an account other than `--account-id`;
- the trail isn't tagged `Project=cloudsoc-lab`;
- the role isn't the lab's denied role.

The secret of the temporary access key is never read or logged.

### 3. Ingest, detect, and scan posture (wait 5–15 minutes for delivery)

```bash
python -m app.ingest_s3 --profile cloudsoc-reader --region us-east-1 \
    --bucket "$(terraform -chdir=../infra/terraform output -raw trail_bucket)" \
    --account-id "$(terraform -chdir=../infra/terraform output -raw account_id)"
python -m app.detect

python -m app.posture_collect --profile cloudsoc-reader --region us-east-1 \
    --output ../local-data/lab-posture.json
python -m app.posture_scan ../local-data/lab-posture.json
```

Use **us-east-1**. IAM is a global service, and CloudTrail records its events in us-east-1, so one region's prefix holds all the scenario activity.

### 4. Verify

Open the dashboard. You should see:

| Source | Expected |
|---|---|
| `iam-persistence` | `iam-user-created` (low), `admin-policy-attached` (high), `access-key-created` (medium), grouped into **"Possible IAM persistence"** for your admin identity |
| `logging-tampering` | `cloudtrail-logging-stopped` (critical) and `cloudtrail-trail-deleted` (**high**, because the call failed), grouped into **"Audit logging tampered"** |
| `failed-call-burst` | `failed-call-burst` (medium) for the denied role's session: **"Possible stolen credential probing"** |
| Posture scan | `sg-admin-port-open-to-internet` (high) for `cloudsoc-lab-open-ssh`. `s3-public-access-not-blocked` for the unblocked bucket **only if** your account-level Block Public Access is off; if it's on, the bucket correctly passes |

Also expect activity you didn't script: Terraform's own API calls, console browsing, and AWS services acting on your behalf. That's normal background telemetry. Real data is noisier than fixtures, so look at which rules stay quiet as well as which fire. Any record the normalizer rejects is logged with its position and reason.

Optional opt-in test against the live bucket: see `tests/test_aws_live.py`.

### 5. Tear down (same day)

```bash
cd infra/terraform
terraform destroy   # review the list: 16 to destroy; the log buckets are emptied first
```

Then check nothing is left:

```bash
aws iam get-user --user-name cloudsoc-lab-scenario-user   # expect NoSuchEntity
aws cloudtrail describe-trails --trail-name-list cloudsoc-lab-trail --query 'trailList'  # expect []
aws resourcegroupstaggingapi get-resources --tag-filters Key=Project,Values=cloudsoc-lab \
    --region us-east-1 --query 'ResourceTagMappingList[].ResourceARN'  # expect []
```

Finally, remove the `cloudsoc-reader` profile from `~/.aws/config` and delete `local-data/lab-posture.json`.

## Cost

| Item | Price (us-east-1) | Lab usage | Cost |
|---|---|---|---|
| CloudTrail management events | First copy in each region is **free**; additional trails $2.00 per 100,000 events | A few thousand events | $0, or cents if you already have a trail |
| S3 storage and requests | ~$0.023/GB-month; $0.005 per 1,000 PUT/LIST; $0.0004 per 1,000 GET | A few MB, a few hundred requests | < $0.01 |
| IAM, VPC, security groups, STS | Free | | $0 |
| Total for a same-day lab | | | **well under $1** |

Nothing in the lab runs compute: no EC2 instances, NAT gateways, or load balancers, which are the usual sources of surprise bills. Set an **AWS Budget** alert (for example $5) on the account anyway.

## Security review

- **Least privilege.**
  - The reader role can list and get objects under the CloudTrail prefix of one bucket, and make the ten read-only configuration calls the posture checks need. It can't write, delete, or decrypt with KMS.
  - The scenario script runs with your admin profile because it *must* make IAM and CloudTrail changes. It's a lab-only tool, guarded by account ID and tags.
- **Trust policies.** Both lab roles trust only principals in the same account, and those principals still need `sts:AssumeRole` permission. No cross-account or public trust.
- **Log integrity.**
  - Only the trail can write to the bucket, and `aws:SourceArn` prevents confused-deputy use by other trails.
  - Log file validation produces signed digests.
  - TLS is enforced.
  - Because this is a lab, `force_destroy` lets teardown delete logs. A production log archive would do the opposite: versioning, Object Lock, a separate account, and an explicit deny on deletes.
- **Deliberate weaknesses, contained.**
  - The open security group is in a VPC with no internet gateway and no instances.
  - The unblocked bucket has no policy and no objects.
  - The denied role has no permissions.
  - The scenario user never holds AdministratorAccess and an access key at the same time, and is deleted even if a step fails.
- **No secrets in Git.** Terraform state, plans, `local-data/`, and AWS credential files are gitignored. CloudSOC never takes keys as arguments; the credential chain supplies temporary role credentials.
- **Logging pause.** `logging-tampering` stops the lab trail for about a second. Activity in that gap isn't logged, which is exactly why the rule exists. Never run it on a trail you depend on (the tag guard enforces this).
