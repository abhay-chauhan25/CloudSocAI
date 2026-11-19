# Demo Script (about 5 minutes)

A walkthrough for showing CloudSOC to someone, with what to click and what to say. Everything runs locally on synthetic data. No AWS account is needed.

## Setup (before the demo)

```bash
cp .env.example .env    # set POSTGRES_PASSWORD and API_KEY; leave GEMINI_API_KEY empty to use the mock analyst
docker compose up -d --build --wait
docker compose run --rm seed
open http://127.0.0.1:8080
```

`seed` loads 27 synthetic CloudTrail events, then runs the anomaly model, the 8 rules, correlation, and a posture scan of an insecure configuration snapshot.

## The story

The synthetic data contains three attacks on account 123456789012, all on 2026-10-06/07:

1. **A stolen developer key.** At 03:04 UTC the `developer` key is used from a new IP (203.0.113.50). It checks who it is, lists its policies, and gets denied listing secrets. It then creates a user `svc-backup`, gives it an access key, and attaches AdministratorAccess.
2. **Root covers its tracks.** At 22:41, root signs in without MFA. At 22:44 it stops CloudTrail logging, and at 22:45 it deletes the trail.
3. **A CI key probing.** At 14:20 the next day, the `ci-deploy` key makes a burst of failed calls across six services in under ten seconds.

## Walkthrough

**1. Overview (30 s).** Three incidents out of 27 events.
> "A SIEM's job is to turn a pile of logs into a short list of things worth a human's time. These are ranked by an explainable risk score."

**2. Open "Possible IAM persistence: developer" (90 s).**
- **Risk breakdown:** the score is built from parts: the highest finding plus corroborating rules.
  > "No mystery numbers. Every point has a reason."
- **Findings:** three rules fired within a minute for the same actor. That's correlation.
- **MITRE ATT&CK:** curated mappings to Persistence and Privilege Escalation.
- **Timeline:** scroll down. The three unflagged events *before* the attack are the reconnaissance.
  > "No rule fired on them, but the timeline shows them, because an analyst needs the context."

**3. Click "AdministratorAccess policy attached" (60 s).** The finding's breakdown:

```text
60 high + 15 new IP + 5 long-term key + 10 behaviour anomaly = 90
```

- **Behaviour anomaly** comes from the Isolation Forest. That hour scored 0.593 against a threshold of 0.588, and the explanation names the unusual feature.
  > "ML adds context to a finding. It never creates one by itself."

**4. Back to the incident: AI analysis (45 s).** Generate it if it isn't shown.
- **Labelled advisory.** It cites event IDs, and the server rejects any answer that cites events or techniques not in the evidence.
  > "The LLM explains; it can't change severity, close incidents, or touch AWS. Log fields are attacker-controlled, so prompt injection is assumed."

**5. Open "Audit logging tampered: root" (30 s).** It contains the MFA-less sign-in, `StopLogging`, and `DeleteTrail`, both critical.
> "These rules fire even when the call *fails* (as high instead of critical): an attempt to blind the defenders matters either way."

**6. Rules page (30 s).**
- **ATT&CK coverage, including the gaps:** 5 of 15 tactics.
  > "CloudTrail management events can't show exfiltration. Knowing your blind spots is part of detection engineering."
- **Posture checks:** a separate table.

**7. Findings list (30 s).** Rows marked "Posture check", for example "S3 bucket is public".
> "That's CSPM: a dangerous *state*, not an *action*. Same Finding model, so the same API and UI work for both."

## Questions to expect

| Question | Short answer |
|---|---|
| Is this real AWS data? | Synthetic, so the demo is reproducible. The S3 collector and the Terraform lab (`docs/aws-lab.md`) run the same pipeline on a real account. |
| How good is the anomaly model? | On synthetic data, it flags all 3 attack hours, with 5.3% of normal hours flagged on a held-out set. The threshold was chosen after seeing results, and real data would need re-evaluation. |
| What stops someone calling your API? | An API key added server-side by nginx, a CSRF check, a Host allowlist, and localhost-only ports. See `docs/security-review.md`. |
| What would you change for production? | SSO and TLS, streaming ingestion, per-user baselines, more detections and data sources, and verified log digests. See `docs/threat-model.md` §6. |

## Reset

```bash
docker compose down --volumes   # deletes the database volume too
```
