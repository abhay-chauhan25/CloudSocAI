# Threat Model

Two questions:
1. **What does CloudSOC detect?** The attacker behaviour it's built to catch in an AWS account.
2. **How could CloudSOC itself be attacked?** A security tool holds sensitive data, credentials, and trust, which makes it a target.

[security-review.md](security-review.md) lists the controls in detail. This page explains *why* they exist.

## 1. What CloudSOC defends against

| Attacker goal | Example | What CloudSOC sees | Gaps |
|---|---|---|---|
| Use stolen credentials | A developer's access key leaked in a public repo, used from a new IP at 3 a.m. | `root-account-use`, `console-login-without-mfa`; risk factors for **new source IP** and **long-term key**; the **anomaly model** flags the unusual hour | Credentials used "normally" from a familiar IP look legitimate |
| Explore permissions | `GetCallerIdentity`, listing policies, denied `ListSecrets` | `failed-call-burst`; the incident **timeline** shows the quiet reconnaissance before the flagged events | Slow probing below 5 failures per 5 minutes |
| Persist | Create a backdoor user, give it a key and admin rights | `iam-user-created`, `access-key-created`, `admin-policy-attached`, correlated into **"Possible IAM persistence"** | Inline policies granting `*:*`, new roles, Lambda backdoors |
| Blind the defenders | `StopLogging`, `DeleteTrail` | Critical findings, **even when the call fails**; posture checks that a multi-region trail is logging with validation on | `UpdateTrail` and event-selector changes |
| Exploit misconfiguration | A public bucket, SSH open to the internet, root without MFA | 9 **posture checks** (CIS-style) | Hundreds of other controls; attack paths across resources |

**Out of scope:** data exfiltration (it needs S3 data events and flow logs), workloads inside EC2 or containers, and other clouds. The ATT&CK coverage on the Rules page shows the tactics with no rules.

## 2. Assets

| Asset | Why it matters |
|---|---|
| Security telemetry and findings | Reveal the account's structure, identities, IPs, and weaknesses: a map for an attacker |
| AWS read access (the reader role) | Read access to logs and configuration across the account |
| API key, database password, Gemini key | Access to the data above, or a way to spend money |
| Integrity of detections | If an attacker can hide or forge findings, the SOC is blind |
| AI analyses | Analysts may trust them; a manipulated analysis could mislead an investigation |

## 3. Trust boundaries

```text
 AWS account ──(1) read-only role──► collectors ──► PostgreSQL ◄── API ◄──(3) nginx ◄──(4) browser
  attacker-influenced log content ──(2)──┘                          │
                                                                    └──(5) HTTPS──► Gemini
```

1. **AWS → CloudSOC.** Credentials come from the boto3 chain, never from CloudSOC's config.
2. **Log content → parser.** Every field of a CloudTrail record that names a user, an agent, or a request can be chosen by an attacker.
3. **nginx → API.** The API key is added here. The API trusts only requests carrying it.
4. **Browser → dashboard.** Other sites open in the same browser are untrusted.
5. **API → LLM provider.** A third party sees whatever is sent, and its output is untrusted text.

## 4. Threats to CloudSOC (STRIDE)

| | Threat | Mitigation | Residual risk |
|---|---|---|---|
| **S**poofing | A process or website calls the API pretending to be the dashboard | API key (constant-time compare); Fetch Metadata CSRF check; Host allowlist against DNS rebinding | The key authenticates the proxy, not a person. Anyone with localhost access is "the analyst" |
| **T**ampering | Crafted log records: duplicate JSON keys, `NaN`, huge files, decompression bombs, non-IP source addresses | Strict envelope parser rejects ambiguity; size caps before and *during* decompression; Pydantic validation; malformed records are reported, never silently dropped | A record that is valid but false (CloudTrail itself is trusted) |
| | An attacker deletes or alters logs in S3 | Log file validation (signed digests); the reader role can't write or delete; a log bucket only CloudTrail can write to | CloudSOC doesn't yet *verify* digests; the lab bucket allows teardown |
| **R**epudiation | "Nobody ran that AI analysis" | Every provider attempt recorded with time, model, prompt version, tokens, outcome | No per-user identity in the records (single user) |
| **I**nformation disclosure | Secrets in Git, images, logs, or the browser | `.env` gitignored and excluded from images; `SecretStr`; masked key IDs; key never in the bundle; generic error messages; `no-store` | Findings are stored unencrypted in the local database |
| | Sensitive data sent to the LLM | Minimal context: no raw events, request parameters, or key IDs | User names and IPs are sent; the mock provider avoids that entirely |
| **D**enial of service | Oversized inputs; spending the AI budget | Size caps; pagination limits; AI cooldown, daily cap, single-flight lock, cache | No general API rate limiting |
| **E**levation of privilege | **Prompt injection** in log fields makes the LLM "decide" something | The LLM has no tools and no fields for verdicts; output is schema-validated and grounding-checked; it can only produce text a human reads | A persuasive but wrong narrative; the UI labels analyses advisory |
| | XSS via attacker-controlled names rendered in the dashboard | React escapes text; strict CSP blocks inline and third-party script | — |
| | Compromise of a container | Non-root, read-only filesystem, no capabilities, no-new-privileges, tiered networks | Shared kernel (containers aren't VMs) |
| | Supply chain (a malicious package or Action) | Exact lock files; `pip-audit` / `npm audit` in CI; Actions pinned by SHA; read-only CI token | Lock files pin versions, not hashes |

## 5. Detection integrity

**Rules and ML decide; the LLM explains.** A model that could set severity or close incidents would turn a prompt-injection bug into a detection bypass. Here the worst a manipulated model can do is write a misleading paragraph, which validation often rejects and which never changes a finding.

**ML is a signal, not a verdict.** The anomaly model only adds 10 risk points. An attacker who learns the baseline can stay under it, which is why rules, not ML, generate findings.

## 6. Production gaps

To run CloudSOC for a real team:
- per-user authentication (SSO) with roles, and TLS;
- secrets in a manager;
- an encrypted managed database;
- verified log digests;
- streaming ingestion with back-pressure;
- per-principal baselines;
- an evaluation set of real, labelled incidents to measure false-positive rates.
