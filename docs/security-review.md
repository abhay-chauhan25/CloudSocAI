# Security Review

A review of CloudSOC's own security: secrets, the API, the AI analyst, and AWS access. It records the controls in place and how each is checked.

## CI pipeline (`.github/workflows/ci.yml`)

Every push to `main` and every pull request runs:

| Job | Checks |
|---|---|
| Backend | Ruff lint, including flake8-bandit security rules; Ruff format; **mypy**; pytest against a real PostgreSQL service. Database tests *fail* rather than skip if it's unreachable (`CLOUDSOC_REQUIRE_DB`) |
| Frontend | TypeScript strict type check, Vitest, production build |
| Dependency audit | `pip-audit` on the exact runtime lock file (PyPI/OSV advisories); `npm audit` on the dashboard's runtime packages |
| Terraform | `fmt -check`, `init -backend=false`, `validate`. No AWS credentials exist in CI, so nothing is planned or applied |
| Stack smoke test | Builds both images, starts the full Compose stack, seeds demo data, and checks that the dashboard and API answer through nginx and that the API refuses a request without the key |

**Supply-chain hardening in the pipeline itself:**
- Third-party actions are pinned to **full commit SHAs**. A tag like `v7` can be re-pointed at malicious code; a SHA can't.
- The workflow token is read-only (`permissions: contents: read`).
- `actions/checkout` doesn't leave the token on disk.
- Dependencies are installed from lock files with exact versions.

**First audit result.** The first `pip-audit` run found 3 advisories in two transitive dependencies, `certifi` and `opentelemetry-api`, which nothing in CloudSOC imports directly. Both were upgraded in `requirements.lock`. That's the point of the job: transitive packages are code you ship without ever choosing it.

**Type checking.** mypy checks `app/` with the pydantic plugin, which knows model constructors validate and coerce their inputs. Its first run found 12 issues, none a runtime bug. Each was fixed by making the types say what the code meant: for example, an `int | None` pair in the burst detector became one optional `(start, end)` tuple, so "end is set whenever start is" is enforced by the type rather than by convention. boto3, botocore, and scikit-learn ship no type information and are treated as `Any`.

## Secrets

| Secret | Where it lives | Never in |
|---|---|---|
| Database password | `.env` (gitignored, mode 600), or CI-generated per run | Images, logs, URLs built by string formatting (`URL.create` escapes it) |
| `GEMINI_API_KEY` | `.env`, read as `SecretStr` (hidden in `repr` and logs) | Requests' URLs (sent as the `x-goog-api-key` header), the browser, stored analyses |
| `API_KEY` | `.env`; injected by the dev proxy and nginx | The browser bundle (checked: the header name doesn't appear in `dist/`), images, Git |
| AWS credentials | `~/.aws` profiles, preferably SSO or an assumed role (temporary) | The repository, CloudSOC's config, command-line arguments, logs |

Other controls:
- `.dockerignore` excludes `.env` from both build contexts.
- Terraform state and plans are gitignored.
- Posture snapshots are written owner-only.
- Sample data uses AWS's documented example identifiers. GitHub secret-scanning alerts on those can be closed as "used in tests".

## API security

| Control | Protects against |
|---|---|
| **API key** on every route except `/health`, compared in constant time; the API refuses to start without one (at least 32 characters) | Any process or person reaching the API directly (port 8000, or the Compose network) |
| **Key injected server-side** by Vite or nginx, overwriting anything the browser sends | Key theft through the page: there is nothing in the page to steal |
| **Fetch Metadata check:** state-changing requests with `Sec-Fetch-Site` other than `same-origin` or `none` are refused | **CSRF.** Because the proxy adds the key automatically, it acts like a cookie, so another site could otherwise make your browser trigger paid AI analyses |
| **Host allowlist** (`localhost`, `127.0.0.1`, `[::1]`, `api`) | **DNS rebinding:** an attacker's domain re-resolved to 127.0.0.1 to make their page "same-origin" with the dashboard |
| **Security headers.** API: `nosniff`, `no-store`, `no-referrer`. Dashboard: a strict **Content-Security-Policy** (scripts, styles, and connections only from its own origin; no framing), `X-Frame-Options: DENY`, `Permissions-Policy` | XSS impact (second layer after React's escaping), clickjacking, cached or leaked security data |
| **Validation everywhere:** Pydantic request and response models, bounded pagination, encoded path segments | Malformed input, mass assignment, over-fetching |
| **Generic errors:** database outages return 503 with no driver details; the dashboard shows server text only for deliberately user-facing messages | Information disclosure |
| **Localhost binding.** Only 127.0.0.1:8080 (dashboard) and 127.0.0.1:5432 (development database) are published; the API isn't published at all | Network exposure |
| **Containers:** non-root, read-only filesystem, all capabilities dropped, `no-new-privileges` | Post-exploitation persistence and privilege escalation |

**What the key doesn't do.** It authenticates the *dashboard proxy*, not a person. Anyone who can open `http://127.0.0.1:8080` uses the API with the dashboard's rights, which is acceptable for a single-user tool on localhost. Exposing CloudSOC beyond localhost would need real user authentication (OIDC/SSO in front of nginx, per-user sessions, and roles), plus TLS.

## AI security

- **Advisory only by construction.** The response schema has no fields for severity, risk, status, or mappings, and the provider has no tools, so the model can't change a verdict or touch AWS.
- **Grounding and validation.** Strict JSON schema (`extra="forbid"`, length limits). Every cited event ID must be in the incident's context, and every ATT&CK technique must be one of its curated mappings. Otherwise the whole answer is rejected (502) and recorded.
- **Prompt injection.**
  - Attacker-controlled log text (user names, user agents) is data inside a delimited JSON block with `<` and `>` escaped, separate from the instructions, and length-capped.
  - The schema limits what a successful injection could produce: text a human reads, never an action.
- **Data minimisation.** No raw events, request parameters, error messages, or access key IDs are sent to the provider.
- **Cost controls:**
  - cache by context hash;
  - a 60-second per-incident cooldown;
  - a daily cap;
  - the CSRF check above;
  - and now **one paid analysis at a time**. A PostgreSQL advisory lock, released automatically with the transaction, closes a race in which two simultaneous requests could both pass the cooldown and cap checks before either was recorded.
- **Audit.** Every attempt that reaches the provider is stored with its model, prompt version, token counts, and outcome.

## AWS least privilege

| Identity | Permissions | Why that much |
|---|---|---|
| CloudSOC reader role (`cloudsoc-lab-reader`) | `s3:ListBucket` and `s3:GetObject` on the trail's `AWSLogs/<account>/CloudTrail/` prefix only; ten read-only configuration actions for posture | Exactly the calls `ingest_s3` and `posture_collect` make. No write, delete, or KMS |
| Lab scenario runner | Your admin profile | It *must* create and delete IAM users and stop and start the trail. Guarded by account ID, the trail's lab tag, and the expected role ARN |
| Denied role | None | Exists only to produce AccessDenied events |
| CI | None; no AWS credentials exist in GitHub | Terraform is only validated |

Both lab roles trust only principals in the same account, and sessions last at most one hour. Details: [aws-ingestion.md](aws-ingestion.md), [aws-lab.md](aws-lab.md).

## Open items

- **No user accounts or TLS.** Fine on localhost, required before any shared deployment.
- **Container images aren't vulnerability-scanned.** Trivy or Docker Scout would add OS-package CVEs to CI.
- **Lock files pin versions, not hashes.** `pip install --require-hashes` would also detect a tampered package on PyPI.
- **The API key is a single shared secret.** Rotating it means editing `.env` and restarting. A real deployment would keep it in a secrets manager.
- **Starlette deprecation warning.** Its test client asks for `httpx2`, which had several releases within the last month. Switch once it settles.
