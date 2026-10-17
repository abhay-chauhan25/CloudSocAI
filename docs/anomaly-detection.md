# Behaviour Anomaly Detection

CloudSOC's rules catch *known* dangerous actions. The anomaly model asks a different question:

> **Is this identity's activity in this hour unlike normal activity in the account?**

Its output is a **signal, not a verdict**. A flagged hour never creates a finding or an incident on its own. It adds an explained **+10 "Behaviour anomaly"** factor to the risk of findings that rules already produced in that hour.

Code: `backend/app/ml/` (features, baseline, model, evaluate). Scores are stored in the `anomaly_scores` table.

## Unit of analysis and features

One **activity window** = one principal (ARN) × one clock hour. Events with no identifiable principal are left out.

| Feature | Meaning |
|---|---|
| `event_count` | API calls in the hour |
| `distinct_actions` | Different (service, API) pairs |
| `distinct_services` | Different AWS services |
| `failed_calls` | Calls that returned an error |
| `write_calls` | Calls with `readOnly: false` (unknown is *not* counted as a write) |
| `security_writes` | Writes to iam, cloudtrail, organizations, kms, guardduty, or config |
| `distinct_source_ips` | Different source IP addresses |

All features are **counts**. Ratios were rejected because they are unstable on small windows: one failed call out of one is a "100% failure rate".

The same `build_windows()` function produces features for training and for scoring, so the model never sees data shaped differently from what it learned on (no *training/serving skew*).

## Training data: a synthetic baseline

CloudSOC's own history is a few dozen events, far too few to learn "normal". So `baseline.py` generates **5,000 normal hours** from four profiles, using a fixed seed:

| Profile | Share | Shape |
|---|---|---|
| developer | 45% | 1–40 calls, mostly reads, ~15% writes, ~3% failures |
| automation | 30% | 5–120 calls repeating 2–5 actions, write-heavy, ~1% failures |
| admin | 15% | 1–25 IAM/CloudTrail/KMS reads; 35% of hours also make 1–2 IAM changes |
| console | 10% | A sign-in plus up to 11 reads, ~5% failures |

These profiles are **assumptions**, not measurements. In production the baseline would be weeks of the account's own history, which brings its own problem: any attack already in that history is learned as normal.

## Model: Isolation Forest

- **How it works.** An Isolation Forest builds many random trees. Each split picks a random feature and a random cut point. Unusual points get isolated after **fewer splits**, and the anomaly score (0–1) rises as the average path gets shorter.
- **Why it fits.** It's unsupervised, so it needs no labelled attacks. It's fast, and it's the standard first choice for tabular anomaly detection.
- **Settings.** 500 trees, `random_state` set to the seed. Results are fully reproducible: same seed, same scores (tested).
- **No model file.** The model is retrained from the seeded baseline each run, which takes about 2 seconds. A stored pickled model would be a code-execution risk if replaced, and a versioning burden.
- **Versioning.** `MODEL_VERSION` (`iforest-1`) is stored with every score. Change it whenever features, baseline, or parameters change, because scores from different versions aren't comparable.

## Threshold

**Flagged = score above the 95th percentile of the baseline's own scores.**

The threshold is chosen *from normal data only*, which fixes the false-positive rate at about 5% by construction. A 95th-percentile cut is only acceptable because of how the signal is used: a false positive adds 10 points to a finding a rule already raised; it never pages anyone.

The first version used the 99th percentile. It flagged **none** of the attack hours, even though it ranked them above every ordinary hour. The threshold was lowered after seeing that, so the scenario results below are **not independent evidence**.

## Evaluation (`python -m app.ml.evaluate`)

| Check | Result |
|---|---|
| Fresh normal hours (new seed) flagged | 107 / 2,000 = **5.3%** false-positive rate |
| Scenario attack hours flagged | **3 / 3** |
| Scenario ordinary hours flagged | **0 / 7** |

| Score | Hour | Explanation |
|---|---|---|
| 0.620 | ci-deploy, failed-call burst | `failed_calls 7 (normally at most 3)` |
| 0.593 | developer, IAM persistence | `security_writes 3 (normally at most 2)` |
| 0.593 | root, logging tampering | unusual combination, no single feature extreme |
| 0.583 | admin-alice attaches a policy *(benign)* | not flagged; 0.005 below the threshold |
| threshold 0.588 | | |

**Honest reading:**
- The margins are thin, and three labelled hours aren't an accuracy measurement.
- The model ranks the scenarios sensibly. It can't tell a developer's IAM changes from an admin's, because a single global model has no per-identity history.

## Explanations

For each flagged hour, CloudSOC lists the features above the baseline's 99th percentile, for example `failed_calls 7 (normally at most 3)`.

This is a **heuristic**, not the forest's internal reasoning. When an hour is anomalous only as a *combination* of ordinary values (the root hour), the explanation says exactly that, instead of inventing a reason.

## Known false positives and negatives (tested)

| Case | Result | Why |
|---|---|---|
| Developer retries a denied call 6 times | **Flagged** (false positive) | Indistinguishable from probing by behaviour alone |
| Deploy surge of 150 writes | **Flagged** (false positive) | More writes than any baseline hour |
| Routine pipeline hour (30 writes + 30 reads) | Not flagged | Within the automation profile |
| A single admin policy change | Not flagged | Admin hours include IAM changes |
| Attacker's single `GetCallerIdentity` with a stolen key (svc-backup) | **Not flagged** (false negative) | One quiet read looks like any ordinary hour |

## Limitations

- **Global, not per-identity.** "Normal for the account" can't express "unusual *for this user*". Per-principal baselines need much more history.
- **Synthetic baseline.** The model learns the generator's assumptions. Real accounts differ, and the threshold would need recalibrating on real data.
- **Possible double counting.** The failed-call-burst rule and the `failed_calls` feature look at the same evidence, so a burst finding's +10 partly recounts it. This is accepted, and documented, because the anomaly factor is small.
- **Stored findings aren't rescored.** Findings keep the risk they were stored with (so triage never silently changes). Anomaly factors apply to findings detected after the hour was scored.
- **No time-of-day feature.** "3 a.m. activity" is a classic signal, but CI runs around the clock and the synthetic timestamps are arbitrary, so it would mostly add noise here.

## How production systems differ

Commercial UEBA tools such as GuardDuty or Sentinel UEBA:
- learn per-identity and peer-group baselines over weeks;
- use many more features (geolocation, ASN, resource sensitivity);
- retrain continuously;
- measure precision and recall against analyst-labelled outcomes.

CloudSOC's model is a small, explainable version of the same idea.
