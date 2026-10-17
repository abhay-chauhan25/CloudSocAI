"""Evaluate the anomaly model on fresh normal data and on the sample scenarios.

Usage (from backend/; no database needed):

    python -m app.ml.evaluate

Two questions are answered:

1. False positives: what share of *new* normal hours, generated with a
   different seed from the training baseline, does the model flag?
2. Detection: are the sample scenarios' attack hours flagged, and are the
   ordinary hours left alone?

The second check uses three labelled attack hours. That is a sanity check,
not an accuracy measurement, and the threshold was chosen after looking at
these hours, so they are not independent evidence either.
"""

import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from app.collectors.cloudtrail_file import load_cloudtrail_file
from app.ml.baseline import generate_baseline
from app.ml.features import FEATURE_NAMES, build_windows
from app.ml.model import (
    BASELINE_SEED,
    BASELINE_WINDOWS,
    THRESHOLD_PERCENTILE,
    AnomalyModel,
    default_model,
    score_windows,
)
from app.normalization.cloudtrail import normalize_cloudtrail_records
from app.schemas.anomaly import AnomalyScore

SAMPLES_DIR = Path(__file__).resolve().parents[3] / "sample-data" / "cloudtrail"
ACCOUNT = "arn:aws:iam::123456789012"

# The hours in the sample data where an attack scenario takes place.
ATTACK_HOURS = frozenset(
    {
        (f"{ACCOUNT}:user/developer", datetime(2026, 10, 6, 3, tzinfo=UTC)),  # IAM persistence
        (f"{ACCOUNT}:root", datetime(2026, 10, 6, 22, tzinfo=UTC)),  # logging tampering
        (f"{ACCOUNT}:user/ci-deploy", datetime(2026, 10, 7, 14, tzinfo=UTC)),  # failed-call burst
    }
)


@dataclass(frozen=True)
class Evaluation:
    holdout_windows: int
    holdout_flagged: int
    scenario_scores: list[AnomalyScore]

    @property
    def holdout_false_positive_rate(self) -> float:
        return self.holdout_flagged / self.holdout_windows

    def attacks(self) -> list[AnomalyScore]:
        return [s for s in self.scenario_scores if (s.principal, s.window_start) in ATTACK_HOURS]

    def ordinary(self) -> list[AnomalyScore]:
        return [
            s for s in self.scenario_scores if (s.principal, s.window_start) not in ATTACK_HOURS
        ]


def evaluate(model: AnomalyModel, samples_dir: Path = SAMPLES_DIR) -> Evaluation:
    holdout = score_windows(model, build_windows(generate_baseline(2000, BASELINE_SEED + 1)))
    events = []
    for path in sorted(samples_dir.glob("*.json")):
        events += normalize_cloudtrail_records(load_cloudtrail_file(path)).events
    return Evaluation(
        holdout_windows=len(holdout),
        holdout_flagged=sum(score.is_anomalous for score in holdout),
        scenario_scores=score_windows(model, build_windows(events)),
    )


def format_evaluation(model: AnomalyModel, evaluation: Evaluation) -> str:
    attacks, ordinary = evaluation.attacks(), evaluation.ordinary()
    lines = [
        f"Model {model.version}: Isolation Forest on {BASELINE_WINDOWS} synthetic normal hours",
        f"Threshold {model.threshold:.3f} = {THRESHOLD_PERCENTILE}th percentile of baseline scores",
        "Unusual-feature limits: "
        + ", ".join(f"{name} > {model.feature_highs[name]:g}" for name in FEATURE_NAMES),
        "",
        f"Fresh normal hours flagged: {evaluation.holdout_flagged}/{evaluation.holdout_windows} "
        f"({evaluation.holdout_false_positive_rate:.1%} false-positive rate)",
        f"Scenario attack hours flagged: {sum(s.is_anomalous for s in attacks)}/{len(attacks)}",
        f"Scenario ordinary hours flagged: {sum(s.is_anomalous for s in ordinary)}/{len(ordinary)}",
        "",
    ]
    for score in sorted(evaluation.scenario_scores, key=lambda s: -s.score):
        label = "attack  " if score in attacks else "ordinary"
        verdict = "FLAGGED" if score.is_anomalous else "-"
        unusual = ", ".join(f"{f.name}={f.value}" for f in score.unusual_features)
        lines.append(
            f"{score.score:.3f}  {verdict:7}  {label}  {score.window_start:%Y-%m-%d %H}:00  "
            f"{score.principal.removeprefix(ACCOUNT + ':')}  {unusual}"
        )
    return "\n".join(lines)


def main() -> int:
    model = default_model()
    print(format_evaluation(model, evaluate(model)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
