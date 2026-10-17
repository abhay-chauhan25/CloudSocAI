"""The anomaly model: an Isolation Forest trained on the synthetic baseline.

Isolation Forest builds many random trees. Each split picks a random feature
and a random cut between that feature's minimum and maximum. Points unlike
the rest are separated from everything else after only a few splits, so a
short average path through the trees means "anomalous". No labelled attacks
are needed: the model only learns what normal looks like.

The model is retrained from the seeded baseline every time it is used. It
takes well under a second, keeps results reproducible, and avoids storing a
model file — loading a pickled model is code execution, so a model file is
something an attacker could replace.
"""

from collections.abc import Sequence
from dataclasses import dataclass
from functools import cache

import numpy as np
from sklearn.ensemble import IsolationForest

from app.ml.baseline import generate_baseline
from app.ml.features import FEATURE_NAMES, ActivityWindow, build_windows
from app.schemas.anomaly import AnomalyScore, UnusualFeature

# Change the version whenever features, baseline, or parameters change:
# stored scores from different versions are not comparable.
MODEL_VERSION = "iforest-1"
BASELINE_SEED = 20261010
BASELINE_WINDOWS = 5000
TREES = 500

# Hours scoring above this percentile of the baseline's own scores are
# flagged, so by construction about 5% of normal hours are flagged. That
# false-positive rate is acceptable only because a flag never raises an alert
# on its own: it adds points to a finding a rule has already produced.
THRESHOLD_PERCENTILE = 95
# A feature is named as unusual when it exceeds this percentile of the baseline.
UNUSUAL_FEATURE_PERCENTILE = 99


@dataclass(frozen=True)
class AnomalyModel:
    forest: IsolationForest
    threshold: float
    feature_highs: dict[str, float]  # per-feature baseline percentile, for explanations
    version: str = MODEL_VERSION

    def raw_scores(self, windows: Sequence[ActivityWindow]) -> np.ndarray:
        # scikit-learn returns the negated anomaly score of the original
        # paper; negating it back gives a value in (0, 1], higher = more unusual.
        return -self.forest.score_samples(_matrix(windows))


def train(windows: int = BASELINE_WINDOWS, seed: int = BASELINE_SEED) -> AnomalyModel:
    baseline = build_windows(generate_baseline(windows, seed))
    matrix = _matrix(baseline)
    forest = IsolationForest(n_estimators=TREES, random_state=seed).fit(matrix)
    baseline_scores = -forest.score_samples(matrix)
    return AnomalyModel(
        forest=forest,
        threshold=round(float(np.percentile(baseline_scores, THRESHOLD_PERCENTILE)), 4),
        feature_highs={
            name: float(np.percentile(matrix[:, column], UNUSUAL_FEATURE_PERCENTILE))
            for column, name in enumerate(FEATURE_NAMES)
        },
    )


@cache
def default_model() -> AnomalyModel:
    """The standard model, trained once per process."""
    return train()


def score_windows(model: AnomalyModel, windows: Sequence[ActivityWindow]) -> list[AnomalyScore]:
    if not windows:
        return []
    scores = model.raw_scores(windows)
    return [
        AnomalyScore(
            principal=window.principal,
            window_start=window.start,
            window_end=window.end,
            score=round(float(score), 4),
            threshold=model.threshold,
            is_anomalous=round(float(score), 4) > model.threshold,
            features=dict(window.features),
            unusual_features=unusual_features(model, window),
            model_version=model.version,
        )
        for window, score in zip(windows, scores, strict=True)
    ]


def unusual_features(model: AnomalyModel, window: ActivityWindow) -> tuple[UnusualFeature, ...]:
    """Features above the baseline's high percentile.

    A heuristic explanation, not the forest's internal reasoning: a window
    can be anomalous because of a rare combination of ordinary values, in
    which case no single feature is listed.
    """
    return tuple(
        UnusualFeature(name=name, value=window.features[name], baseline_high=high)
        for name, high in model.feature_highs.items()
        if window.features[name] > high
    )


def _matrix(windows: Sequence[ActivityWindow]) -> np.ndarray:
    return np.array([window.vector() for window in windows], dtype=float)
