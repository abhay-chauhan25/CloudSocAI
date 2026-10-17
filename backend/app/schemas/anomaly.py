"""Anomaly scores: how unusual one principal-hour looked to the anomaly model.

A score is a signal for risk scoring, never a finding by itself.
"""

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field


class UnusualFeature(BaseModel):
    """A feature whose value was above what the baseline normally shows."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    value: int
    baseline_high: float = Field(description="The baseline's 99th percentile for this feature")


class AnomalyScore(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    principal: str
    window_start: AwareDatetime
    window_end: AwareDatetime
    # Isolation Forest anomaly score in (0, 1]: higher means isolated in fewer splits.
    score: float = Field(gt=0, le=1)
    threshold: float = Field(gt=0, le=1)
    is_anomalous: bool
    features: dict[str, int]
    unusual_features: tuple[UnusualFeature, ...]
    model_version: str

    def describe(self) -> str:
        """One sentence an analyst can check against the features."""
        if not self.unusual_features:
            unusual = "an unusual combination of features, none extreme on its own"
        else:
            unusual = "; ".join(
                f"{f.name} {f.value} (normally at most {f.baseline_high:g})"
                for f in self.unusual_features
            )
        return (
            f"Activity {self.window_start:%Y-%m-%d %H:%M}-{self.window_end:%H:%M}Z scored "
            f"{self.score:.3f} against a threshold of {self.threshold:.3f}: {unusual}."
        )
