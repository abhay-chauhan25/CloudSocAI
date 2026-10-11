"""Explainable risk: a score that is always stored with the factors behind it."""

from typing import Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

MIN_SCORE = 0
MAX_SCORE = 100


class RiskFactor(BaseModel):
    """One line of a risk breakdown: what was observed and how many points it adds."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str = Field(min_length=1, description='Short label, e.g. "New source IP"')
    points: int = Field(description="May be negative for factors that lower risk")
    explanation: str = Field(min_length=1, description="The evidence behind the points")


class RiskAssessment(BaseModel):
    """A risk score from 0 to 100 that is exactly the capped sum of its factors."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    score: int = Field(ge=MIN_SCORE, le=MAX_SCORE)
    factors: tuple[RiskFactor, ...] = Field(min_length=1)

    @classmethod
    def from_factors(cls, factors: list[RiskFactor]) -> Self:
        return cls(score=capped_total(factors), factors=tuple(factors))

    @model_validator(mode="after")
    def _score_matches_factors(self) -> Self:
        # A score that cannot be rebuilt from its breakdown would not be explainable.
        if self.score != capped_total(self.factors):
            raise ValueError("score must equal the sum of its factors, capped to 0-100")
        return self


def capped_total(factors: tuple[RiskFactor, ...] | list[RiskFactor]) -> int:
    return max(MIN_SCORE, min(MAX_SCORE, sum(factor.points for factor in factors)))
