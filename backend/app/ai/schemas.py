"""What the AI analyst receives (IncidentContext) and must return (AnalysisResult).

The response schema is the main safety boundary: it has no fields for
severity, risk, status, MITRE mappings, or actions, so the model cannot
change any of them. It can only describe and suggest.
"""

from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

# --- context: the evidence package sent to the model ---------------------------


class ContextRiskFactor(BaseModel):
    name: str
    points: int


class ContextFinding(BaseModel):
    finding_id: str
    rule: str
    title: str
    severity: str
    risk_score: int
    reason: str
    event_ids: list[str]


class ContextTechnique(BaseModel):
    technique_id: str
    name: str
    tactics: list[str]


class ContextEvent(BaseModel):
    event_id: str
    time: datetime
    service: str
    action: str
    succeeded: bool
    error_code: str | None
    source: str | None
    user_agent: str | None  # attacker-controlled; truncated
    flagged_by: list[str]


class ContextIncident(BaseModel):
    incident_id: str
    title: str
    pattern: str
    severity: str
    risk_score: int
    risk_factors: list[ContextRiskFactor]
    actor: str | None
    actor_arn: str | None
    account_id: str | None
    first_seen: datetime
    last_seen: datetime


class IncidentContext(BaseModel):
    """Only what the analysis needs. No raw events, request parameters, error
    messages, or credentials ever leave CloudSOC."""

    incident: ContextIncident
    findings: list[ContextFinding]
    techniques: list[ContextTechnique]  # curated mappings; the model may cite, never change
    timeline: list[ContextEvent]
    timeline_truncated: bool

    def event_ids(self) -> set[str]:
        return {event.event_id for event in self.timeline}

    def technique_ids(self) -> set[str]:
        return {technique.technique_id for technique in self.techniques}


# --- result: what the model must return ----------------------------------------

Item = Annotated[str, Field(min_length=1, max_length=400)]


class NarrativeStep(BaseModel):
    model_config = ConfigDict(extra="forbid")

    description: str = Field(min_length=1, max_length=600)
    event_ids: list[Item] = Field(min_length=1, max_length=20, description="Evidence for the step")


class AnalysisResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    summary: str = Field(min_length=1, max_length=1500)
    attack_narrative: list[NarrativeStep] = Field(min_length=1, max_length=15)
    likely_objective: str = Field(min_length=1, max_length=600)
    objective_confidence: Literal["low", "medium", "high"]
    investigation_steps: list[Item] = Field(min_length=1, max_length=8)
    containment_suggestions: list[Item] = Field(max_length=8)
    benign_explanations: list[Item] = Field(max_length=5)
    techniques_referenced: list[Item] = Field(max_length=10)


# The same contract in the OpenAPI-subset format Gemini's responseSchema
# accepts. Pydantic validation is still applied afterwards: the model is
# asked to follow this schema, never trusted to have done so.
GEMINI_RESPONSE_SCHEMA: dict = {
    "type": "OBJECT",
    "properties": {
        "summary": {"type": "STRING"},
        "attack_narrative": {
            "type": "ARRAY",
            "items": {
                "type": "OBJECT",
                "properties": {
                    "description": {"type": "STRING"},
                    "event_ids": {"type": "ARRAY", "items": {"type": "STRING"}},
                },
                "required": ["description", "event_ids"],
            },
        },
        "likely_objective": {"type": "STRING"},
        "objective_confidence": {"type": "STRING", "enum": ["low", "medium", "high"]},
        "investigation_steps": {"type": "ARRAY", "items": {"type": "STRING"}},
        "containment_suggestions": {"type": "ARRAY", "items": {"type": "STRING"}},
        "benign_explanations": {"type": "ARRAY", "items": {"type": "STRING"}},
        "techniques_referenced": {"type": "ARRAY", "items": {"type": "STRING"}},
    },
    "required": [
        "summary",
        "attack_narrative",
        "likely_objective",
        "objective_confidence",
        "investigation_steps",
        "containment_suggestions",
        "benign_explanations",
        "techniques_referenced",
    ],
}


class StoredAnalysis(BaseModel):
    """A successful analysis as kept in the database."""

    model_config = ConfigDict(frozen=True)

    analysis_id: int
    incident_id: str
    provider: str
    model: str
    prompt_version: str
    context_hash: str
    result: AnalysisResult
    input_tokens: int | None
    output_tokens: int | None
    created_at: datetime
