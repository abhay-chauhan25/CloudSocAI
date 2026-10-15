"""LLM providers behind one small interface.

The rest of CloudSOC only calls ``provider.generate(context)`` and gets text
back; swapping Gemini for another model means writing one more class here.
"""

import logging
from dataclasses import dataclass
from typing import Protocol

import httpx

from app.ai.errors import AnalysisError
from app.ai.prompt import SYSTEM_INSTRUCTION, build_user_prompt
from app.ai.schemas import (
    GEMINI_RESPONSE_SCHEMA,
    AnalysisResult,
    IncidentContext,
    NarrativeStep,
)

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ProviderResponse:
    text: str  # expected to be JSON matching AnalysisResult; validated by the caller
    input_tokens: int | None = None
    output_tokens: int | None = None


class AnalystProvider(Protocol):
    name: str
    model: str

    def generate(self, context: IncidentContext) -> ProviderResponse: ...


class MockProvider:
    """Deterministic, offline stand-in for an LLM, built only from the context.

    Used in tests and when no API key is configured. Its output is valid and
    grounded by construction, so it exercises the whole pipeline for free.
    """

    name = "mock"
    model = "mock-analyst-1"

    def generate(self, context: IncidentContext) -> ProviderResponse:
        incident = context.incident
        flagged = [e for e in context.timeline if e.flagged_by] or context.timeline[:1]
        steps = [
            NarrativeStep(
                description=(
                    f"{e.action} ({e.service}) at {e.time:%H:%M:%S} UTC "
                    f"{'succeeded' if e.succeeded else 'failed'}; flagged by "
                    f"{', '.join(e.flagged_by) or 'no rule'}."
                ),
                event_ids=[e.event_id],
            )
            for e in flagged[:15]
        ]
        result = AnalysisResult(
            summary=(
                f"[Mock analysis — no language model was called.] {incident.title}: "
                f"{len(context.findings)} finding(s) between {incident.first_seen:%H:%M} and "
                f"{incident.last_seen:%H:%M} UTC."
            ),
            attack_narrative=steps,
            likely_objective="Not assessed by the mock provider.",
            objective_confidence="low",
            investigation_steps=[
                f"Confirm with the owner of {incident.actor or 'the actor'} whether this "
                "activity was expected."
            ],
            containment_suggestions=[],
            benign_explanations=[],
            techniques_referenced=[t.technique_id for t in context.techniques],
        )
        return ProviderResponse(text=result.model_dump_json())


class GeminiProvider:
    """Google Gemini over its REST API (models.generateContent)."""

    name = "gemini"
    BASE_URL = "https://generativelanguage.googleapis.com/v1beta/models"
    TIMEOUT_SECONDS = 45.0
    MAX_OUTPUT_TOKENS = 4096

    def __init__(self, api_key: str, model: str, client: httpx.Client | None = None) -> None:
        self._api_key = api_key
        self.model = model
        self._client = client or httpx.Client(timeout=self.TIMEOUT_SECONDS)

    def generate(self, context: IncidentContext) -> ProviderResponse:
        body = {
            "systemInstruction": {"parts": [{"text": SYSTEM_INSTRUCTION}]},
            "contents": [{"role": "user", "parts": [{"text": build_user_prompt(context)}]}],
            "generationConfig": {
                "responseMimeType": "application/json",
                "responseSchema": GEMINI_RESPONSE_SCHEMA,
                "temperature": 0.2,  # low: favour consistent, evidence-bound answers
                "maxOutputTokens": self.MAX_OUTPUT_TOKENS,
            },
        }
        try:
            response = self._client.post(
                f"{self.BASE_URL}/{self.model}:generateContent",
                # The key goes in a header, never the URL, so it cannot end up
                # in proxy logs or exception messages that include the URL.
                headers={"x-goog-api-key": self._api_key},
                json=body,
            )
        except httpx.TimeoutException as exc:
            raise AnalysisError("timeout", "The AI provider did not respond in time.") from exc
        except httpx.HTTPError as exc:
            raise AnalysisError("unavailable", "Could not reach the AI provider.") from exc

        if response.status_code in (401, 403):
            raise AnalysisError("rejected", "The AI provider rejected the API key.")
        if response.status_code == 429:
            raise AnalysisError("unavailable", "The AI provider's rate limit was reached.")
        if response.status_code >= 400:
            # The body may echo the request; log only the status.
            logger.warning("Gemini returned HTTP %d", response.status_code)
            raise AnalysisError(
                "unavailable", f"The AI provider returned an error (HTTP {response.status_code})."
            )
        return _parse_gemini_response(response)


def _parse_gemini_response(response: httpx.Response) -> ProviderResponse:
    try:
        payload = response.json()
    except ValueError as exc:
        raise AnalysisError("malformed", "The AI provider returned invalid JSON.") from exc

    block_reason = (payload.get("promptFeedback") or {}).get("blockReason")
    if block_reason:
        raise AnalysisError("blocked", f"The AI provider blocked the request ({block_reason}).")

    candidates = payload.get("candidates") or []
    if not candidates:
        raise AnalysisError("malformed", "The AI provider returned no answer.")
    candidate = candidates[0]
    finish_reason = candidate.get("finishReason")
    if finish_reason == "MAX_TOKENS":
        raise AnalysisError("truncated", "The AI answer was cut off at the length limit.")
    if finish_reason not in (None, "STOP"):
        raise AnalysisError("blocked", f"The AI provider stopped early ({finish_reason}).")

    parts = (candidate.get("content") or {}).get("parts") or []
    text = "".join(part.get("text", "") for part in parts if isinstance(part, dict))
    if not text:
        raise AnalysisError("malformed", "The AI provider returned an empty answer.")

    usage = payload.get("usageMetadata") or {}
    return ProviderResponse(
        text=text,
        input_tokens=usage.get("promptTokenCount"),
        output_tokens=usage.get("candidatesTokenCount"),
    )
