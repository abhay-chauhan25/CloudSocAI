"""Run an AI analysis for an incident, with caching and cost controls.

Order of checks: unknown incident → cached answer (free) → cooldown and
daily cap (only when a paid call would be made) → call the provider →
validate → record. Every attempt that reaches the provider is recorded,
failures included, so usage is auditable and counts toward the limits.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from app.ai.context import build_context, context_hash
from app.ai.errors import AnalysisError
from app.ai.prompt import PROMPT_VERSION
from app.ai.providers import AnalystProvider, GeminiProvider, MockProvider
from app.ai.schemas import StoredAnalysis
from app.ai.validation import validate_analysis
from app.config import Settings
from app.correlation.view import load_incident_view
from app.repositories.analyses import (
    count_attempts_since,
    latest_attempt_at,
    latest_success,
    record_failure,
    record_success,
)


@dataclass(frozen=True)
class AnalystConfig:
    provider: AnalystProvider | None  # None when the AI analyst is disabled
    daily_limit: int
    cooldown: timedelta


def build_analyst_config(settings: Settings) -> AnalystConfig:
    choice = settings.resolved_ai_provider()
    provider: AnalystProvider | None
    if choice == "gemini":
        if settings.gemini_api_key is None:
            raise ValueError("AI_PROVIDER=gemini requires GEMINI_API_KEY")
        provider = GeminiProvider(settings.gemini_api_key.get_secret_value(), settings.gemini_model)
    elif choice == "mock":
        provider = MockProvider()
    else:
        provider = None
    return AnalystConfig(
        provider=provider,
        daily_limit=settings.ai_daily_limit,
        cooldown=timedelta(seconds=settings.ai_cooldown_seconds),
    )


class IncidentNotFound(Exception):
    pass


class RateLimited(Exception):
    def __init__(self, message: str, retry_after_seconds: int) -> None:
        super().__init__(message)
        self.message = message
        self.retry_after_seconds = retry_after_seconds


@dataclass(frozen=True)
class AnalysisOutcome:
    analysis: StoredAnalysis
    cached: bool


def current_context_hash(session: Session, incident_id: str) -> str | None:
    view = load_incident_view(session, incident_id)
    return context_hash(build_context(view)) if view is not None else None


def analyze_incident(
    session: Session, incident_id: str, config: AnalystConfig, now: datetime
) -> AnalysisOutcome:
    """Return a current analysis, generating one if needed. Does not commit."""
    provider = config.provider
    if provider is None:
        raise AnalysisError("not_configured", "The AI analyst is disabled.")

    view = load_incident_view(session, incident_id)
    if view is None:
        raise IncidentNotFound(incident_id)
    context = build_context(view)
    digest = context_hash(context)

    cached = latest_success(session, incident_id)
    if (
        cached is not None
        and cached.context_hash == digest
        and (cached.provider, cached.model, cached.prompt_version)
        == (provider.name, provider.model, PROMPT_VERSION)
    ):
        return AnalysisOutcome(cached, cached=True)

    _enforce_limits(session, incident_id, config, now)

    attempt = {
        "incident_id": incident_id,
        "provider": provider.name,
        "model": provider.model,
        "prompt_version": PROMPT_VERSION,
        "context_hash": digest,
    }
    response = None
    try:
        response = provider.generate(context)
        result = validate_analysis(response.text, context)
    except AnalysisError as error:
        record_failure(
            session,
            **attempt,
            error_kind=error.kind,
            error_message=error.message,
            input_tokens=response.input_tokens if response else None,
            output_tokens=response.output_tokens if response else None,
        )
        raise
    stored = record_success(
        session,
        **attempt,
        result=result,
        input_tokens=response.input_tokens,
        output_tokens=response.output_tokens,
    )
    return AnalysisOutcome(stored, cached=False)


def _enforce_limits(
    session: Session, incident_id: str, config: AnalystConfig, now: datetime
) -> None:
    last = latest_attempt_at(session, incident_id)
    if last is not None and now - last < config.cooldown:
        wait = int((config.cooldown - (now - last)).total_seconds()) + 1
        raise RateLimited(f"This incident was analysed moments ago; retry in {wait}s.", wait)
    if count_attempts_since(session, now - timedelta(days=1)) >= config.daily_limit:
        raise RateLimited(f"The daily limit of {config.daily_limit} AI analyses was reached.", 3600)
