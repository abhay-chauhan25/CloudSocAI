"""AI analysis of an incident: advisory text, generated on request and cached.

POST is the API's only write: it may call an external AI provider, so it is
rate-limited and every attempt is recorded. It never changes the incident.
"""

from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.ai.errors import AnalysisError
from app.ai.schemas import AnalysisResult, StoredAnalysis
from app.ai.service import (
    AnalystConfig,
    IncidentNotFound,
    RateLimited,
    analyze_incident,
    current_context_hash,
)
from app.api.deps import get_session
from app.repositories.analyses import latest_success

router = APIRouter(prefix="/incidents", tags=["ai analysis"])


def get_analyst_config(request: Request) -> AnalystConfig:
    return request.app.state.analyst


class AnalysisResponse(BaseModel):
    incident_id: str
    provider: str
    model: str
    created_at: datetime
    # False when the incident changed after this analysis was generated.
    is_current: bool
    cached: bool
    input_tokens: int | None
    output_tokens: int | None
    result: AnalysisResult

    @classmethod
    def build(
        cls, analysis: StoredAnalysis, *, is_current: bool, cached: bool
    ) -> "AnalysisResponse":
        return cls(
            incident_id=analysis.incident_id,
            provider=analysis.provider,
            model=analysis.model,
            created_at=analysis.created_at,
            is_current=is_current,
            cached=cached,
            input_tokens=analysis.input_tokens,
            output_tokens=analysis.output_tokens,
            result=analysis.result,
        )


@router.get("/{incident_id}/analysis")
def read_analysis(
    incident_id: str, session: Annotated[Session, Depends(get_session)]
) -> AnalysisResponse:
    """The latest successful analysis, and whether the incident has changed since."""
    digest = current_context_hash(session, incident_id)
    if digest is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Incident not found")
    analysis = latest_success(session, incident_id)
    if analysis is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="No analysis yet")
    return AnalysisResponse.build(analysis, is_current=analysis.context_hash == digest, cached=True)


@router.post(
    "/{incident_id}/analysis",
    status_code=status.HTTP_201_CREATED,
    responses={
        200: {"description": "An analysis of the unchanged incident already existed"},
        404: {"description": "Incident not found"},
        429: {"description": "Cooldown or daily limit reached"},
        502: {"description": "The AI provider failed or its answer was rejected"},
        503: {"description": "The AI analyst is disabled"},
    },
)
def create_analysis(
    incident_id: str,
    response: Response,
    session: Annotated[Session, Depends(get_session)],
    config: Annotated[AnalystConfig, Depends(get_analyst_config)],
) -> AnalysisResponse:
    """Generate an advisory AI analysis, or return the cached one if nothing changed."""
    try:
        outcome = analyze_incident(session, incident_id, config, datetime.now(UTC))
    except IncidentNotFound:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Incident not found") from None
    except RateLimited as limited:
        return JSONResponse(  # type: ignore[return-value]
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            content={"detail": limited.message},
            headers={"Retry-After": str(limited.retry_after_seconds)},
        )
    except AnalysisError as error:
        # Keep the record of the failed attempt: it counts toward the limits.
        session.commit()
        code = (
            status.HTTP_503_SERVICE_UNAVAILABLE
            if error.kind == "not_configured"
            else status.HTTP_502_BAD_GATEWAY
        )
        return JSONResponse(  # type: ignore[return-value]
            status_code=code, content={"detail": error.message, "kind": error.kind}
        )

    session.commit()
    if outcome.cached:
        response.status_code = status.HTTP_200_OK
    return AnalysisResponse.build(outcome.analysis, is_current=True, cached=outcome.cached)
