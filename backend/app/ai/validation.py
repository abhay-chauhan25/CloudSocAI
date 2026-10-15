"""Check a model's answer before anyone sees it.

Three layers: the text must be JSON, the JSON must match AnalysisResult
exactly, and every reference must be grounded in the context that was sent.
Any failure rejects the whole answer; nothing is partially accepted.
"""

import json

from pydantic import ValidationError

from app.ai.errors import AnalysisError
from app.ai.schemas import AnalysisResult, IncidentContext


def validate_analysis(text: str, context: IncidentContext) -> AnalysisResult:
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise AnalysisError("malformed", "The AI answer was not valid JSON.") from exc

    try:
        result = AnalysisResult.model_validate(data)
    except ValidationError as exc:
        fields = sorted({".".join(str(p) for p in error["loc"]) for error in exc.errors()})
        raise AnalysisError(
            "malformed", f"The AI answer did not match the expected format ({', '.join(fields)})."
        ) from exc

    known_events = context.event_ids()
    cited = {event_id for step in result.attack_narrative for event_id in step.event_ids}
    unknown_events = cited - known_events
    if unknown_events:
        raise AnalysisError(
            "ungrounded",
            f"The AI answer cited {len(unknown_events)} event(s) that are not in the incident.",
        )

    unknown_techniques = set(result.techniques_referenced) - context.technique_ids()
    if unknown_techniques:
        raise AnalysisError(
            "ungrounded",
            f"The AI answer referenced {len(unknown_techniques)} MITRE technique(s) that are "
            "not mapped to this incident.",
        )
    return result
