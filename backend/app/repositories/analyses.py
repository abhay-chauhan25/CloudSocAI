"""Record AI analysis attempts and read them back. Callers own the transaction."""

from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.ai.schemas import AnalysisResult, StoredAnalysis
from app.models.analysis import AnalysisRecord


def record_success(
    session: Session,
    *,
    incident_id: str,
    provider: str,
    model: str,
    prompt_version: str,
    context_hash: str,
    result: AnalysisResult,
    input_tokens: int | None,
    output_tokens: int | None,
) -> StoredAnalysis:
    record = AnalysisRecord(
        incident_id=incident_id,
        status="succeeded",
        provider=provider,
        model=model,
        prompt_version=prompt_version,
        context_hash=context_hash,
        result=result.model_dump(mode="json"),
        input_tokens=input_tokens,
        output_tokens=output_tokens,
    )
    session.add(record)
    session.flush()
    session.refresh(record)  # load the database-assigned id and created_at
    return _to_stored(record)


def record_failure(
    session: Session,
    *,
    incident_id: str,
    provider: str,
    model: str,
    prompt_version: str,
    context_hash: str,
    error_kind: str,
    error_message: str,
    input_tokens: int | None = None,
    output_tokens: int | None = None,
) -> None:
    session.add(
        AnalysisRecord(
            incident_id=incident_id,
            status="failed",
            provider=provider,
            model=model,
            prompt_version=prompt_version,
            context_hash=context_hash,
            error_kind=error_kind,
            error_message=error_message,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
        )
    )
    session.flush()


def latest_success(session: Session, incident_id: str) -> StoredAnalysis | None:
    record = session.scalar(
        select(AnalysisRecord)
        .where(AnalysisRecord.incident_id == incident_id, AnalysisRecord.status == "succeeded")
        .order_by(AnalysisRecord.created_at.desc(), AnalysisRecord.id.desc())
        .limit(1)
    )
    return _to_stored(record) if record is not None else None


def latest_attempt_at(session: Session, incident_id: str) -> datetime | None:
    return session.scalar(
        select(func.max(AnalysisRecord.created_at)).where(AnalysisRecord.incident_id == incident_id)
    )


def count_attempts_since(session: Session, since: datetime) -> int:
    return (
        session.scalar(
            select(func.count())
            .select_from(AnalysisRecord)
            .where(AnalysisRecord.created_at >= since)
        )
        or 0
    )


def _to_stored(record: AnalysisRecord) -> StoredAnalysis:
    return StoredAnalysis(
        analysis_id=record.id,
        incident_id=record.incident_id,
        provider=record.provider,
        model=record.model,
        prompt_version=record.prompt_version,
        context_hash=record.context_hash,
        result=AnalysisResult.model_validate(record.result),
        input_tokens=record.input_tokens,
        output_tokens=record.output_tokens,
        created_at=record.created_at,
    )
