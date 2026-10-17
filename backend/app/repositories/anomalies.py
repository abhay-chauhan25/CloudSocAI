"""Save and load anomaly scores. Callers own the transaction."""

from collections.abc import Sequence

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.models.anomaly import AnomalyScoreRecord
from app.schemas.anomaly import AnomalyScore, UnusualFeature

INSERT_BATCH_SIZE = 1000


def save_anomaly_scores(session: Session, scores: Sequence[AnomalyScore]) -> None:
    """Insert scores, replacing any earlier score for the same window and model.

    Unlike findings, a score is overwritten: if more events arrive for an
    hour, the hour's features change and the old score is simply out of date.
    """
    for start in range(0, len(scores), INSERT_BATCH_SIZE):
        statement = insert(AnomalyScoreRecord).values(
            [_to_row(score) for score in scores[start : start + INSERT_BATCH_SIZE]]
        )
        session.execute(
            statement.on_conflict_do_update(
                constraint="uq_anomaly_scores_principal",
                set_={
                    column: statement.excluded[column]
                    for column in (
                        "window_end",
                        "score",
                        "threshold",
                        "is_anomalous",
                        "features",
                        "unusual_features",
                    )
                }
                | {"updated_at": func.now()},
            )
        )


def list_anomaly_scores(
    session: Session, model_version: str, *, anomalous_only: bool = False
) -> list[AnomalyScore]:
    query = (
        select(AnomalyScoreRecord)
        .where(AnomalyScoreRecord.model_version == model_version)
        .order_by(AnomalyScoreRecord.window_start, AnomalyScoreRecord.principal)
    )
    if anomalous_only:
        query = query.where(AnomalyScoreRecord.is_anomalous)
    return [_to_score(record) for record in session.scalars(query)]


def _to_row(score: AnomalyScore) -> dict:
    return score.model_dump(mode="json") | {
        "window_start": score.window_start,
        "window_end": score.window_end,
    }


def _to_score(record: AnomalyScoreRecord) -> AnomalyScore:
    return AnomalyScore(
        principal=record.principal,
        window_start=record.window_start,
        window_end=record.window_end,
        score=record.score,
        threshold=record.threshold,
        is_anomalous=record.is_anomalous,
        features=record.features,
        unusual_features=tuple(UnusualFeature(**item) for item in record.unusual_features),
        model_version=record.model_version,
    )
