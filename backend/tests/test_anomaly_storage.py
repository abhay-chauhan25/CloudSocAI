"""Anomaly scores persist, are replaced when a window is rescored, and are kept per model."""

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.anomaly import AnomalyScoreRecord
from app.repositories.anomalies import list_anomaly_scores, save_anomaly_scores
from app.schemas.anomaly import AnomalyScore, UnusualFeature

pytestmark = pytest.mark.db

HOUR = datetime(2026, 10, 6, 3, tzinfo=UTC)


def make_score(
    *, principal: str = "developer", score: float = 0.6, version: str = "v1", hour: datetime = HOUR
) -> AnomalyScore:
    return AnomalyScore(
        principal=f"arn:aws:iam::123456789012:user/{principal}",
        window_start=hour,
        window_end=hour + timedelta(hours=1),
        score=score,
        threshold=0.588,
        is_anomalous=score > 0.588,
        features={"event_count": 6, "security_writes": 3},
        unusual_features=(UnusualFeature(name="security_writes", value=3, baseline_high=2),),
        model_version=version,
    )


def stored_rows(session: Session) -> int:
    return session.scalar(select(func.count()).select_from(AnomalyScoreRecord)) or 0


def test_scores_round_trip(db_session: Session) -> None:
    score = make_score()

    save_anomaly_scores(db_session, [score])

    assert list_anomaly_scores(db_session, "v1") == [score]


def test_rescoring_a_window_replaces_its_score(db_session: Session) -> None:
    save_anomaly_scores(db_session, [make_score(score=0.6)])

    save_anomaly_scores(db_session, [make_score(score=0.5)])

    [stored] = list_anomaly_scores(db_session, "v1")
    assert (stored.score, stored.is_anomalous) == (0.5, False)
    assert stored_rows(db_session) == 1


def test_each_model_version_keeps_its_own_scores(db_session: Session) -> None:
    save_anomaly_scores(db_session, [make_score(version="v1"), make_score(version="v2")])

    assert stored_rows(db_session) == 2
    assert [s.model_version for s in list_anomaly_scores(db_session, "v2")] == ["v2"]


def test_listing_can_return_only_anomalous_windows(db_session: Session) -> None:
    save_anomaly_scores(
        db_session,
        [make_score(principal="quiet", score=0.4), make_score(principal="loud", score=0.7)],
    )

    flagged = list_anomaly_scores(db_session, "v1", anomalous_only=True)

    assert [s.principal.rsplit("/", 1)[-1] for s in flagged] == ["loud"]


def test_the_database_rejects_an_out_of_range_score(db_session: Session) -> None:
    db_session.add(
        AnomalyScoreRecord(
            principal="p",
            window_start=HOUR,
            window_end=HOUR + timedelta(hours=1),
            model_version="v1",
            score=1.5,
            threshold=0.5,
            is_anomalous=True,
            features={},
            unusual_features=[],
        )
    )

    with pytest.raises(IntegrityError):
        db_session.flush()
