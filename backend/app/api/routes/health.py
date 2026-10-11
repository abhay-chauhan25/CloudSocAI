"""Health check: is the API up, and can it reach the database?"""

from typing import Annotated

from fastapi import APIRouter, Depends, Response, status
from sqlalchemy import text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from app.api.deps import get_session
from app.api.schemas import HealthStatus

router = APIRouter(tags=["health"])


@router.get("/health")
def health(session: Annotated[Session, Depends(get_session)], response: Response) -> HealthStatus:
    try:
        session.execute(text("SELECT 1"))
    except OperationalError:
        # 503 tells load balancers and monitors not to send traffic here.
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return HealthStatus(status="degraded", database="unavailable")
    return HealthStatus(status="ok", database="ok")
