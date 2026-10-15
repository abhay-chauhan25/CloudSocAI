"""Ways an analysis can fail. Messages are safe to show to users."""

from typing import Literal

FailureKind = Literal[
    "not_configured",
    "timeout",
    "unavailable",
    "rejected",
    "blocked",
    "truncated",
    "malformed",
    "ungrounded",
]


class AnalysisError(Exception):
    def __init__(self, kind: FailureKind, message: str) -> None:
        super().__init__(message)
        self.kind = kind
        self.message = message
