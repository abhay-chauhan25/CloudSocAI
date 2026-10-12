"""Correlation patterns: named shapes that say what a group of findings means.

The engine groups findings by actor and time; a pattern then names the
group, based on which rules fired inside it. Patterns are checked in order
and the first match wins, so the most specific and severe story comes first.
"""

from collections.abc import Collection
from dataclasses import dataclass


@dataclass(frozen=True)
class IncidentPattern:
    pattern_id: str
    title: str
    description: str
    # The pattern matches when at least ``min_matches`` of these rules fired.
    # An empty set matches any group (the fallback pattern).
    detector_ids: frozenset[str]
    min_matches: int = 1

    def matched_detectors(self, detector_ids: Collection[str]) -> set[str]:
        return set(detector_ids) & self.detector_ids

    def matches(self, detector_ids: Collection[str]) -> bool:
        if not self.detector_ids:
            return True
        return len(self.matched_detectors(detector_ids)) >= self.min_matches


AUDIT_LOGGING_TAMPERED = IncidentPattern(
    pattern_id="audit-logging-tampered",
    title="Audit logging tampered",
    description=(
        "CloudTrail logging was stopped or a trail deleted. Whatever else the actor "
        "did may be missing from the logs, so treat the whole account as suspect."
    ),
    detector_ids=frozenset({"cloudtrail-logging-stopped", "cloudtrail-trail-deleted"}),
)

IAM_PERSISTENCE = IncidentPattern(
    pattern_id="iam-persistence",
    title="Possible IAM persistence",
    description=(
        "The same actor created an identity or credential and changed privileges in a "
        "short time: the typical way an attacker keeps access after the original "
        "credentials are revoked."
    ),
    detector_ids=frozenset({"iam-user-created", "access-key-created", "admin-policy-attached"}),
    min_matches=2,
)

ROOT_ACCOUNT_ACTIVITY = IncidentPattern(
    pattern_id="root-account-activity",
    title="Root account activity",
    description="The account root user was used; confirm who used it and why.",
    detector_ids=frozenset({"root-account-use"}),
)

CREDENTIAL_PROBING = IncidentPattern(
    pattern_id="credential-probing",
    title="Possible stolen credential probing",
    description=(
        "Repeated denied calls across services suggest someone exploring what a "
        "credential can do. Check whether the credential's owner made these calls."
    ),
    detector_ids=frozenset({"failed-call-burst"}),
)

RELATED_SUSPICIOUS_ACTIVITY = IncidentPattern(
    pattern_id="related-suspicious-activity",
    title="Related suspicious activity",
    description="Several findings for the same actor close together in time.",
    detector_ids=frozenset(),
)

PATTERNS: tuple[IncidentPattern, ...] = (
    AUDIT_LOGGING_TAMPERED,
    IAM_PERSISTENCE,
    ROOT_ACCOUNT_ACTIVITY,
    CREDENTIAL_PROBING,
    RELATED_SUSPICIOUS_ACTIVITY,
)


def match_pattern(detector_ids: Collection[str]) -> IncidentPattern:
    return next(pattern for pattern in PATTERNS if pattern.matches(detector_ids))
