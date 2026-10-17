"""The posture-check interface.

A detection rule judges what someone *did* (events). A posture check judges
how things *are* (configuration): a public bucket is a risk even if nobody
has touched it today. Checks are deterministic functions of one snapshot and
produce the same Finding type as rules, so storage, risk, the API, and the
dashboard treat both alike.
"""

from abc import ABC, abstractmethod
from typing import ClassVar, Literal

from app.posture.snapshot import PostureSnapshot
from app.schemas.finding import Finding, Severity, make_finding_id

Service = Literal["iam", "s3", "ec2", "cloudtrail"]


class MissingSection(Exception):
    """A check ran on a snapshot without the section it needs."""


def require[T](section: T | None) -> T:
    """The snapshot section a check needs. The engine skips checks whose
    section is missing, so this only fails if a check is called directly."""
    if section is None:
        raise MissingSection("snapshot section not collected")
    return section


class PostureCheck(ABC):
    check_id: ClassVar[str]  # stable and unique, e.g. "s3-public-access-not-blocked"
    name: ClassVar[str]
    description: ClassVar[str]  # what fails the check
    rationale: ClassVar[str]  # why it matters, and when it may be acceptable
    remediation: ClassVar[str]
    reference: ClassVar[str]  # the industry control it follows
    severity: ClassVar[Severity]
    service: ClassVar[Service]  # the snapshot section the check needs

    @abstractmethod
    def evaluate(self, snapshot: PostureSnapshot) -> list[Finding]:
        """Findings for every failing resource. Only called when the section exists."""

    def build_finding(
        self,
        snapshot: PostureSnapshot,
        *,
        resource: str,
        reason: str,
        severity: Severity | None = None,
    ) -> Finding:
        """A finding about one resource, dated when the snapshot was taken.

        The ID depends only on the check and the resource, so the same
        misconfiguration seen in every scan stays one finding, not one per scan.
        Posture findings have no actor and no evidence events: the evidence is
        the configuration quoted in the reason.
        """
        return Finding(
            finding_id=make_finding_id(self.check_id, [resource]),
            detector_id=self.check_id,
            title=self.name,
            severity=severity or self.severity,
            reason=reason,
            first_seen=snapshot.captured_at,
            last_seen=snapshot.captured_at,
            account_id=snapshot.account_id,
            principal=None,
            principal_arn=None,
            resource=resource,
            event_ids=(),
        )
