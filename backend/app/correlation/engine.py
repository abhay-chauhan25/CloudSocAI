"""Group findings into incidents: same actor, close together in time.

Pure logic with no database access: it receives the open incidents and the
findings not yet in any incident, and decides which findings join which
incident and which new incidents to create.
"""

from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from app.correlation.patterns import match_pattern
from app.schemas.finding import Finding, Severity, StoredFinding
from app.schemas.incident import Incident, make_incident_id
from app.schemas.risk import RiskAssessment, RiskFactor

# Findings by the same actor at most this far apart belong to one incident.
CORRELATION_WINDOW = timedelta(hours=1)
# A single finding becomes an incident on its own only if it is this serious.
STANDALONE_MIN_SEVERITY = Severity.HIGH
STANDALONE_MIN_RISK = 60
# Each additional, independent rule in an incident corroborates the story.
CORROBORATING_RULE_POINTS = 5


@dataclass
class IncidentGroup:
    """Findings that belong together, and the incident they already form, if any."""

    findings: list[StoredFinding]
    existing: Incident | None = None
    added: list[StoredFinding] = field(default_factory=list)

    @property
    def first_seen(self) -> datetime:
        return min(f.finding.first_seen for f in self.findings)

    @property
    def last_seen(self) -> datetime:
        return max(f.finding.last_seen for f in self.findings)

    def is_close_to(self, finding: Finding, window: timedelta) -> bool:
        return (
            finding.first_seen <= self.last_seen + window
            and finding.last_seen >= self.first_seen - window
        )


def correlation_key(finding: Finding) -> str | None:
    """The actor whose findings are grouped. Findings with no actor are not correlated."""
    return finding.principal_arn or finding.principal


def group_findings(
    open_incidents: Sequence[tuple[Incident, list[StoredFinding]]],
    unassigned: Sequence[StoredFinding],
    window: timedelta = CORRELATION_WINDOW,
) -> list[IncidentGroup]:
    """Assign each unassigned finding to an open incident or a new group.

    Returns only the groups that changed. Findings are processed in time
    order, so a chain of findings each within the window of the previous
    one forms a single group.
    """
    groups_by_actor: defaultdict[str, list[IncidentGroup]] = defaultdict(list)
    for incident, findings in open_incidents:
        key = correlation_key(findings[0].finding)
        if key is not None:
            groups_by_actor[key].append(IncidentGroup(findings=list(findings), existing=incident))

    for stored in sorted(unassigned, key=lambda s: (s.finding.first_seen, s.finding.finding_id)):
        key = correlation_key(stored.finding)
        if key is None:
            continue
        group = next(
            (g for g in groups_by_actor[key] if g.is_close_to(stored.finding, window)), None
        )
        if group is None:
            group = IncidentGroup(findings=[])
            groups_by_actor[key].append(group)
        group.findings.append(stored)
        group.added.append(stored)

    return [group for groups in groups_by_actor.values() for group in groups if group.added]


def qualifies_as_incident(findings: Sequence[StoredFinding]) -> bool:
    """Two or more related findings, or one finding serious enough on its own."""
    if len(findings) >= 2:
        return True
    [only] = findings
    return (
        only.finding.severity.rank >= STANDALONE_MIN_SEVERITY.rank
        or only.risk.score >= STANDALONE_MIN_RISK
    )


def build_incident(findings: Sequence[StoredFinding], incident_id: str | None = None) -> Incident:
    """Describe a group of findings as an incident, recalculating everything from them."""
    ordered = sorted(findings, key=lambda s: (s.finding.first_seen, s.finding.finding_id))
    first = ordered[0].finding
    detector_ids = {s.finding.detector_id for s in ordered}
    pattern = match_pattern(detector_ids)
    principal = first.principal or "unknown actor"
    first_seen = min(s.finding.first_seen for s in ordered)
    last_seen = max(s.finding.last_seen for s in ordered)

    rules = ", ".join(sorted(detector_ids))
    summary = (
        f"{len(ordered)} finding(s) for {principal!r} between {first_seen:%Y-%m-%d %H:%M:%S}Z "
        f"and {last_seen:%H:%M:%S}Z from {len(detector_ids)} rule(s): {rules}. "
        f"{pattern.description}"
    )
    return Incident(
        incident_id=incident_id or make_incident_id(first.finding_id),
        pattern_id=pattern.pattern_id,
        title=f"{pattern.title}: {principal}",
        summary=summary,
        severity=max((s.finding.severity for s in ordered), key=lambda sev: sev.rank),
        risk=incident_risk(ordered),
        first_seen=first_seen,
        last_seen=last_seen,
        account_id=first.account_id,
        principal=first.principal,
        principal_arn=first.principal_arn,
        finding_ids=tuple(s.finding.finding_id for s in ordered),
    )


def incident_risk(findings: Sequence[StoredFinding]) -> RiskAssessment:
    """Highest finding risk, plus points for each additional rule that fired.

    Summing every finding's score would reach 100 almost immediately and
    stop meaning anything; instead, the worst finding sets the level and
    independent corroborating rules raise it.
    """
    top = max(findings, key=lambda s: (s.risk.score, s.finding.severity.rank))
    factors = [
        RiskFactor(
            name="Highest finding risk",
            points=top.risk.score,
            explanation=f"{top.finding.title} ({top.finding.detector_id}) scored {top.risk.score}.",
        )
    ]
    counts: defaultdict[str, int] = defaultdict(int)
    for stored in findings:
        counts[stored.finding.detector_id] += 1
    for detector_id in sorted(counts):
        if detector_id == top.finding.detector_id:
            continue
        factors.append(
            RiskFactor(
                name=f"Corroborating rule: {detector_id}",
                points=CORROBORATING_RULE_POINTS,
                explanation=(
                    f"{counts[detector_id]} finding(s) from {detector_id} by the same actor "
                    "within the correlation window."
                ),
            )
        )
    return RiskAssessment.from_factors(factors)
