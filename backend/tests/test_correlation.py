"""Correlation logic: grouping, qualification, patterns, risk, and timelines (no database)."""

from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from pathlib import Path

import pytest

from app.collectors.cloudtrail_file import load_cloudtrail_file
from app.correlation.engine import (
    CORRELATION_WINDOW,
    build_incident,
    group_findings,
    incident_risk,
    qualifies_as_incident,
)
from app.correlation.patterns import PATTERNS, match_pattern
from app.correlation.timeline import build_timeline
from app.detection.engine import run_detectors
from app.detection.registry import DEFAULT_DETECTORS
from app.normalization.cloudtrail import normalize_cloudtrail_records
from app.risk.scoring import RiskContext, score_finding
from app.schemas.event import Event, PrincipalType
from app.schemas.finding import (
    Finding,
    FindingStatus,
    Severity,
    StoredFinding,
    make_finding_id,
)
from app.schemas.incident import make_incident_id
from app.schemas.risk import RiskAssessment, RiskFactor

START = datetime(2026, 10, 6, 3, 0, tzinfo=UTC)
_counter = 0


def stored(
    detector_id: str = "iam-user-created",
    *,
    principal: str = "developer",
    at: datetime = START,
    severity: Severity = Severity.LOW,
    risk: int = 20,
) -> StoredFinding:
    global _counter
    _counter += 1
    finding = Finding(
        finding_id=make_finding_id(detector_id, [f"event-{_counter}"]),
        detector_id=detector_id,
        title=detector_id,
        severity=severity,
        reason="test",
        first_seen=at,
        last_seen=at,
        account_id="123456789012",
        principal=principal,
        principal_arn=f"arn:aws:iam::123456789012:user/{principal}",
        resource=None,
        event_ids=(f"event-{_counter}",),
    )
    assessment = RiskAssessment(
        score=risk, factors=(RiskFactor(name="Base", points=risk, explanation="test"),)
    )
    return StoredFinding(finding=finding, risk=assessment, status=FindingStatus.OPEN, created_at=at)


def finding_ids(findings: list[StoredFinding]) -> list[str]:
    return [f.finding.finding_id for f in findings]


# --- grouping ------------------------------------------------------------------


def test_same_actor_within_the_window_is_one_group() -> None:
    a = stored(at=START)
    b = stored("access-key-created", at=START + timedelta(minutes=50))

    [group] = group_findings([], [b, a])

    assert finding_ids(group.findings) == finding_ids([a, b])  # time order
    assert group.existing is None


def test_a_chain_of_close_findings_is_one_group_even_if_the_ends_are_far_apart() -> None:
    chain = [stored(at=START + timedelta(minutes=50 * i)) for i in range(4)]  # spans 2.5 h

    [group] = group_findings([], chain)

    assert len(group.findings) == 4


def test_a_gap_longer_than_the_window_splits_groups() -> None:
    early = stored(at=START)
    late = stored(at=START + CORRELATION_WINDOW + timedelta(seconds=1))

    groups = group_findings([], [early, late])

    assert [len(g.findings) for g in groups] == [1, 1]


def test_different_actors_are_never_grouped() -> None:
    groups = group_findings([], [stored(principal="alice"), stored(principal="bob")])

    assert len(groups) == 2


def test_new_finding_joins_an_open_incident() -> None:
    first, second = stored(at=START), stored("access-key-created", at=START + timedelta(minutes=5))
    incident = build_incident([first, second])
    newcomer = stored("admin-policy-attached", at=START + timedelta(minutes=30))

    [group] = group_findings([(incident, [first, second])], [newcomer])

    assert group.existing == incident
    assert finding_ids(group.added) == finding_ids([newcomer])
    assert len(group.findings) == 3


def test_unchanged_incidents_are_not_returned() -> None:
    first = stored(at=START)
    incident = build_incident([first])

    assert group_findings([(incident, [first])], []) == []


# --- qualification -------------------------------------------------------------


def test_two_related_findings_qualify() -> None:
    assert qualifies_as_incident([stored(), stored("access-key-created")])


@pytest.mark.parametrize(
    ("severity", "risk", "expected"),
    [
        (Severity.LOW, 20, False),
        (Severity.MEDIUM, 40, False),
        (Severity.MEDIUM, 60, True),  # risk high enough on its own
        (Severity.HIGH, 50, True),  # severity high enough on its own
        (Severity.CRITICAL, 80, True),
    ],
)
def test_single_finding_qualifies_only_if_serious(
    severity: Severity, risk: int, expected: bool
) -> None:
    assert qualifies_as_incident([stored(severity=severity, risk=risk)]) is expected


# --- patterns ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("detector_ids", "pattern_id"),
    [
        ({"cloudtrail-logging-stopped", "root-account-use"}, "audit-logging-tampered"),
        ({"iam-user-created", "access-key-created"}, "iam-persistence"),
        ({"access-key-created", "admin-policy-attached"}, "iam-persistence"),
        ({"iam-user-created"}, "related-suspicious-activity"),  # one IAM rule is not enough
        ({"root-account-use", "console-login-without-mfa"}, "root-account-activity"),
        ({"failed-call-burst"}, "credential-probing"),
        ({"console-login-without-mfa"}, "related-suspicious-activity"),
    ],
)
def test_pattern_selection(detector_ids: set[str], pattern_id: str) -> None:
    assert match_pattern(detector_ids).pattern_id == pattern_id


def test_patterns_only_reference_real_detectors() -> None:
    known = {d.detector_id for d in DEFAULT_DETECTORS}

    for pattern in PATTERNS:
        assert pattern.detector_ids <= known, pattern.pattern_id
    assert not PATTERNS[-1].detector_ids  # the last pattern is the catch-all


# --- incident risk -------------------------------------------------------------


def test_risk_is_the_top_finding_plus_five_per_other_rule() -> None:
    findings = [
        stored("admin-policy-attached", severity=Severity.HIGH, risk=80),
        stored("access-key-created", risk=60),
        stored("iam-user-created", risk=40),
        stored("iam-user-created", risk=40),  # same rule again adds nothing extra
    ]

    risk = incident_risk(findings)

    assert risk.score == 90
    assert [f.points for f in risk.factors] == [80, 5, 5]
    assert "2 finding(s) from iam-user-created" in risk.factors[2].explanation


def test_incident_risk_is_capped_at_100() -> None:
    rules = [f"rule-{i}" for i in range(10)]
    findings = [stored(rules[0], risk=80)] + [stored(rule, risk=10) for rule in rules[1:]]

    assert incident_risk(findings).score == 100


def test_incident_takes_highest_severity_and_a_stable_id() -> None:
    low = stored(at=START)
    high = stored("admin-policy-attached", at=START + timedelta(minutes=1), severity=Severity.HIGH)

    incident = build_incident([high, low])

    assert incident.severity is Severity.HIGH
    assert incident.incident_id == make_incident_id(low.finding.finding_id)
    assert incident.finding_ids == (low.finding.finding_id, high.finding.finding_id)
    assert incident.title == "Possible IAM persistence: developer"
    assert build_incident([low, high]) == incident


# --- over the fixtures ---------------------------------------------------------


def fixture_events(samples_dir: Path) -> list[Event]:
    events: list[Event] = []
    for path in sorted(samples_dir.glob("*.json")):
        events += normalize_cloudtrail_records(load_cloudtrail_file(path)).events
    return events


def test_fixtures_produce_three_incidents(cloudtrail_samples_dir: Path) -> None:
    events = fixture_events(cloudtrail_samples_dir)
    context = RiskContext.from_events(events)
    findings = [
        StoredFinding(
            finding=f, risk=score_finding(f, context), status=FindingStatus.OPEN, created_at=START
        )
        for f in run_detectors(events).findings
    ]

    incidents = [
        build_incident(group.findings)
        for group in group_findings([], findings)
        if qualifies_as_incident(group.findings)
    ]

    summary = sorted(
        (i.pattern_id, i.principal, i.risk.score, len(i.finding_ids)) for i in incidents
    )
    assert summary == [
        ("audit-logging-tampered", "root", 95, 7),
        ("credential-probing", "ci-deploy", 60, 1),
        ("iam-persistence", "developer", 90, 3),
    ]


# --- timeline ------------------------------------------------------------------


def make_event(event_id: str, at: datetime) -> Event:
    return Event(
        event_id=event_id,
        source="cloudtrail",
        timestamp=at,
        account_id="123456789012",
        service="iam",
        event_name="GetCallerIdentity",
        event_type="AwsApiCall",
        read_only=True,
        region="us-east-1",
        principal_type=PrincipalType.IAM_USER,
        principal="developer",
        principal_arn="arn:aws:iam::123456789012:user/developer",
        session_name=None,
        access_key_id=None,
        mfa_authenticated=None,
        source_address="203.0.113.50",
        source_ip=ip_address("203.0.113.50"),
        user_agent=None,
        success=True,
        error_code=None,
        error_message=None,
        request_parameters=None,
        raw_event={},
    )


def test_timeline_orders_events_and_marks_the_flagged_ones() -> None:
    finding = stored("iam-user-created", at=START + timedelta(minutes=2))
    flagged_id = finding.finding.event_ids[0]
    events = [
        make_event(flagged_id, START + timedelta(minutes=2)),
        make_event("recon", START),
    ]

    timeline = build_timeline([finding], events)

    assert [(e.event.event_id, e.detector_ids) for e in timeline] == [
        ("recon", ()),
        (flagged_id, ("iam-user-created",)),
    ]
