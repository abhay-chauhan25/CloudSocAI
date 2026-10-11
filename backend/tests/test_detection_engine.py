"""The registry and engine: every rule runs over the fixtures with the expected results."""

import logging
import re
from collections import Counter
from collections.abc import Sequence
from pathlib import Path

import pytest

from app.collectors.cloudtrail_file import load_cloudtrail_file
from app.detection.base import Detector
from app.detection.engine import run_detectors
from app.detection.registry import DEFAULT_DETECTORS, check_unique_ids
from app.detection.rules.iam import IamUserCreated
from app.normalization.cloudtrail import normalize_cloudtrail_records
from app.schemas.event import Event
from app.schemas.finding import Finding, Severity

FIXTURE_FILES = [
    "normal-user-activity.json",
    "iam-privilege-change.json",
    "cloudtrail-disabled.json",
    "failed-api-burst.json",
]
MITRE_TECHNIQUE_ID = r"^T\d{4}(\.\d{3})?$"


def events_from(samples_dir: Path, *filenames: str) -> list[Event]:
    events: list[Event] = []
    for name in filenames:
        result = normalize_cloudtrail_records(load_cloudtrail_file(samples_dir / name))
        assert result.errors == []
        events += result.events
    return events


def detector_counts(findings: list[Finding]) -> Counter[str]:
    return Counter(f.detector_id for f in findings)


# --- registry ------------------------------------------------------------------


def test_registry_has_the_eight_rules_with_complete_metadata() -> None:
    assert len(DEFAULT_DETECTORS) == 8
    for detector in DEFAULT_DETECTORS:
        assert detector.detector_id and detector.name and detector.description
        assert len(detector.rationale) > 50, detector.detector_id
        assert isinstance(detector.severity, Severity)
        for technique in detector.mitre_techniques:
            assert re.fullmatch(MITRE_TECHNIQUE_ID, technique), technique


def test_duplicate_detector_ids_are_rejected() -> None:
    with pytest.raises(ValueError, match="duplicate detector ID: iam-user-created"):
        check_unique_ids([IamUserCreated(), IamUserCreated()])


# --- engine over the fixtures --------------------------------------------------


def test_normal_activity_produces_no_findings(cloudtrail_samples_dir: Path) -> None:
    result = run_detectors(events_from(cloudtrail_samples_dir, "normal-user-activity.json"))

    assert result.findings == []
    assert result.failures == []


def test_iam_privilege_change_findings(cloudtrail_samples_dir: Path) -> None:
    result = run_detectors(events_from(cloudtrail_samples_dir, "iam-privilege-change.json"))

    assert [(f.detector_id, f.resource) for f in result.findings] == [
        ("iam-user-created", "svc-backup"),
        ("access-key-created", "svc-backup"),
        ("admin-policy-attached", "user 'svc-backup'"),
    ]
    assert {f.principal for f in result.findings} == {"developer"}


def test_cloudtrail_disabled_findings(cloudtrail_samples_dir: Path) -> None:
    result = run_detectors(events_from(cloudtrail_samples_dir, "cloudtrail-disabled.json"))

    assert detector_counts(result.findings) == {
        "root-account-use": 4,
        "console-login-without-mfa": 1,
        "cloudtrail-logging-stopped": 1,
        "cloudtrail-trail-deleted": 1,
    }
    [login] = [f for f in result.findings if f.detector_id == "console-login-without-mfa"]
    assert login.severity is Severity.HIGH  # root without MFA


def test_all_fixtures_together(cloudtrail_samples_dir: Path) -> None:
    result = run_detectors(events_from(cloudtrail_samples_dir, *FIXTURE_FILES))

    assert len(result.findings) == 11
    assert detector_counts(result.findings)["failed-call-burst"] == 1
    times = [f.first_seen for f in result.findings]
    assert times == sorted(times)


def test_detection_is_deterministic_and_order_independent(cloudtrail_samples_dir: Path) -> None:
    events = events_from(cloudtrail_samples_dir, *FIXTURE_FILES)

    forwards = run_detectors(events)
    backwards = run_detectors(list(reversed(events)))

    assert forwards.findings == backwards.findings


def test_every_finding_references_real_events(cloudtrail_samples_dir: Path) -> None:
    events = events_from(cloudtrail_samples_dir, *FIXTURE_FILES)
    known_ids = {e.event_id for e in events}

    for finding in run_detectors(events).findings:
        assert finding.event_ids
        assert set(finding.event_ids) <= known_ids


# --- failure isolation ---------------------------------------------------------


class BrokenDetector(Detector):
    detector_id = "broken"
    name = "Broken"
    description = "Always raises."
    rationale = "Used to test that one failing rule does not stop the others."
    severity = Severity.LOW
    mitre_techniques = ()

    def detect(self, events: Sequence[Event]) -> list[Finding]:
        raise RuntimeError("bug in rule")


def test_a_failing_detector_is_reported_and_others_still_run(
    cloudtrail_samples_dir: Path, caplog: pytest.LogCaptureFixture
) -> None:
    events = events_from(cloudtrail_samples_dir, "iam-privilege-change.json")

    with caplog.at_level(logging.ERROR):
        result = run_detectors(events, [BrokenDetector(), IamUserCreated()])

    assert [(f.detector_id, f.error) for f in result.failures] == [("broken", "RuntimeError")]
    assert detector_counts(result.findings) == {"iam-user-created": 1}
    assert "'broken' failed" in caplog.text
