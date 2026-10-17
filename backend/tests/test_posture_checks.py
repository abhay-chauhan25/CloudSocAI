"""Posture checks: snapshot parsing, each check's positive and negative cases, and the engine."""

import copy
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from app.detection.registry import DETECTORS_BY_ID
from app.posture.base import MissingSection, PostureCheck, require
from app.posture.engine import run_posture_checks
from app.posture.registry import CHECKS_BY_ID, DEFAULT_CHECKS, check_unique_ids
from app.posture.snapshot import PostureSnapshot, SnapshotError, load_snapshot, parse_snapshot
from app.schemas.finding import Finding, Severity

SNAPSHOTS = Path(__file__).resolve().parents[2] / "sample-data" / "aws-config"


def raw(name: str) -> dict[str, Any]:
    return json.loads((SNAPSHOTS / f"{name}-account.json").read_text(encoding="utf-8"))


def changed(name: str, edit: Callable[[dict[str, Any]], object]) -> PostureSnapshot:
    """A fixture snapshot with one edit applied."""
    data = copy.deepcopy(raw(name))
    edit(data)
    return parse_snapshot(data)


def run(check_id: str, snapshot: PostureSnapshot) -> list[Finding]:
    return CHECKS_BY_ID[check_id].evaluate(snapshot)


@pytest.fixture(scope="module")
def insecure() -> PostureSnapshot:
    return load_snapshot(SNAPSHOTS / "insecure-account.json")


@pytest.fixture(scope="module")
def secure() -> PostureSnapshot:
    return load_snapshot(SNAPSHOTS / "secure-account.json")


# --- snapshot ------------------------------------------------------------------


def test_fixtures_parse_and_unknown_aws_fields_are_ignored(insecure: PostureSnapshot) -> None:
    assert insecure.account_id == "123456789012"
    assert insecure.iam is not None
    developer = insecure.iam.credential_report[1]
    # The fixture also has fields CloudSOC does not model, like password_last_used.
    assert (developer.user, developer.password_enabled, developer.mfa_active) == (
        "developer",
        True,
        False,
    )


def test_credential_report_text_cells_are_interpreted() -> None:
    snapshot = parse_snapshot(raw("insecure"))
    assert snapshot.iam is not None
    root = snapshot.iam.credential_report[0]

    assert root.is_root
    assert root.password_enabled is False  # "not_supported"
    assert root.access_key_2_last_rotated is None  # "N/A"


def test_a_snapshot_with_a_bad_account_id_is_rejected() -> None:
    data = raw("secure") | {"account_id": "12345"}

    with pytest.raises(SnapshotError, match="account_id"):
        parse_snapshot(data)


def test_a_snapshot_missing_a_required_aws_field_names_it() -> None:
    data = raw("secure")
    del data["iam"]["account_summary"]["AccountMFAEnabled"]

    with pytest.raises(SnapshotError, match="iam.account_summary.AccountMFAEnabled"):
        parse_snapshot(data)


def test_unreadable_and_non_json_files_are_snapshot_errors(tmp_path: Path) -> None:
    broken = tmp_path / "broken.json"
    broken.write_text("{not json", encoding="utf-8")

    with pytest.raises(SnapshotError, match="not valid JSON"):
        load_snapshot(broken)
    with pytest.raises(SnapshotError, match="cannot read"):
        load_snapshot(tmp_path / "missing.json")


# --- IAM -----------------------------------------------------------------------


def test_root_without_mfa(insecure: PostureSnapshot, secure: PostureSnapshot) -> None:
    [finding] = run("root-mfa-disabled", insecure)

    assert finding.severity == Severity.CRITICAL
    assert finding.resource == "arn:aws:iam::123456789012:root"
    assert run("root-mfa-disabled", secure) == []


def test_root_access_keys(insecure: PostureSnapshot, secure: PostureSnapshot) -> None:
    [finding] = run("root-access-keys-present", insecure)

    assert "AccountAccessKeysPresent = 1" in finding.reason
    assert run("root-access-keys-present", secure) == []


def test_only_console_users_without_mfa_are_flagged(insecure: PostureSnapshot) -> None:
    # developer: password, no MFA. ci-deploy: no password. admin-alice: MFA. root: excluded.
    findings = run("iam-user-console-without-mfa", insecure)

    assert [f.resource for f in findings] == ["arn:aws:iam::123456789012:user/developer"]


def test_console_user_check_passes_when_everyone_has_mfa(secure: PostureSnapshot) -> None:
    assert run("iam-user-console-without-mfa", secure) == []


def test_only_active_keys_older_than_90_days_are_flagged(insecure: PostureSnapshot) -> None:
    # developer key 1: 265 days, active. ci-deploy key 2: old but inactive.
    # root key: old and active, but reported by the root-access-keys check instead.
    [finding] = run("iam-access-key-not-rotated", insecure)

    assert finding.resource == "arn:aws:iam::123456789012:user/developer/access-key-1"
    assert "265 days" in finding.reason


@pytest.mark.parametrize(
    ("rotated", "flagged"), [("2026-07-10T09:00:00Z", False), ("2026-07-09T08:59:00Z", True)]
)
def test_key_age_boundary_is_90_days(rotated: str, flagged: bool) -> None:
    def edit(data: dict[str, Any]) -> None:
        data["iam"]["credential_report"][2]["access_key_1_last_rotated"] = rotated

    findings = run("iam-access-key-not-rotated", changed("secure", edit))

    assert bool(findings) is flagged


# --- S3 ------------------------------------------------------------------------


def test_buckets_without_full_block_public_access(insecure: PostureSnapshot) -> None:
    findings = run("s3-public-access-not-blocked", insecure)

    assert [f.resource for f in findings] == [
        "arn:aws:s3:::cloudsoc-public-reports",
        "arn:aws:s3:::cloudsoc-logs",
    ]
    assert "BlockPublicPolicy, RestrictPublicBuckets off" in findings[1].reason


def test_account_level_block_public_access_protects_every_bucket(secure: PostureSnapshot) -> None:
    # Neither bucket has its own setting; the account-wide one covers them.
    assert run("s3-public-access-not-blocked", secure) == []


def test_settings_combine_across_account_and_bucket() -> None:
    def edit(data: dict[str, Any]) -> None:
        data["s3"]["account_public_access_block"] |= {
            "BlockPublicAcls": False,
            "IgnorePublicAcls": False,
            "RestrictPublicBuckets": False,
        }
        data["s3"]["buckets"][0]["PublicAccessBlockConfiguration"] = {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": False,
            "BlockPublicPolicy": False,
            "RestrictPublicBuckets": True,
        }

    findings = run("s3-public-access-not-blocked", changed("secure", edit))

    # Only IgnorePublicAcls is off at both levels for the first bucket.
    assert "'cloudsoc-legacy-site': IgnorePublicAcls off" in findings[0].reason


def test_public_bucket_policy(insecure: PostureSnapshot) -> None:
    [finding] = run("s3-bucket-public", insecure)

    assert finding.severity == Severity.CRITICAL
    assert finding.resource == "arn:aws:s3:::cloudsoc-public-reports"


def test_restrict_public_buckets_neutralises_a_public_policy(secure: PostureSnapshot) -> None:
    # cloudsoc-legacy-site has a public policy, but the account restricts public buckets.
    assert run("s3-bucket-public", secure) == []


# --- EC2 -----------------------------------------------------------------------


def test_admin_ports_open_to_the_internet(insecure: PostureSnapshot) -> None:
    findings = run("sg-admin-port-open-to-internet", insecure)

    assert [f.resource.rsplit("/", 1)[-1] for f in findings if f.resource] == [
        "sg-0a1b2c3d4e5f60001",
        "sg-0a1b2c3d4e5f60003",
    ]
    assert "SSH (22) from 0.0.0.0/0" in findings[0].reason
    # All-protocol rule over IPv6 exposes both ports.
    assert "RDP (3389) from ::/0; SSH (22) from ::/0" in findings[1].reason


def test_restricted_or_non_admin_rules_pass(secure: PostureSnapshot) -> None:
    # SSH from an office range, and 80-443 from anywhere.
    assert run("sg-admin-port-open-to-internet", secure) == []


@pytest.mark.parametrize(
    ("permission", "flagged"),
    [
        ({"IpProtocol": "tcp", "FromPort": 0, "ToPort": 65535}, True),
        ({"IpProtocol": "6", "FromPort": 3389, "ToPort": 3389}, True),
        ({"IpProtocol": "udp", "FromPort": 22, "ToPort": 22}, False),
        ({"IpProtocol": "tcp", "FromPort": 23, "ToPort": 3388}, False),
    ],
    ids=["all-tcp-ports", "protocol-number", "udp", "range-between"],
)
def test_port_ranges_and_protocols(permission: dict[str, Any], flagged: bool) -> None:
    def edit(data: dict[str, Any]) -> None:
        data["ec2"]["security_groups"][0]["IpPermissions"] = [
            permission | {"IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
        ]

    assert bool(run("sg-admin-port-open-to-internet", changed("secure", edit))) is flagged


# --- CloudTrail ----------------------------------------------------------------


def test_a_single_region_trail_is_not_enough(insecure: PostureSnapshot) -> None:
    [finding] = run("cloudtrail-no-multi-region-logging", insecure)

    assert "management-events (multi-region: False, logging: True)" in finding.reason


def test_a_logging_multi_region_trail_passes(secure: PostureSnapshot) -> None:
    assert run("cloudtrail-no-multi-region-logging", secure) == []


@pytest.mark.parametrize(
    ("edit", "expected"),
    [
        (lambda d: d["cloudtrail"].update(trails=[], status={}), "no trails"),
        (lambda d: d["cloudtrail"].update(status={}), "logging: unknown"),
        (
            lambda d: d["cloudtrail"]["status"][
                "arn:aws:cloudtrail:us-east-1:123456789012:trail/organization-trail"
            ].update(IsLogging=False),
            "logging: False",
        ),
    ],
    ids=["no-trails", "status-unknown", "stopped"],
)
def test_missing_or_stopped_trails_are_flagged(edit: Callable, expected: str) -> None:
    [finding] = run("cloudtrail-no-multi-region-logging", changed("secure", edit))

    assert expected in finding.reason


def test_log_file_validation(insecure: PostureSnapshot, secure: PostureSnapshot) -> None:
    [finding] = run("cloudtrail-log-validation-disabled", insecure)

    assert finding.resource == "arn:aws:cloudtrail:us-east-1:123456789012:trail/management-events"
    assert run("cloudtrail-log-validation-disabled", secure) == []


# --- engine and registry -------------------------------------------------------


def test_the_insecure_account_fails_every_check_and_the_secure_one_none(
    insecure: PostureSnapshot, secure: PostureSnapshot
) -> None:
    bad, good = run_posture_checks(insecure), run_posture_checks(secure)

    assert len(bad.findings) == 11
    assert {f.detector_id for f in bad.findings} == set(CHECKS_BY_ID)
    assert (good.findings, len(good.passed)) == ([], len(DEFAULT_CHECKS))
    # Most severe first.
    assert [f.severity.rank for f in bad.findings] == sorted(
        (f.severity.rank for f in bad.findings), reverse=True
    )


def test_posture_findings_describe_configuration_not_activity(insecure: PostureSnapshot) -> None:
    finding = run_posture_checks(insecure).findings[0]

    assert finding.event_ids == ()
    assert (finding.principal, finding.principal_arn) == (None, None)
    assert finding.first_seen == finding.last_seen == insecure.captured_at
    assert finding.account_id == "123456789012"


def test_the_same_problem_keeps_the_same_id_in_a_later_snapshot(insecure: PostureSnapshot) -> None:
    later = insecure.model_copy(update={"captured_at": insecure.captured_at.replace(day=20)})

    first = {f.finding_id for f in run_posture_checks(insecure).findings}
    second = {f.finding_id for f in run_posture_checks(later).findings}

    assert first == second


def test_missing_sections_are_not_evaluated_rather_than_passed() -> None:
    partial = changed("insecure", lambda d: (d.pop("s3"), d.pop("ec2")))

    result = run_posture_checks(partial)

    assert sorted(result.not_evaluated) == [
        "s3-bucket-public",
        "s3-public-access-not-blocked",
        "sg-admin-port-open-to-internet",
    ]
    assert not set(result.not_evaluated) & set(result.passed)
    assert {f.detector_id for f in result.findings}.isdisjoint(result.not_evaluated)


class BrokenCheck(PostureCheck):
    check_id = "broken"
    name = description = rationale = remediation = reference = "broken"
    severity = Severity.LOW
    service = "iam"

    def evaluate(self, snapshot: PostureSnapshot) -> list[Finding]:
        raise KeyError("secret-looking configuration value")


def test_a_failing_check_is_reported_and_does_not_stop_the_others(
    insecure: PostureSnapshot,
) -> None:
    result = run_posture_checks(insecure, [BrokenCheck(), CHECKS_BY_ID["root-mfa-disabled"]])

    assert [(f.check_id, f.error) for f in result.failures] == [("broken", "KeyError")]
    assert [f.detector_id for f in result.findings] == ["root-mfa-disabled"]


def test_check_ids_are_unique_and_never_clash_with_rule_ids() -> None:
    assert set(CHECKS_BY_ID).isdisjoint(DETECTORS_BY_ID)
    with pytest.raises(ValueError, match="duplicate check ID: root-account-use"):
        clash = type("Clash", (BrokenCheck,), {"check_id": "root-account-use"})
        check_unique_ids([clash()])


def test_every_check_documents_itself() -> None:
    for check in DEFAULT_CHECKS:
        for text in (check.name, check.description, check.rationale, check.remediation):
            assert text.strip(), check.check_id
        assert check.reference.startswith("CIS AWS Foundations Benchmark: ")


def test_require_refuses_a_missing_section() -> None:
    with pytest.raises(MissingSection):
        require(None)
