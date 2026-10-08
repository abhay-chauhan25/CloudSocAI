"""Contract tests for the synthetic CloudTrail fixtures.

Later detector and normalizer tests depend on these fixtures, so the
scenarios they encode — and their safety — are pinned down here.
"""

import ipaddress
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from app.collectors.cloudtrail_file import RawRecord, load_cloudtrail_file

FIXTURE_FILES = [
    "normal-user-activity.json",
    "iam-privilege-change.json",
    "cloudtrail-disabled.json",
]

# Fields every fixture record must carry, as real management events do.
REQUIRED_FIELDS = [
    "eventVersion",
    "userIdentity",
    "eventTime",
    "eventSource",
    "eventName",
    "awsRegion",
    "sourceIPAddress",
    "eventID",
    "eventType",
    "recipientAccountId",
]

# Values reserved for documentation, so fixtures can never reference real
# accounts, networks, or credentials. See docs/cloudtrail.md.
EXAMPLE_ACCOUNT_ID = "123456789012"
DOCUMENTATION_NETWORKS = [
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
]


REPO_ROOT = Path(__file__).resolve().parents[2]

# Long-term (AKIA) and temporary (ASIA) AWS access key IDs are 20 characters.
AWS_KEY_ID_PATTERN = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")
SCANNED_DIRECTORIES = ["sample-data", "backend/app", "backend/tests", "backend/migrations", "docs"]
SCANNED_SUFFIXES = {".json", ".py", ".md", ".log", ".txt", ".yml", ".yaml", ".toml", ".ini"}


def is_documentation_style_key_id(key_id: str) -> bool:
    return len(key_id) == 20 and key_id.endswith("EXAMPLE")


def repository_text_files() -> list[Path]:
    root_files = [p for p in REPO_ROOT.iterdir() if p.is_file() and p.suffix in SCANNED_SUFFIXES]
    nested = [
        path
        for directory in SCANNED_DIRECTORIES
        for path in (REPO_ROOT / directory).rglob("*")
        if path.is_file() and path.suffix in SCANNED_SUFFIXES
    ]
    return root_files + nested


def load(samples_dir: Path, filename: str) -> list[RawRecord]:
    return load_cloudtrail_file(samples_dir / filename)


def all_records(samples_dir: Path) -> list[RawRecord]:
    return [record for name in FIXTURE_FILES for record in load(samples_dir, name)]


def values_for_key(node: Any, key: str) -> Iterator[Any]:
    """Yield every value stored under ``key`` anywhere in a nested structure."""
    if isinstance(node, dict):
        for child_key, child in node.items():
            if child_key == key:
                yield child
            yield from values_for_key(child, key)
    elif isinstance(node, list):
        for child in node:
            yield from values_for_key(child, key)


def find(records: list[RawRecord], event_name: str) -> list[RawRecord]:
    return [record for record in records if record["eventName"] == event_name]


# --- structure --------------------------------------------------------------


@pytest.mark.parametrize("filename", FIXTURE_FILES)
def test_every_record_has_required_fields(cloudtrail_samples_dir: Path, filename: str) -> None:
    for record in load(cloudtrail_samples_dir, filename):
        missing = [field for field in REQUIRED_FIELDS if field not in record]
        assert not missing, f"{record.get('eventID')} is missing {missing}"
        assert "type" in record["userIdentity"]


def test_event_ids_are_unique_across_fixtures(cloudtrail_samples_dir: Path) -> None:
    event_ids = [record["eventID"] for record in all_records(cloudtrail_samples_dir)]

    assert len(event_ids) == len(set(event_ids))


def test_failed_calls_have_error_details(cloudtrail_samples_dir: Path) -> None:
    failed = [r for r in all_records(cloudtrail_samples_dir) if "errorCode" in r]

    assert {r["errorCode"] for r in failed} == {"AccessDenied", "Client.UnauthorizedOperation"}
    assert all(r["errorMessage"] for r in failed)
    assert all(r["responseElements"] is None for r in failed)


# --- safety: synthetic identifiers only -------------------------------------


def test_only_the_example_account_id_is_used(cloudtrail_samples_dir: Path) -> None:
    records = all_records(cloudtrail_samples_dir)
    account_ids = {
        value
        for key in ("accountId", "recipientAccountId")
        for value in values_for_key(records, key)
    }

    assert account_ids == {EXAMPLE_ACCOUNT_ID}


def test_source_ips_are_documentation_addresses_or_service_names(
    cloudtrail_samples_dir: Path,
) -> None:
    for record in all_records(cloudtrail_samples_dir):
        source = record["sourceIPAddress"]
        if source.endswith(".amazonaws.com") or source == "AWS Internal":
            continue
        address = ipaddress.ip_address(source)
        assert any(address in network for network in DOCUMENTATION_NETWORKS), source


def test_access_key_ids_are_obviously_fake(cloudtrail_samples_dir: Path) -> None:
    key_ids = list(values_for_key(all_records(cloudtrail_samples_dir), "accessKeyId"))

    assert key_ids, "expected fixtures to contain access key IDs"
    for key_id in key_ids:
        assert key_id == "" or is_documentation_style_key_id(key_id), key_id


def test_no_realistic_key_ids_anywhere_in_the_repository() -> None:
    # Secret scanners (e.g. GitHub's) flag any string shaped like a real AWS
    # key ID. Fake IDs must follow AWS's documentation style — ending in
    # EXAMPLE — so they are both obviously fake and ignored by scanners.
    offenders = [
        f"{path.relative_to(REPO_ROOT)}: {match}"
        for path in repository_text_files()
        for match in AWS_KEY_ID_PATTERN.findall(path.read_text(encoding="utf-8"))
        if not is_documentation_style_key_id(match)
    ]

    assert offenders == []


# --- scenarios that later detector tests rely on ----------------------------


def test_normal_activity_attaches_only_a_non_admin_policy(cloudtrail_samples_dir: Path) -> None:
    records = load(cloudtrail_samples_dir, "normal-user-activity.json")

    policies = [r["requestParameters"]["policyArn"] for r in find(records, "AttachUserPolicy")]
    assert policies == ["arn:aws:iam::aws:policy/ReadOnlyAccess"]
    assert all(r["userIdentity"]["type"] != "Root" for r in records)


def test_iam_scenario_creates_backdoor_admin(cloudtrail_samples_dir: Path) -> None:
    records = load(cloudtrail_samples_dir, "iam-privilege-change.json")

    [create_key] = find(records, "CreateAccessKey")
    [attach] = find(records, "AttachUserPolicy")
    assert create_key["requestParameters"]["userName"] == "svc-backup"
    assert attach["requestParameters"] == {
        "userName": "svc-backup",
        "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
    }
    assert {r["sourceIPAddress"] for r in records} == {"203.0.113.50"}


def test_tampering_scenario_is_root_without_mfa(cloudtrail_samples_dir: Path) -> None:
    records = load(cloudtrail_samples_dir, "cloudtrail-disabled.json")

    assert all(r["userIdentity"]["type"] == "Root" for r in records)
    [login] = find(records, "ConsoleLogin")
    assert login["additionalEventData"]["MFAUsed"] == "No"
    assert [r["eventName"] for r in records if not r["readOnly"]] == [
        "ConsoleLogin",
        "StopLogging",
        "DeleteTrail",
    ]
