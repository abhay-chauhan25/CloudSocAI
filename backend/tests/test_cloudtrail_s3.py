"""Reading CloudTrail logs from S3, against stubbed AWS responses (no network, no account)."""

import gzip
import io
import json
from collections.abc import Iterator
from datetime import UTC, date, datetime
from pathlib import Path

import boto3
import pytest
from botocore import UNSIGNED
from botocore.client import BaseClient
from botocore.config import Config
from botocore.exceptions import NoCredentialsError
from botocore.response import StreamingBody
from botocore.stub import Stubber
from sqlalchemy import URL, Engine, text

from app import ingest_s3
from app.collectors import cloudtrail_s3
from app.collectors.aws import AwsAccessError, describe_aws_error
from app.collectors.cloudtrail_file import CloudTrailFileError
from app.collectors.cloudtrail_s3 import (
    LogLocation,
    gunzip_capped,
    list_log_keys,
    read_log_object,
)
from app.db import create_db_engine

BUCKET = "cloudsoc-lab-trail-logs-example"
PREFIX = "AWSLogs/123456789012/CloudTrail/us-east-1/2026/10/06/"
LOG_KEY = PREFIX + "123456789012_CloudTrail_us-east-1_20261006T0305Z_EXAMPLE.json.gz"


@pytest.fixture
def s3() -> BaseClient:
    # Unsigned and stubbed: no credentials are looked up and no request leaves the process.
    return boto3.Session(region_name="us-east-1").client(
        "s3", config=Config(signature_version=UNSIGNED)
    )


@pytest.fixture
def stub(s3: BaseClient) -> Iterator[Stubber]:
    with Stubber(s3) as stubber:
        yield stubber
        stubber.assert_no_pending_responses()


def listing_page(keys: list[str], next_page: str | None = None) -> dict:
    page: dict = {
        "Contents": [
            {"Key": key, "Size": 100, "LastModified": datetime(2026, 10, 6, tzinfo=UTC)}
            for key in keys
        ],
        "IsTruncated": next_page is not None,
    }
    if next_page:
        page["NextContinuationToken"] = next_page
    return page


def object_response(data: bytes) -> dict:
    return {"Body": StreamingBody(io.BytesIO(data), len(data)), "ContentLength": len(data)}


def sample_log(cloudtrail_samples_dir: Path) -> bytes:
    return gzip.compress((cloudtrail_samples_dir / "cloudtrail-disabled.json").read_bytes())


# --- where logs live ------------------------------------------------------------


def test_day_prefix_follows_cloudtrail_key_layout() -> None:
    location = LogLocation(BUCKET, "123456789012", "us-east-1")

    assert location.day_prefix(date(2026, 10, 6)) == PREFIX


def test_day_prefix_includes_trail_prefix_and_organization() -> None:
    location = LogLocation(
        BUCKET, "123456789012", "eu-west-2", prefix="/lab/", organization_id="o-exampleorg1"
    )

    assert location.day_prefix(date(2026, 10, 6)) == (
        "lab/AWSLogs/o-exampleorg1/123456789012/CloudTrail/eu-west-2/2026/10/06/"
    )


@pytest.mark.parametrize(
    ("account_id", "region", "organization_id"),
    [
        ("12345678901", "us-east-1", None),  # 11 digits
        ("123456789012/..", "us-east-1", None),  # path tricks
        ("123456789012", "us-east", None),
        ("123456789012", "us-east-1", "org-1"),
    ],
)
def test_location_rejects_invalid_identifiers(
    account_id: str, region: str, organization_id: str | None
) -> None:
    with pytest.raises(ValueError):
        LogLocation(BUCKET, account_id, region, organization_id=organization_id)


# --- listing --------------------------------------------------------------------


def test_listing_follows_pages_and_reports_non_log_objects(s3: BaseClient, stub: Stubber) -> None:
    first, second = PREFIX + "a.json.gz", PREFIX + "b.json.gz"
    stub.add_response(
        "list_objects_v2",
        listing_page([first, PREFIX + "notes.txt"], next_page="page-2"),
        {"Bucket": BUCKET, "Prefix": PREFIX},
    )
    stub.add_response(
        "list_objects_v2",
        listing_page([second]),
        {"Bucket": BUCKET, "Prefix": PREFIX, "ContinuationToken": "page-2"},
    )

    listing = list_log_keys(s3, BUCKET, PREFIX, max_objects=10)

    assert listing.keys == [first, second]
    assert listing.skipped == [PREFIX + "notes.txt"]
    assert listing.truncated is False


def test_listing_stops_at_max_objects(s3: BaseClient, stub: Stubber) -> None:
    keys = [PREFIX + f"{n}.json.gz" for n in range(3)]
    stub.add_response("list_objects_v2", listing_page(keys), {"Bucket": BUCKET, "Prefix": PREFIX})

    listing = list_log_keys(s3, BUCKET, PREFIX, max_objects=2)

    assert listing.keys == keys[:2]
    assert listing.truncated is True


def test_empty_day_lists_nothing(s3: BaseClient, stub: Stubber) -> None:
    stub.add_response(
        "list_objects_v2", {"IsTruncated": False}, {"Bucket": BUCKET, "Prefix": PREFIX}
    )

    assert list_log_keys(s3, BUCKET, PREFIX, max_objects=10).keys == []


def test_listing_access_denied_is_explained(s3: BaseClient, stub: Stubber) -> None:
    stub.add_client_error("list_objects_v2", "AccessDenied", http_status_code=403)

    with pytest.raises(AwsAccessError, match="access denied calling ListObjectsV2"):
        list_log_keys(s3, BUCKET, PREFIX, max_objects=10)


# --- reading objects ------------------------------------------------------------


def test_reads_and_parses_a_gzip_log(
    s3: BaseClient, stub: Stubber, cloudtrail_samples_dir: Path
) -> None:
    data = sample_log(cloudtrail_samples_dir)
    stub.add_response("get_object", object_response(data), {"Bucket": BUCKET, "Key": LOG_KEY})

    records = read_log_object(s3, BUCKET, LOG_KEY)

    expected = json.loads((cloudtrail_samples_dir / "cloudtrail-disabled.json").read_text())
    assert records == expected["Records"]


def test_uncompressed_object_is_rejected(s3: BaseClient, stub: Stubber) -> None:
    stub.add_response("get_object", object_response(b'{"Records": []}'))

    with pytest.raises(CloudTrailFileError, match="not gzip-compressed"):
        read_log_object(s3, BUCKET, LOG_KEY)


def test_oversized_object_is_not_downloaded(
    s3: BaseClient, stub: Stubber, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(cloudtrail_s3, "MAX_FILE_BYTES", 10)
    stub.add_response("get_object", object_response(b"x" * 11))

    with pytest.raises(CloudTrailFileError, match="limit is 10"):
        read_log_object(s3, BUCKET, LOG_KEY)


def test_invalid_log_inside_gzip_is_rejected(s3: BaseClient, stub: Stubber) -> None:
    stub.add_response("get_object", object_response(gzip.compress(b'{"Records": {}}')))

    with pytest.raises(CloudTrailFileError, match='"Records" must be a list'):
        read_log_object(s3, BUCKET, LOG_KEY)


def test_get_object_access_denied_is_explained(s3: BaseClient, stub: Stubber) -> None:
    stub.add_client_error("get_object", "AccessDenied", http_status_code=403)

    with pytest.raises(AwsAccessError, match=f"s3://{BUCKET}/{LOG_KEY}: access denied"):
        read_log_object(s3, BUCKET, LOG_KEY)


def test_decompression_bomb_is_stopped() -> None:
    bomb = gzip.compress(b"\0" * 10_000)  # ~30 bytes that expand 300-fold

    with pytest.raises(CloudTrailFileError, match="decompresses to more than 1000 bytes"):
        gunzip_capped(bomb, "test", limit=1000)


def test_truncated_and_trailing_gzip_data_are_rejected() -> None:
    data = gzip.compress(b'{"Records": []}')

    with pytest.raises(CloudTrailFileError, match="truncated"):
        gunzip_capped(data[:-10], "test")
    with pytest.raises(CloudTrailFileError, match="unexpected data"):
        gunzip_capped(data + b"extra", "test")


def test_missing_credentials_message_is_actionable() -> None:
    assert "--profile" in describe_aws_error(NoCredentialsError())


# --- the ingest_s3 command ------------------------------------------------------


class FakeSession:
    def __init__(self, client: BaseClient) -> None:
        self._client = client

    def client(self, service: str) -> BaseClient:
        assert service == "s3"
        return self._client


ARGS = ["--bucket", BUCKET, "--account-id", "123456789012", "--region", "us-east-1"]
ARGS += ["--date", "2026-10-06"]


@pytest.mark.db
def test_command_ingests_logs_and_skips_duplicates_on_rerun(
    s3: BaseClient,
    stub: Stubber,
    db_engine: Engine,
    test_database_url: URL,
    cloudtrail_samples_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.setattr(ingest_s3, "create_session", lambda profile, region: FakeSession(s3))
    monkeypatch.setattr(ingest_s3, "create_db_engine", lambda: create_db_engine(test_database_url))
    data = sample_log(cloudtrail_samples_dir)
    for _ in range(2):
        stub.add_response(
            "list_objects_v2", listing_page([LOG_KEY]), {"Bucket": BUCKET, "Prefix": PREFIX}
        )
        stub.add_response("get_object", object_response(data), {"Bucket": BUCKET, "Key": LOG_KEY})

    try:
        with caplog.at_level("INFO"):
            assert ingest_s3.main(ARGS) == ingest_s3.EXIT_OK
            assert ingest_s3.main(ARGS) == ingest_s3.EXIT_OK
        with db_engine.connect() as connection:
            stored = connection.scalar(text("SELECT count(*) FROM events"))
    finally:
        with db_engine.begin() as connection:
            connection.execute(text("TRUNCATE events CASCADE"))

    sample = json.loads((cloudtrail_samples_dir / "cloudtrail-disabled.json").read_text())
    records = len(sample["Records"])
    assert stored == records
    assert f"s3://{BUCKET}/{LOG_KEY}: {records} records, {records} stored" in caplog.text
    assert f"{records} records, 0 stored, {records} duplicates skipped" in caplog.text


@pytest.mark.db
def test_command_continues_past_a_bad_object(
    s3: BaseClient,
    stub: Stubber,
    db_engine: Engine,
    test_database_url: URL,
    cloudtrail_samples_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(ingest_s3, "create_session", lambda profile, region: FakeSession(s3))
    monkeypatch.setattr(ingest_s3, "create_db_engine", lambda: create_db_engine(test_database_url))
    bad_key = PREFIX + "corrupt.json.gz"
    stub.add_response("list_objects_v2", listing_page([bad_key, LOG_KEY]))
    stub.add_response("get_object", object_response(b"\x1f\x8bnot really gzip"))
    stub.add_response("get_object", object_response(sample_log(cloudtrail_samples_dir)))

    try:
        assert ingest_s3.main(ARGS) == ingest_s3.EXIT_PROBLEMS
        with db_engine.connect() as connection:
            stored = connection.scalar(text("SELECT count(*) FROM events"))
    finally:
        with db_engine.begin() as connection:
            connection.execute(text("TRUNCATE events CASCADE"))

    assert stored > 0


def test_command_stops_when_listing_is_denied(
    s3: BaseClient, stub: Stubber, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ingest_s3, "create_session", lambda profile, region: FakeSession(s3))
    monkeypatch.setattr(ingest_s3, "create_db_engine", lambda: _NoDatabase())
    stub.add_client_error("list_objects_v2", "AccessDenied", http_status_code=403)

    assert ingest_s3.main(ARGS) == ingest_s3.EXIT_AWS_UNAVAILABLE


@pytest.mark.parametrize("extra", [["--account-id", "not-an-account"], ["--max-objects", "0"]])
def test_command_rejects_invalid_arguments(extra: list[str]) -> None:
    assert ingest_s3.main(ARGS + extra) == ingest_s3.EXIT_INVALID_ARGUMENTS


class _NoDatabase:
    """Stands in for an engine in tests that fail before touching the database."""

    def dispose(self) -> None:
        pass
