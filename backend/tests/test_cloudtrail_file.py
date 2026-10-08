"""Loader behaviour: valid CloudTrail files load; anything malformed fails loudly."""

import gzip
from pathlib import Path

import pytest

from app.collectors import cloudtrail_file
from app.collectors.cloudtrail_file import (
    CloudTrailFileError,
    load_cloudtrail_file,
    parse_cloudtrail_json,
)


def write(tmp_path: Path, content: str) -> Path:
    path = tmp_path / "trail.json"
    path.write_text(content, encoding="utf-8")
    return path


# --- valid input ------------------------------------------------------------


@pytest.mark.parametrize(
    ("filename", "expected_count"),
    [
        ("normal-user-activity.json", 7),
        ("iam-privilege-change.json", 7),
        ("cloudtrail-disabled.json", 4),
    ],
)
def test_loads_sample_fixtures(
    cloudtrail_samples_dir: Path, filename: str, expected_count: int
) -> None:
    records = load_cloudtrail_file(cloudtrail_samples_dir / filename)

    assert len(records) == expected_count
    assert all(isinstance(record, dict) for record in records)


def test_records_are_returned_unmodified(tmp_path: Path) -> None:
    # The loader must not reshape raw evidence; normalization happens later.
    path = write(tmp_path, '{"Records": [{"eventName": "ListBuckets", "custom": {"x": [1, 2]}}]}')

    assert load_cloudtrail_file(path) == [{"eventName": "ListBuckets", "custom": {"x": [1, 2]}}]


def test_empty_records_list_is_valid(tmp_path: Path) -> None:
    assert load_cloudtrail_file(write(tmp_path, '{"Records": []}')) == []


def test_extra_top_level_keys_are_tolerated(tmp_path: Path) -> None:
    path = write(tmp_path, '{"Records": [{"eventName": "X"}], "note": "ignored"}')

    assert load_cloudtrail_file(path) == [{"eventName": "X"}]


# --- malformed envelope -----------------------------------------------------


@pytest.mark.parametrize(
    ("content", "expected_message"),
    [
        ("", "invalid JSON"),
        ('{"Records": [', "invalid JSON"),
        ("[]", "top level must be a JSON object, got list"),
        ('"just a string"', "top level must be a JSON object, got str"),
        ("{}", 'missing "Records" key'),
        ('{"records": []}', 'missing "Records" key'),
        ('{"Records": {"eventName": "X"}}', '"Records" must be a list, got dict'),
        ('{"Records": null}', '"Records" must be a list, got NoneType'),
        ('{"Records": [{"eventName": "X"}, "oops"]}', "Records[1] must be a JSON object, got str"),
        ('{"Records": [null]}', "Records[0] must be a JSON object, got NoneType"),
    ],
)
def test_malformed_envelope_is_rejected(
    tmp_path: Path, content: str, expected_message: str
) -> None:
    with pytest.raises(CloudTrailFileError, match="trail.json") as excinfo:
        load_cloudtrail_file(write(tmp_path, content))

    assert expected_message in str(excinfo.value)


def test_digest_file_shape_is_rejected(tmp_path: Path) -> None:
    # CloudTrail digest files live alongside logs but are not event files.
    digest = '{"awsAccountId": "123456789012", "digestStartTime": "2026-10-06T00:00:00Z"}'

    with pytest.raises(CloudTrailFileError, match='missing "Records" key'):
        load_cloudtrail_file(write(tmp_path, digest))


# --- ambiguous or hostile input ---------------------------------------------


def test_duplicate_keys_are_rejected(tmp_path: Path) -> None:
    content = '{"Records": [{"eventName": "ListBuckets", "eventName": "StopLogging"}]}'

    with pytest.raises(CloudTrailFileError, match="duplicate key 'eventName'"):
        load_cloudtrail_file(write(tmp_path, content))


@pytest.mark.parametrize("constant", ["NaN", "Infinity", "-Infinity"])
def test_non_standard_json_constants_are_rejected(tmp_path: Path, constant: str) -> None:
    content = f'{{"Records": [{{"eventName": "X", "value": {constant}}}]}}'

    with pytest.raises(CloudTrailFileError, match="non-standard JSON constant"):
        load_cloudtrail_file(write(tmp_path, content))


def test_non_utf8_file_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "trail.json"
    path.write_bytes(b'{"Records": [{"eventName": "\xff\xfe"}]}')

    with pytest.raises(CloudTrailFileError, match="not valid UTF-8"):
        load_cloudtrail_file(path)


def test_gzip_file_is_rejected_not_misread(tmp_path: Path) -> None:
    # Real S3 delivery is gzipped, which this loader does not decompress.
    # A gzip file must fail clearly instead of being parsed as garbage.
    path = tmp_path / "trail.json.gz"
    path.write_bytes(gzip.compress(b'{"Records": []}'))

    with pytest.raises(CloudTrailFileError):
        load_cloudtrail_file(path)


def test_oversized_file_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cloudtrail_file, "MAX_FILE_BYTES", 10)

    with pytest.raises(CloudTrailFileError, match="limit is 10"):
        load_cloudtrail_file(write(tmp_path, '{"Records": []}'))


def test_missing_file_raises_file_not_found(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        load_cloudtrail_file(tmp_path / "does-not-exist.json")


def test_parse_reports_the_given_source_name() -> None:
    with pytest.raises(CloudTrailFileError, match="^s3://bucket/key.json: "):
        parse_cloudtrail_json("[]", source="s3://bucket/key.json")
