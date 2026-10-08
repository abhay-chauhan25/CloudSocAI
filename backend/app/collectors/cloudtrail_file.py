"""Load raw CloudTrail records from local JSON log files.

CloudTrail delivers logs to S3 as files shaped like ``{"Records": [...]}``.
This module reads files of the same shape from disk, so the pipeline can run
on synthetic data before any AWS integration exists.

Records are returned as raw, *untrusted* dictionaries. This module only
enforces the file envelope; field-level validation is the normalizer's job.
Anything malformed or ambiguous is rejected with ``CloudTrailFileError``
rather than guessed at or silently skipped, because silently dropping
security telemetry hides exactly the events an investigation may need.
"""

import json
from pathlib import Path
from typing import Any

# Real CloudTrail log files are small (kilobytes to a few megabytes). The cap
# stops an accidental or malicious oversized file from exhausting memory,
# since the whole file is parsed in one go.
MAX_FILE_BYTES = 50 * 1024 * 1024

RawRecord = dict[str, Any]


class CloudTrailFileError(ValueError):
    """The input is not a valid CloudTrail log file."""


def load_cloudtrail_file(path: Path) -> list[RawRecord]:
    """Read a CloudTrail log file and return its raw records.

    Raises:
        FileNotFoundError: the file does not exist.
        CloudTrailFileError: the file is too large, not UTF-8, not valid JSON,
            or not shaped like a CloudTrail log file.
    """
    size = path.stat().st_size
    if size > MAX_FILE_BYTES:
        raise CloudTrailFileError(f"{path}: file is {size} bytes; limit is {MAX_FILE_BYTES}")

    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise CloudTrailFileError(f"{path}: file is not valid UTF-8") from exc

    return parse_cloudtrail_json(text, source=str(path))


def parse_cloudtrail_json(text: str, source: str) -> list[RawRecord]:
    """Parse CloudTrail log file content and return its raw records.

    Kept separate from file reading so the S3 collector can reuse it on
    downloaded, decompressed content. ``source`` names the input in errors.
    """
    try:
        document = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_non_standard_constant,
        )
    except (json.JSONDecodeError, CloudTrailFileError) as exc:
        raise CloudTrailFileError(f"{source}: invalid JSON: {exc}") from exc

    return _extract_records(document, source)


def _extract_records(document: Any, source: str) -> list[RawRecord]:
    if not isinstance(document, dict):
        raise CloudTrailFileError(
            f"{source}: top level must be a JSON object, got {type(document).__name__}"
        )
    if "Records" not in document:
        raise CloudTrailFileError(f'{source}: missing "Records" key')

    records = document["Records"]
    if not isinstance(records, list):
        raise CloudTrailFileError(
            f'{source}: "Records" must be a list, got {type(records).__name__}'
        )

    for index, record in enumerate(records):
        if not isinstance(record, dict):
            raise CloudTrailFileError(
                f"{source}: Records[{index}] must be a JSON object, got {type(record).__name__}"
            )
    return records


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    # Python's json module silently keeps the *last* duplicate key. Two parsers
    # disagreeing on which value wins is a known way to smuggle data past a
    # check, so ambiguous input is rejected instead.
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CloudTrailFileError(f"duplicate key {key!r}")
        result[key] = value
    return result


def _reject_non_standard_constant(name: str) -> None:
    # Python accepts NaN/Infinity by default, but they are not valid JSON.
    raise CloudTrailFileError(f"non-standard JSON constant {name!r}")
