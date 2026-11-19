"""Read CloudTrail log files from the S3 bucket a trail delivers to.

CloudTrail writes one gzip-compressed JSON file every few minutes per
account and region, under a fixed key layout::

    [<prefix>/]AWSLogs/[<org-id>/]<account-id>/CloudTrail/<region>/YYYY/MM/DD/<file>.json.gz

so one day of one region's logs is a single S3 prefix. Digest files (used
for log file integrity validation) live under ``CloudTrail-Digest/`` and are
never listed.

Downloaded content is as untrusted as a local file: it goes through the
same envelope parser, with size limits on both the compressed and the
decompressed bytes so a crafted object cannot exhaust memory.
"""

import re
import zlib
from dataclasses import dataclass
from datetime import date

from botocore.client import BaseClient

from app.collectors.aws import AWS_ERRORS, AwsAccessError, describe_aws_error
from app.collectors.cloudtrail_file import (
    MAX_FILE_BYTES,
    CloudTrailFileError,
    RawRecord,
    parse_cloudtrail_json,
)

LOG_SUFFIX = ".json.gz"
GZIP_MAGIC = b"\x1f\x8b"

ACCOUNT_ID = re.compile(r"\d{12}")
REGION = re.compile(r"[a-z]{2}(-[a-z]+)+-\d")
ORGANIZATION_ID = re.compile(r"o-[a-z0-9]{10,32}")


@dataclass(frozen=True)
class LogLocation:
    """Where one trail's logs for one account and region are stored."""

    bucket: str
    account_id: str
    region: str
    prefix: str = ""  # the trail's optional S3 key prefix
    organization_id: str | None = None  # set for organization trails

    def __post_init__(self) -> None:
        # These values become part of an S3 prefix; validating them stops a
        # typo (or "../") from silently listing the wrong place.
        if not ACCOUNT_ID.fullmatch(self.account_id):
            raise ValueError(f"account ID must be 12 digits, got {self.account_id!r}")
        if not REGION.fullmatch(self.region):
            raise ValueError(f"not an AWS region name: {self.region!r}")
        if self.organization_id is not None and not ORGANIZATION_ID.fullmatch(self.organization_id):
            raise ValueError(f"not an organization ID: {self.organization_id!r}")

    def day_prefix(self, day: date) -> str:
        parts = ["AWSLogs", self.account_id, "CloudTrail", self.region, f"{day:%Y/%m/%d}"]
        if self.organization_id:
            parts.insert(1, self.organization_id)
        if self.prefix.strip("/"):
            parts.insert(0, self.prefix.strip("/"))
        return "/".join(parts) + "/"


@dataclass(frozen=True)
class LogListing:
    keys: list[str]  # log files, oldest first (file names start with a timestamp)
    skipped: list[str]  # other objects under the prefix, reported rather than read
    truncated: bool  # more log files exist than were returned


def list_log_keys(s3: BaseClient, bucket: str, prefix: str, max_objects: int) -> LogListing:
    """List the log files under ``prefix``, stopping after ``max_objects``.

    Raises:
        AwsAccessError: the listing failed (no credentials, access denied, ...).
    """
    keys: list[str] = []
    skipped: list[str] = []
    try:
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix):
            for item in page.get("Contents", []):
                key = item["Key"]
                if not key.endswith(LOG_SUFFIX):
                    skipped.append(key)
                elif len(keys) == max_objects:
                    return LogListing(keys, skipped, truncated=True)
                else:
                    keys.append(key)
    except AWS_ERRORS as exc:
        raise AwsAccessError(describe_aws_error(exc)) from exc
    return LogListing(keys, skipped, truncated=False)


def read_log_object(s3: BaseClient, bucket: str, key: str) -> list[RawRecord]:
    """Download, decompress, and parse one CloudTrail log file.

    Raises:
        AwsAccessError: the download failed.
        CloudTrailFileError: the object is too large, not gzip, not UTF-8,
            or not a valid CloudTrail log file.
    """
    source = f"s3://{bucket}/{key}"
    try:
        response = s3.get_object(Bucket=bucket, Key=key)
        size = response.get("ContentLength", 0)
        if size > MAX_FILE_BYTES:
            raise CloudTrailFileError(
                f"{source}: object is {size} bytes; limit is {MAX_FILE_BYTES}"
            )
        body = response["Body"]
        try:
            # Read at most one byte past the limit: enough to detect an
            # object that is larger than its ContentLength claimed.
            compressed = body.read(MAX_FILE_BYTES + 1)
        finally:
            body.close()
    except AWS_ERRORS as exc:
        raise AwsAccessError(f"{source}: {describe_aws_error(exc)}") from exc

    if len(compressed) > MAX_FILE_BYTES:
        raise CloudTrailFileError(f"{source}: object exceeds {MAX_FILE_BYTES} bytes")

    try:
        text = gunzip_capped(compressed, source).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CloudTrailFileError(f"{source}: content is not valid UTF-8") from exc
    return parse_cloudtrail_json(text, source=source)


def gunzip_capped(data: bytes, source: str, limit: int = MAX_FILE_BYTES) -> bytes:
    """Decompress one gzip stream, refusing output larger than ``limit``.

    A few kilobytes of gzip can expand to gigabytes (a "decompression
    bomb"), so the output is capped while decompressing, not checked after.
    """
    if not data.startswith(GZIP_MAGIC):
        raise CloudTrailFileError(f"{source}: not gzip-compressed")

    decompressor = zlib.decompressobj(wbits=zlib.MAX_WBITS | 16)  # | 16: expect a gzip header
    try:
        output = decompressor.decompress(data, limit + 1)
    except zlib.error as exc:
        raise CloudTrailFileError(f"{source}: corrupt gzip data: {exc}") from exc

    if len(output) > limit:
        raise CloudTrailFileError(f"{source}: decompresses to more than {limit} bytes")
    if not decompressor.eof:
        raise CloudTrailFileError(f"{source}: gzip data is truncated")
    if decompressor.unused_data:
        raise CloudTrailFileError(f"{source}: unexpected data after the gzip stream")
    return output
