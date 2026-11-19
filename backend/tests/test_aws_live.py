"""Opt-in check against a real CloudTrail bucket. Skipped unless explicitly configured.

Read-only and database-free: lists one day of logs, downloads at most two
files, and normalizes them. Run it against the Terraform lab only:

    CLOUDSOC_LIVE_BUCKET=<bucket> CLOUDSOC_LIVE_ACCOUNT_ID=<account> \\
    CLOUDSOC_LIVE_REGION=us-east-1 AWS_PROFILE=cloudsoc-reader \\
    pytest -m aws
"""

import os
from datetime import UTC, date, datetime

import pytest

from app.collectors.aws import create_session
from app.collectors.cloudtrail_s3 import LogLocation, list_log_keys, read_log_object
from app.normalization.cloudtrail import normalize_cloudtrail_records

pytestmark = pytest.mark.aws

SETTINGS = ("CLOUDSOC_LIVE_BUCKET", "CLOUDSOC_LIVE_ACCOUNT_ID", "CLOUDSOC_LIVE_REGION")


@pytest.fixture
def location() -> LogLocation:
    missing = [name for name in SETTINGS if not os.environ.get(name)]
    if missing:
        pytest.skip(f"live AWS test not configured: set {', '.join(missing)}")
    return LogLocation(
        bucket=os.environ["CLOUDSOC_LIVE_BUCKET"],
        account_id=os.environ["CLOUDSOC_LIVE_ACCOUNT_ID"],
        region=os.environ["CLOUDSOC_LIVE_REGION"],
    )


def test_live_logs_download_and_normalize(location: LogLocation) -> None:
    day_setting = os.environ.get("CLOUDSOC_LIVE_DATE")
    day = date.fromisoformat(day_setting) if day_setting else datetime.now(UTC).date()
    s3 = create_session(region=location.region).client("s3")

    listing = list_log_keys(s3, location.bucket, location.day_prefix(day), max_objects=2)
    if not listing.keys:
        pytest.skip(f"no CloudTrail logs delivered for {day} yet (delivery takes ~5-15 minutes)")

    for key in listing.keys:
        result = normalize_cloudtrail_records(read_log_object(s3, location.bucket, key))
        assert result.errors == [], f"{key}: records the normalizer rejected"
        assert result.events
