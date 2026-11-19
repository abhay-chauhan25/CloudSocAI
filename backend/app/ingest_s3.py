"""Ingest CloudTrail logs from the trail's S3 bucket: list -> download -> normalize -> store.

Usage (from backend/, with the database running and AWS credentials
configured, e.g. `aws configure --profile cloudsoc-reader`):

    python -m app.ingest_s3 --bucket cloudsoc-lab-trail-logs \\
        --account-id 123456789012 --region us-east-1 --profile cloudsoc-reader

Reads one UTC day per --date (default: today) and is safe to re-run:
events already stored are skipped. Every S3 object is stored in its own
transaction, like a local file, so one unreadable object does not stop
the others. The command only reads from AWS; see docs/aws-ingestion.md for
the read-only policy it needs.
"""

import argparse
import logging
import sys
from datetime import UTC, date, datetime

from sqlalchemy.exc import OperationalError

from app.collectors.aws import AwsAccessError, create_session
from app.collectors.cloudtrail_file import CloudTrailFileError
from app.collectors.cloudtrail_s3 import LogLocation, list_log_keys, read_log_object
from app.db import create_db_engine, create_session_factory
from app.ingest import ingest_records, log_report

logger = logging.getLogger(__name__)

EXIT_OK = 0
EXIT_PROBLEMS = 1  # some objects or records could not be ingested
EXIT_DATABASE_UNAVAILABLE = 2
EXIT_AWS_UNAVAILABLE = 3  # credentials missing, access denied, bucket not found, ...
EXIT_INVALID_ARGUMENTS = 4

DEFAULT_MAX_OBJECTS = 1000


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Ingest CloudTrail logs from S3.")
    parser.add_argument("--bucket", required=True, help="S3 bucket the trail delivers to")
    parser.add_argument("--account-id", required=True, help="account whose logs to read")
    parser.add_argument("--region", required=True, help="region whose logs to read")
    parser.add_argument("--prefix", default="", help="the trail's S3 key prefix, if any")
    parser.add_argument("--organization-id", help="organization ID, for organization trails")
    parser.add_argument(
        "--date",
        dest="dates",
        action="append",
        type=date.fromisoformat,
        help="UTC day to read, YYYY-MM-DD (repeatable; default: today)",
    )
    parser.add_argument("--profile", help="AWS profile (default: the standard credential chain)")
    parser.add_argument(
        "--max-objects",
        type=int,
        default=DEFAULT_MAX_OBJECTS,
        help=f"stop after this many log files per day (default {DEFAULT_MAX_OBJECTS})",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    try:
        location = LogLocation(
            bucket=args.bucket,
            account_id=args.account_id,
            region=args.region,
            prefix=args.prefix,
            organization_id=args.organization_id,
        )
    except ValueError as exc:
        logger.error("%s", exc)
        return EXIT_INVALID_ARGUMENTS
    if args.max_objects < 1:
        logger.error("--max-objects must be at least 1")
        return EXIT_INVALID_ARGUMENTS
    days = args.dates or [datetime.now(UTC).date()]

    try:
        s3 = create_session(args.profile, args.region).client("s3")
    except AwsAccessError as exc:
        logger.error("%s", exc)
        return EXIT_AWS_UNAVAILABLE

    engine = create_db_engine()
    sessions = create_session_factory(engine)
    all_clean = True
    try:
        for day in days:
            prefix = location.day_prefix(day)
            try:
                listing = list_log_keys(s3, location.bucket, prefix, args.max_objects)
            except AwsAccessError as exc:
                logger.error("s3://%s/%s: cannot list logs: %s", location.bucket, prefix, exc)
                return EXIT_AWS_UNAVAILABLE

            logger.info("s3://%s/%s: %d log files", location.bucket, prefix, len(listing.keys))
            for key in listing.skipped:
                logger.info("skipped %r: not a CloudTrail log file", key)
            if listing.truncated:
                logger.warning(
                    "more than %d log files for %s; rerun with a higher --max-objects",
                    args.max_objects,
                    day,
                )
                all_clean = False

            for key in listing.keys:
                source = f"s3://{location.bucket}/{key}"
                try:
                    records = read_log_object(s3, location.bucket, key)
                    with sessions.begin() as session:
                        report = ingest_records(session, source, records)
                except (AwsAccessError, CloudTrailFileError) as exc:
                    logger.error("not ingested: %s", exc)  # the error names the object
                    all_clean = False
                    continue
                log_report(report)
                all_clean = all_clean and not report.errors
    except OperationalError as exc:
        logger.error("database unavailable (is `docker compose up -d` running?): %s", exc.orig)
        return EXIT_DATABASE_UNAVAILABLE
    finally:
        engine.dispose()

    return EXIT_OK if all_clean else EXIT_PROBLEMS


if __name__ == "__main__":
    sys.exit(main())
