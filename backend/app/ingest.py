"""Ingest CloudTrail log files: load -> normalize -> store.

Usage (from backend/, with the database running):

    python -m app.ingest ../sample-data/cloudtrail/*.json

Each file is stored in its own transaction: a file that cannot be read does
not stop the others, and a partially processed file is never half-saved.
Records that fail normalization are logged with their position, never
silently dropped, and make the command exit non-zero.
"""

import argparse
import logging
import sys
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from app.collectors.cloudtrail_file import CloudTrailFileError, RawRecord, load_cloudtrail_file
from app.db import create_db_engine, create_session_factory
from app.normalization.cloudtrail import RecordError, normalize_cloudtrail_records
from app.repositories.events import save_events

logger = logging.getLogger(__name__)

EXIT_OK = 0
EXIT_PROBLEMS = 1  # some files or records could not be ingested
EXIT_DATABASE_UNAVAILABLE = 2


@dataclass(frozen=True)
class IngestReport:
    source: str
    records: int
    inserted: int
    duplicates: int
    errors: list[RecordError]


def ingest_records(session: Session, source: str, records: list[RawRecord]) -> IngestReport:
    """Normalize and store one log file's records inside the caller's transaction.

    Shared by local files and S3 objects: ``source`` names where the records
    came from in logs and reports.
    """
    result = normalize_cloudtrail_records(records)
    inserted = save_events(session, result.events)

    for error in result.errors:
        # %r escapes newlines and control characters, so an attacker-controlled
        # eventID cannot forge extra lines in the log (log injection).
        logger.warning(
            "%s: record %d (eventID=%r) rejected: %s",
            source,
            error.index,
            error.event_id,
            error.reason,
        )

    return IngestReport(
        source=source,
        records=len(records),
        inserted=inserted,
        duplicates=len(result.events) - inserted,
        errors=result.errors,
    )


def ingest_cloudtrail_file(session: Session, path: Path) -> IngestReport:
    """Load, normalize, and store one file inside the caller's transaction."""
    return ingest_records(session, str(path), load_cloudtrail_file(path))


def log_report(report: IngestReport) -> None:
    logger.info(
        "%s: %d records, %d stored, %d duplicates skipped, %d rejected",
        report.source,
        report.records,
        report.inserted,
        report.duplicates,
        len(report.errors),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Ingest CloudTrail JSON log files.")
    parser.add_argument("files", nargs="+", type=Path, help="CloudTrail JSON log files")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    engine = create_db_engine()
    sessions = create_session_factory(engine)
    all_clean = True
    try:
        for path in args.files:
            try:
                with sessions.begin() as session:
                    report = ingest_cloudtrail_file(session, path)
            except (OSError, CloudTrailFileError) as exc:
                logger.error("%s: not ingested: %s", path, exc)
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
