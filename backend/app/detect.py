"""Run the detection rules over the stored events and print the findings.

Usage (from backend/, with the database running and events ingested):

    python -m app.detect

Findings are printed, not stored: this command shows what the rules see in
the current data. Exits non-zero if any detector failed.
"""

import argparse
import logging
import sys

from sqlalchemy.exc import OperationalError

from app.db import create_db_engine, create_session_factory
from app.detection.engine import DetectionResult, run_detectors
from app.repositories.events import list_events

logger = logging.getLogger(__name__)

EXIT_OK = 0
EXIT_DETECTOR_FAILED = 1
EXIT_DATABASE_UNAVAILABLE = 2


def format_report(result: DetectionResult, event_count: int) -> str:
    lines = [f"{event_count} events analysed, {len(result.findings)} findings"]
    for finding in result.findings:
        lines.append(
            f"\n[{finding.severity.upper()}] {finding.title} "
            f"({finding.detector_id}) at {finding.first_seen:%Y-%m-%d %H:%M:%S}Z"
        )
        lines.append(f"    {finding.reason}")
        lines.append(f"    evidence: {', '.join(finding.event_ids)}")
    for failure in result.failures:
        lines.append(f"\nDETECTOR FAILED: {failure.detector_id} ({failure.error})")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run detection rules over stored events.")
    parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    engine = create_db_engine()
    sessions = create_session_factory(engine)
    try:
        with sessions() as session:
            events = list_events(session)
    except OperationalError as exc:
        logger.error("database unavailable (is `docker compose up -d` running?): %s", exc.orig)
        return EXIT_DATABASE_UNAVAILABLE
    finally:
        engine.dispose()

    result = run_detectors(events)
    print(format_report(result, len(events)))
    return EXIT_DETECTOR_FAILED if result.failures else EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
