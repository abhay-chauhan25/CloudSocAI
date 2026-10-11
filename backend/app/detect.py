"""Run the detection rules over the stored events, then score and store the findings.

Usage (from backend/, with the database running and events ingested):

    python -m app.detect

Safe to re-run: findings that are already stored are skipped, so their
triage status is never reset. Exits non-zero if any detector failed.
"""

import argparse
import logging
import sys

from sqlalchemy.exc import OperationalError

from app.db import create_db_engine, create_session_factory
from app.detection.engine import DetectionResult, run_detectors
from app.repositories.events import list_events
from app.repositories.findings import ScoredFinding, save_findings
from app.risk.scoring import RiskContext, score_finding

logger = logging.getLogger(__name__)

EXIT_OK = 0
EXIT_DETECTOR_FAILED = 1
EXIT_DATABASE_UNAVAILABLE = 2


def format_report(
    result: DetectionResult, scored: list[ScoredFinding], event_count: int, stored: int
) -> str:
    lines = [
        f"{event_count} events analysed, {len(scored)} findings "
        f"({stored} new, {len(scored) - stored} already stored)"
    ]
    for item in scored:
        finding, risk = item.finding, item.risk
        lines.append(
            f"\n[{finding.severity.upper()}] risk {risk.score:>3}  {finding.title} "
            f"({finding.detector_id}) at {finding.first_seen:%Y-%m-%d %H:%M:%S}Z"
        )
        lines.append(f"    {finding.reason}")
        for factor in risk.factors:
            lines.append(f"    {factor.points:+4d}  {factor.name}: {factor.explanation}")
        lines.append(f"    evidence: {', '.join(finding.event_ids)}")
    for failure in result.failures:
        lines.append(f"\nDETECTOR FAILED: {failure.detector_id} ({failure.error})")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Detect, score, and store findings.")
    parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    engine = create_db_engine()
    sessions = create_session_factory(engine)
    try:
        # One transaction: the findings are stored all together or not at all.
        with sessions.begin() as session:
            events = list_events(session)
            result = run_detectors(events)
            context = RiskContext.from_events(events)
            scored = [ScoredFinding(f, score_finding(f, context)) for f in result.findings]
            stored = save_findings(session, scored)
    except OperationalError as exc:
        logger.error("database unavailable (is `docker compose up -d` running?): %s", exc.orig)
        return EXIT_DATABASE_UNAVAILABLE
    finally:
        engine.dispose()

    print(format_report(result, scored, len(events), stored))
    return EXIT_DETECTOR_FAILED if result.failures else EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
