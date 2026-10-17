"""Posture scan: check an AWS configuration snapshot and store the failures as findings.

Usage (from backend/, with the database running):

    python -m app.posture_scan ../sample-data/aws-config/insecure-account.json

Safe to re-run: a misconfiguration already stored for the same resource is
skipped, so each problem stays one finding however often it is scanned.
Exits non-zero if the snapshot is invalid, a check failed, or the database
is unreachable.
"""

import argparse
import logging
import sys
from pathlib import Path

from sqlalchemy.exc import OperationalError

from app.db import create_db_engine, create_session_factory
from app.posture.engine import PostureResult, run_posture_checks
from app.posture.snapshot import SnapshotError, load_snapshot
from app.repositories.findings import ScoredFinding, save_findings
from app.risk.scoring import RiskContext, score_finding

logger = logging.getLogger(__name__)

EXIT_OK = 0
EXIT_CHECK_FAILED = 1
EXIT_DATABASE_UNAVAILABLE = 2
EXIT_INVALID_SNAPSHOT = 3


def format_report(result: PostureResult, scored: list[ScoredFinding], stored: int) -> str:
    lines = [
        f"{len(result.passed)} checks passed, {len(scored)} findings "
        f"({stored} new, {len(scored) - stored} already stored)"
    ]
    for item in scored:
        finding = item.finding
        lines.append(
            f"\n[{finding.severity.upper()}] risk {item.risk.score:>3}  {finding.title} "
            f"({finding.detector_id})"
        )
        lines.append(f"    {finding.reason}")
        lines.append(f"    resource: {finding.resource}")
    for check_id in result.not_evaluated:
        lines.append(f"\nNOT EVALUATED: {check_id} (its data is missing from the snapshot)")
    for failure in result.failures:
        lines.append(f"\nCHECK FAILED: {failure.check_id} ({failure.error})")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run posture checks on a configuration snapshot.")
    parser.add_argument("snapshot", type=Path, help="snapshot JSON file")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    try:
        snapshot = load_snapshot(args.snapshot)
    except SnapshotError as exc:
        logger.error("%s", exc)
        return EXIT_INVALID_SNAPSHOT

    result = run_posture_checks(snapshot)
    # Posture findings have no evidence events, so only the base severity applies.
    context = RiskContext.from_events([])
    scored = [ScoredFinding(f, score_finding(f, context)) for f in result.findings]

    engine = create_db_engine()
    sessions = create_session_factory(engine)
    try:
        with sessions.begin() as session:
            stored = save_findings(session, scored)
    except OperationalError as exc:
        logger.error("database unavailable (is `docker compose up -d` running?): %s", exc.orig)
        return EXIT_DATABASE_UNAVAILABLE
    finally:
        engine.dispose()

    print(format_report(result, scored, stored))
    return EXIT_CHECK_FAILED if result.failures else EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
