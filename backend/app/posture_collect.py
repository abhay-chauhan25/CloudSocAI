"""Collect a posture snapshot from a live AWS account and save it as JSON.

Usage (from backend/, with read-only AWS credentials):

    python -m app.posture_collect --profile cloudsoc-reader --region us-east-1 \\
        --output ../local-data/posture-snapshot.json
    python -m app.posture_scan ../local-data/posture-snapshot.json

Collecting and scanning are separate steps, so the exact configuration a
scan judged is kept as a file that can be inspected or re-scanned later.
The file holds account configuration (user names, security group rules),
so it is written readable by its owner only; local-data/ is gitignored.
"""

import argparse
import json
import logging
import os
import sys
from pathlib import Path

from app.collectors.aws import AwsAccessError, create_session
from app.posture.collect import SECTIONS, collect_snapshot
from app.posture.snapshot import SnapshotError, parse_snapshot

logger = logging.getLogger(__name__)

EXIT_OK = 0
EXIT_INCOMPLETE = 1  # some sections could not be read; their checks will be "not evaluated"
EXIT_AWS_UNAVAILABLE = 3
EXIT_INVALID_SNAPSHOT = 4  # AWS returned something the snapshot model does not accept


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Collect a posture snapshot from AWS.")
    parser.add_argument("--region", required=True, help="region for regional sections")
    parser.add_argument("--profile", help="AWS profile (default: the standard credential chain)")
    parser.add_argument("--output", required=True, type=Path, help="snapshot JSON file to write")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    try:
        collection = collect_snapshot(create_session(args.profile, args.region), args.region)
    except AwsAccessError as exc:
        logger.error("%s", exc)
        return EXIT_AWS_UNAVAILABLE

    # Validate before writing, so a file on disk is always one posture_scan accepts.
    try:
        parse_snapshot(collection.snapshot)
    except SnapshotError as exc:
        logger.error("collected configuration does not fit the snapshot model: %s", exc)
        return EXIT_INVALID_SNAPSHOT

    args.output.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.fchmod(descriptor, 0o600)  # also when overwriting a file created with wider permissions
    with os.fdopen(descriptor, "w", encoding="utf-8") as file:
        json.dump(collection.snapshot, file, indent=2)

    for section, reason in collection.missing.items():
        logger.warning("%s not collected (its checks will be not evaluated): %s", section, reason)
    collected = len(SECTIONS) - len(collection.missing)
    logger.info("wrote %s: %d of %d sections", args.output, collected, len(SECTIONS))
    return EXIT_INCOMPLETE if collection.missing else EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
