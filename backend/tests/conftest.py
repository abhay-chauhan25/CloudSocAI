"""Shared pytest fixtures."""

from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
CLOUDTRAIL_SAMPLES_DIR = REPO_ROOT / "sample-data" / "cloudtrail"


@pytest.fixture
def cloudtrail_samples_dir() -> Path:
    return CLOUDTRAIL_SAMPLES_DIR
