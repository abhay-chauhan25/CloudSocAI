"""The posture scan command and posture findings through the API, against a real database."""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import URL, Engine, text
from sqlalchemy.orm import Session

from app import posture_scan
from app.correlation.service import run_correlation
from app.db import create_db_engine
from app.posture.engine import run_posture_checks
from app.posture.snapshot import load_snapshot
from app.repositories.findings import ScoredFinding, save_findings
from app.risk.scoring import RiskContext, score_finding

pytestmark = pytest.mark.db

SNAPSHOTS = Path(__file__).resolve().parents[2] / "sample-data" / "aws-config"


def store_insecure_findings(session: Session) -> None:
    findings = run_posture_checks(load_snapshot(SNAPSHOTS / "insecure-account.json")).findings
    context = RiskContext.from_events([])
    save_findings(session, [ScoredFinding(f, score_finding(f, context)) for f in findings])


def test_scan_stores_findings_once(
    db_engine: Engine,
    test_database_url: URL,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        posture_scan, "create_db_engine", lambda: create_db_engine(test_database_url)
    )
    snapshot = str(SNAPSHOTS / "insecure-account.json")

    try:
        assert posture_scan.main([snapshot]) == posture_scan.EXIT_OK
        first = capsys.readouterr().out
        assert posture_scan.main([snapshot]) == posture_scan.EXIT_OK
        second = capsys.readouterr().out
    finally:
        with db_engine.begin() as connection:
            connection.execute(text("TRUNCATE findings CASCADE"))

    assert first.startswith("0 checks passed, 11 findings (11 new, 0 already stored)")
    assert second.startswith("0 checks passed, 11 findings (0 new, 11 already stored)")
    assert "[CRITICAL] risk  80  Root user has no MFA (root-mfa-disabled)" in first
    assert "resource: arn:aws:s3:::cloudsoc-public-reports" in first


def test_scan_rejects_an_invalid_snapshot(tmp_path: Path) -> None:
    broken = tmp_path / "broken.json"
    broken.write_text('{"account_id": "nope"}', encoding="utf-8")

    assert posture_scan.main([str(broken)]) == posture_scan.EXIT_INVALID_SNAPSHOT


def test_posture_findings_are_never_correlated_into_incidents(db_session: Session) -> None:
    store_insecure_findings(db_session)

    report = run_correlation(db_session)

    assert (report.created, report.updated) == ([], [])


def test_posture_finding_detail_explains_the_check(client: TestClient, db_session: Session) -> None:
    store_insecure_findings(db_session)
    items = client.get("/findings", params={"detector_id": "s3-bucket-public"}).json()["items"]

    [summary] = items
    detail = client.get(f"/findings/{summary['finding_id']}").json()

    assert (summary["kind"], summary["principal"], summary["event_count"]) == ("posture", None, 0)
    assert detail["kind"] == "posture"
    assert detail["detector"] is None
    assert detail["posture_check"]["remediation"].startswith("Remove the public statement")
    assert detail["resource"] == "arn:aws:s3:::cloudsoc-public-reports"
    assert detail["evidence"] == []


def test_catalog_lists_posture_checks_alongside_rules(client: TestClient) -> None:
    catalog = client.get("/detectors").json()

    assert len(catalog["detectors"]) == 8
    assert len(catalog["posture_checks"]) == 9
    assert {"check_id": "root-mfa-disabled", "service": "iam", "severity": "critical"}.items() <= (
        catalog["posture_checks"][0].items()
    )
