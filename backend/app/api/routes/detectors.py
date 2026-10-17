"""The catalog of detection rules (with curated ATT&CK mappings) and posture checks."""

from fastapi import APIRouter

from app.api.schemas import DetectorCatalog, DetectorInfo, PostureCheckInfo, TacticInfo
from app.detection.registry import DEFAULT_DETECTORS
from app.mitre.catalog import ATTACK_VERSION, TACTICS
from app.posture.registry import DEFAULT_CHECKS

router = APIRouter(prefix="/detectors", tags=["detectors"])


@router.get("")
def list_detectors() -> DetectorCatalog:
    """Every active rule and posture check, with severities and ATT&CK mappings.

    The tactic list makes coverage visible: tactics no rule maps to are gaps.
    """
    return DetectorCatalog(
        attack_version=ATTACK_VERSION,
        tactics=[TacticInfo.from_tactic(tactic) for tactic in TACTICS],
        detectors=[DetectorInfo.from_detector(d) for d in DEFAULT_DETECTORS],
        posture_checks=[PostureCheckInfo.from_check(c) for c in DEFAULT_CHECKS],
    )
