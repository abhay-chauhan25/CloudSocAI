"""The detection rule catalog, with curated MITRE ATT&CK mappings."""

from fastapi import APIRouter

from app.api.schemas import DetectorCatalog, DetectorInfo, TacticInfo
from app.detection.registry import DEFAULT_DETECTORS
from app.mitre.catalog import ATTACK_VERSION, TACTICS

router = APIRouter(prefix="/detectors", tags=["detectors"])


@router.get("")
def list_detectors() -> DetectorCatalog:
    """Every active rule, its default severity, and the techniques it maps to.

    The tactic list makes coverage visible: tactics no rule maps to are gaps.
    """
    return DetectorCatalog(
        attack_version=ATTACK_VERSION,
        tactics=[TacticInfo.from_tactic(tactic) for tactic in TACTICS],
        detectors=[DetectorInfo.from_detector(d) for d in DEFAULT_DETECTORS],
    )
