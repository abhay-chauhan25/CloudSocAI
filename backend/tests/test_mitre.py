"""The curated ATT&CK catalog and every rule's mapping to it."""

import re

import pytest

from app.detection.registry import DEFAULT_DETECTORS
from app.mitre.catalog import ATTACK_VERSION, TACTICS, TECHNIQUES, tactic_rank


def test_catalog_is_pinned_to_a_version() -> None:
    assert ATTACK_VERSION == "20.0"


def test_tactics_are_the_15_enterprise_tactics_in_matrix_order() -> None:
    assert [t.name for t in TACTICS] == [
        "Reconnaissance",
        "Resource Development",
        "Initial Access",
        "Execution",
        "Persistence",
        "Privilege Escalation",
        "Stealth",
        "Defense Impairment",
        "Credential Access",
        "Discovery",
        "Lateral Movement",
        "Collection",
        "Command and Control",
        "Exfiltration",
        "Impact",
    ]
    assert len({t.tactic_id for t in TACTICS}) == 15
    assert all(re.fullmatch(r"TA\d{4}", t.tactic_id) for t in TACTICS)


@pytest.mark.parametrize("technique", TECHNIQUES.values(), ids=lambda t: t.technique_id)
def test_techniques_are_well_formed(technique) -> None:
    assert re.fullmatch(r"T\d{4}(\.\d{3})?", technique.technique_id)
    assert technique.tactics, "every technique serves at least one tactic"
    assert all(tactic in TACTICS for tactic in technique.tactics)
    ranks = [tactic_rank(t) for t in technique.tactics]
    assert ranks == sorted(ranks), "tactics listed in matrix order"
    path = technique.technique_id.replace(".", "/")
    assert technique.url == f"https://attack.mitre.org/techniques/{path}/"


@pytest.mark.parametrize("detector", DEFAULT_DETECTORS, ids=lambda d: d.detector_id)
def test_every_mapping_uses_a_catalog_technique_and_explains_itself(detector) -> None:
    for mapping in detector.mitre:
        assert mapping.technique_id in TECHNIQUES, mapping.technique_id
        assert len(mapping.rationale) > 40, detector.detector_id


def test_only_the_burst_rule_is_deliberately_unmapped() -> None:
    unmapped = [d.detector_id for d in DEFAULT_DETECTORS if not d.mitre]

    assert unmapped == ["failed-call-burst"]


def test_every_catalog_technique_is_used() -> None:
    used = {m.technique_id for d in DEFAULT_DETECTORS for m in d.mitre}

    assert used == set(TECHNIQUES)


def test_retired_technique_ids_are_not_mapped() -> None:
    # v20 moved cloud-log tampering from T1562.008 to T1685.002.
    assert "T1562.008" not in TECHNIQUES
