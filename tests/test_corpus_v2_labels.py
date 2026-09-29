"""Corpus v2 annotations obey the documented labelling rule
(``data/calibration/corpus/v2/labelling-rules.json``): every included unit runs
a tool its family's documented procedure names and that is not a generic host;
every other inventoried unit is declared excluded with a reason; deferred
families have no annotation; annotations are valid contracts; blind-actor
material is only ever in the blind population."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from attribution_platform.calibration.contracts import CaseRole
from attribution_platform.calibration.corpus_builder import load_scenario_annotation

CORPUS = Path(__file__).resolve().parents[1] / "data" / "calibration" / "corpus" / "v2"
RULES: dict[str, Any] = json.loads((CORPUS / "labelling-rules.json").read_text("utf-8"))
FAMILIES = {f["family_id"]: f for f in RULES["families"]}
GENERIC = set(RULES["generic_hosts"])


def _annotation(family_id: str) -> dict[str, Any]:
    return dict(
        json.loads((CORPUS / "annotations" / f"{family_id}.annotation.json").read_text("utf-8"))
    )


def _inventory(recording_id: str) -> dict[str, Any]:
    return dict(json.loads((CORPUS / "inventory" / f"{recording_id}.json").read_text("utf-8")))


LABELLED = sorted(f for f, spec in FAMILIES.items() if "deferred" not in spec)


def test_deferred_families_have_a_reason_and_no_annotation() -> None:
    deferred = [f for f, spec in FAMILIES.items() if "deferred" in spec]
    assert deferred  # CALDERA and three LSASS runs
    for family_id in deferred:
        assert FAMILIES[family_id]["deferred"].strip()
        assert not (CORPUS / "annotations" / f"{family_id}.annotation.json").exists()


@pytest.mark.parametrize("family_id", LABELLED)
def test_annotation_is_a_valid_contract(family_id: str) -> None:
    annotation = load_scenario_annotation(CORPUS / "annotations" / f"{family_id}.annotation.json")
    assert annotation.case_role.value == FAMILIES[family_id]["case_role"]


@pytest.mark.parametrize("family_id", LABELLED)
def test_every_unit_follows_the_rule(family_id: str) -> None:
    spec = FAMILIES[family_id]
    tools = {t.lower() for t in spec["documented_tools"]}
    inventory = {u["anchor_observation_id"]: u for u in _inventory(spec["recording_id"])["units"]}
    units = _annotation(family_id)["units"]
    assert len(units) == len(inventory)  # every produced unit is declared
    for unit in units:
        (anchor,) = unit["anchor_scenario_ids"]
        named = (set(inventory[anchor]["image_names"]) & tools) - GENERIC
        if named:
            assert "exclusion_reason" not in unit
            assert set(unit["documented_tools"]) == named
            provenance = unit["expected_output_shape"]["authorship_provenance"]
            assert "NOT derived from the engine's detections" in provenance
        else:
            assert unit["exclusion_reason"].strip()
            assert "expected_output_shape" not in unit


def test_blind_actor_stays_in_the_blind_population() -> None:
    for family_id in LABELLED:
        annotation = _annotation(family_id)
        if annotation["ground_truth"]["actor_label"] == "APT29":
            assert annotation["case_role"] == CaseRole.BLIND_ACTOR_HOLDOUT.value
        else:
            assert annotation["case_role"] != CaseRole.BLIND_ACTOR_HOLDOUT.value


def test_generic_hosts_are_never_label_evidence() -> None:
    for family_id in LABELLED:
        for unit in _annotation(family_id)["units"]:
            assert not set(unit.get("documented_tools", ())) & GENERIC
