"""Tests for Phase-3 prerequisite B3: `build_coverage_profile`
(ADR-0005 §D2 as clarified by Amendment C (2026-09-21);
docs/architecture/11-coverage-model.md).

Construction only — the four-state rule, the calibration/production availability
separation, deterministic identity, and non-mutation. No coverage *consumption*,
no scoring. Reuses the B3 detection-graph synthetic-KB builder.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from attribution_platform.attack_knowledge import verification as verification_module
from attribution_platform.attack_knowledge.loader import AttackKnowledge, _load_from_dir
from attribution_platform.attack_knowledge.traversal import UnknownAttackEntityError
from attribution_platform.attack_knowledge.verification import EXPECTED_ARTIFACT_FILENAME
from attribution_platform.attribution.contracts import (
    AttributionProvenance,
    CoverageProfile,
    CoverageState,
    compute_coverage_profile_id,
)
from attribution_platform.attribution.coverage import (
    COVERAGE_CONSTRUCTION_METHOD,
    COVERAGE_CONSTRUCTION_METHOD_VERSION,
    _derive_coverage_state,
    build_coverage_profile,
)
from attribution_platform.attribution.errors import AttributionError
from attribution_platform.domain.entities import TimeSpan

_GROUP_ID = "correlation-group--case-1"
_ACTIVE: dict[str, bool] = {}


# ---------------------------------------------------------------------------
# Self-contained B3 detection-graph fixture builder (same verified-bundle
# pattern the G3.5 / P1 tests established; kept local per the repository's
# self-contained-test-file convention).
# ---------------------------------------------------------------------------


def _tech(i: int) -> str:
    return f"attack-pattern--{i:08d}-0000-0000-0000-000000000000"


def _strategy(i: int) -> str:
    return f"x-mitre-detection-strategy--{i:08d}-0000-0000-0000-000000000000"


def _analytic(i: int) -> str:
    return f"x-mitre-analytic--{i:08d}-0000-0000-0000-000000000000"


def _dc(i: int) -> str:
    return f"x-mitre-data-component--{i:08d}-0000-0000-0000-000000000000"


def _flagged(base: dict[str, Any], flags: dict[str, bool]) -> dict[str, Any]:
    if flags.get("revoked"):
        base["revoked"] = True
    if flags.get("deprecated"):
        base["x_mitre_deprecated"] = True
    return base


def _chain(
    tmp_path: Path,
    *,
    technique_flags: dict[str, bool] = _ACTIVE,
    strategy_flags: dict[str, bool] = _ACTIVE,
    component_name: str = "Process Creation",
) -> AttackKnowledge:
    """One technique T1 ← DS1 → AN1 → one active data-component (default name
    "Process Creation"), so ``required_data_components(T1) == (component_name,)``
    unless the strategy is flagged inactive (then ``()``)."""
    objects: list[dict[str, Any]] = [
        {
            "type": "x-mitre-collection",
            "id": "x-mitre-collection--b3-cov-fixture",
            "name": "Enterprise ATT&CK",
            "x_mitre_version": "19.0",
            "spec_version": "2.1",
            "created": "2020-01-01T00:00:00.000Z",
            "modified": "2020-01-01T00:00:00.000Z",
        },
        _flagged(
            {"type": "attack-pattern", "id": _tech(1), "x_mitre_is_subtechnique": False},
            technique_flags,
        ),
        {"type": "x-mitre-data-component", "id": _dc(1), "name": component_name},
        {
            "type": "x-mitre-analytic",
            "id": _analytic(1),
            "x_mitre_log_source_references": [
                {"x_mitre_data_component_ref": _dc(1), "name": "log:0", "channel": "ch0"}
            ],
        },
        _flagged(
            {
                "type": "x-mitre-detection-strategy",
                "id": _strategy(1),
                "x_mitre_analytic_refs": [_analytic(1)],
            },
            strategy_flags,
        ),
        {
            "type": "relationship",
            "id": "relationship--00000001-0000-0000-0000-000000000000",
            "relationship_type": "detects",
            "source_ref": _strategy(1),
            "target_ref": _tech(1),
        },
    ]
    bundle = {"type": "bundle", "id": "bundle--b3-cov-fixture", "objects": objects}
    artifact_dir = tmp_path / "fixture"
    artifact_dir.mkdir(parents=True)
    artifact_path = artifact_dir / EXPECTED_ARTIFACT_FILENAME
    artifact_path.write_text(json.dumps(bundle), encoding="utf-8")

    fingerprint = verification_module.compute_object_fingerprint(objects)
    collection = verification_module.extract_collection_info(objects)
    manifest = {
        "attack_kb_version": verification_module.EXPECTED_ATTACK_KB_VERSION,
        "attack_domain": verification_module.EXPECTED_ATTACK_DOMAIN,
        "stix_spec": verification_module.EXPECTED_STIX_SPEC,
        "artifact": {
            "filename": EXPECTED_ARTIFACT_FILENAME,
            "relative_path": str(artifact_path),
            "size_bytes": artifact_path.stat().st_size,
            "sha256": verification_module.compute_sha256(artifact_path),
        },
        "stix_collection": {
            "id": collection.id,
            "name": collection.name,
            "x_mitre_version": collection.x_mitre_version,
            "spec_version": collection.spec_version,
            "created": collection.created,
            "modified": collection.modified,
        },
        "object_fingerprint": {
            "total_objects": fingerprint.total_objects,
            "tactics": fingerprint.tactics,
            "techniques": fingerprint.techniques,
            "sub_techniques": fingerprint.sub_techniques,
            "groups": fingerprint.groups,
            "software_malware": fingerprint.software_malware,
            "software_tool": fingerprint.software_tool,
            "campaigns": fingerprint.campaigns,
            "relationships": fingerprint.relationships,
            "mitigations": fingerprint.mitigations,
            "data_sources": fingerprint.data_sources,
            "data_components": fingerprint.data_components,
            "marking_definitions": fingerprint.marking_definitions,
            "identity": fingerprint.identity,
        },
    }
    (artifact_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return _load_from_dir(artifact_dir)


def _provenance(**overrides: Any) -> AttributionProvenance:
    kwargs: dict[str, Any] = {
        "method": COVERAGE_CONSTRUCTION_METHOD,
        "method_version": COVERAGE_CONSTRUCTION_METHOD_VERSION,
        "source_group_id": _GROUP_ID,
        "source_sequence_id": "behavioral-sequence--case-1",
        "source_evidence_ids": ("evidence--1",),
        "source_observation_ids": ("observation--1",),
    }
    kwargs.update(overrides)
    return AttributionProvenance(**kwargs)


# ===========================================================================
# 1. Pure state-derivation rule (doc 11 §5) — no KB required
# ===========================================================================


def test_state_observed_present_takes_precedence() -> None:
    # OBSERVED_PRESENT regardless of required/available.
    assert (
        _derive_coverage_state(observed_present=True, required=(), available=None)
        is CoverageState.OBSERVED_PRESENT
    )
    assert (
        _derive_coverage_state(observed_present=True, required=("A",), available=())
        is CoverageState.OBSERVED_PRESENT
    )


def test_state_adequate_absence_on_nonempty_intersection() -> None:
    assert (
        _derive_coverage_state(observed_present=False, required=("A", "B"), available=("B", "C"))
        is CoverageState.OBSERVED_ABSENT_WITH_ADEQUATE_COVERAGE
    )


def test_state_not_observable_on_empty_intersection() -> None:
    assert (
        _derive_coverage_state(observed_present=False, required=("A",), available=("B",))
        is CoverageState.NOT_OBSERVABLE
    )
    # production empty availability with a non-empty requirement -> NOT_OBSERVABLE
    assert (
        _derive_coverage_state(observed_present=False, required=("A",), available=())
        is CoverageState.NOT_OBSERVABLE
    )


def test_state_unknown_on_empty_required() -> None:
    assert (
        _derive_coverage_state(observed_present=False, required=(), available=("A",))
        is CoverageState.UNKNOWN
    )


def test_state_unknown_on_indeterminate_availability() -> None:
    assert (
        _derive_coverage_state(observed_present=False, required=("A",), available=None)
        is CoverageState.UNKNOWN
    )


# ===========================================================================
# 2. build_coverage_profile — full construction over a real detection graph
# ===========================================================================


def _build(kb: Any, **overrides: Any) -> CoverageProfile:
    kwargs: dict[str, Any] = {
        "group_id": _GROUP_ID,
        "technique_stix_id": _tech(1),
        "observed_present": False,
        "provenance": _provenance(),
        "available_data_components": (),
    }
    kwargs.update(overrides)
    return build_coverage_profile(kb, **kwargs)


def test_observed_present(tmp_path: Path) -> None:
    kb = _chain(tmp_path)
    profile = _build(kb, observed_present=True)
    assert profile.state is CoverageState.OBSERVED_PRESENT
    assert profile.data_sources_required == ("Process Creation",)


def test_unobserved_with_available_intersection_is_adequate_absence(tmp_path: Path) -> None:
    kb = _chain(tmp_path)  # required == ("Process Creation",)
    profile = _build(
        kb, available_data_components=("Process Creation", "Network Connection Creation")
    )
    assert profile.state is CoverageState.OBSERVED_ABSENT_WITH_ADEQUATE_COVERAGE


def test_unobserved_with_disjoint_availability_is_not_observable(tmp_path: Path) -> None:
    kb = _chain(tmp_path)
    profile = _build(kb, available_data_components=("WMI Creation",))
    assert profile.state is CoverageState.NOT_OBSERVABLE


def test_empty_required_is_unknown(tmp_path: Path) -> None:
    # technique with no detection strategy -> required == () -> UNKNOWN
    kb = _chain(tmp_path, strategy_flags={"revoked": True})
    profile = _build(kb, available_data_components=("Process Creation",))
    assert profile.data_sources_required == ()
    assert profile.state is CoverageState.UNKNOWN


def test_indeterminate_availability_is_unknown(tmp_path: Path) -> None:
    kb = _chain(tmp_path)
    profile = _build(kb, available_data_components=None)
    assert profile.state is CoverageState.UNKNOWN
    assert profile.data_sources_available == ()


# ===========================================================================
# 3. Production fail-closed / calibration path / no leakage
# ===========================================================================


def test_production_empty_availability_fails_closed(tmp_path: Path) -> None:
    # Production passes available=(): an unobserved technique with a non-empty
    # requirement is NOT_OBSERVABLE and can never be adequate-absence.
    kb = _chain(tmp_path)
    profile = _build(kb, available_data_components=())
    assert profile.state is CoverageState.NOT_OBSERVABLE
    assert profile.data_sources_available == ()


def test_calibration_coverage_assumptions_path(tmp_path: Path) -> None:
    # A calibration caller supplies declared coverage_assumptions (canonical
    # data-component names) as availability.
    kb = _chain(tmp_path)
    coverage_assumptions = ("Process Creation",)
    profile = _build(kb, available_data_components=coverage_assumptions)
    assert profile.state is CoverageState.OBSERVED_ABSENT_WITH_ADEQUATE_COVERAGE
    assert profile.data_sources_available == ("Process Creation",)


def test_calibration_declaration_does_not_leak_into_production(tmp_path: Path) -> None:
    # Same KB/technique: the declared-availability (calibration) profile and the
    # empty-availability (production) profile differ only by the caller's input;
    # nothing carries the calibration value into the production construction.
    kb = _chain(tmp_path)
    calib = _build(kb, available_data_components=("Process Creation",))
    prod = _build(kb, available_data_components=())
    assert calib.state is CoverageState.OBSERVED_ABSENT_WITH_ADEQUATE_COVERAGE
    assert prod.state is CoverageState.NOT_OBSERVABLE
    assert prod.data_sources_available == ()


# ===========================================================================
# 4. Identity / versioning / provenance / determinism / fail-closed
# ===========================================================================


def test_identity_uses_existing_contract_function(tmp_path: Path) -> None:
    kb = _chain(tmp_path)
    profile = _build(kb)
    assert profile.coverage_id == compute_coverage_profile_id(_GROUP_ID, _tech(1))


def test_pinned_attack_kb_version_preserved(tmp_path: Path) -> None:
    kb = _chain(tmp_path)
    profile = _build(kb)
    assert profile.attack_kb_version == kb.attack_kb_version


def test_provenance_and_observation_interval_preserved(tmp_path: Path) -> None:
    from datetime import UTC, datetime

    kb = _chain(tmp_path)
    provenance = _provenance()
    interval = TimeSpan(
        start=datetime(2026, 1, 1, tzinfo=UTC),
        end=datetime(2026, 1, 2, tzinfo=UTC),
    )
    profile = _build(kb, provenance=provenance, observation_interval=interval)
    assert profile.provenance == provenance
    assert profile.observation_interval == interval


def test_construction_deterministic(tmp_path: Path) -> None:
    kb = _chain(tmp_path)
    assert _build(kb) == _build(kb)


def test_unknown_technique_fails_closed(tmp_path: Path) -> None:
    kb = _chain(tmp_path)
    with pytest.raises(UnknownAttackEntityError):
        _build(kb, technique_stix_id=_tech(999))


def test_wrong_entity_type_fails_closed(tmp_path: Path) -> None:
    kb = _chain(tmp_path)
    with pytest.raises(UnknownAttackEntityError):
        _build(kb, technique_stix_id=_strategy(1))


def test_malformed_availability_element_fails_closed_at_contract(tmp_path: Path) -> None:
    # A provided (non-None) availability tuple must contain valid data-component
    # names; an empty-string element is rejected fail-closed by the contract.
    kb = _chain(tmp_path)
    with pytest.raises(AttributionError):
        _build(kb, available_data_components=("",))


def test_result_is_a_valid_coverage_profile_contract(tmp_path: Path) -> None:
    kb = _chain(tmp_path)
    profile = _build(kb)
    assert isinstance(profile, CoverageProfile)
    assert profile.group_id == _GROUP_ID
    assert profile.technique_stix_id == _tech(1)


def test_construction_does_not_mutate_knowledge(tmp_path: Path) -> None:
    kb = _chain(tmp_path)
    fingerprint = kb.object_fingerprint
    component_before = dict(kb.get_by_id(_dc(1)) or {})
    _build(kb)
    assert kb.object_fingerprint is fingerprint
    after = kb.get_by_id(_dc(1))
    assert after is not None and dict(after) == component_before
