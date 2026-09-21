"""Tests for Phase-3 prerequisite B3 traversal: `required_data_components`
(ADR-0005 §D2 as clarified by Amendment C (2026-09-21);
docs/architecture/11-coverage-model.md).

Derives the active ATT&CK v19 `x-mitre-data-component` names required to observe
a technique, through the pinned detection graph:

    technique ← active detects ← active detection-strategy → active analytic
              → x_mitre_log_source_references → active x-mitre-data-component

Edge cases (inactive objects at each hop, dangling references) use small
synthetic bundles built with the verified-fixture pattern the G3.5 / P1 tests
established; the real pinned v19 bundle is used for determinism,
PYTHONHASHSEED-independence, and non-mutation. Offline, deterministic.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from attribution_platform.attack_knowledge import traversal as traversal_module
from attribution_platform.attack_knowledge import verification as verification_module
from attribution_platform.attack_knowledge.loader import (
    AttackKnowledge,
    _load_from_dir,
    load_attack_knowledge,
)
from attribution_platform.attack_knowledge.traversal import (
    UnknownAttackEntityError,
    is_active,
    required_data_components,
)
from attribution_platform.attack_knowledge.verification import EXPECTED_ARTIFACT_FILENAME

_ACTIVE: dict[str, bool] = {}


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


def _build_kb(
    tmp_path: Path,
    *,
    techniques: dict[str, dict[str, bool]],
    data_components: dict[str, dict[str, Any]],
    analytics: dict[str, dict[str, Any]],
    strategies: dict[str, dict[str, Any]],
    detects: list[tuple[str, str, dict[str, bool]]],
) -> AttackKnowledge:
    """Verified synthetic detection-graph bundle.

    - ``techniques``: id -> flags.
    - ``data_components``: id -> ``{"name": str, **flags}``.
    - ``analytics``: id -> ``{"components": [dc_id, ...], **flags}`` (turned into
      ``x_mitre_log_source_references`` each carrying ``x_mitre_data_component_ref``;
      a dangling component id is allowed for fail-closed tests).
    - ``strategies``: id -> ``{"analytics": [analytic_id, ...], **flags}`` (turned
      into ``x_mitre_analytic_refs``; a dangling analytic id is allowed).
    - ``detects``: ``(strategy_id, technique_id, flags)`` relationship tuples.
    """
    objects: list[dict[str, Any]] = [
        {
            "type": "x-mitre-collection",
            "id": "x-mitre-collection--b3-fixture",
            "name": "Enterprise ATT&CK",
            "x_mitre_version": "19.0",
            "spec_version": "2.1",
            "created": "2020-01-01T00:00:00.000Z",
            "modified": "2020-01-01T00:00:00.000Z",
        },
    ]
    for tid in sorted(techniques):
        objects.append(
            _flagged(
                {"type": "attack-pattern", "id": tid, "x_mitre_is_subtechnique": False},
                techniques[tid],
            )
        )
    for dc_id in sorted(data_components):
        spec = dict(data_components[dc_id])
        name = spec.pop("name")
        objects.append(
            _flagged(
                {"type": "x-mitre-data-component", "id": dc_id, "name": name},
                {k: bool(v) for k, v in spec.items()},
            )
        )
    for an_id in sorted(analytics):
        spec = dict(analytics[an_id])
        components = spec.pop("components", [])
        refs = [
            {"x_mitre_data_component_ref": dc_id, "name": f"log:{i}", "channel": f"ch{i}"}
            for i, dc_id in enumerate(components)
        ]
        objects.append(
            _flagged(
                {"type": "x-mitre-analytic", "id": an_id, "x_mitre_log_source_references": refs},
                {k: bool(v) for k, v in spec.items()},
            )
        )
    for st_id in sorted(strategies):
        spec = dict(strategies[st_id])
        analytic_refs = spec.pop("analytics", [])
        objects.append(
            _flagged(
                {
                    "type": "x-mitre-detection-strategy",
                    "id": st_id,
                    "x_mitre_analytic_refs": list(analytic_refs),
                },
                {k: bool(v) for k, v in spec.items()},
            )
        )
    for i, (strategy_id, technique_id, flags) in enumerate(detects, start=1):
        objects.append(
            _flagged(
                {
                    "type": "relationship",
                    "id": f"relationship--{i:08d}-0000-0000-0000-000000000000",
                    "relationship_type": "detects",
                    "source_ref": strategy_id,
                    "target_ref": technique_id,
                },
                flags,
            )
        )

    bundle = {"type": "bundle", "id": "bundle--b3-fixture", "objects": objects}
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


def _chain(
    tmp_path: Path,
    *,
    technique_flags: dict[str, bool] = _ACTIVE,
    strategy_flags: dict[str, bool] = _ACTIVE,
    analytic_flags: dict[str, bool] = _ACTIVE,
    detect_flags: dict[str, bool] = _ACTIVE,
    component_specs: dict[str, dict[str, Any]] | None = None,
) -> AttackKnowledge:
    """One technique T1 ← DS1 → AN1 → the given data-components (default: one
    active component named "Process Creation")."""
    components = component_specs or {_dc(1): {"name": "Process Creation"}}
    return _build_kb(
        tmp_path,
        techniques={_tech(1): technique_flags},
        data_components=components,
        analytics={_analytic(1): {"components": list(components), **analytic_flags}},
        strategies={_strategy(1): {"analytics": [_analytic(1)], **strategy_flags}},
        detects=[(_strategy(1), _tech(1), detect_flags)],
    )


# ===========================================================================
# 1-3. Happy path: required components, multiple, deterministic sorted
# ===========================================================================


def test_required_components_from_valid_detection_graph(tmp_path: Path) -> None:
    kb = _chain(tmp_path)
    assert required_data_components(kb, _tech(1)) == ("Process Creation",)


def test_multiple_data_components_sorted_unique(tmp_path: Path) -> None:
    # Two analytics under one strategy, three distinct components (one shared)
    # inserted out of alphabetical order -> sorted-unique names.
    kb = _build_kb(
        tmp_path,
        techniques={_tech(1): _ACTIVE},
        data_components={
            _dc(1): {"name": "WMI Creation"},
            _dc(2): {"name": "Process Creation"},
            _dc(3): {"name": "Network Connection Creation"},
        },
        analytics={
            _analytic(1): {"components": [_dc(1), _dc(2)]},
            _analytic(2): {"components": [_dc(2), _dc(3)]},
        },
        strategies={_strategy(1): {"analytics": [_analytic(1), _analytic(2)]}},
        detects=[(_strategy(1), _tech(1), _ACTIVE)],
    )
    result = required_data_components(kb, _tech(1))
    assert result == ("Network Connection Creation", "Process Creation", "WMI Creation")
    assert list(result) == sorted(result)


def test_repeated_invocation_deterministic(tmp_path: Path) -> None:
    kb = _chain(tmp_path)
    assert required_data_components(kb, _tech(1)) == required_data_components(kb, _tech(1))


# ===========================================================================
# 4-8. Active filtering / fail-closed at every hop
# ===========================================================================


@pytest.mark.parametrize("flag", ["revoked", "deprecated"])
def test_inactive_detection_strategy_excluded(tmp_path: Path, flag: str) -> None:
    kb = _chain(tmp_path, strategy_flags={flag: True})
    assert required_data_components(kb, _tech(1)) == ()


@pytest.mark.parametrize("flag", ["revoked", "deprecated"])
def test_inactive_analytic_excluded(tmp_path: Path, flag: str) -> None:
    kb = _chain(tmp_path, analytic_flags={flag: True})
    assert required_data_components(kb, _tech(1)) == ()


@pytest.mark.parametrize("flag", ["revoked", "deprecated"])
def test_inactive_data_component_excluded(tmp_path: Path, flag: str) -> None:
    kb = _chain(tmp_path, component_specs={_dc(1): {"name": "Process Creation", flag: True}})
    assert required_data_components(kb, _tech(1)) == ()


def test_inactive_detects_relationship_excluded(tmp_path: Path) -> None:
    kb = _chain(tmp_path, detect_flags={"revoked": True})
    assert required_data_components(kb, _tech(1)) == ()


def test_only_active_component_survives_a_mixed_graph(tmp_path: Path) -> None:
    # One active + one revoked component on the same analytic -> only the active.
    kb = _build_kb(
        tmp_path,
        techniques={_tech(1): _ACTIVE},
        data_components={
            _dc(1): {"name": "Process Creation"},
            _dc(2): {"name": "WMI Creation", "revoked": True},
        },
        analytics={_analytic(1): {"components": [_dc(1), _dc(2)]}},
        strategies={_strategy(1): {"analytics": [_analytic(1)]}},
        detects=[(_strategy(1), _tech(1), _ACTIVE)],
    )
    assert required_data_components(kb, _tech(1)) == ("Process Creation",)


def test_dangling_references_skipped_fail_closed(tmp_path: Path) -> None:
    # analytic references a non-existent data-component; strategy references a
    # non-existent analytic -> both skipped, no raise, only the resolvable
    # active component remains.
    kb = _build_kb(
        tmp_path,
        techniques={_tech(1): _ACTIVE},
        data_components={_dc(1): {"name": "Process Creation"}},
        analytics={_analytic(1): {"components": [_dc(1), _dc(99)]}},
        strategies={_strategy(1): {"analytics": [_analytic(1), _analytic(98)]}},
        detects=[(_strategy(1), _tech(1), _ACTIVE)],
    )
    assert required_data_components(kb, _tech(1)) == ("Process Creation",)


# ===========================================================================
# 9-11. Entity resolution / empty result
# ===========================================================================


def test_unknown_technique_fails_closed(tmp_path: Path) -> None:
    kb = _chain(tmp_path)
    with pytest.raises(UnknownAttackEntityError):
        required_data_components(kb, _tech(999))


def test_wrong_entity_type_fails_closed(tmp_path: Path) -> None:
    kb = _chain(tmp_path)
    with pytest.raises(UnknownAttackEntityError):
        required_data_components(kb, _strategy(1))  # a detection-strategy, not a technique


def test_technique_with_no_detection_strategy_returns_empty(tmp_path: Path) -> None:
    kb = _build_kb(
        tmp_path,
        techniques={_tech(1): _ACTIVE},
        data_components={},
        analytics={},
        strategies={},
        detects=[],
    )
    assert required_data_components(kb, _tech(1)) == ()


@pytest.mark.parametrize("flag", ["revoked", "deprecated"])
def test_inactive_technique_returns_empty(tmp_path: Path, flag: str) -> None:
    # An inactive technique contributes no requirements (doc 11 §11) -> ().
    kb = _chain(tmp_path, technique_flags={flag: True})
    assert required_data_components(kb, _tech(1)) == ()


# ===========================================================================
# 12-14. Determinism / PYTHONHASHSEED / non-mutation (real pinned bundle)
# ===========================================================================


def test_real_bundle_required_components_are_all_active_data_components() -> None:
    kb = load_attack_knowledge()
    seen = 0
    for technique in kb.techniques():
        if not is_active(technique):
            continue
        for name in required_data_components(kb, str(technique["id"])):
            assert isinstance(name, str) and name
            seen += 1
    assert seen > 0  # non-vacuous: the real v19 graph yields requirements


_SUBPROCESS = """
from attribution_platform.attack_knowledge.loader import load_attack_knowledge
from attribution_platform.attack_knowledge.traversal import required_data_components
kb = load_attack_knowledge()
out = []
for t in sorted(kb.techniques(), key=lambda o: str(o["id"]))[:25]:
    tid = str(t["id"])
    out.append(tid + ":" + ",".join(required_data_components(kb, tid)))
print("|".join(out))
"""


def _run_under_seed(seed: str) -> str:
    return subprocess.run(
        [sys.executable, "-c", _SUBPROCESS],
        capture_output=True,
        text=True,
        env={"PYTHONHASHSEED": seed, "PYTHONPATH": "src"},
        check=True,
    ).stdout.strip()


def test_real_bundle_pythonhashseed_independent() -> None:
    first = _run_under_seed("0")
    assert first  # non-vacuous
    assert first == _run_under_seed("1") == _run_under_seed("424242")


def test_required_components_does_not_mutate_knowledge(tmp_path: Path) -> None:
    kb = _chain(tmp_path)
    fingerprint = kb.object_fingerprint
    component_before = dict(kb.get_by_id(_dc(1)) or {})

    required_data_components(kb, _tech(1))

    assert kb.object_fingerprint is fingerprint
    after = kb.get_by_id(_dc(1))
    assert after is not None and dict(after) == component_before


def test_two_fresh_loads_identical(tmp_path: Path) -> None:
    kb1 = _chain(tmp_path / "a")
    kb2 = _chain(tmp_path / "b")
    assert required_data_components(kb1, _tech(1)) == required_data_components(kb2, _tech(1))


def test_traversal_module_imports_no_networking_libraries() -> None:
    for name in ("socket", "urllib", "http", "requests"):
        assert not hasattr(traversal_module, name), f"traversal.py must not import {name!r}"
