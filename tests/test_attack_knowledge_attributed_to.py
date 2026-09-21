"""Tests for prerequisite P1: ATT&CK ``attributed-to`` traversal
(ADR-0005 Amendment B "ATT&CK attributed-to traversal prerequisite").

Real-bundle tests discover their facts dynamically from the pinned v19.0
bundle (no hard-coded ATT&CK ids), mirroring ``test_attack_knowledge_traversal``.
Edge cases the real bundle does not contain (revoked/deprecated edges,
inactive Groups, multi-attribution) use small synthetic bundles built with the
same verified-fixture pattern the G3.5 tests established.

Scope: the two additive traversal queries only. No candidate generation, no
scoring, no active-target rewrite of ``group_profile`` (a separate gate).
"""

from __future__ import annotations

import ast
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
    campaigns_attributed_to_group,
    group_profile,
    groups_attributed_to_campaign,
    is_active,
)
from attribution_platform.attack_knowledge.verification import EXPECTED_ARTIFACT_FILENAME

_REL = "attributed-to"


def _group(i: int) -> str:
    return f"intrusion-set--{i:08d}-0000-0000-0000-000000000000"


def _campaign(i: int) -> str:
    return f"campaign--{i:08d}-0000-0000-0000-000000000000"


_TECHNIQUE = "attack-pattern--10000000-0000-0000-0000-000000000000"
_UNKNOWN_ID = "campaign--ffffffff-ffff-ffff-ffff-ffffffffffff"


def _edge(
    i: int,
    source: str,
    target: str,
    *,
    rel_type: str = _REL,
    revoked: bool = False,
    deprecated: bool = False,
) -> dict[str, Any]:
    edge: dict[str, Any] = {
        "type": "relationship",
        "id": f"relationship--{i:08d}-0000-0000-0000-000000000000",
        "relationship_type": rel_type,
        "source_ref": source,
        "target_ref": target,
    }
    if revoked:
        edge["revoked"] = True
    if deprecated:
        edge["x_mitre_deprecated"] = True
    return edge


def _build_kb(
    tmp_path: Path,
    *,
    groups: dict[str, dict[str, bool]],
    campaigns: dict[str, dict[str, bool]],
    edges: list[dict[str, Any]],
) -> AttackKnowledge:
    """Verified synthetic bundle. ``groups``/``campaigns`` map id -> flags
    (``revoked`` / ``deprecated``)."""
    objects: list[dict[str, Any]] = [
        {
            "type": "x-mitre-collection",
            "id": "x-mitre-collection--p1-fixture",
            "name": "Enterprise ATT&CK",
            "x_mitre_version": "19.0",
            "spec_version": "2.1",
            "created": "2020-01-01T00:00:00.000Z",
            "modified": "2020-01-01T00:00:00.000Z",
        },
        {"type": "attack-pattern", "id": _TECHNIQUE, "x_mitre_is_subtechnique": False},
    ]
    for stix_type, entities in (("intrusion-set", groups), ("campaign", campaigns)):
        for stix_id in sorted(entities):
            entry: dict[str, Any] = {
                "type": stix_type,
                "id": stix_id,
                "name": stix_id,
                "aliases": [stix_id],
            }
            if entities[stix_id].get("revoked"):
                entry["revoked"] = True
            if entities[stix_id].get("deprecated"):
                entry["x_mitre_deprecated"] = True
            objects.append(entry)
    objects.extend(edges)

    bundle = {"type": "bundle", "id": "bundle--p1-fixture", "objects": objects}
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


_ACTIVE: dict[str, bool] = {}


# ===========================================================================
# 1-2. Forward / reverse lookup (synthetic, hand-verifiable)
# ===========================================================================


def test_campaign_to_group_forward_lookup(tmp_path: Path) -> None:
    kb = _build_kb(
        tmp_path,
        groups={_group(1): _ACTIVE, _group(2): _ACTIVE},
        campaigns={_campaign(1): _ACTIVE},
        edges=[_edge(1, _campaign(1), _group(1))],
    )
    assert groups_attributed_to_campaign(kb, _campaign(1)) == (_group(1),)


def test_group_to_campaign_reverse_lookup(tmp_path: Path) -> None:
    kb = _build_kb(
        tmp_path,
        groups={_group(1): _ACTIVE},
        campaigns={_campaign(1): _ACTIVE, _campaign(2): _ACTIVE},
        edges=[_edge(1, _campaign(1), _group(1))],
    )
    assert campaigns_attributed_to_group(kb, _group(1)) == (_campaign(1),)


def test_direction_is_campaign_source_to_group_target(tmp_path: Path) -> None:
    # A (non-STIX) reversed edge Group -> Campaign must never match either query.
    kb = _build_kb(
        tmp_path,
        groups={_group(1): _ACTIVE},
        campaigns={_campaign(1): _ACTIVE},
        edges=[_edge(1, _group(1), _campaign(1))],
    )
    assert groups_attributed_to_campaign(kb, _campaign(1)) == ()
    assert campaigns_attributed_to_group(kb, _group(1)) == ()


# ===========================================================================
# 3-4, 11. Multiplicity and deterministic sorted output
# ===========================================================================


def test_multiple_groups_attributed_to_one_campaign_sorted(tmp_path: Path) -> None:
    kb = _build_kb(
        tmp_path,
        groups={_group(i): _ACTIVE for i in (1, 2, 3)},
        campaigns={_campaign(1): _ACTIVE},
        # inserted deliberately out of id order
        edges=[
            _edge(1, _campaign(1), _group(3)),
            _edge(2, _campaign(1), _group(1)),
            _edge(3, _campaign(1), _group(2)),
        ],
    )
    result = groups_attributed_to_campaign(kb, _campaign(1))
    assert result == (_group(1), _group(2), _group(3))
    assert list(result) == sorted(result)


def test_multiple_campaigns_for_a_group_sorted(tmp_path: Path) -> None:
    kb = _build_kb(
        tmp_path,
        groups={_group(1): _ACTIVE},
        campaigns={_campaign(i): _ACTIVE for i in (1, 2, 3)},
        edges=[
            _edge(1, _campaign(3), _group(1)),
            _edge(2, _campaign(1), _group(1)),
            _edge(3, _campaign(2), _group(1)),
        ],
    )
    result = campaigns_attributed_to_group(kb, _group(1))
    assert result == (_campaign(1), _campaign(2), _campaign(3))
    assert list(result) == sorted(result)


def test_duplicate_edges_yield_a_single_result(tmp_path: Path) -> None:
    kb = _build_kb(
        tmp_path,
        groups={_group(1): _ACTIVE},
        campaigns={_campaign(1): _ACTIVE},
        edges=[_edge(1, _campaign(1), _group(1)), _edge(2, _campaign(1), _group(1))],
    )
    assert groups_attributed_to_campaign(kb, _campaign(1)) == (_group(1),)
    assert campaigns_attributed_to_group(kb, _group(1)) == (_campaign(1),)


# ===========================================================================
# 5-6. Inactive relationship / inactive target Group exclusion
# ===========================================================================


@pytest.mark.parametrize("flag", ["revoked", "deprecated"])
def test_inactive_attributed_to_relationship_excluded(tmp_path: Path, flag: str) -> None:
    kb = _build_kb(
        tmp_path,
        groups={_group(1): _ACTIVE, _group(2): _ACTIVE},
        campaigns={_campaign(1): _ACTIVE},
        edges=[
            _edge(
                1,
                _campaign(1),
                _group(1),
                revoked=flag == "revoked",
                deprecated=flag == "deprecated",
            ),
            _edge(2, _campaign(1), _group(2)),
        ],
    )
    assert groups_attributed_to_campaign(kb, _campaign(1)) == (_group(2),)
    assert campaigns_attributed_to_group(kb, _group(1)) == ()
    assert campaigns_attributed_to_group(kb, _group(2)) == (_campaign(1),)


@pytest.mark.parametrize("flag", ["revoked", "deprecated"])
def test_inactive_target_group_excluded(tmp_path: Path, flag: str) -> None:
    kb = _build_kb(
        tmp_path,
        groups={_group(1): {flag: True}, _group(2): _ACTIVE},
        campaigns={_campaign(1): _ACTIVE},
        edges=[_edge(1, _campaign(1), _group(1)), _edge(2, _campaign(1), _group(2))],
    )
    # forward: the inactive target Group is dropped, the active one kept
    assert groups_attributed_to_campaign(kb, _campaign(1)) == (_group(2),)
    # reverse: querying the inactive Group resolves fine but yields nothing
    assert campaigns_attributed_to_group(kb, _group(1)) == ()


def test_relationship_type_must_be_exactly_attributed_to(tmp_path: Path) -> None:
    kb = _build_kb(
        tmp_path,
        groups={_group(1): _ACTIVE},
        campaigns={_campaign(1): _ACTIVE},
        edges=[
            _edge(1, _campaign(1), _group(1), rel_type="uses"),
            _edge(2, _campaign(1), _group(1), rel_type="attributed_to"),
        ],
    )
    assert groups_attributed_to_campaign(kb, _campaign(1)) == ()
    assert campaigns_attributed_to_group(kb, _group(1)) == ()


def test_edge_to_non_group_target_is_ignored(tmp_path: Path) -> None:
    kb = _build_kb(
        tmp_path,
        groups={_group(1): _ACTIVE},
        campaigns={_campaign(1): _ACTIVE, _campaign(2): _ACTIVE},
        edges=[_edge(1, _campaign(1), _campaign(2)), _edge(2, _campaign(1), _TECHNIQUE)],
    )
    assert groups_attributed_to_campaign(kb, _campaign(1)) == ()


# ===========================================================================
# 7-10. Fail-closed / empty behaviour
# ===========================================================================


def test_unknown_campaign_id_fails_closed(tmp_path: Path) -> None:
    kb = _build_kb(tmp_path, groups={_group(1): _ACTIVE}, campaigns={}, edges=[])
    with pytest.raises(UnknownAttackEntityError):
        groups_attributed_to_campaign(kb, _UNKNOWN_ID)


def test_unknown_group_id_fails_closed(tmp_path: Path) -> None:
    kb = _build_kb(tmp_path, groups={}, campaigns={_campaign(1): _ACTIVE}, edges=[])
    with pytest.raises(UnknownAttackEntityError):
        campaigns_attributed_to_group(kb, _group(99))


def test_wrong_entity_type_fails_closed(tmp_path: Path) -> None:
    kb = _build_kb(
        tmp_path,
        groups={_group(1): _ACTIVE},
        campaigns={_campaign(1): _ACTIVE},
        edges=[_edge(1, _campaign(1), _group(1))],
    )
    with pytest.raises(UnknownAttackEntityError):
        groups_attributed_to_campaign(kb, _group(1))  # a Group, not a campaign
    with pytest.raises(UnknownAttackEntityError):
        groups_attributed_to_campaign(kb, _TECHNIQUE)
    with pytest.raises(UnknownAttackEntityError):
        campaigns_attributed_to_group(kb, _campaign(1))  # a campaign, not a Group
    with pytest.raises(UnknownAttackEntityError):
        campaigns_attributed_to_group(kb, _TECHNIQUE)


def test_no_matching_relationship_returns_empty_tuple(tmp_path: Path) -> None:
    kb = _build_kb(
        tmp_path, groups={_group(1): _ACTIVE}, campaigns={_campaign(1): _ACTIVE}, edges=[]
    )
    assert groups_attributed_to_campaign(kb, _campaign(1)) == ()
    assert campaigns_attributed_to_group(kb, _group(1)) == ()


# ===========================================================================
# Real pinned bundle (facts discovered dynamically, not hard-coded)
# ===========================================================================


def _real_active_edges(kb: AttackKnowledge) -> list[tuple[str, str]]:
    edges = []
    for rel in kb.relationships():
        if rel.get("relationship_type") != _REL or not is_active(rel):
            continue
        source, target = kb.get_by_id(str(rel["source_ref"])), kb.get_by_id(str(rel["target_ref"]))
        if (
            source is not None
            and target is not None
            and source.get("type") == "campaign"
            and target.get("type") == "intrusion-set"
            and is_active(target)
        ):
            edges.append((str(rel["source_ref"]), str(rel["target_ref"])))
    return edges


def test_real_bundle_forward_and_reverse_are_consistent() -> None:
    kb = load_attack_knowledge()
    edges = _real_active_edges(kb)
    assert edges, "expected active campaign->group attributed-to edges in the real v19.0 bundle"
    expected_forward: dict[str, set[str]] = {}
    expected_reverse: dict[str, set[str]] = {}
    for campaign_id, group_id in edges:
        expected_forward.setdefault(campaign_id, set()).add(group_id)
        expected_reverse.setdefault(group_id, set()).add(campaign_id)
    for campaign_id, group_ids in expected_forward.items():
        assert groups_attributed_to_campaign(kb, campaign_id) == tuple(sorted(group_ids))
    for group_id, campaign_ids in expected_reverse.items():
        assert campaigns_attributed_to_group(kb, group_id) == tuple(sorted(campaign_ids))


def test_real_bundle_repeated_and_fresh_load_results_identical() -> None:
    kb = load_attack_knowledge()
    fresh = load_attack_knowledge()
    for campaign_id, group_id in _real_active_edges(kb):
        first = groups_attributed_to_campaign(kb, campaign_id)
        assert first == groups_attributed_to_campaign(kb, campaign_id)
        assert first == groups_attributed_to_campaign(fresh, campaign_id)
        assert campaigns_attributed_to_group(kb, group_id) == campaigns_attributed_to_group(
            fresh, group_id
        )


def test_real_bundle_knowledge_not_mutated() -> None:
    kb = load_attack_knowledge()
    before = (
        kb.attack_kb_version,
        len(kb.relationships()),
        len(kb.groups()),
        len(kb.campaigns()),
        kb.object_fingerprint,
    )
    for campaign in kb.campaigns():
        cid = str(campaign["id"])
        groups_attributed_to_campaign(kb, cid)
    for group in kb.groups():
        campaigns_attributed_to_group(kb, str(group["id"]))
    after = (
        kb.attack_kb_version,
        len(kb.relationships()),
        len(kb.groups()),
        len(kb.campaigns()),
        kb.object_fingerprint,
    )
    assert before == after


def test_real_bundle_every_result_is_active_group_or_campaign_typed() -> None:
    kb = load_attack_knowledge()
    for source_campaign in kb.campaigns():
        for gid in groups_attributed_to_campaign(kb, str(source_campaign["id"])):
            result_group = kb.get_by_id(gid)
            assert result_group is not None
            assert result_group["type"] == "intrusion-set" and is_active(result_group)
    for source_group in kb.groups():
        for cid in campaigns_attributed_to_group(kb, str(source_group["id"])):
            result_campaign = kb.get_by_id(cid)
            assert result_campaign is not None and result_campaign["type"] == "campaign"


# ===========================================================================
# 12-13. Determinism, PYTHONHASHSEED independence, in-memory non-mutation
# ===========================================================================

_SUBPROCESS = """
from attribution_platform.attack_knowledge.loader import load_attack_knowledge
from attribution_platform.attack_knowledge.traversal import (
    campaigns_attributed_to_group, groups_attributed_to_campaign)
kb = load_attack_knowledge()
out = []
for c in kb.campaigns():
    out.append(str(c["id"]) + ">" + ",".join(groups_attributed_to_campaign(kb, str(c["id"]))))
for g in kb.groups():
    out.append(str(g["id"]) + "<" + ",".join(campaigns_attributed_to_group(kb, str(g["id"]))))
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


def test_pythonhashseed_independent() -> None:
    first = _run_under_seed("0")
    assert first  # non-vacuous: real output was produced
    assert first == _run_under_seed("1") == _run_under_seed("424242")


def test_synthetic_repeated_calls_identical_and_kb_unchanged(tmp_path: Path) -> None:
    kb = _build_kb(
        tmp_path,
        groups={_group(1): _ACTIVE, _group(2): {"revoked": True}},
        campaigns={_campaign(1): _ACTIVE},
        edges=[_edge(1, _campaign(1), _group(1)), _edge(2, _campaign(1), _group(2))],
    )
    fingerprint = kb.object_fingerprint
    relationships = kb.relationships()
    runs = [groups_attributed_to_campaign(kb, _campaign(1)) for _ in range(3)]
    assert runs[0] == runs[1] == runs[2] == (_group(1),)
    assert kb.object_fingerprint is fingerprint
    assert kb.relationships() is relationships


# ===========================================================================
# Boundaries: P1 does not touch group_profile / consume as evidence
# ===========================================================================


def test_group_profile_behaviour_unchanged_by_attributed_to_edges(tmp_path: Path) -> None:
    # attributed-to edges are not `uses` edges: group_profile() must ignore them.
    kb = _build_kb(
        tmp_path,
        groups={_group(1): _ACTIVE},
        campaigns={_campaign(1): _ACTIVE},
        edges=[_edge(1, _campaign(1), _group(1))],
    )
    assert group_profile(kb, _group(1)) == ()
    assert group_profile(kb, _campaign(1)) == ()


def test_new_functions_take_only_knowledge_and_one_id() -> None:
    import inspect

    for func in (groups_attributed_to_campaign, campaigns_attributed_to_group):
        params = list(inspect.signature(func).parameters)
        assert len(params) == 2 and params[0] == "knowledge"


def test_traversal_module_still_free_of_scoring_vocabulary() -> None:
    tree = ast.parse(Path(traversal_module.__file__).read_text(encoding="utf-8"))
    names = {n.name.lower() for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)}
    assert {"groups_attributed_to_campaign", "campaigns_attributed_to_group"} <= names
    for forbidden in ("candidate", "hypothesis", "likelihood", "confidence", "calibration"):
        assert not any(forbidden in name for name in names)
