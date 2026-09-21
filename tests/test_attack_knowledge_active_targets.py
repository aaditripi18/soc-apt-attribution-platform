"""Tests for prerequisite P2: the ATT&CK **active-target policy** applied to
forward ``uses`` profiles (ADR-0005 Amendment B "Active-target policy for
``ProfileBreadth`` and every prevalence/traversal quantity"; ADR-0006
§Decision-path scale).

P2 makes :func:`group_profile`, :func:`techniques_used_by`, and
:func:`software_used_by` exclude **revoked / deprecated target** techniques and
software from a source's profile, via the single shared active predicate
:func:`~attribution_platform.attack_knowledge.traversal.is_active` (no second
definition of "active"). It changes nothing else: reverse lookups
(``groups_using_technique`` = ``g(x)``) and the combination superset queries
(``groups_using_all_techniques`` = ``g(C)``) already restrict the *source*
population to active Groups/Campaigns and are untouched.

The real pinned v19.0 bundle's curated ``uses`` edges point at active targets,
so the exclusion behaviour is exercised with small synthetic bundles built with
the same verified-fixture pattern the G3.5 / P1 tests established; the real
bundle is used for determinism, PYTHONHASHSEED-independence and non-mutation.
Offline, deterministic, no Elastic/Docker/network required.
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
    group_profile,
    groups_using_technique,
    is_active,
    software_used_by,
    techniques_used_by,
)
from attribution_platform.attack_knowledge.verification import EXPECTED_ARTIFACT_FILENAME

_ACTIVE: dict[str, bool] = {}


def _tech(i: int) -> str:
    return f"attack-pattern--{i:08d}-0000-0000-0000-000000000000"


def _malware(i: int) -> str:
    return f"malware--{i:08d}-0000-0000-0000-000000000000"


def _tool(i: int) -> str:
    return f"tool--{i:08d}-0000-0000-0000-000000000000"


def _grp(i: int) -> str:
    return f"intrusion-set--{i:08d}-0000-0000-0000-000000000000"


def _camp(i: int) -> str:
    return f"campaign--{i:08d}-0000-0000-0000-000000000000"


def _uses_edge(i: int, source: str, target: str) -> dict[str, Any]:
    return {
        "type": "relationship",
        "id": f"relationship--{i:08d}-0000-0000-0000-000000000000",
        "relationship_type": "uses",
        "source_ref": source,
        "target_ref": target,
    }


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
    software: dict[str, dict[str, bool]] | None = None,
    groups: dict[str, dict[str, bool]] | None = None,
    campaigns: dict[str, dict[str, bool]] | None = None,
    uses: list[tuple[str, str]],
) -> AttackKnowledge:
    """Verified synthetic bundle with ``uses`` edges whose *targets* may be
    revoked/deprecated. ``techniques``/``software``/``groups``/``campaigns``
    map STIX id -> flags (``revoked`` / ``deprecated``); a software id's STIX
    type is taken from its ``malware--`` / ``tool--`` prefix. One ``uses``
    relationship is emitted per ``(source, target)`` pair in ``uses``.
    """
    software = software or {}
    groups = groups or {}
    campaigns = campaigns or {}
    objects: list[dict[str, Any]] = [
        {
            "type": "x-mitre-collection",
            "id": "x-mitre-collection--p2-fixture",
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
    for sid in sorted(software):
        stix_type = "malware" if sid.startswith("malware--") else "tool"
        objects.append(
            _flagged({"type": stix_type, "id": sid, "name": sid, "aliases": [sid]}, software[sid])
        )
    for stix_type, entities in (("intrusion-set", groups), ("campaign", campaigns)):
        for stix_id in sorted(entities):
            objects.append(
                _flagged(
                    {"type": stix_type, "id": stix_id, "name": stix_id, "aliases": [stix_id]},
                    entities[stix_id],
                )
            )
    for i, (source, target) in enumerate(uses, start=1):
        objects.append(_uses_edge(i, source, target))

    bundle = {"type": "bundle", "id": "bundle--p2-fixture", "objects": objects}
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


# ===========================================================================
# 1. Active targets are included; revoked / deprecated targets are excluded
# ===========================================================================


def test_group_profile_includes_active_technique_and_software_targets(tmp_path: Path) -> None:
    kb = _build_kb(
        tmp_path,
        techniques={_tech(1): _ACTIVE},
        software={_malware(1): _ACTIVE, _tool(1): _ACTIVE},
        groups={_grp(1): _ACTIVE},
        uses=[(_grp(1), _tech(1)), (_grp(1), _malware(1)), (_grp(1), _tool(1))],
    )
    # canonical STIX-id sort: "attack-pattern" < "malware" < "tool"
    assert group_profile(kb, _grp(1)) == (_tech(1), _malware(1), _tool(1))


@pytest.mark.parametrize("flag", ["revoked", "deprecated"])
def test_group_profile_excludes_inactive_technique_target(tmp_path: Path, flag: str) -> None:
    kb = _build_kb(
        tmp_path,
        techniques={_tech(1): _ACTIVE, _tech(2): {flag: True}},
        groups={_grp(1): _ACTIVE},
        uses=[(_grp(1), _tech(1)), (_grp(1), _tech(2))],
    )
    assert group_profile(kb, _grp(1)) == (_tech(1),)


@pytest.mark.parametrize("flag", ["revoked", "deprecated"])
def test_group_profile_excludes_inactive_software_target(tmp_path: Path, flag: str) -> None:
    kb = _build_kb(
        tmp_path,
        techniques={_tech(1): _ACTIVE},
        software={_malware(1): _ACTIVE, _malware(2): {flag: True}},
        groups={_grp(1): _ACTIVE},
        uses=[(_grp(1), _tech(1)), (_grp(1), _malware(1)), (_grp(1), _malware(2))],
    )
    assert group_profile(kb, _grp(1)) == (_tech(1), _malware(1))


def test_group_profile_mixed_targets_returns_active_only_sorted(tmp_path: Path) -> None:
    # A profile with two active + two inactive targets, uses edges emitted in a
    # deliberately non-sorted order -> only the two active ids, canonically sorted.
    kb = _build_kb(
        tmp_path,
        techniques={_tech(1): _ACTIVE, _tech(3): {"revoked": True}},
        software={_malware(1): _ACTIVE, _tool(3): {"deprecated": True}},
        groups={_grp(1): _ACTIVE},
        uses=[
            (_grp(1), _tool(3)),
            (_grp(1), _tech(3)),
            (_grp(1), _tech(1)),
            (_grp(1), _malware(1)),
        ],
    )
    profile = group_profile(kb, _grp(1))
    assert profile == (_tech(1), _malware(1))
    assert list(profile) == sorted(profile)


def test_active_target_policy_applies_to_campaign_profiles(tmp_path: Path) -> None:
    kb = _build_kb(
        tmp_path,
        techniques={_tech(1): _ACTIVE, _tech(2): {"revoked": True}},
        campaigns={_camp(1): _ACTIVE},
        uses=[(_camp(1), _tech(1)), (_camp(1), _tech(2))],
    )
    assert group_profile(kb, _camp(1)) == (_tech(1),)


# ===========================================================================
# 2. techniques_used_by / software_used_by apply the same policy consistently
# ===========================================================================


def test_techniques_used_by_excludes_inactive_technique_targets(tmp_path: Path) -> None:
    kb = _build_kb(
        tmp_path,
        techniques={_tech(1): _ACTIVE, _tech(2): {"revoked": True}, _tech(3): {"deprecated": True}},
        software={_malware(1): _ACTIVE},
        groups={_grp(1): _ACTIVE},
        uses=[
            (_grp(1), _tech(1)),
            (_grp(1), _tech(2)),
            (_grp(1), _tech(3)),
            (_grp(1), _malware(1)),
        ],
    )
    assert techniques_used_by(kb, _grp(1)) == (_tech(1),)


def test_software_used_by_excludes_inactive_software_targets(tmp_path: Path) -> None:
    kb = _build_kb(
        tmp_path,
        techniques={_tech(1): _ACTIVE},
        software={
            _malware(1): _ACTIVE,
            _malware(2): {"revoked": True},
            _tool(3): {"deprecated": True},
        },
        groups={_grp(1): _ACTIVE},
        uses=[
            (_grp(1), _tech(1)),
            (_grp(1), _malware(1)),
            (_grp(1), _malware(2)),
            (_grp(1), _tool(3)),
        ],
    )
    assert software_used_by(kb, _grp(1)) == (_malware(1),)


def test_split_invariant_preserved_with_inactive_targets(tmp_path: Path) -> None:
    # group_profile == techniques_used_by ∪ software_used_by must still hold
    # once the active-target filter runs on all three functions consistently.
    kb = _build_kb(
        tmp_path,
        techniques={_tech(1): _ACTIVE, _tech(2): {"revoked": True}},
        software={_malware(1): _ACTIVE, _tool(2): {"deprecated": True}},
        groups={_grp(1): _ACTIVE},
        uses=[
            (_grp(1), _tech(1)),
            (_grp(1), _tech(2)),
            (_grp(1), _malware(1)),
            (_grp(1), _tool(2)),
        ],
    )
    full = set(group_profile(kb, _grp(1)))
    split = set(techniques_used_by(kb, _grp(1))) | set(software_used_by(kb, _grp(1)))
    assert split == full == {_tech(1), _malware(1)}


# ===========================================================================
# 3. Profile breadth (len group_profile) counts only active targets
# ===========================================================================


def test_profile_breadth_counts_only_active_targets(tmp_path: Path) -> None:
    # Two active + three inactive targets -> ProfileBreadth == 2, not 5.
    kb = _build_kb(
        tmp_path,
        techniques={
            _tech(1): _ACTIVE,
            _tech(2): {"revoked": True},
            _tech(3): {"deprecated": True},
        },
        software={_malware(1): _ACTIVE, _malware(2): {"revoked": True}},
        groups={_grp(1): _ACTIVE},
        uses=[
            (_grp(1), _tech(1)),
            (_grp(1), _tech(2)),
            (_grp(1), _tech(3)),
            (_grp(1), _malware(1)),
            (_grp(1), _malware(2)),
        ],
    )
    assert len(group_profile(kb, _grp(1))) == 2


# ===========================================================================
# 4. Regression / non-vacuity: the raw uses set DID contain the inactive
#    target, so pre-P2 group_profile would have returned it.
# ===========================================================================


def test_raw_uses_set_contains_inactive_target_that_profile_now_drops(tmp_path: Path) -> None:
    kb = _build_kb(
        tmp_path,
        techniques={_tech(1): _ACTIVE, _tech(2): {"revoked": True}},
        groups={_grp(1): _ACTIVE},
        uses=[(_grp(1), _tech(1)), (_grp(1), _tech(2))],
    )
    raw = traversal_module._uses_index_by_source(kb).get(_grp(1), frozenset())
    # The unfiltered `uses` index still records the edge to the revoked target
    # (nothing was mutated away) -- pre-P2 group_profile returned this set raw.
    assert raw == {_tech(1), _tech(2)}
    # ...but the active-target policy now drops the revoked target from the profile.
    assert group_profile(kb, _grp(1)) == (_tech(1),)


# ===========================================================================
# 5. Ripple bounds: g(x) source population and all-active behaviour unchanged
# ===========================================================================


def test_gx_reverse_lookup_unaffected_by_a_sources_inactive_targets(tmp_path: Path) -> None:
    # Two active groups use the active technique; one of them also "uses" a
    # revoked technique. g(active technique) counts the active-Group source
    # population and is entirely unaffected by that inactive target.
    kb = _build_kb(
        tmp_path,
        techniques={_tech(1): _ACTIVE, _tech(2): {"revoked": True}},
        groups={_grp(1): _ACTIVE, _grp(2): _ACTIVE},
        uses=[(_grp(1), _tech(1)), (_grp(1), _tech(2)), (_grp(2), _tech(1))],
    )
    assert groups_using_technique(kb, _tech(1)) == (_grp(1), _grp(2))


def test_all_active_kb_profile_equals_full_raw_uses_set(tmp_path: Path) -> None:
    # When nothing is revoked/deprecated, the active-target policy is a no-op:
    # group_profile equals the full raw `uses` set -> G3.4/G3.5 quantities that
    # consume it are unchanged for an all-active KB.
    kb = _build_kb(
        tmp_path,
        techniques={_tech(1): _ACTIVE, _tech(2): _ACTIVE},
        software={_malware(1): _ACTIVE},
        groups={_grp(1): _ACTIVE},
        uses=[(_grp(1), _tech(1)), (_grp(1), _tech(2)), (_grp(1), _malware(1))],
    )
    raw = traversal_module._uses_index_by_source(kb).get(_grp(1), frozenset())
    assert set(group_profile(kb, _grp(1))) == raw == {_tech(1), _tech(2), _malware(1)}


# ===========================================================================
# 6. Determinism, PYTHONHASHSEED independence, non-mutation
# ===========================================================================


def test_repeated_and_fresh_load_profiles_identical(tmp_path: Path) -> None:
    build = dict(
        techniques={_tech(1): _ACTIVE, _tech(2): {"revoked": True}},
        software={_malware(1): _ACTIVE},
        groups={_grp(1): _ACTIVE},
        uses=[(_grp(1), _tech(1)), (_grp(1), _tech(2)), (_grp(1), _malware(1))],
    )
    kb1 = _build_kb(tmp_path / "a", **build)  # type: ignore[arg-type]
    kb2 = _build_kb(tmp_path / "b", **build)  # type: ignore[arg-type]
    first = group_profile(kb1, _grp(1))
    assert first == group_profile(kb1, _grp(1)) == group_profile(kb2, _grp(1))
    assert first == (_tech(1), _malware(1))


_SUBPROCESS = """
from attribution_platform.attack_knowledge.loader import load_attack_knowledge
from attribution_platform.attack_knowledge.traversal import (
    group_profile, software_used_by, techniques_used_by)
kb = load_attack_knowledge()
out = []
for g in sorted(kb.groups(), key=lambda o: str(o["id"]))[:25]:
    gid = str(g["id"])
    out.append(
        gid
        + "|P:" + ",".join(group_profile(kb, gid))
        + "|T:" + ",".join(techniques_used_by(kb, gid))
        + "|S:" + ",".join(software_used_by(kb, gid))
    )
print("~".join(out))
"""


def _run_under_seed(seed: str) -> str:
    return subprocess.run(
        [sys.executable, "-c", _SUBPROCESS],
        capture_output=True,
        text=True,
        env={"PYTHONHASHSEED": seed, "PYTHONPATH": "src"},
        check=True,
    ).stdout.strip()


def test_real_bundle_profiles_pythonhashseed_independent() -> None:
    first = _run_under_seed("0")
    assert first  # non-vacuous: real profiles were produced
    assert first == _run_under_seed("1") == _run_under_seed("424242")


def test_real_bundle_forward_profiles_are_all_active_targets() -> None:
    kb = load_attack_knowledge()
    for group in kb.groups():
        if not is_active(group):
            continue
        for target_id in group_profile(kb, str(group["id"])):
            target = kb.get_by_id(target_id)
            assert target is not None and is_active(target)


def test_profile_queries_do_not_mutate_knowledge(tmp_path: Path) -> None:
    kb = _build_kb(
        tmp_path,
        techniques={_tech(1): _ACTIVE, _tech(2): {"revoked": True}},
        software={_malware(1): _ACTIVE},
        groups={_grp(1): _ACTIVE},
        uses=[(_grp(1), _tech(1)), (_grp(1), _tech(2)), (_grp(1), _malware(1))],
    )
    fingerprint = kb.object_fingerprint
    revoked_before = dict(kb.get_by_id(_tech(2)) or {})

    group_profile(kb, _grp(1))
    techniques_used_by(kb, _grp(1))
    software_used_by(kb, _grp(1))

    assert kb.object_fingerprint is fingerprint
    after = kb.get_by_id(_tech(2))
    assert after is not None and dict(after) == revoked_before
    # the excluded target still physically exists and is still flagged inactive
    assert not is_active(after)
