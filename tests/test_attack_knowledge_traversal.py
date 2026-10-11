"""Tests for gate G3.1: ATT&CK knowledge traversal and entity resolution.

Covers: canonical entity resolution (fail-closed on unknown ids), alias
resolution (including genuine ambiguity across active entities, discovered
dynamically from the real pinned bundle rather than hard-coded), active/
revoked/deprecated filtering, forward/reverse ``uses``-relationship
traversal, multi-technique combination/intersection queries, determinism,
no-network operation, pinned-version scoping, and non-mutation of the
underlying loaded knowledge.

All facts asserted about specific ATT&CK content (which group is revoked,
which alias collides, etc.) are *discovered* from the real vendored v19.0
bundle at test time rather than hard-coded — mirroring
``test_attack_knowledge_loader.py``'s own "no hard-coded ATT&CK vocabulary"
discipline, extended here to test *logic* as well as test *literals*, so
these tests keep working if a future deliberate KB upgrade changes which
specific groups/aliases happen to collide.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from attribution_platform.attack_knowledge import traversal as traversal_module
from attribution_platform.attack_knowledge.loader import AttackKnowledge, load_attack_knowledge
from attribution_platform.attack_knowledge.traversal import (
    AmbiguousAliasError,
    InvalidCombinationQueryError,
    UnknownAttackEntityError,
    active_campaigns,
    active_groups,
    aliases_for,
    campaigns_using_all_techniques,
    campaigns_using_technique,
    group_profile,
    groups_using_all_techniques,
    groups_using_software,
    groups_using_technique,
    is_active,
    resolve_alias,
    resolve_entity,
    software_used_by,
    software_using_technique,
    techniques_used_by,
)

_UNKNOWN_STIX_ID = "attack-pattern--00000000-0000-0000-0000-000000000000"


# ===========================================================================
# 1. Entity resolution
# ===========================================================================


def test_resolve_entity_returns_the_canonical_object_for_a_known_id() -> None:
    kb = load_attack_knowledge()
    technique = kb.techniques()[0]
    resolved = resolve_entity(kb, technique["id"])
    assert resolved is technique


def test_resolve_entity_honors_expected_type() -> None:
    kb = load_attack_knowledge()
    group = kb.groups()[0]
    resolved = resolve_entity(kb, group["id"], expected_type="intrusion-set")
    assert resolved is group


def test_resolve_entity_fails_closed_on_unknown_id() -> None:
    kb = load_attack_knowledge()
    with pytest.raises(UnknownAttackEntityError):
        resolve_entity(kb, _UNKNOWN_STIX_ID)


def test_resolve_entity_fails_closed_on_type_mismatch() -> None:
    kb = load_attack_knowledge()
    technique = kb.techniques()[0]
    with pytest.raises(UnknownAttackEntityError):
        resolve_entity(kb, technique["id"], expected_type="intrusion-set")


# ===========================================================================
# 2. Alias resolution
# ===========================================================================


def _find_active_group_with_multiple_aliases(kb: AttackKnowledge) -> str:
    for group in active_groups(kb):
        group_id = str(group["id"])
        if len(aliases_for(kb, group_id)) >= 2:
            return group_id
    pytest.fail("expected at least one active group with >=2 aliases in the real v19.0 bundle")


def _find_ambiguous_active_alias(kb: AttackKnowledge) -> tuple[str, str, str]:
    """Dynamically discover a real alias string shared by two distinct
    active Groups in the pinned bundle (this genuinely occurs in v19.0 —
    verified against the vendored artifact, not assumed)."""
    alias_to_ids: dict[str, set[str]] = {}
    for group in active_groups(kb):
        for alias in aliases_for(kb, group["id"]):
            key = alias.strip().casefold()
            alias_to_ids.setdefault(key, set()).add(str(group["id"]))
    for alias_key, ids in alias_to_ids.items():
        if len(ids) > 1:
            sorted_ids = tuple(sorted(ids))
            return alias_key, sorted_ids[0], sorted_ids[1]
    pytest.fail(
        "expected at least one alias shared by two distinct active groups in the "
        "real v19.0 bundle"
    )


def test_group_alias_resolves_to_canonical_group_id() -> None:
    kb = load_attack_knowledge()
    group_id = _find_active_group_with_multiple_aliases(kb)
    alias = next(iter(aliases_for(kb, group_id)))
    assert resolve_alias(kb, alias) == group_id


def test_multiple_aliases_of_one_group_resolve_to_the_same_canonical_id() -> None:
    kb = load_attack_knowledge()
    group_id = _find_active_group_with_multiple_aliases(kb)
    aliases = tuple(aliases_for(kb, group_id))
    resolved_ids = {resolve_alias(kb, alias) for alias in aliases}
    assert resolved_ids == {group_id}


def test_alias_resolution_is_case_and_whitespace_insensitive() -> None:
    kb = load_attack_knowledge()
    group_id = _find_active_group_with_multiple_aliases(kb)
    alias = next(iter(aliases_for(kb, group_id)))
    assert resolve_alias(kb, f"  {alias.upper()}  ") == group_id


def test_ambiguous_alias_across_active_groups_does_not_arbitrarily_resolve() -> None:
    kb = load_attack_knowledge()
    alias_key, _first_id, _second_id = _find_ambiguous_active_alias(kb)
    with pytest.raises(AmbiguousAliasError):
        resolve_alias(kb, alias_key)


def test_unknown_alias_fails_closed_rather_than_guessing() -> None:
    kb = load_attack_knowledge()
    with pytest.raises(UnknownAttackEntityError):
        resolve_alias(kb, "this-alias-does-not-exist-in-any-active-entity-xyz123")


def test_aliases_for_fails_closed_on_unknown_id() -> None:
    kb = load_attack_knowledge()
    with pytest.raises(UnknownAttackEntityError):
        aliases_for(kb, _UNKNOWN_STIX_ID)


# ===========================================================================
# 3. Active / revoked / deprecated filtering
# ===========================================================================


def _find_group(kb: AttackKnowledge, *, revoked: bool, deprecated: bool) -> str:
    for group in kb.groups():
        if (
            bool(group.get("revoked")) is revoked
            and bool(group.get("x_mitre_deprecated")) is deprecated
        ):
            return str(group["id"])
    pytest.fail(f"expected a group with revoked={revoked}, deprecated={deprecated}")


def test_revoked_group_is_not_active_and_is_excluded_from_active_groups() -> None:
    kb = load_attack_knowledge()
    revoked_group_id = _find_group(kb, revoked=True, deprecated=False)
    revoked_group = kb.get_by_id(revoked_group_id)
    assert revoked_group is not None
    assert is_active(revoked_group) is False
    active_ids = {g["id"] for g in active_groups(kb)}
    assert revoked_group_id not in active_ids


def test_deprecated_group_is_not_active_and_is_excluded_from_active_groups() -> None:
    kb = load_attack_knowledge()
    deprecated_group_id = _find_group(kb, revoked=False, deprecated=True)
    deprecated_group = kb.get_by_id(deprecated_group_id)
    assert deprecated_group is not None
    assert is_active(deprecated_group) is False
    active_ids = {g["id"] for g in active_groups(kb)}
    assert deprecated_group_id not in active_ids


def test_active_groups_excludes_every_revoked_or_deprecated_group() -> None:
    kb = load_attack_knowledge()
    active_ids = {g["id"] for g in active_groups(kb)}
    for group in kb.groups():
        if group.get("revoked") or group.get("x_mitre_deprecated"):
            assert group["id"] not in active_ids
        else:
            assert group["id"] in active_ids


def test_active_groups_count_matches_manual_filter() -> None:
    kb = load_attack_knowledge()
    expected = sum(
        1 for g in kb.groups() if not g.get("revoked") and not g.get("x_mitre_deprecated")
    )
    assert len(active_groups(kb)) == expected


# ===========================================================================
# 4. Forward relationship traversal
# ===========================================================================


def _find_real_uses_edge(
    kb: AttackKnowledge, source_type: str, target_type: str = "attack-pattern"
) -> tuple[str, str]:
    for rel in kb.relationships():
        if rel.get("relationship_type") != "uses":
            continue
        source = kb.get_by_id(rel["source_ref"])
        target = kb.get_by_id(rel["target_ref"])
        if (
            source is not None
            and target is not None
            and source.get("type") == source_type
            and target.get("type") == target_type
        ):
            return str(rel["source_ref"]), str(rel["target_ref"])
    pytest.fail(f"expected a real 'uses' edge {source_type} -> {target_type} in the v19.0 bundle")


def _find_active_uses_edge(
    kb: AttackKnowledge, source_type: str, target_type: str = "attack-pattern"
) -> tuple[str, str]:
    """Same as :func:`_find_real_uses_edge`, but additionally guarantees the
    *source* object is active -- used by reverse-traversal tests that assert
    active-only filtering, so they deterministically exercise the assertion
    instead of skipping when the first-found edge happens to belong to a
    revoked/deprecated source."""
    for rel in kb.relationships():
        if rel.get("relationship_type") != "uses":
            continue
        source = kb.get_by_id(rel["source_ref"])
        target = kb.get_by_id(rel["target_ref"])
        if (
            source is not None
            and target is not None
            and source.get("type") == source_type
            and target.get("type") == target_type
            and is_active(source)
        ):
            return str(rel["source_ref"]), str(rel["target_ref"])
    pytest.fail(
        f"expected a real, ACTIVE-sourced 'uses' edge {source_type} -> {target_type} "
        "in the v19.0 bundle"
    )


def test_group_to_technique_forward_traversal() -> None:
    kb = load_attack_knowledge()
    group_id, technique_id = _find_real_uses_edge(kb, "intrusion-set")
    assert technique_id in techniques_used_by(kb, group_id)
    assert technique_id in group_profile(kb, group_id)


def test_campaign_to_technique_forward_traversal() -> None:
    kb = load_attack_knowledge()
    campaign_id, technique_id = _find_real_uses_edge(kb, "campaign")
    assert technique_id in techniques_used_by(kb, campaign_id)
    assert technique_id in group_profile(kb, campaign_id)


def test_software_to_technique_forward_traversal() -> None:
    kb = load_attack_knowledge()
    software_id, technique_id = _find_real_uses_edge(kb, "malware")
    assert technique_id in techniques_used_by(kb, software_id)


# ===========================================================================
# 5. Reverse relationship traversal
# ===========================================================================


def test_technique_to_group_reverse_traversal() -> None:
    kb = load_attack_knowledge()
    group_id, technique_id = _find_active_uses_edge(kb, "intrusion-set")
    assert group_id in groups_using_technique(kb, technique_id)


def test_technique_to_campaign_reverse_traversal() -> None:
    kb = load_attack_knowledge()
    campaign_id, technique_id = _find_active_uses_edge(kb, "campaign")
    assert campaign_id in campaigns_using_technique(kb, technique_id)


def test_technique_to_software_reverse_traversal() -> None:
    kb = load_attack_knowledge()
    software_id, technique_id = _find_real_uses_edge(kb, "malware")
    assert software_id in software_using_technique(kb, technique_id)


def test_groups_using_technique_only_returns_active_groups() -> None:
    kb = load_attack_knowledge()
    # Find a technique used by at least one active group, then confirm no
    # revoked/deprecated group id ever appears in the reverse result.
    technique = next(t for t in kb.techniques() if groups_using_technique(kb, t["id"]) != ())
    active_ids = {g["id"] for g in active_groups(kb)}
    for group_id in groups_using_technique(kb, technique["id"]):
        assert group_id in active_ids


def test_groups_using_software_reverse_traversal_and_type_guard() -> None:
    kb = load_attack_knowledge()
    group_id, software_id = _find_active_uses_edge(kb, "intrusion-set", target_type="malware")
    assert group_id in groups_using_software(kb, software_id)
    with pytest.raises(UnknownAttackEntityError):
        groups_using_software(kb, kb.techniques()[0]["id"])


def test_software_used_by_matches_techniques_used_by_split() -> None:
    kb = load_attack_knowledge()
    group_id, _technique_id = _find_real_uses_edge(kb, "intrusion-set")
    full_profile = set(group_profile(kb, group_id))
    split = set(techniques_used_by(kb, group_id)) | set(software_used_by(kb, group_id))
    assert split == full_profile


# ===========================================================================
# 6. Combination / intersection queries
# ===========================================================================


def test_multi_technique_intersection_query_returns_a_real_matching_group() -> None:
    kb = load_attack_knowledge()
    group = next(g for g in active_groups(kb) if len(techniques_used_by(kb, g["id"])) >= 2)
    techniques = techniques_used_by(kb, group["id"])[:2]
    combo = frozenset(techniques)
    result = groups_using_all_techniques(kb, combo)
    assert group["id"] in result
    for matched_id in result:
        assert combo <= set(group_profile(kb, matched_id))


def test_campaign_multi_technique_intersection_query() -> None:
    kb = load_attack_knowledge()
    campaign = next(c for c in active_campaigns(kb) if len(techniques_used_by(kb, c["id"])) >= 2)
    techniques = techniques_used_by(kb, campaign["id"])[:2]
    combo = frozenset(techniques)
    result = campaigns_using_all_techniques(kb, combo)
    assert campaign["id"] in result


def test_empty_intersection_returns_empty_tuple_without_raising() -> None:
    kb = load_attack_knowledge()
    # A technique used by exactly one active group, combined with a
    # technique that group does NOT use, guarantees zero active groups can
    # satisfy the combination (only that one group could satisfy the first
    # member, and it fails the second) -- a deterministic, provably-empty
    # case rather than an assumed one.
    sole_user_technique: str | None = None
    sole_group_id: str | None = None
    for technique in kb.techniques():
        users = groups_using_technique(kb, technique["id"])
        if len(users) == 1:
            sole_user_technique = str(technique["id"])
            sole_group_id = users[0]
            break
    if sole_user_technique is None or sole_group_id is None:
        pytest.skip("no technique with exactly one active-group user found in this bundle")

    sole_group_profile = set(techniques_used_by(kb, sole_group_id))
    other_technique = next(t["id"] for t in kb.techniques() if t["id"] not in sole_group_profile)

    result = groups_using_all_techniques(kb, frozenset({sole_user_technique, other_technique}))
    assert result == ()


def test_combination_query_rejects_empty_technique_set() -> None:
    kb = load_attack_knowledge()
    with pytest.raises(InvalidCombinationQueryError):
        groups_using_all_techniques(kb, frozenset())


def test_combination_query_fails_closed_on_unknown_technique_id() -> None:
    kb = load_attack_knowledge()
    with pytest.raises(UnknownAttackEntityError):
        groups_using_all_techniques(kb, frozenset({_UNKNOWN_STIX_ID}))


# ===========================================================================
# 7. Determinism
# ===========================================================================


def test_traversal_queries_are_deterministic_across_repeated_calls() -> None:
    kb = load_attack_knowledge()
    group_id, technique_id = _find_real_uses_edge(kb, "intrusion-set")

    assert techniques_used_by(kb, group_id) == techniques_used_by(kb, group_id)
    assert groups_using_technique(kb, technique_id) == groups_using_technique(kb, technique_id)
    assert active_groups(kb) == active_groups(kb)


def test_returned_id_tuples_are_sorted() -> None:
    kb = load_attack_knowledge()
    group_id, _technique_id = _find_real_uses_edge(kb, "intrusion-set")
    profile = techniques_used_by(kb, group_id)
    assert profile == tuple(sorted(profile))

    group_ids = tuple(g["id"] for g in active_groups(kb))
    assert group_ids == tuple(sorted(group_ids))


def test_deterministic_result_independent_of_a_second_freshly_loaded_kb() -> None:
    """Two independently loaded KB instances (same pinned artifact) must
    produce logically identical traversal results -- not merely stable
    within one process's object identity."""
    kb1 = load_attack_knowledge()
    kb2 = load_attack_knowledge()
    group_id, technique_id = _find_real_uses_edge(kb1, "intrusion-set")

    assert techniques_used_by(kb1, group_id) == techniques_used_by(kb2, group_id)
    assert groups_using_technique(kb1, technique_id) == groups_using_technique(kb2, technique_id)
    assert {g["id"] for g in active_groups(kb1)} == {g["id"] for g in active_groups(kb2)}


# ===========================================================================
# 8. No network dependency
# ===========================================================================


def test_traversal_module_imports_no_networking_libraries() -> None:
    for name in ("socket", "urllib", "http", "requests"):
        assert not hasattr(traversal_module, name), f"traversal.py must not import {name!r}"


def test_traversal_queries_work_with_network_forcibly_blocked() -> None:
    import socket
    from typing import Any

    original_connect = socket.socket.connect
    original_connect_ex = socket.socket.connect_ex

    def _blocked(self: Any, *_args: Any, **_kwargs: Any) -> Any:
        raise RuntimeError("NETWORK ACCESS BLOCKED FOR TEST")

    socket.socket.connect = _blocked  # type: ignore[method-assign]
    socket.socket.connect_ex = _blocked  # type: ignore[method-assign]
    try:
        kb = load_attack_knowledge()
        group_id, technique_id = _find_real_uses_edge(kb, "intrusion-set")
        assert technique_id in techniques_used_by(kb, group_id)
        assert len(active_groups(kb)) > 0
    finally:
        socket.socket.connect = original_connect  # type: ignore[method-assign]
        socket.socket.connect_ex = original_connect_ex  # type: ignore[method-assign]


# ===========================================================================
# 9. Pinned v19.0 version exposure
# ===========================================================================


def test_traversal_functions_take_no_version_or_path_argument() -> None:
    """Every public traversal function operates only on an already-loaded
    AttackKnowledge -- there is no version-string or path parameter a caller
    could use to redirect a query to a different/arbitrary KB."""
    import inspect
    from collections.abc import Callable
    from typing import Any

    public_functions: list[Callable[..., Any]] = [
        resolve_entity,
        aliases_for,
        resolve_alias,
        active_groups,
        active_campaigns,
        group_profile,
        techniques_used_by,
        software_used_by,
        groups_using_technique,
        campaigns_using_technique,
        groups_using_all_techniques,
        campaigns_using_all_techniques,
    ]
    forbidden_param_names = {"attack_kb_version", "version", "path", "artifact_dir", "kb_version"}
    for func in public_functions:
        params = inspect.signature(func).parameters
        assert (
            next(iter(params)) == "knowledge"
        ), f"{func.__name__} must take the already-loaded `knowledge` as its first parameter"
        assert forbidden_param_names.isdisjoint(
            params.keys()
        ), f"{func.__name__} must not accept a version/path override parameter"


def test_unknown_entity_error_message_names_the_pinned_kb_version() -> None:
    kb = load_attack_knowledge()
    with pytest.raises(UnknownAttackEntityError, match=re.escape(kb.attack_kb_version)):
        resolve_entity(kb, _UNKNOWN_STIX_ID)


# ===========================================================================
# 10. No mutation of the underlying knowledge artifact
# ===========================================================================


def test_traversal_queries_do_not_mutate_loaded_objects() -> None:
    kb = load_attack_knowledge()
    group_id, technique_id = _find_real_uses_edge(kb, "intrusion-set")
    before_obj = kb.get_by_id(group_id)
    assert before_obj is not None
    before = dict(before_obj)

    techniques_used_by(kb, group_id)
    groups_using_technique(kb, technique_id)
    group_profile(kb, group_id)
    active_groups(kb)
    aliases_for(kb, group_id)

    after_obj = kb.get_by_id(group_id)
    assert after_obj is not None
    after = dict(after_obj)
    assert before == after
    assert kb.get_by_id(group_id) is kb.get_by_id(group_id)


def test_traversal_queries_do_not_change_object_counts() -> None:
    kb = load_attack_knowledge()
    fingerprint_before = kb.object_fingerprint
    group_id, technique_id = _find_real_uses_edge(kb, "intrusion-set")

    groups_using_all_techniques(kb, frozenset({technique_id}))
    software_used_by(kb, group_id)

    assert kb.object_fingerprint == fingerprint_before
    assert kb.object_fingerprint is fingerprint_before


# ===========================================================================
# 11. No hard-coded ATT&CK vocabulary in the traversal source
# ===========================================================================

_TECHNIQUE_ID_PATTERN = r"\bT\d{4}(\.\d{3})?\b"
_TACTIC_ID_PATTERN = r"\bTA\d{4}\b"


def test_traversal_source_contains_no_hard_coded_technique_or_tactic_ids() -> None:
    source_path = Path(traversal_module.__file__)
    source_text = source_path.read_text(encoding="utf-8")

    assert not re.findall(_TECHNIQUE_ID_PATTERN, source_text)
    assert not re.findall(_TACTIC_ID_PATTERN, source_text)


def test_traversal_module_never_references_scoring_or_calibration_vocabulary() -> None:
    """Structural guard: this gate must not creep into D3/D7+ territory --
    the traversal module source must never bind an identifier belonging to
    diagnosticity/candidate/likelihood/confidence machinery."""
    import ast

    source_path = Path(traversal_module.__file__)
    tree = ast.parse(source_path.read_text(encoding="utf-8"))
    forbidden_substrings = (
        "diagnosticity",
        "candidate",
        "hypothesis",
        "likelihood",
        "confidence",
        "calibration",
        "attributionresult",
    )
    identifiers = (
        {node.id.lower() for node in ast.walk(tree) if isinstance(node, ast.Name)}
        | {node.attr.lower() for node in ast.walk(tree) if isinstance(node, ast.Attribute)}
        | {
            node.name.lower()
            for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef | ast.ClassDef)
        }
    )
    for identifier in identifiers:
        for forbidden in forbidden_substrings:
            assert forbidden not in identifier, (
                f"traversal.py binds identifier {identifier!r} referencing "
                f"out-of-scope vocabulary {forbidden!r}"
            )


# ===========================================================================
# Relationship indexes are remembered per knowledge base (ADR-0009 Amendment D)
# ===========================================================================


def test_relationship_index_is_built_once_per_knowledge_base_and_read_only() -> None:
    import dataclasses
    import gc

    from attribution_platform.attack_knowledge import traversal
    from attribution_platform.attack_knowledge.loader import load_attack_knowledge

    knowledge = load_attack_knowledge()
    first = traversal._uses_index_by_target(knowledge)
    assert traversal._uses_index_by_target(knowledge) is first  # remembered
    assert dict(first) == traversal._build_uses_index_by_target(knowledge)  # and unchanged
    with pytest.raises(TypeError):
        first["x"] = frozenset()  # type: ignore[index]

    # An equal but distinct knowledge base gets its own index, never another's.
    twin = dataclasses.replace(knowledge)
    other = traversal._uses_index_by_target(twin)
    assert other is not first and dict(other) == dict(first)
    key = (id(twin), "uses_by_target")
    assert key in traversal._INDEXES
    del twin, other
    gc.collect()
    assert key not in traversal._INDEXES  # dropped with its knowledge base
