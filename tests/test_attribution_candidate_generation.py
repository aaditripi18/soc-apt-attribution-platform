"""Tests for gate G3.3: dynamic candidate generation (ADR-0005 §D7).

Covers the required edge-case list using two complementary fixtures:

- A small, deliberately-constructed synthetic ATT&CK bundle (mirroring
  ``test_attack_knowledge_loader.py``'s own ``_write_tiny_valid_fixture``
  pattern) giving full, deterministic control over active/revoked/
  deprecated Groups *and* Campaigns, group+campaign overlap, software
  evidence, and an intentionally-unmatched technique — the real v19.0
  bundle happens to contain **no** revoked/deprecated Campaign at all, so a
  synthetic fixture is the only way to test that exclusion precisely.
- The real, pinned v19.0 bundle for integration/sanity checks: one real
  observed technique produces real, dynamically-discovered Group/Campaign
  candidates; no hard-coded actor vocabulary; determinism across two
  independently-loaded KB instances; no network dependency.

Every real fact used from the v19.0 bundle (which technique has both
Group and Campaign users, etc.) is *discovered* at module-collection time
via the same traversal functions gate G3.1 already tests, not hard-coded
from prior knowledge of ATT&CK content.

Offline, deterministic, no Elastic/Docker/Windows/network required.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path
from typing import Any

import pytest

from attribution_platform.attack_knowledge import verification as verification_module
from attribution_platform.attack_knowledge.loader import (
    AttackKnowledge,
    _load_from_dir,
    load_attack_knowledge,
)
from attribution_platform.attack_knowledge.traversal import (
    campaigns_using_technique,
    groups_using_technique,
)
from attribution_platform.attack_knowledge.verification import EXPECTED_ARTIFACT_FILENAME
from attribution_platform.attribution import candidate_generation as candidate_generation_module
from attribution_platform.attribution.candidate_generation import (
    CandidateGenerationResult,
    generate_candidates,
)
from attribution_platform.attribution.contracts import (
    UNATTRIBUTED_CANDIDATE_ID,
    CandidateType,
    compute_candidate_id,
    compute_hypothesis_id,
)
from attribution_platform.attribution.errors import AttributionError
from attribution_platform.correlation import (
    BehavioralSequence,
    BehavioralStep,
    CorrelationGroup,
    CorrelationProvenance,
    compute_sequence_id,
    compute_step_id,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
CANDIDATE_GENERATION_SOURCE = (
    REPO_ROOT / "src" / "attribution_platform" / "attribution" / "candidate_generation.py"
)

_UNKNOWN_TECHNIQUE_ID = "attack-pattern--ffffffff-ffff-ffff-ffff-ffffffffffff"


# ===========================================================================
# Synthetic ATT&CK fixture (full control over active/revoked/deprecated
# Groups AND Campaigns, group+campaign overlap, and software evidence)
# ===========================================================================

T_A = "attack-pattern--10000000-0000-0000-0000-000000000001"
T_SHARED = "attack-pattern--10000000-0000-0000-0000-000000000002"
T_REVOKED_ONLY = "attack-pattern--10000000-0000-0000-0000-000000000003"
T_DEPRECATED_ONLY = "attack-pattern--10000000-0000-0000-0000-000000000004"
T_ZERO_USERS = "attack-pattern--10000000-0000-0000-0000-000000000005"
M_SOFTWARE = "malware--10000000-0000-0000-0000-000000000006"

G_ACTIVE = "intrusion-set--20000000-0000-0000-0000-000000000001"
G_REVOKED = "intrusion-set--20000000-0000-0000-0000-000000000002"
G_DEPRECATED = "intrusion-set--20000000-0000-0000-0000-000000000003"
G_SOFTWARE_USER = "intrusion-set--20000000-0000-0000-0000-000000000004"

C_ACTIVE = "campaign--30000000-0000-0000-0000-000000000001"
C_REVOKED = "campaign--30000000-0000-0000-0000-000000000002"
C_DEPRECATED = "campaign--30000000-0000-0000-0000-000000000003"


def _uses(source: str, target: str, rel_id: str) -> dict[str, Any]:
    return {
        "type": "relationship",
        "id": f"relationship--{rel_id}",
        "relationship_type": "uses",
        "source_ref": source,
        "target_ref": target,
    }


def _build_synthetic_attack_knowledge(tmp_path: Path) -> AttackKnowledge:
    objects: list[dict[str, Any]] = [
        {
            "type": "x-mitre-collection",
            "id": "x-mitre-collection--g33-fixture",
            "name": "Enterprise ATT&CK",
            "x_mitre_version": "19.0",
            "spec_version": "2.1",
            "created": "2020-01-01T00:00:00.000Z",
            "modified": "2020-01-01T00:00:00.000Z",
        },
        {"type": "attack-pattern", "id": T_A, "x_mitre_is_subtechnique": False},
        {"type": "attack-pattern", "id": T_SHARED, "x_mitre_is_subtechnique": False},
        {"type": "attack-pattern", "id": T_REVOKED_ONLY, "x_mitre_is_subtechnique": False},
        {"type": "attack-pattern", "id": T_DEPRECATED_ONLY, "x_mitre_is_subtechnique": False},
        {"type": "attack-pattern", "id": T_ZERO_USERS, "x_mitre_is_subtechnique": False},
        {"type": "malware", "id": M_SOFTWARE, "name": "TestMalware"},
        {
            "type": "intrusion-set",
            "id": G_ACTIVE,
            "name": "Active Group",
            "aliases": ["Active Group"],
        },
        {
            "type": "intrusion-set",
            "id": G_REVOKED,
            "name": "Revoked Group",
            "revoked": True,
            "aliases": ["Revoked Group"],
        },
        {
            "type": "intrusion-set",
            "id": G_DEPRECATED,
            "name": "Deprecated Group",
            "x_mitre_deprecated": True,
            "aliases": ["Deprecated Group"],
        },
        {
            "type": "intrusion-set",
            "id": G_SOFTWARE_USER,
            "name": "Software User Group",
            "aliases": ["Software User Group"],
        },
        {
            "type": "campaign",
            "id": C_ACTIVE,
            "name": "Active Campaign",
            "aliases": ["Active Campaign"],
        },
        {
            "type": "campaign",
            "id": C_REVOKED,
            "name": "Revoked Campaign",
            "revoked": True,
            "aliases": ["Revoked Campaign"],
        },
        {
            "type": "campaign",
            "id": C_DEPRECATED,
            "name": "Deprecated Campaign",
            "x_mitre_deprecated": True,
            "aliases": ["Deprecated Campaign"],
        },
        _uses(G_ACTIVE, T_A, "1"),
        _uses(G_ACTIVE, T_SHARED, "2"),
        _uses(C_ACTIVE, T_SHARED, "3"),
        _uses(G_REVOKED, T_REVOKED_ONLY, "4"),
        _uses(C_REVOKED, T_REVOKED_ONLY, "5"),
        _uses(G_DEPRECATED, T_DEPRECATED_ONLY, "6"),
        _uses(C_DEPRECATED, T_DEPRECATED_ONLY, "7"),
        _uses(G_SOFTWARE_USER, M_SOFTWARE, "8"),
    ]
    bundle = {"type": "bundle", "id": "bundle--g33-fixture", "objects": objects}

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


@pytest.fixture
def synthetic_kb(tmp_path: Path) -> AttackKnowledge:
    return _build_synthetic_attack_knowledge(tmp_path)


# ===========================================================================
# CorrelationGroup / BehavioralSequence test helpers
# ===========================================================================


def _correlation_provenance(**overrides: object) -> CorrelationProvenance:
    kwargs: dict[str, object] = {
        "method": "candidate-generation-test",
        "method_version": "1.0",
        "source_evidence_ids": ("ev-1", "ev-2"),
        "source_observation_ids": ("obs-1", "obs-2"),
    }
    kwargs.update(overrides)
    return CorrelationProvenance(**kwargs)  # type: ignore[arg-type]


def _correlation_group(group_id: str = "group-1", **overrides: object) -> CorrelationGroup:
    kwargs: dict[str, object] = {
        "group_id": group_id,
        "member_evidence_ids": ("ev-1", "ev-2"),
        "member_observation_ids": ("obs-1", "obs-2"),
        "structural_link_ids": ("link-1",),
        "provenance": _correlation_provenance(),
    }
    kwargs.update(overrides)
    return CorrelationGroup(**kwargs)  # type: ignore[arg-type]


def _sequence_from_feature_lists(
    group_id: str, feature_lists: list[tuple[str, ...]]
) -> BehavioralSequence:
    """Builds one BehavioralStep per entry in ``feature_lists`` (each a
    tuple of technique/software ids that step's Evidence would have carried)
    -- mirrors exactly what G2.4.1 mechanically derives onto
    BehavioralStep.technique_stix_ids, without needing real Evidence."""
    steps = []
    for i, features in enumerate(feature_lists):
        evidence_ids = (f"ev-{i}",)
        step_id = compute_step_id(group_id, evidence_ids)
        steps.append(
            BehavioralStep(
                step_id=step_id,
                group_id=group_id,
                evidence_ids=evidence_ids,
                observation_id=f"obs-{i}",
                technique_stix_ids=features,
            )
        )
    sequence_id = compute_sequence_id(group_id, [s.step_id for s in steps])
    return BehavioralSequence(
        sequence_id=sequence_id,
        group_id=group_id,
        steps=tuple(steps),
        provenance=_correlation_provenance(),
    )


def _find_unattributed_hypothesis_id(result: CandidateGenerationResult) -> str:
    return compute_hypothesis_id(result.group_id, UNATTRIBUTED_CANDIDATE_ID)


# ===========================================================================
# 1. No ATT&CK evidence -> Unattributed only
# ===========================================================================


def test_no_evidence_yields_unattributed_only(synthetic_kb: AttackKnowledge) -> None:
    group = _correlation_group()
    sequence = _sequence_from_feature_lists(group.group_id, [()])
    result = generate_candidates(group, sequence, synthetic_kb)
    assert result.candidates == ()
    assert len(result.hypotheses) == 1
    assert result.hypotheses[0].candidate_id == UNATTRIBUTED_CANDIDATE_ID
    assert result.hypotheses[0].hypothesis_id == _find_unattributed_hypothesis_id(result)


# ===========================================================================
# 2. One technique -> matching Groups/Campaigns + Unattributed
# ===========================================================================


def test_single_technique_yields_matching_group_and_campaign_plus_unattributed(
    synthetic_kb: AttackKnowledge,
) -> None:
    group = _correlation_group()
    sequence = _sequence_from_feature_lists(group.group_id, [(T_SHARED,)])
    result = generate_candidates(group, sequence, synthetic_kb)

    candidate_refs = {(c.actor_ref, c.campaign_ref) for c in result.candidates}
    assert (G_ACTIVE, None) in candidate_refs
    assert (None, C_ACTIVE) in candidate_refs
    assert len(result.candidates) == 2  # exactly the two active matches, nothing else
    unattributed_ids = {h.candidate_id for h in result.hypotheses}
    assert UNATTRIBUTED_CANDIDATE_ID in unattributed_ids


def test_no_attribution_decision_is_made() -> None:
    """A single matching candidate does not become 'the answer' -- both it
    and Unattributed remain co-equal members of the hypothesis set; there is
    no 'leading'/'winner' concept anywhere in this gate's output type."""
    assert not hasattr(CandidateGenerationResult, "leading_hypothesis_id")
    assert not hasattr(CandidateGenerationResult, "leading_candidate_id")


# ===========================================================================
# 3. Multiple techniques -> union candidate universe
# ===========================================================================


def test_multiple_techniques_union_candidate_universe(synthetic_kb: AttackKnowledge) -> None:
    group = _correlation_group()
    # T_A -> only G_ACTIVE. M_SOFTWARE -> only G_SOFTWARE_USER. Union of both.
    sequence = _sequence_from_feature_lists(group.group_id, [(T_A,), (M_SOFTWARE,)])
    result = generate_candidates(group, sequence, synthetic_kb)

    actor_refs = {c.actor_ref for c in result.candidates if c.actor_ref is not None}
    assert G_ACTIVE in actor_refs
    assert G_SOFTWARE_USER in actor_refs


def test_union_not_intersection_across_observed_techniques(synthetic_kb: AttackKnowledge) -> None:
    """A candidate matching only ONE of several observed features is still
    included -- candidate generation is not an AND across all techniques."""
    group = _correlation_group()
    sequence = _sequence_from_feature_lists(group.group_id, [(T_A,), (T_ZERO_USERS,)])
    result = generate_candidates(group, sequence, synthetic_kb)
    actor_refs = {c.actor_ref for c in result.candidates if c.actor_ref is not None}
    assert G_ACTIVE in actor_refs


# ===========================================================================
# 4. Duplicate technique evidence -> no duplicate Candidate
# ===========================================================================


def test_duplicate_technique_evidence_does_not_duplicate_candidate(
    synthetic_kb: AttackKnowledge,
) -> None:
    group = _correlation_group()
    # T_A observed via two separate BehavioralSteps (e.g. two process
    # instances both asserting the same technique -- G2.4.1's own,
    # already-legitimate independent-evidence case).
    sequence = _sequence_from_feature_lists(group.group_id, [(T_A,), (T_A,)])
    result = generate_candidates(group, sequence, synthetic_kb)
    matching = [c for c in result.candidates if c.actor_ref == G_ACTIVE]
    assert len(matching) == 1
    assert matching[0].generation_basis == (T_A,)


# ===========================================================================
# 5. Same candidate via multiple techniques -> one Candidate, combined basis
# ===========================================================================


def test_same_candidate_via_multiple_features_gets_combined_generation_basis(
    synthetic_kb: AttackKnowledge,
) -> None:
    group = _correlation_group()
    # G_ACTIVE uses both T_A and T_SHARED.
    sequence = _sequence_from_feature_lists(group.group_id, [(T_A,), (T_SHARED,)])
    result = generate_candidates(group, sequence, synthetic_kb)
    matching = [c for c in result.candidates if c.actor_ref == G_ACTIVE]
    assert len(matching) == 1
    assert matching[0].generation_basis == tuple(sorted((T_A, T_SHARED)))


def test_generation_basis_is_deterministically_ordered(synthetic_kb: AttackKnowledge) -> None:
    group = _correlation_group()
    sequence_a = _sequence_from_feature_lists(group.group_id, [(T_SHARED,), (T_A,)])
    sequence_b = _sequence_from_feature_lists(group.group_id, [(T_A,), (T_SHARED,)])
    result_a = generate_candidates(group, sequence_a, synthetic_kb)
    result_b = generate_candidates(group, sequence_b, synthetic_kb)
    basis_a = next(c.generation_basis for c in result_a.candidates if c.actor_ref == G_ACTIVE)
    basis_b = next(c.generation_basis for c in result_b.candidates if c.actor_ref == G_ACTIVE)
    assert basis_a == basis_b == tuple(sorted((T_A, T_SHARED)))


# ===========================================================================
# 6. Unknown technique -> no fabricated candidate
# ===========================================================================


def test_unknown_technique_fails_closed_without_fabricating_a_candidate(
    synthetic_kb: AttackKnowledge,
) -> None:
    group = _correlation_group()
    sequence = _sequence_from_feature_lists(group.group_id, [(_UNKNOWN_TECHNIQUE_ID,)])
    result = generate_candidates(group, sequence, synthetic_kb)
    assert result.candidates == ()
    assert len(result.hypotheses) == 1
    assert result.hypotheses[0].candidate_id == UNATTRIBUTED_CANDIDATE_ID


def test_unknown_technique_mixed_with_known_technique_only_skips_the_unknown_one(
    synthetic_kb: AttackKnowledge,
) -> None:
    group = _correlation_group()
    sequence = _sequence_from_feature_lists(group.group_id, [(T_A,), (_UNKNOWN_TECHNIQUE_ID,)])
    result = generate_candidates(group, sequence, synthetic_kb)
    matching = [c for c in result.candidates if c.actor_ref == G_ACTIVE]
    assert len(matching) == 1
    assert matching[0].generation_basis == (T_A,)


# ===========================================================================
# 7-10. Revoked/deprecated Group AND Campaign excluded
# ===========================================================================


def test_revoked_group_excluded(synthetic_kb: AttackKnowledge) -> None:
    group = _correlation_group()
    sequence = _sequence_from_feature_lists(group.group_id, [(T_REVOKED_ONLY,)])
    result = generate_candidates(group, sequence, synthetic_kb)
    actor_refs = {c.actor_ref for c in result.candidates}
    assert G_REVOKED not in actor_refs


def test_deprecated_group_excluded(synthetic_kb: AttackKnowledge) -> None:
    group = _correlation_group()
    sequence = _sequence_from_feature_lists(group.group_id, [(T_DEPRECATED_ONLY,)])
    result = generate_candidates(group, sequence, synthetic_kb)
    actor_refs = {c.actor_ref for c in result.candidates}
    assert G_DEPRECATED not in actor_refs


def test_revoked_campaign_excluded(synthetic_kb: AttackKnowledge) -> None:
    group = _correlation_group()
    sequence = _sequence_from_feature_lists(group.group_id, [(T_REVOKED_ONLY,)])
    result = generate_candidates(group, sequence, synthetic_kb)
    campaign_refs = {c.campaign_ref for c in result.candidates}
    assert C_REVOKED not in campaign_refs


def test_deprecated_campaign_excluded(synthetic_kb: AttackKnowledge) -> None:
    group = _correlation_group()
    sequence = _sequence_from_feature_lists(group.group_id, [(T_DEPRECATED_ONLY,)])
    result = generate_candidates(group, sequence, synthetic_kb)
    campaign_refs = {c.campaign_ref for c in result.candidates}
    assert C_DEPRECATED not in campaign_refs


# ===========================================================================
# 11. No matching active entity -> Unattributed only
# ===========================================================================


def test_only_revoked_and_deprecated_entities_match_leaves_only_unattributed(
    synthetic_kb: AttackKnowledge,
) -> None:
    group = _correlation_group()
    sequence = _sequence_from_feature_lists(
        group.group_id, [(T_REVOKED_ONLY,), (T_DEPRECATED_ONLY,)]
    )
    result = generate_candidates(group, sequence, synthetic_kb)
    assert result.candidates == ()
    assert result.hypotheses[0].candidate_id == UNATTRIBUTED_CANDIDATE_ID


def test_technique_with_zero_users_contributes_no_candidates(
    synthetic_kb: AttackKnowledge,
) -> None:
    group = _correlation_group()
    sequence = _sequence_from_feature_lists(group.group_id, [(T_ZERO_USERS,)])
    result = generate_candidates(group, sequence, synthetic_kb)
    assert result.candidates == ()


# ===========================================================================
# 12. Group and Campaign overlap -> both retained
# ===========================================================================


def test_group_and_campaign_overlap_both_retained(synthetic_kb: AttackKnowledge) -> None:
    group = _correlation_group()
    sequence = _sequence_from_feature_lists(group.group_id, [(T_SHARED,)])
    result = generate_candidates(group, sequence, synthetic_kb)
    types = {c.candidate_type for c in result.candidates}
    assert CandidateType.GROUP in types
    assert CandidateType.CAMPAIGN in types
    actor_refs = {c.actor_ref for c in result.candidates if c.actor_ref}
    campaign_refs = {c.campaign_ref for c in result.candidates if c.campaign_ref}
    assert G_ACTIVE in actor_refs
    assert C_ACTIVE in campaign_refs


# ===========================================================================
# 13-14. Alias resolution never creates duplicate identities / never
# arbitrarily resolved -- proven structurally (no alias-name resolution
# occurs anywhere in this module's data flow).
# ===========================================================================


def test_generator_never_calls_resolve_alias(
    monkeypatch: pytest.MonkeyPatch, synthetic_kb: AttackKnowledge
) -> None:
    """Structural proof for §9.M: even monkeypatched to raise on any call,
    resolve_alias is never invoked by generate_candidates -- there is no
    alias *name* string anywhere in this module's data flow for it to
    resolve, so ambiguity can never arise here."""
    import attribution_platform.attack_knowledge.traversal as traversal_module

    def _boom(*_args: object, **_kwargs: object) -> str:
        raise AssertionError("resolve_alias must never be called by generate_candidates")

    monkeypatch.setattr(traversal_module, "resolve_alias", _boom)

    group = _correlation_group()
    sequence = _sequence_from_feature_lists(group.group_id, [(T_A, T_SHARED, M_SOFTWARE)])
    generate_candidates(group, sequence, synthetic_kb)  # must not raise


def test_candidate_identity_is_canonical_stix_id_never_alias_derived(
    synthetic_kb: AttackKnowledge,
) -> None:
    group = _correlation_group()
    sequence = _sequence_from_feature_lists(group.group_id, [(T_A,)])
    result = generate_candidates(group, sequence, synthetic_kb)
    matching = next(c for c in result.candidates if c.actor_ref == G_ACTIVE)
    assert matching.candidate_id == compute_candidate_id(G_ACTIVE)


def test_candidate_alias_stix_ids_left_empty_this_gate(synthetic_kb: AttackKnowledge) -> None:
    """Deliberately not populated this gate -- see the module docstring's
    note on the still-open alias_stix_ids representation question."""
    group = _correlation_group()
    sequence = _sequence_from_feature_lists(group.group_id, [(T_A,)])
    result = generate_candidates(group, sequence, synthetic_kb)
    matching = next(c for c in result.candidates if c.actor_ref == G_ACTIVE)
    assert matching.alias_stix_ids == ()


# ===========================================================================
# 15. Software evidence only used when legitimately available
# ===========================================================================


def test_software_evidence_produces_a_matching_candidate(synthetic_kb: AttackKnowledge) -> None:
    group = _correlation_group()
    sequence = _sequence_from_feature_lists(group.group_id, [(M_SOFTWARE,)])
    result = generate_candidates(group, sequence, synthetic_kb)
    actor_refs = {c.actor_ref for c in result.candidates}
    assert G_SOFTWARE_USER in actor_refs
    matching = next(c for c in result.candidates if c.actor_ref == G_SOFTWARE_USER)
    assert matching.generation_basis == (M_SOFTWARE,)


def test_no_software_evidence_means_no_software_derived_candidates(
    synthetic_kb: AttackKnowledge,
) -> None:
    group = _correlation_group()
    sequence = _sequence_from_feature_lists(group.group_id, [(T_A,)])
    result = generate_candidates(group, sequence, synthetic_kb)
    actor_refs = {c.actor_ref for c in result.candidates}
    assert G_SOFTWARE_USER not in actor_refs


# ===========================================================================
# 16. No hard-coded actor IDs in source
# ===========================================================================


def test_source_contains_no_hard_coded_technique_or_tactic_ids() -> None:
    import re

    source_text = CANDIDATE_GENERATION_SOURCE.read_text(encoding="utf-8")
    assert not re.findall(r"\bT\d{4}(\.\d{3})?\b", source_text)
    assert not re.findall(r"\bTA\d{4}\b", source_text)


def test_source_binds_no_literal_stix_id() -> None:
    """No 'intrusion-set--<uuid>'/'campaign--<uuid>' literal appears in the
    generator's own source -- the candidate universe is entirely
    KB-derived, never a hard-coded actor list."""
    source_text = CANDIDATE_GENERATION_SOURCE.read_text(encoding="utf-8")
    import re

    assert not re.findall(r"intrusion-set--[0-9a-f-]{36}", source_text)
    assert not re.findall(r"campaign--[0-9a-f-]{36}", source_text)


# ===========================================================================
# 17. Unattributed always present
# ===========================================================================


@pytest.mark.parametrize(
    "feature_lists",
    [
        [()],
        [(T_A,)],
        [(T_A,), (T_SHARED,), (M_SOFTWARE,)],
        [(_UNKNOWN_TECHNIQUE_ID,)],
        [(T_REVOKED_ONLY,), (T_DEPRECATED_ONLY,)],
    ],
)
def test_unattributed_always_present(
    synthetic_kb: AttackKnowledge, feature_lists: list[tuple[str, ...]]
) -> None:
    group = _correlation_group()
    sequence = _sequence_from_feature_lists(group.group_id, feature_lists)
    result = generate_candidates(group, sequence, synthetic_kb)
    candidate_ids = {h.candidate_id for h in result.hypotheses}
    assert UNATTRIBUTED_CANDIDATE_ID in candidate_ids


# ===========================================================================
# 18-19. Determinism
# ===========================================================================


def test_deterministic_ordering_across_repeated_calls(synthetic_kb: AttackKnowledge) -> None:
    group = _correlation_group()
    sequence = _sequence_from_feature_lists(group.group_id, [(T_A,), (T_SHARED,), (M_SOFTWARE,)])
    result_a = generate_candidates(group, sequence, synthetic_kb)
    result_b = generate_candidates(group, sequence, synthetic_kb)
    assert result_a.candidates == result_b.candidates
    assert result_a.hypotheses == result_b.hypotheses


def test_candidate_and_hypothesis_tuples_are_sorted_by_id(synthetic_kb: AttackKnowledge) -> None:
    group = _correlation_group()
    sequence = _sequence_from_feature_lists(group.group_id, [(T_A,), (T_SHARED,), (M_SOFTWARE,)])
    result = generate_candidates(group, sequence, synthetic_kb)
    assert [c.candidate_id for c in result.candidates] == sorted(
        c.candidate_id for c in result.candidates
    )
    assert [h.hypothesis_id for h in result.hypotheses] == sorted(
        h.hypothesis_id for h in result.hypotheses
    )


def test_deterministic_result_across_independently_loaded_kb_instances(
    tmp_path: Path,
) -> None:
    kb_a = _build_synthetic_attack_knowledge(tmp_path / "a")
    kb_b = _build_synthetic_attack_knowledge(tmp_path / "b")
    group = _correlation_group()
    sequence = _sequence_from_feature_lists(group.group_id, [(T_A,), (T_SHARED,), (M_SOFTWARE,)])
    result_a = generate_candidates(group, sequence, kb_a)
    result_b = generate_candidates(group, sequence, kb_b)
    assert result_a.candidates == result_b.candidates
    assert result_a.hypotheses == result_b.hypotheses


# ===========================================================================
# 20. No network dependency
# ===========================================================================


def test_candidate_generation_module_imports_no_networking_libraries() -> None:
    for name in ("socket", "urllib", "http", "requests"):
        assert not hasattr(
            candidate_generation_module, name
        ), f"candidate_generation.py must not import {name!r}"


def test_candidate_generation_works_with_network_forcibly_blocked(
    synthetic_kb: AttackKnowledge,
) -> None:
    import socket

    original_connect = socket.socket.connect
    original_connect_ex = socket.socket.connect_ex

    def _blocked(self: Any, *_args: Any, **_kwargs: Any) -> Any:
        raise RuntimeError("NETWORK ACCESS BLOCKED FOR TEST")

    socket.socket.connect = _blocked  # type: ignore[method-assign]
    socket.socket.connect_ex = _blocked  # type: ignore[method-assign]
    try:
        group = _correlation_group()
        sequence = _sequence_from_feature_lists(group.group_id, [(T_SHARED,)])
        result = generate_candidates(group, sequence, synthetic_kb)
        assert result.candidates
    finally:
        socket.socket.connect = original_connect  # type: ignore[method-assign]
        socket.socket.connect_ex = original_connect_ex  # type: ignore[method-assign]


# ===========================================================================
# 21. No mutation of upstream Phase 0-2 objects
# ===========================================================================


def test_generation_does_not_mutate_group_sequence_or_knowledge(
    synthetic_kb: AttackKnowledge,
) -> None:
    group = _correlation_group()
    sequence = _sequence_from_feature_lists(group.group_id, [(T_A,), (T_SHARED,)])
    group_before = (group.group_id, group.member_evidence_ids, group.structural_link_ids)
    sequence_before = (sequence.sequence_id, tuple(s.step_id for s in sequence.steps))
    fingerprint_before = synthetic_kb.object_fingerprint

    generate_candidates(group, sequence, synthetic_kb)

    assert (group.group_id, group.member_evidence_ids, group.structural_link_ids) == group_before
    assert (sequence.sequence_id, tuple(s.step_id for s in sequence.steps)) == sequence_before
    assert synthetic_kb.object_fingerprint == fingerprint_before
    assert synthetic_kb.object_fingerprint is fingerprint_before


def test_mismatched_group_and_sequence_fails_closed(synthetic_kb: AttackKnowledge) -> None:
    group = _correlation_group(group_id="group-1")
    other_sequence = _sequence_from_feature_lists("group-2", [(T_A,)])
    with pytest.raises(AttributionError, match="group_id"):
        generate_candidates(group, other_sequence, synthetic_kb)


def test_generate_candidates_rejects_wrong_argument_types(synthetic_kb: AttackKnowledge) -> None:
    group = _correlation_group()
    sequence = _sequence_from_feature_lists(group.group_id, [(T_A,)])
    with pytest.raises(AttributionError):
        generate_candidates("not-a-group", sequence, synthetic_kb)  # type: ignore[arg-type]
    with pytest.raises(AttributionError):
        generate_candidates(group, "not-a-sequence", synthetic_kb)  # type: ignore[arg-type]
    with pytest.raises(AttributionError):
        generate_candidates(group, sequence, "not-a-knowledge")  # type: ignore[arg-type]


# ===========================================================================
# 22. No scoring/likelihood/confidence behavior in the generator
# ===========================================================================


def test_candidate_generation_result_has_no_scoring_fields() -> None:
    import dataclasses

    field_names = {f.name for f in dataclasses.fields(CandidateGenerationResult)}
    forbidden = {
        "score",
        "likelihood",
        "confidence",
        "diagnosticity",
        "support",
        "leading_hypothesis_id",
    }
    assert field_names.isdisjoint(forbidden)


def test_source_never_references_scoring_or_calibration_vocabulary() -> None:
    source_text = CANDIDATE_GENERATION_SOURCE.read_text(encoding="utf-8")
    tree = ast.parse(source_text)
    forbidden_substrings = (
        "diagnosticity",
        "compute_likelihood",
        "compute_confidence",
        "compute_support",
        "abstain",
        "run_calibration",
        "fit_calibration",
        "elasticsearch",
        "elastic_client",
        "ach_matrix",
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
                f"candidate_generation.py binds identifier {identifier!r} referencing "
                f"out-of-scope vocabulary {forbidden!r}"
            )


def test_source_imports_no_dataplane_or_elastic_or_scoring_modules() -> None:
    source_text = CANDIDATE_GENERATION_SOURCE.read_text(encoding="utf-8")
    tree = ast.parse(source_text)
    imported_modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            imported_modules.add(node.module)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                imported_modules.add(alias.name)

    forbidden_modules = {
        "attribution_platform.dataplane",
        "attribution_platform.api",
        "attribution_platform.elastic_detections",
    }
    assert imported_modules.isdisjoint(forbidden_modules)


# ===========================================================================
# Integration / sanity checks against the real, pinned v19.0 bundle
# ===========================================================================


def _find_real_technique_with_group_and_campaign_users(kb: AttackKnowledge) -> str:
    for technique in kb.techniques():
        tid = str(technique["id"])
        if groups_using_technique(kb, tid) and campaigns_using_technique(kb, tid):
            return tid
    pytest.fail("expected a technique with both active Group and Campaign users in v19.0")


def test_real_pinned_kb_single_technique_produces_real_dynamic_candidates() -> None:
    kb = load_attack_knowledge()
    technique_id = _find_real_technique_with_group_and_campaign_users(kb)
    expected_groups = set(groups_using_technique(kb, technique_id))
    expected_campaigns = set(campaigns_using_technique(kb, technique_id))

    group = _correlation_group()
    sequence = _sequence_from_feature_lists(group.group_id, [(technique_id,)])
    result = generate_candidates(group, sequence, kb)

    actor_refs = {c.actor_ref for c in result.candidates if c.actor_ref}
    campaign_refs = {c.campaign_ref for c in result.candidates if c.campaign_ref}
    assert actor_refs == expected_groups
    assert campaign_refs == expected_campaigns
    assert UNATTRIBUTED_CANDIDATE_ID in {h.candidate_id for h in result.hypotheses}


def test_real_pinned_kb_deterministic_across_independently_loaded_instances() -> None:
    kb_a = load_attack_knowledge()
    kb_b = load_attack_knowledge()
    technique_id = _find_real_technique_with_group_and_campaign_users(kb_a)

    group = _correlation_group()
    sequence = _sequence_from_feature_lists(group.group_id, [(technique_id,)])
    result_a = generate_candidates(group, sequence, kb_a)
    result_b = generate_candidates(group, sequence, kb_b)
    assert result_a.candidates == result_b.candidates
    assert result_a.hypotheses == result_b.hypotheses


def test_generated_candidate_attack_kb_version_matches_loaded_kb() -> None:
    kb = load_attack_knowledge()
    technique_id = _find_real_technique_with_group_and_campaign_users(kb)
    group = _correlation_group()
    sequence = _sequence_from_feature_lists(group.group_id, [(technique_id,)])
    result = generate_candidates(group, sequence, kb)
    assert result.attack_kb_version == kb.attack_kb_version
    for candidate in result.candidates:
        assert candidate.attack_kb_version == kb.attack_kb_version
