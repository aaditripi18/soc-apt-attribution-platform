"""Tests for gate G3.4: ACH evidence-assessment / matrix construction
(ADR-0005 §D4/§D8).

Covers the required test list using the same synthetic-ATT&CK-fixture
pattern gate G3.3's own test file established (full, deterministic control
over active/revoked/deprecated Groups and Campaigns), plus real v19.0
integration checks.

Central design finding under test: the matrix this gate builds is
deliberately SPARSE -- only CONSISTENT/SUPPORTING cells are ever
materialized, because genuine contradiction (INCONSISTENT/CONTRADICTING)
requires CoverageProfile data this gate is explicitly forbidden from
computing, and EvidenceRole has no third "neutral" value for an
UNKNOWN-relevance combination to carry. Several tests below prove this
structurally (never merely by omission).

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
from attribution_platform.attribution import ach_matrix as ach_matrix_module
from attribution_platform.attribution.ach_matrix import (
    ACHMatrix,
    build_ach_matrix,
    compute_diagnosticity_ref,
)
from attribution_platform.attribution.candidate_generation import (
    CandidateGenerationResult,
    generate_candidates,
)
from attribution_platform.attribution.contracts import (
    UNATTRIBUTED_CANDIDATE_ID,
    CandidateType,
    EvidenceRole,
    Relevance,
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
ACH_MATRIX_SOURCE = REPO_ROOT / "src" / "attribution_platform" / "attribution" / "ach_matrix.py"

_UNKNOWN_TECHNIQUE_ID = "attack-pattern--ffffffff-ffff-ffff-ffff-ffffffffffff"


# ===========================================================================
# Synthetic ATT&CK fixture -- mirrors test_attribution_candidate_generation.py
# ===========================================================================

T_A = "attack-pattern--10000000-0000-0000-0000-000000000001"
T_SHARED = "attack-pattern--10000000-0000-0000-0000-000000000002"
T_B = "attack-pattern--10000000-0000-0000-0000-000000000007"
M_SOFTWARE = "malware--10000000-0000-0000-0000-000000000006"

G_ACTIVE = "intrusion-set--20000000-0000-0000-0000-000000000001"
G_OTHER = "intrusion-set--20000000-0000-0000-0000-000000000005"
G_SOFTWARE_USER = "intrusion-set--20000000-0000-0000-0000-000000000004"

C_ACTIVE = "campaign--30000000-0000-0000-0000-000000000001"


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
            "id": "x-mitre-collection--g34-fixture",
            "name": "Enterprise ATT&CK",
            "x_mitre_version": "19.0",
            "spec_version": "2.1",
            "created": "2020-01-01T00:00:00.000Z",
            "modified": "2020-01-01T00:00:00.000Z",
        },
        {"type": "attack-pattern", "id": T_A, "x_mitre_is_subtechnique": False},
        {"type": "attack-pattern", "id": T_SHARED, "x_mitre_is_subtechnique": False},
        {"type": "attack-pattern", "id": T_B, "x_mitre_is_subtechnique": False},
        {"type": "malware", "id": M_SOFTWARE, "name": "TestMalware"},
        {
            "type": "intrusion-set",
            "id": G_ACTIVE,
            "name": "Active Group",
            "aliases": ["Active Group"],
        },
        {
            "type": "intrusion-set",
            "id": G_OTHER,
            "name": "Other Group",
            "aliases": ["Other Group"],
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
        _uses(G_ACTIVE, T_A, "1"),
        _uses(G_ACTIVE, T_SHARED, "2"),
        _uses(C_ACTIVE, T_SHARED, "3"),
        _uses(G_OTHER, T_B, "4"),
        _uses(G_SOFTWARE_USER, M_SOFTWARE, "5"),
    ]
    bundle = {"type": "bundle", "id": "bundle--g34-fixture", "objects": objects}

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
# CorrelationGroup / BehavioralSequence / CandidateGenerationResult helpers
# ===========================================================================


def _correlation_provenance(**overrides: object) -> CorrelationProvenance:
    kwargs: dict[str, object] = {
        "method": "ach-matrix-test",
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


def _generate(
    group: CorrelationGroup, sequence: BehavioralSequence, knowledge: AttackKnowledge
) -> CandidateGenerationResult:
    return generate_candidates(group, sequence, knowledge)


# ===========================================================================
# 1-2. One evidence feature x one Group / Campaign candidate
# ===========================================================================


def test_one_technique_one_group_candidate_cell(synthetic_kb: AttackKnowledge) -> None:
    group = _correlation_group()
    sequence = _sequence_from_feature_lists(group.group_id, [(T_A,)])
    candidate_result = _generate(group, sequence, synthetic_kb)
    matrix = build_ach_matrix(group, sequence, candidate_result, synthetic_kb)

    group_candidate = next(c for c in candidate_result.candidates if c.actor_ref == G_ACTIVE)
    group_hypothesis_id = compute_hypothesis_id(group.group_id, group_candidate.candidate_id)
    matching = [a for a in matrix.assessments if a.hypothesis_id == group_hypothesis_id]
    assert len(matching) == 1
    assert matching[0].technique_stix_id == T_A
    assert matching[0].relevance is Relevance.CONSISTENT
    assert matching[0].role is EvidenceRole.SUPPORTING


def test_one_technique_one_campaign_candidate_cell(synthetic_kb: AttackKnowledge) -> None:
    group = _correlation_group()
    sequence = _sequence_from_feature_lists(group.group_id, [(T_SHARED,)])
    candidate_result = _generate(group, sequence, synthetic_kb)
    matrix = build_ach_matrix(group, sequence, candidate_result, synthetic_kb)

    campaign_candidate = next(c for c in candidate_result.candidates if c.campaign_ref == C_ACTIVE)
    campaign_hypothesis_id = compute_hypothesis_id(group.group_id, campaign_candidate.candidate_id)
    matching = [a for a in matrix.assessments if a.hypothesis_id == campaign_hypothesis_id]
    assert len(matching) == 1
    assert matching[0].technique_stix_id == T_SHARED


# ===========================================================================
# 3-4. Multiple candidates / Unattributed included
# ===========================================================================


def test_multiple_candidates_and_unattributed_in_matrix(synthetic_kb: AttackKnowledge) -> None:
    group = _correlation_group()
    sequence = _sequence_from_feature_lists(group.group_id, [(T_A,), (T_B,)])
    candidate_result = _generate(group, sequence, synthetic_kb)
    matrix = build_ach_matrix(group, sequence, candidate_result, synthetic_kb)

    assert len(candidate_result.candidates) >= 2
    candidate_ids_in_matrix = {h.candidate_id for h in matrix.hypotheses}
    assert UNATTRIBUTED_CANDIDATE_ID in candidate_ids_in_matrix
    for candidate in candidate_result.candidates:
        assert candidate.candidate_id in candidate_ids_in_matrix


def test_unattributed_hypothesis_object_identity_preserved(synthetic_kb: AttackKnowledge) -> None:
    group = _correlation_group()
    sequence = _sequence_from_feature_lists(group.group_id, [(T_A,)])
    candidate_result = _generate(group, sequence, synthetic_kb)
    matrix = build_ach_matrix(group, sequence, candidate_result, synthetic_kb)
    assert matrix.hypotheses == candidate_result.hypotheses


# ===========================================================================
# 5-7. CONSISTENT / INCONSISTENT / UNKNOWN semantics
# ===========================================================================


def test_consistent_relationship(synthetic_kb: AttackKnowledge) -> None:
    group = _correlation_group()
    sequence = _sequence_from_feature_lists(group.group_id, [(T_A,)])
    candidate_result = _generate(group, sequence, synthetic_kb)
    matrix = build_ach_matrix(group, sequence, candidate_result, synthetic_kb)
    assert matrix.assessments
    assert all(a.relevance is Relevance.CONSISTENT for a in matrix.assessments)


def test_inconsistent_relevance_is_never_produced_by_this_gate(
    synthetic_kb: AttackKnowledge,
) -> None:
    """The Gate 3.4 task asks for an INCONSISTENT test 'where the accepted
    knowledge/evidence semantics actually establish contradiction'. This
    gate's own design finding (see ach_matrix.py's module docstring) is that
    no such semantics are reachable without CoverageProfile, which this gate
    is explicitly forbidden from computing. This test proves that finding
    structurally: across every candidate in a rich, multi-feature scenario,
    not one INCONSISTENT/CONTRADICTING cell is ever produced."""
    group = _correlation_group()
    sequence = _sequence_from_feature_lists(
        group.group_id, [(T_A,), (T_SHARED,), (T_B,), (M_SOFTWARE,)]
    )
    candidate_result = _generate(group, sequence, synthetic_kb)
    matrix = build_ach_matrix(group, sequence, candidate_result, synthetic_kb)
    assert matrix.assessments  # sanity: the scenario is non-trivial
    assert all(a.relevance is not Relevance.INCONSISTENT for a in matrix.assessments)
    assert all(a.role is not EvidenceRole.CONTRADICTING for a in matrix.assessments)


def test_unknown_relationship_is_not_materialized_as_a_cell(
    synthetic_kb: AttackKnowledge,
) -> None:
    """G_OTHER does not use T_A -- that combination is UNKNOWN relevance,
    and per this gate's design is correctly represented by the ABSENCE of a
    cell, never a fabricated one."""
    group = _correlation_group()
    sequence = _sequence_from_feature_lists(group.group_id, [(T_A,), (T_B,)])
    candidate_result = _generate(group, sequence, synthetic_kb)
    matrix = build_ach_matrix(group, sequence, candidate_result, synthetic_kb)

    other_candidate = next(c for c in candidate_result.candidates if c.actor_ref == G_OTHER)
    other_hypothesis_id = compute_hypothesis_id(group.group_id, other_candidate.candidate_id)
    # G_OTHER matched via T_B; it has no cell for T_A (UNKNOWN, not materialized).
    cells_for_other = [a for a in matrix.assessments if a.hypothesis_id == other_hypothesis_id]
    assert all(a.technique_stix_id != T_A for a in cells_for_other)
    assert any(a.technique_stix_id == T_B for a in cells_for_other)


# ===========================================================================
# 8. Unknown ATT&CK technique
# ===========================================================================


def test_unknown_technique_fails_closed_without_fabricating_a_cell(
    synthetic_kb: AttackKnowledge,
) -> None:
    group = _correlation_group()
    sequence = _sequence_from_feature_lists(group.group_id, [(_UNKNOWN_TECHNIQUE_ID,)])
    candidate_result = _generate(group, sequence, synthetic_kb)
    matrix = build_ach_matrix(group, sequence, candidate_result, synthetic_kb)
    assert matrix.assessments == ()
    assert candidate_result.candidates == ()


# ===========================================================================
# 9. Duplicate evidence/technique does not create uncontrolled duplicates
# ===========================================================================


def test_duplicate_technique_across_two_steps_creates_two_independent_cells(
    synthetic_kb: AttackKnowledge,
) -> None:
    """ADR-0005 D4: two DISTINCT BehavioralSteps asserting the same
    technique contribute independently -- two cells, not zero, not a
    silently-collapsed one, and each with a distinct assessment_id (the
    step_id differs)."""
    group = _correlation_group()
    sequence = _sequence_from_feature_lists(group.group_id, [(T_A,), (T_A,)])
    candidate_result = _generate(group, sequence, synthetic_kb)
    matrix = build_ach_matrix(group, sequence, candidate_result, synthetic_kb)

    group_candidate = next(c for c in candidate_result.candidates if c.actor_ref == G_ACTIVE)
    group_hypothesis_id = compute_hypothesis_id(group.group_id, group_candidate.candidate_id)
    cells = [a for a in matrix.assessments if a.hypothesis_id == group_hypothesis_id]
    assert len(cells) == 2
    assert len({a.assessment_id for a in cells}) == 2
    assert len({a.step_id for a in cells}) == 2


def test_rebuilding_the_matrix_from_identical_input_does_not_duplicate(
    synthetic_kb: AttackKnowledge,
) -> None:
    group = _correlation_group()
    sequence = _sequence_from_feature_lists(group.group_id, [(T_A,)])
    candidate_result = _generate(group, sequence, synthetic_kb)
    matrix_a = build_ach_matrix(group, sequence, candidate_result, synthetic_kb)
    matrix_b = build_ach_matrix(group, sequence, candidate_result, synthetic_kb)
    assert matrix_a.assessments == matrix_b.assessments
    assert len({a.assessment_id for a in matrix_a.assessments}) == len(matrix_a.assessments)


# ===========================================================================
# 10-11. Multiple techniques across multiple candidates / Group+Campaign distinct
# ===========================================================================


def test_multiple_techniques_across_multiple_candidates(synthetic_kb: AttackKnowledge) -> None:
    group = _correlation_group()
    sequence = _sequence_from_feature_lists(group.group_id, [(T_A,), (T_SHARED,), (T_B,)])
    candidate_result = _generate(group, sequence, synthetic_kb)
    matrix = build_ach_matrix(group, sequence, candidate_result, synthetic_kb)

    techniques_seen = {a.technique_stix_id for a in matrix.assessments}
    assert techniques_seen == {T_A, T_SHARED, T_B}
    hypotheses_with_cells = {a.hypothesis_id for a in matrix.assessments}
    assert len(hypotheses_with_cells) >= 3  # G_ACTIVE, C_ACTIVE, G_OTHER


def test_group_and_campaign_candidates_remain_distinct_in_matrix(
    synthetic_kb: AttackKnowledge,
) -> None:
    group = _correlation_group()
    sequence = _sequence_from_feature_lists(group.group_id, [(T_SHARED,)])
    candidate_result = _generate(group, sequence, synthetic_kb)
    matrix = build_ach_matrix(group, sequence, candidate_result, synthetic_kb)

    group_candidate = next(c for c in candidate_result.candidates if c.actor_ref == G_ACTIVE)
    campaign_candidate = next(c for c in candidate_result.candidates if c.campaign_ref == C_ACTIVE)
    assert group_candidate.candidate_type is CandidateType.GROUP
    assert campaign_candidate.candidate_type is CandidateType.CAMPAIGN
    group_hyp_id = compute_hypothesis_id(group.group_id, group_candidate.candidate_id)
    campaign_hyp_id = compute_hypothesis_id(group.group_id, campaign_candidate.candidate_id)
    assert group_hyp_id != campaign_hyp_id
    assert {a.hypothesis_id for a in matrix.assessments} >= {group_hyp_id, campaign_hyp_id}


# ===========================================================================
# 12-13. Software evidence only when genuinely reachable / no fabrication
# ===========================================================================


def test_software_evidence_produces_no_ach_cell_but_candidate_still_present(
    synthetic_kb: AttackKnowledge,
) -> None:
    """EvidenceAssessment.technique_stix_id is attack-pattern-only per the
    frozen Gate 3.2 contract -- a software feature cannot be represented as
    a cell here, but the software-matched candidate (from Gate 3.3) still
    legitimately appears as a column."""
    group = _correlation_group()
    sequence = _sequence_from_feature_lists(group.group_id, [(M_SOFTWARE,)])
    candidate_result = _generate(group, sequence, synthetic_kb)
    matrix = build_ach_matrix(group, sequence, candidate_result, synthetic_kb)

    assert any(c.actor_ref == G_SOFTWARE_USER for c in candidate_result.candidates)
    assert matrix.assessments == ()
    software_hypothesis_id = compute_hypothesis_id(
        group.group_id, compute_candidate_id(G_SOFTWARE_USER)
    )
    assert software_hypothesis_id in {h.hypothesis_id for h in matrix.hypotheses}


def test_no_fabricated_software_cell_when_mixed_with_real_technique_evidence(
    synthetic_kb: AttackKnowledge,
) -> None:
    group = _correlation_group()
    sequence = _sequence_from_feature_lists(group.group_id, [(T_A,), (M_SOFTWARE,)])
    candidate_result = _generate(group, sequence, synthetic_kb)
    matrix = build_ach_matrix(group, sequence, candidate_result, synthetic_kb)
    assert all(not a.technique_stix_id.startswith("malware--") for a in matrix.assessments)
    assert any(a.technique_stix_id == T_A for a in matrix.assessments)


# ===========================================================================
# 14. Diagnosticity reference preserved but D/g not calculated
# ===========================================================================


def test_diagnosticity_ref_is_a_string_reference_never_a_number(
    synthetic_kb: AttackKnowledge,
) -> None:
    group = _correlation_group()
    sequence = _sequence_from_feature_lists(group.group_id, [(T_A,)])
    candidate_result = _generate(group, sequence, synthetic_kb)
    matrix = build_ach_matrix(group, sequence, candidate_result, synthetic_kb)
    assert matrix.assessments
    for assessment in matrix.assessments:
        assert isinstance(assessment.diagnosticity_ref, str)
        assert assessment.diagnosticity_ref  # non-empty
        with pytest.raises(ValueError):
            float(assessment.diagnosticity_ref)


def test_diagnosticity_ref_deterministic_and_feature_specific() -> None:
    ref_a = compute_diagnosticity_ref(T_A, "enterprise-attack-19.0")
    ref_a_again = compute_diagnosticity_ref(T_A, "enterprise-attack-19.0")
    ref_b = compute_diagnosticity_ref(T_B, "enterprise-attack-19.0")
    assert ref_a == ref_a_again
    assert ref_a != ref_b


# ===========================================================================
# 15. Coverage reference preserved without inventing contradiction
# ===========================================================================


def test_coverage_id_is_none_for_observed_present_cells(synthetic_kb: AttackKnowledge) -> None:
    """ADR-0005 D11's OBSERVED_PRESENT row: 'no CoverageProfile reference
    needed beyond confirming presence' -- every cell this gate produces IS
    exactly that row, so coverage_id is always None, never invented."""
    group = _correlation_group()
    sequence = _sequence_from_feature_lists(group.group_id, [(T_A,), (T_SHARED,)])
    candidate_result = _generate(group, sequence, synthetic_kb)
    matrix = build_ach_matrix(group, sequence, candidate_result, synthetic_kb)
    assert matrix.assessments
    assert all(a.coverage_id is None for a in matrix.assessments)


# ===========================================================================
# 16. Provenance preserved
# ===========================================================================


def test_provenance_traceable_to_step_technique_hypothesis(synthetic_kb: AttackKnowledge) -> None:
    group = _correlation_group()
    sequence = _sequence_from_feature_lists(group.group_id, [(T_A,)])
    candidate_result = _generate(group, sequence, synthetic_kb)
    matrix = build_ach_matrix(group, sequence, candidate_result, synthetic_kb)
    assessment = matrix.assessments[0]
    assert assessment.step_id == sequence.steps[0].step_id
    assert assessment.technique_stix_id in sequence.steps[0].technique_stix_ids
    assert assessment.hypothesis_id in {h.hypothesis_id for h in matrix.hypotheses}
    assert matrix.group_id == group.group_id
    assert matrix.attack_kb_version == synthetic_kb.attack_kb_version


# ===========================================================================
# 17-19. Determinism
# ===========================================================================


def test_deterministic_matrix_ordering(synthetic_kb: AttackKnowledge) -> None:
    group = _correlation_group()
    sequence = _sequence_from_feature_lists(group.group_id, [(T_A,), (T_SHARED,), (T_B,)])
    candidate_result = _generate(group, sequence, synthetic_kb)
    matrix = build_ach_matrix(group, sequence, candidate_result, synthetic_kb)
    ids = [a.assessment_id for a in matrix.assessments]
    assert ids == sorted(ids)


def test_deterministic_ids(synthetic_kb: AttackKnowledge) -> None:
    group = _correlation_group()
    sequence = _sequence_from_feature_lists(group.group_id, [(T_A,)])
    candidate_result = _generate(group, sequence, synthetic_kb)
    matrix_a = build_ach_matrix(group, sequence, candidate_result, synthetic_kb)
    matrix_b = build_ach_matrix(group, sequence, candidate_result, synthetic_kb)
    assert [a.assessment_id for a in matrix_a.assessments] == [
        a.assessment_id for a in matrix_b.assessments
    ]


def test_repeated_calls_produce_identical_output(synthetic_kb: AttackKnowledge) -> None:
    group = _correlation_group()
    sequence = _sequence_from_feature_lists(group.group_id, [(T_A,), (T_B,)])
    candidate_result = _generate(group, sequence, synthetic_kb)
    matrix_a = build_ach_matrix(group, sequence, candidate_result, synthetic_kb)
    matrix_b = build_ach_matrix(group, sequence, candidate_result, synthetic_kb)
    assert matrix_a == matrix_b


def test_independently_loaded_kb_produces_identical_output(tmp_path: Path) -> None:
    kb_a = _build_synthetic_attack_knowledge(tmp_path / "a")
    kb_b = _build_synthetic_attack_knowledge(tmp_path / "b")
    group = _correlation_group()
    sequence = _sequence_from_feature_lists(group.group_id, [(T_A,), (T_SHARED,)])
    candidate_result_a = _generate(group, sequence, kb_a)
    candidate_result_b = _generate(group, sequence, kb_b)
    matrix_a = build_ach_matrix(group, sequence, candidate_result_a, kb_a)
    matrix_b = build_ach_matrix(group, sequence, candidate_result_b, kb_b)
    assert matrix_a.assessments == matrix_b.assessments
    assert matrix_a.hypotheses == matrix_b.hypotheses


# ===========================================================================
# 20-21. No network dependency / no mutation of upstream objects
# ===========================================================================


def test_ach_matrix_module_imports_no_networking_libraries() -> None:
    for name in ("socket", "urllib", "http", "requests"):
        assert not hasattr(ach_matrix_module, name), f"ach_matrix.py must not import {name!r}"


def test_ach_matrix_works_with_network_forcibly_blocked(synthetic_kb: AttackKnowledge) -> None:
    import socket

    original_connect = socket.socket.connect
    original_connect_ex = socket.socket.connect_ex

    def _blocked(self: Any, *_args: Any, **_kwargs: Any) -> Any:
        raise RuntimeError("NETWORK ACCESS BLOCKED FOR TEST")

    socket.socket.connect = _blocked  # type: ignore[method-assign]
    socket.socket.connect_ex = _blocked  # type: ignore[method-assign]
    try:
        group = _correlation_group()
        sequence = _sequence_from_feature_lists(group.group_id, [(T_A,)])
        candidate_result = _generate(group, sequence, synthetic_kb)
        matrix = build_ach_matrix(group, sequence, candidate_result, synthetic_kb)
        assert matrix.assessments
    finally:
        socket.socket.connect = original_connect  # type: ignore[method-assign]
        socket.socket.connect_ex = original_connect_ex  # type: ignore[method-assign]


def test_no_mutation_of_upstream_objects(synthetic_kb: AttackKnowledge) -> None:
    group = _correlation_group()
    sequence = _sequence_from_feature_lists(group.group_id, [(T_A,), (T_SHARED,)])
    candidate_result = _generate(group, sequence, synthetic_kb)

    group_before = (group.group_id, group.member_evidence_ids)
    sequence_before = tuple(s.step_id for s in sequence.steps)
    candidates_before = candidate_result.candidates
    hypotheses_before = candidate_result.hypotheses
    fingerprint_before = synthetic_kb.object_fingerprint

    build_ach_matrix(group, sequence, candidate_result, synthetic_kb)

    assert (group.group_id, group.member_evidence_ids) == group_before
    assert tuple(s.step_id for s in sequence.steps) == sequence_before
    assert candidate_result.candidates == candidates_before
    assert candidate_result.candidates is candidates_before
    assert candidate_result.hypotheses is hypotheses_before
    assert synthetic_kb.object_fingerprint is fingerprint_before


def test_mismatched_group_and_sequence_fails_closed(synthetic_kb: AttackKnowledge) -> None:
    group = _correlation_group(group_id="group-1")
    other_sequence = _sequence_from_feature_lists("group-2", [(T_A,)])
    fake_candidate_result = CandidateGenerationResult(
        group_id="group-1", attack_kb_version=synthetic_kb.attack_kb_version
    )
    with pytest.raises(AttributionError, match="group_id"):
        build_ach_matrix(group, other_sequence, fake_candidate_result, synthetic_kb)


def test_mismatched_candidate_result_group_id_fails_closed(synthetic_kb: AttackKnowledge) -> None:
    group = _correlation_group(group_id="group-1")
    sequence = _sequence_from_feature_lists("group-1", [(T_A,)])
    fake_candidate_result = CandidateGenerationResult(
        group_id="group-2", attack_kb_version=synthetic_kb.attack_kb_version
    )
    with pytest.raises(AttributionError, match="candidate_result.group_id"):
        build_ach_matrix(group, sequence, fake_candidate_result, synthetic_kb)


def test_mismatched_kb_version_fails_closed(synthetic_kb: AttackKnowledge) -> None:
    group = _correlation_group()
    sequence = _sequence_from_feature_lists(group.group_id, [(T_A,)])
    fake_candidate_result = CandidateGenerationResult(
        group_id=group.group_id, attack_kb_version="enterprise-attack-99.9"
    )
    with pytest.raises(AttributionError, match="attack_kb_version"):
        build_ach_matrix(group, sequence, fake_candidate_result, synthetic_kb)


def test_build_ach_matrix_rejects_wrong_argument_types(synthetic_kb: AttackKnowledge) -> None:
    group = _correlation_group()
    sequence = _sequence_from_feature_lists(group.group_id, [(T_A,)])
    candidate_result = _generate(group, sequence, synthetic_kb)
    with pytest.raises(AttributionError):
        build_ach_matrix("not-a-group", sequence, candidate_result, synthetic_kb)  # type: ignore[arg-type]
    with pytest.raises(AttributionError):
        build_ach_matrix(group, "not-a-sequence", candidate_result, synthetic_kb)  # type: ignore[arg-type]
    with pytest.raises(AttributionError):
        build_ach_matrix(group, sequence, "not-a-result", synthetic_kb)  # type: ignore[arg-type]
    with pytest.raises(AttributionError):
        build_ach_matrix(group, sequence, candidate_result, "not-a-knowledge")  # type: ignore[arg-type]


# ===========================================================================
# 22-23. No likelihood/confidence/score fields / no candidate regeneration
# ===========================================================================


def test_ach_matrix_has_no_scoring_fields() -> None:
    import dataclasses

    field_names = {f.name for f in dataclasses.fields(ACHMatrix)}
    forbidden = {
        "score",
        "likelihood",
        "confidence",
        "support",
        "leading_hypothesis_id",
        "winner",
        "ranking",
    }
    assert field_names.isdisjoint(forbidden)


def test_matrix_does_not_regenerate_candidates(synthetic_kb: AttackKnowledge) -> None:
    """The candidate set in the matrix's hypotheses must be object-identical
    (same tuple) to what Gate 3.3 produced -- never re-derived."""
    group = _correlation_group()
    sequence = _sequence_from_feature_lists(group.group_id, [(T_A,)])
    candidate_result = _generate(group, sequence, synthetic_kb)
    matrix = build_ach_matrix(group, sequence, candidate_result, synthetic_kb)
    assert matrix.hypotheses is candidate_result.hypotheses


# ===========================================================================
# 24-25. No hard-coded actor IDs
# ===========================================================================


def test_source_contains_no_hard_coded_technique_or_tactic_ids() -> None:
    import re

    source_text = ACH_MATRIX_SOURCE.read_text(encoding="utf-8")
    assert not re.findall(r"\bT\d{4}(\.\d{3})?\b", source_text)
    assert not re.findall(r"\bTA\d{4}\b", source_text)


def test_source_binds_no_literal_stix_id() -> None:
    import re

    source_text = ACH_MATRIX_SOURCE.read_text(encoding="utf-8")
    assert not re.findall(r"intrusion-set--[0-9a-f-]{36}", source_text)
    assert not re.findall(r"campaign--[0-9a-f-]{36}", source_text)


# ===========================================================================
# 26. Unattributed remains present even with zero real candidates
# ===========================================================================


def test_unattributed_present_with_zero_real_candidates(synthetic_kb: AttackKnowledge) -> None:
    group = _correlation_group()
    sequence = _sequence_from_feature_lists(group.group_id, [(_UNKNOWN_TECHNIQUE_ID,)])
    candidate_result = _generate(group, sequence, synthetic_kb)
    matrix = build_ach_matrix(group, sequence, candidate_result, synthetic_kb)
    assert candidate_result.candidates == ()
    assert len(matrix.hypotheses) == 1
    assert matrix.hypotheses[0].candidate_id == UNATTRIBUTED_CANDIDATE_ID
    assert matrix.assessments == ()


# ===========================================================================
# Negative architecture guards (§20)
# ===========================================================================


def test_source_never_references_scoring_or_calibration_vocabulary() -> None:
    source_text = ACH_MATRIX_SOURCE.read_text(encoding="utf-8")
    tree = ast.parse(source_text)
    forbidden_substrings = (
        "compute_likelihood",
        "compute_confidence",
        "compute_support",
        "abstain",
        "run_calibration",
        "fit_calibration",
        "elasticsearch",
        "elastic_client",
        "next_evidence",
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
                f"ach_matrix.py binds identifier {identifier!r} referencing "
                f"out-of-scope vocabulary {forbidden!r}"
            )


def test_source_imports_no_dataplane_elastic_or_scoring_modules() -> None:
    source_text = ACH_MATRIX_SOURCE.read_text(encoding="utf-8")
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


def test_source_does_not_import_candidate_generation_internals_to_regenerate() -> None:
    """This module may (and does) import CandidateGenerationResult (the
    output type) but must never import generate_candidates itself -- it
    consumes an already-generated result, never re-runs generation."""
    source_text = ACH_MATRIX_SOURCE.read_text(encoding="utf-8")
    tree = ast.parse(source_text)
    imported_names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                imported_names.add(alias.name)
    assert "generate_candidates" not in imported_names


# ===========================================================================
# Integration / sanity checks against the real, pinned v19.0 bundle
# ===========================================================================


def _find_real_technique_with_group_and_campaign_users(kb: AttackKnowledge) -> str:
    for technique in kb.techniques():
        tid = str(technique["id"])
        if groups_using_technique(kb, tid) and campaigns_using_technique(kb, tid):
            return tid
    pytest.fail("expected a technique with both active Group and Campaign users in v19.0")


def test_real_pinned_kb_single_technique_produces_real_matrix_cells() -> None:
    kb = load_attack_knowledge()
    technique_id = _find_real_technique_with_group_and_campaign_users(kb)

    group = _correlation_group()
    sequence = _sequence_from_feature_lists(group.group_id, [(technique_id,)])
    candidate_result = generate_candidates(group, sequence, kb)
    matrix = build_ach_matrix(group, sequence, candidate_result, kb)

    assert matrix.assessments
    assert all(a.relevance is Relevance.CONSISTENT for a in matrix.assessments)
    assert all(a.role is EvidenceRole.SUPPORTING for a in matrix.assessments)
    assert len(matrix.assessments) == len(candidate_result.candidates)


def test_real_pinned_kb_deterministic_across_independently_loaded_instances() -> None:
    kb_a = load_attack_knowledge()
    kb_b = load_attack_knowledge()
    technique_id = _find_real_technique_with_group_and_campaign_users(kb_a)

    group = _correlation_group()
    sequence = _sequence_from_feature_lists(group.group_id, [(technique_id,)])
    result_a = generate_candidates(group, sequence, kb_a)
    result_b = generate_candidates(group, sequence, kb_b)
    matrix_a = build_ach_matrix(group, sequence, result_a, kb_a)
    matrix_b = build_ach_matrix(group, sequence, result_b, kb_b)
    assert matrix_a.assessments == matrix_b.assessments
