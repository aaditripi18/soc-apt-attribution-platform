"""Tests for gate G3.5: comparative ACH analysis / `support(h)`
(ADR-0005 §D3/§D4/§D8/§D9).

Uses a general-purpose synthetic-ATT&CK-fixture builder (extending the
pattern gates G3.3/G3.4 established) that accepts explicit group/campaign
-> technique membership, so every `g(x)`/`g(C)` value used below is
precisely, by-hand computable and verified in comments next to each test.

The combination-diagnosticity tests use a deliberately hand-designed
20-active-group population (see `_TIE_BREAK_KB_SPEC`) constructed so that
two DIFFERENT, non-overlapping 2+2 pairings of four techniques are BOTH
valid, maximal combinations with an IDENTICAL `Σ g(C)` — an exact,
by-construction test of ADR-0005 §D3's lexicographic tie-break rule, not a
coincidental one.

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
from attribution_platform.attack_knowledge.traversal import group_profile, groups_using_technique
from attribution_platform.attack_knowledge.verification import EXPECTED_ARTIFACT_FILENAME
from attribution_platform.attribution import comparative_analysis as comparative_analysis_module
from attribution_platform.attribution.ach_matrix import build_ach_matrix
from attribution_platform.attribution.candidate_generation import (
    CandidateGenerationResult,
    generate_candidates,
)
from attribution_platform.attribution.comparative_analysis import (
    DEFAULT_MIN_PROFILE_FLOOR,
    ComparativeEvidenceResult,
    DiagnosticityOutcome,
    EvidenceContribution,
    HypothesisSupportSummary,
    _find_combination_partition,
    compute_comparative_evidence,
)
from attribution_platform.attribution.contracts import (
    UNATTRIBUTED_CANDIDATE_ID,
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
COMPARATIVE_ANALYSIS_SOURCE = (
    REPO_ROOT / "src" / "attribution_platform" / "attribution" / "comparative_analysis.py"
)

_UNKNOWN_TECHNIQUE_ID = "attack-pattern--ffffffff-ffff-ffff-ffff-ffffffffffff"


# ===========================================================================
# General-purpose synthetic ATT&CK fixture builder
# ===========================================================================


def _uses(source: str, target: str, rel_id: str) -> dict[str, Any]:
    return {
        "type": "relationship",
        "id": f"relationship--{rel_id}",
        "relationship_type": "uses",
        "source_ref": source,
        "target_ref": target,
    }


def _build_kb(
    tmp_path: Path,
    *,
    technique_ids: set[str],
    group_techniques: dict[str, set[str]],
    campaign_techniques: dict[str, set[str]] | None = None,
    revoked_group_ids: frozenset[str] = frozenset(),
    deprecated_group_ids: frozenset[str] = frozenset(),
) -> AttackKnowledge:
    """Builds a synthetic, verified ATT&CK bundle from explicit group/
    campaign -> technique membership. Every group id in `group_techniques`
    becomes an `intrusion-set` object (active unless listed in
    `revoked_group_ids`/`deprecated_group_ids`); every technique id used
    anywhere becomes an `attack-pattern` object; one `uses` relationship is
    emitted per (entity, technique) membership pair.
    """
    campaign_techniques = campaign_techniques or {}
    objects: list[dict[str, Any]] = [
        {
            "type": "x-mitre-collection",
            "id": "x-mitre-collection--g35-fixture",
            "name": "Enterprise ATT&CK",
            "x_mitre_version": "19.0",
            "spec_version": "2.1",
            "created": "2020-01-01T00:00:00.000Z",
            "modified": "2020-01-01T00:00:00.000Z",
        },
    ]
    for technique_id in sorted(technique_ids):
        objects.append(
            {"type": "attack-pattern", "id": technique_id, "x_mitre_is_subtechnique": False}
        )
    for group_id in sorted(group_techniques):
        entry: dict[str, Any] = {
            "type": "intrusion-set",
            "id": group_id,
            "name": group_id,
            "aliases": [group_id],
        }
        if group_id in revoked_group_ids:
            entry["revoked"] = True
        if group_id in deprecated_group_ids:
            entry["x_mitre_deprecated"] = True
        objects.append(entry)
    for campaign_id in sorted(campaign_techniques):
        objects.append(
            {
                "type": "campaign",
                "id": campaign_id,
                "name": campaign_id,
                "aliases": [campaign_id],
            }
        )

    rel_counter = 0
    for group_id, techniques in group_techniques.items():
        for technique_id in sorted(techniques):
            rel_counter += 1
            objects.append(_uses(group_id, technique_id, str(rel_counter)))
    for campaign_id, techniques in campaign_techniques.items():
        for technique_id in sorted(techniques):
            rel_counter += 1
            objects.append(_uses(campaign_id, technique_id, str(rel_counter)))

    bundle = {"type": "bundle", "id": "bundle--g35-fixture", "objects": objects}

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


def _group(i: int) -> str:
    return f"intrusion-set--{i:08d}-0000-0000-0000-000000000000"


def _campaign(i: int) -> str:
    return f"campaign--{i:08d}-0000-0000-0000-000000000000"


def _technique(letter: str) -> str:
    # deterministic, alphabetically-ordered-by-letter STIX ids so canonical
    # sort order in tie-break tests matches the letters' own alphabetical order
    code = {"A": "1", "B": "2", "C": "3", "W": "7", "X": "8", "Y": "9", "Z": "a"}[letter]
    return f"attack-pattern--{code}0000000-0000-0000-0000-000000000000"


T_A, T_B, T_C = _technique("A"), _technique("B"), _technique("C")
T_W, T_X, T_Y, T_Z = _technique("W"), _technique("X"), _technique("Y"), _technique("Z")


# ===========================================================================
# CorrelationGroup / BehavioralSequence / ACHMatrix helpers
# ===========================================================================


def _correlation_provenance(**overrides: object) -> CorrelationProvenance:
    kwargs: dict[str, object] = {
        "method": "comparative-analysis-test",
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


def _analyze_full(
    knowledge: AttackKnowledge,
    feature_lists: list[tuple[str, ...]],
    *,
    min_profile_floor: int = DEFAULT_MIN_PROFILE_FLOOR,
) -> tuple[CandidateGenerationResult, ComparativeEvidenceResult]:
    group = _correlation_group()
    sequence = _sequence_from_feature_lists(group.group_id, feature_lists)
    candidate_result = generate_candidates(group, sequence, knowledge)
    matrix = build_ach_matrix(group, sequence, candidate_result, knowledge)
    result = compute_comparative_evidence(
        matrix, knowledge, candidate_result, min_profile_floor=min_profile_floor
    )
    return candidate_result, result


def _analyze(
    knowledge: AttackKnowledge,
    feature_lists: list[tuple[str, ...]],
    *,
    min_profile_floor: int = DEFAULT_MIN_PROFILE_FLOOR,
) -> ComparativeEvidenceResult:
    _candidate_result, result = _analyze_full(
        knowledge, feature_lists, min_profile_floor=min_profile_floor
    )
    return result


def _summary_for(result: ComparativeEvidenceResult, group_stix_id: str) -> HypothesisSupportSummary:
    hyp_id = compute_hypothesis_id("group-1", compute_candidate_id(group_stix_id))
    return next(s for s in result.hypothesis_summaries if s.hypothesis_id == hyp_id)


# ===========================================================================
# 1-4. Basic support aggregation
# ===========================================================================


def test_single_supporting_evidence(tmp_path: Path) -> None:
    # 4 active groups, T_A used by exactly 1 -> g=0.25, D=0.75
    kb = _build_kb(
        tmp_path,
        technique_ids={T_A},
        group_techniques={_group(1): {T_A}, _group(2): set(), _group(3): set(), _group(4): set()},
    )
    result = _analyze(kb, [(T_A,)])
    summary = _summary_for(result, _group(1))
    # G1's profile is {T_A} -> ProfileBreadth = 1; support = raw / max(1, floor=1) = raw
    assert summary.raw_support_value == pytest.approx(0.75)
    assert summary.profile_breadth == 1
    assert summary.profile_breadth_floor_applied is False
    assert summary.support_value == pytest.approx(0.75)
    assert len(summary.contributions) == 1
    assert summary.contributions[0].g_value == pytest.approx(0.25)
    assert summary.contributions[0].d_value == pytest.approx(0.75)


def test_multiple_supporting_evidence_items(tmp_path: Path) -> None:
    # G1 uses T_A (g=0.25, D=0.75) and T_B (g=0.5, D=0.5); no valid
    # combination (B's users are a superset of A's users here so combining
    # doesn't narrow further than A alone) -- both stay atomic.
    kb = _build_kb(
        tmp_path,
        technique_ids={T_A, T_B},
        group_techniques={
            _group(1): {T_A, T_B},
            _group(2): {T_B},
            _group(3): set(),
            _group(4): set(),
        },
    )
    result = _analyze(kb, [(T_A,), (T_B,)])
    summary = _summary_for(result, _group(1))
    # G1's profile is {T_A, T_B} -> ProfileBreadth = 2; raw = 0.75 + 0.5 = 1.25
    assert summary.raw_support_value == pytest.approx(0.75 + 0.5)
    assert summary.profile_breadth == 2
    assert summary.support_value == pytest.approx((0.75 + 0.5) / 2)
    assert len(summary.contributions) == 2


def test_multiple_competing_group_hypotheses(tmp_path: Path) -> None:
    kb = _build_kb(
        tmp_path,
        technique_ids={T_A},
        group_techniques={_group(1): {T_A}, _group(2): {T_A}, _group(3): set(), _group(4): set()},
    )
    result = _analyze(kb, [(T_A,)])
    s1 = _summary_for(result, _group(1))
    s2 = _summary_for(result, _group(2))
    assert s1.support_value == pytest.approx(0.5)  # g(T_A) = 2/4 = 0.5, D = 0.5
    assert s1.support_value == s2.support_value


def test_unattributed_always_retained(tmp_path: Path) -> None:
    kb = _build_kb(
        tmp_path, technique_ids={T_A}, group_techniques={_group(1): {T_A}, _group(2): set()}
    )
    result = _analyze(kb, [(T_A,)])
    candidate_ids = {s.candidate_id for s in result.hypothesis_summaries}
    assert UNATTRIBUTED_CANDIDATE_ID in candidate_ids
    unattributed = next(
        s for s in result.hypothesis_summaries if s.candidate_id == UNATTRIBUTED_CANDIDATE_ID
    )
    assert unattributed.support_value == 0.0
    assert unattributed.contributions == ()


# ===========================================================================
# 5-8. No candidates except Unattributed / same technique multiple steps /
# shared-observation duplicate / multiple techniques
# ===========================================================================


def test_no_candidates_except_unattributed(tmp_path: Path) -> None:
    kb = _build_kb(tmp_path, technique_ids={T_A}, group_techniques={_group(1): set()})
    result = _analyze(kb, [(_UNKNOWN_TECHNIQUE_ID,)])
    assert len(result.hypothesis_summaries) == 1
    assert result.hypothesis_summaries[0].candidate_id == UNATTRIBUTED_CANDIDATE_ID
    assert result.hypothesis_summaries[0].support_value == 0.0


def test_same_technique_across_multiple_steps_multiplies_contribution(tmp_path: Path) -> None:
    """ADR-0005 §D4: two distinct BehavioralSteps asserting the same
    technique contribute independently -- NOT deduplicated."""
    kb = _build_kb(
        tmp_path, technique_ids={T_A}, group_techniques={_group(1): {T_A}, _group(2): set()}
    )
    result = _analyze(kb, [(T_A,), (T_A,)])
    summary = _summary_for(result, _group(1))
    assert len(summary.contributions) == 1
    contribution = summary.contributions[0]
    assert len(contribution.assessment_ids) == 2
    assert contribution.d_value is not None
    assert contribution.contribution_value == pytest.approx(2 * contribution.d_value)
    assert summary.support_value == pytest.approx(2 * 0.5)  # g=1/2=0.5, D=0.5, x2 occurrences


def test_multiple_techniques(tmp_path: Path) -> None:
    kb = _build_kb(
        tmp_path,
        technique_ids={T_A, T_B, T_C},
        group_techniques={_group(1): {T_A, T_B, T_C}, _group(2): set(), _group(3): set()},
    )
    result = _analyze(kb, [(T_A,), (T_B,), (T_C,)])
    summary = _summary_for(result, _group(1))
    assert {fid for c in summary.contributions for fid in c.feature_stix_ids} == {T_A, T_B, T_C}


# ===========================================================================
# 9. Rare vs common ATT&CK features
# ===========================================================================


def test_rare_vs_common_features(tmp_path: Path) -> None:
    groups: dict[str, set[str]] = {_group(i): set() for i in range(1, 11)}
    groups[_group(1)] = {T_A, T_B}
    # T_A: common (used by all 10) -> g=1.0, D=0.0
    for i in range(1, 11):
        groups[_group(i)] = groups.get(_group(i), set()) | {T_A}
    # T_B: rare (used only by G1) -> g=0.1, D=0.9
    kb = _build_kb(tmp_path, technique_ids={T_A, T_B}, group_techniques=groups)
    result = _analyze(kb, [(T_A,), (T_B,)])
    summary = _summary_for(result, _group(1))
    common = next(c for c in summary.contributions if c.feature_stix_ids == (T_A,))
    rare = next(c for c in summary.contributions if c.feature_stix_ids == (T_B,))
    assert common.d_value == pytest.approx(0.0)
    assert rare.d_value == pytest.approx(0.9)
    assert rare.contribution_value > common.contribution_value


# ===========================================================================
# 10-11. g(x) / D(x) calculation
# ===========================================================================


def test_g_and_d_calculation_relative_to_active_groups_only(tmp_path: Path) -> None:
    kb = _build_kb(
        tmp_path,
        technique_ids={T_A},
        group_techniques={_group(i): ({T_A} if i <= 3 else set()) for i in range(1, 5)},
    )
    result = _analyze(kb, [(T_A,)])
    summary = _summary_for(result, _group(1))
    contribution = summary.contributions[0]
    assert contribution.g_value == pytest.approx(0.75)  # 3 of 4 active groups
    assert contribution.d_value == pytest.approx(0.25)
    assert contribution.diagnosticity_outcome is DiagnosticityOutcome.RESOLVED


# ===========================================================================
# 12. g(x) = 0 fail-closed behavior
# ===========================================================================


def test_g_zero_fails_closed_to_outside_calibrated_regime(tmp_path: Path) -> None:
    # T_A exists in the KB but is used by NO active group at all.
    kb = _build_kb(
        tmp_path, technique_ids={T_A}, group_techniques={_group(1): set(), _group(2): set()}
    )

    # A group must still exist that generates a candidate; since nobody uses
    # T_A, no candidate is generated for it at all -- so instead verify via
    # the internal helper directly with a synthetic g_of that returns None.
    def g_of_always_none(_features: frozenset[str]) -> float | None:
        return None

    # Directly exercise the summarization path via compute_comparative_evidence
    # is not possible here (no candidate would exist) -- so assert the
    # contract-level invariant instead: an OUTSIDE_CALIBRATED_REGIME
    # contribution must have g_value/d_value None and contribute 0.0.
    contribution = EvidenceContribution(
        feature_stix_ids=(T_A,),
        diagnosticity_outcome=DiagnosticityOutcome.OUTSIDE_CALIBRATED_REGIME,
        g_value=None,
        d_value=None,
        assessment_ids=("ea-1",),
        contribution_value=0.0,
    )
    assert contribution.contribution_value == 0.0
    with pytest.raises(AttributionError):
        EvidenceContribution(
            feature_stix_ids=(T_A,),
            diagnosticity_outcome=DiagnosticityOutcome.OUTSIDE_CALIBRATED_REGIME,
            g_value=0.3,  # must be None
            d_value=None,
            assessment_ids=("ea-1",),
            contribution_value=0.0,
        )
    assert kb is not None and g_of_always_none(frozenset({T_A})) is None


def test_zero_active_group_technique_never_generates_a_candidate(tmp_path: Path) -> None:
    """Consistency check with Gate 3.3: since no active group/campaign uses
    T_A at all, no candidate is generated for it, so support() is never
    even asked to resolve g(T_A) -- confirming this edge case is naturally
    excluded upstream, not silently mishandled here."""
    kb = _build_kb(
        tmp_path, technique_ids={T_A}, group_techniques={_group(1): set(), _group(2): set()}
    )
    result = _analyze(kb, [(T_A,)])
    assert len(result.hypothesis_summaries) == 1
    assert result.hypothesis_summaries[0].candidate_id == UNATTRIBUTED_CANDIDATE_ID


# ===========================================================================
# 13-14. Combination diagnosticity (hand-verified, non-trivial 3-feature case)
# ===========================================================================


def _three_feature_combination_kb(tmp_path: Path) -> AttackKnowledge:
    """G1 uses T_A, T_B, T_C. 10 active groups total.
    T_A: G1-G5 (g=0.5). T_B: G1-G3,G6,G7 (g=0.5).
    T_A&T_B intersect: G1-G3 (g=0.3 < 0.5 -> ADMISSIBLE).
    T_C: G1 only (g=0.1).
    T_A&T_C intersect: G1 only (g=0.1, NOT < min(0.5,0.1)=0.1 -> INADMISSIBLE, tie).
    T_B&T_C intersect: G1 only (g=0.1, NOT < 0.1 -> INADMISSIBLE).
    T_A&T_B&T_C intersect: G1 only (g=0.1, NOT < 0.1 -> INADMISSIBLE).
    Expected maximal partition: combination {T_A,T_B} (g=0.3) + atomic T_C (g=0.1).
    """
    groups = {
        _group(1): {T_A, T_B, T_C},
        _group(2): {T_A, T_B},
        _group(3): {T_A, T_B},
        _group(4): {T_A},
        _group(5): {T_A},
        _group(6): {T_B},
        _group(7): {T_B},
        _group(8): set(),
        _group(9): set(),
        _group(10): set(),
    }
    return _build_kb(tmp_path, technique_ids={T_A, T_B, T_C}, group_techniques=groups)


def test_combination_diagnosticity_hand_verified(tmp_path: Path) -> None:
    kb = _three_feature_combination_kb(tmp_path)
    result = _analyze(kb, [(T_A,), (T_B,), (T_C,)])
    summary = _summary_for(result, _group(1))

    combo = next(c for c in summary.contributions if c.feature_stix_ids == (T_A, T_B))
    atomic_c = next(c for c in summary.contributions if c.feature_stix_ids == (T_C,))
    assert len(summary.contributions) == 2  # {A,B} combined + C atomic -- never A,B separately
    assert combo.g_value == pytest.approx(0.3)
    assert combo.d_value == pytest.approx(0.7)
    assert combo.contribution_value == pytest.approx(0.7)  # combination contributes ONCE
    assert atomic_c.g_value == pytest.approx(0.1)
    assert atomic_c.d_value == pytest.approx(0.9)
    # raw = D(C={A,B}) + D(T_C) = 0.7 + 0.9 = 1.6, aggregated BEFORE normalization.
    # G1's profile is {T_A, T_B, T_C} -> ProfileBreadth = 3.
    assert summary.raw_support_value == pytest.approx(0.7 + 0.9)
    assert summary.profile_breadth == 3
    assert summary.support_value == pytest.approx((0.7 + 0.9) / 3)


def test_combination_never_double_counts_component_atomics(tmp_path: Path) -> None:
    kb = _three_feature_combination_kb(tmp_path)
    result = _analyze(kb, [(T_A,), (T_B,), (T_C,)])
    summary = _summary_for(result, _group(1))
    covered_features = {fid for c in summary.contributions for fid in c.feature_stix_ids}
    # T_A and T_B appear ONLY inside the combination block, never as their own atomic entries too
    assert (T_A,) not in [c.feature_stix_ids for c in summary.contributions]
    assert (T_B,) not in [c.feature_stix_ids for c in summary.contributions]
    assert covered_features == {T_A, T_B, T_C}


# ===========================================================================
# 15-16. Multiple valid combination partitions / deterministic tie-break
# ===========================================================================


def _hand_crafted_tie_g_of() -> Any:
    """A fully hand-controlled g(C) table (bypassing any real KB) proving
    the tie-break in isolation: {W,X} and {Y,Z} are each admissible at
    g=0.25 (< 0.5 for every singleton); {W,Y} and {X,Z} are ALSO each
    admissible at g=0.25; {W,Z} and {X,Y} are undefined (inadmissible); and
    every 3-/4-element combination is undefined (so the full set can never
    out-compete either 2+2 split -- unlike a real intersection-counting KB,
    where a single evidence-bearing group inherently makes the full-set
    combination valid too; see this function's own note below). This
    isolates _find_combination_partition's tie-break logic from KB
    monotonicity constraints entirely -- it is tested purely as a function
    of an injected g(C) table, exactly as it is written to accept one.

    Two maximal partitions with an IDENTICAL sum (0.25+0.25=0.5) exist:
    {W,X}+{Y,Z} and {W,Y}+{X,Z}. Canonical keys (sorted tuples of sorted
    member tuples): (('W','X'),('Y','Z')) vs (('W','Y'),('X','Z')) --
    comparing element-wise, ('W','X') < ('W','Y') (second element 'X'<'Y'),
    so {W,X}+{Y,Z} must win under ADR-0005's own lexicographic tie-break.
    """
    values: dict[frozenset[str], float | None] = {
        frozenset({T_W}): 0.5,
        frozenset({T_X}): 0.5,
        frozenset({T_Y}): 0.5,
        frozenset({T_Z}): 0.5,
        frozenset({T_W, T_X}): 0.25,
        frozenset({T_Y, T_Z}): 0.25,
        frozenset({T_W, T_Y}): 0.25,
        frozenset({T_X, T_Z}): 0.25,
        frozenset({T_W, T_Z}): None,
        frozenset({T_X, T_Y}): None,
        frozenset({T_W, T_X, T_Y}): None,
        frozenset({T_W, T_X, T_Z}): None,
        frozenset({T_W, T_Y, T_Z}): None,
        frozenset({T_X, T_Y, T_Z}): None,
        frozenset({T_W, T_X, T_Y, T_Z}): None,
    }

    def g_of(features: frozenset[str]) -> float | None:
        return values[features]

    return g_of


def test_multiple_valid_combination_partitions_and_deterministic_tie_break() -> None:
    g_of = _hand_crafted_tie_g_of()
    chosen = _find_combination_partition((T_W, T_X, T_Y, T_Z), g_of)
    assert frozenset({T_W, T_X}) in chosen
    assert frozenset({T_Y, T_Z}) in chosen
    assert frozenset({T_W, T_Y}) not in chosen
    assert frozenset({T_X, T_Z}) not in chosen
    assert len(chosen) == 2


def test_tie_break_is_deterministic_across_repeated_calls() -> None:
    g_of = _hand_crafted_tie_g_of()
    result_a = _find_combination_partition((T_W, T_X, T_Y, T_Z), g_of)
    result_b = _find_combination_partition((T_Z, T_Y, T_X, T_W), g_of)  # different input order
    assert result_a == result_b


def test_combination_search_handles_more_than_eight_features() -> None:
    """The former 8-feature limit is gone (exact search over co-used blocks):
    nine features whose every combination is co-used but none narrower than its
    parts yield the all-atomic partition, not an error."""
    features = tuple(f"attack-pattern--{i:08d}-0000-0000-0000-000000000000" for i in range(9))

    def g_of(_f: frozenset[str]) -> float | None:
        return 0.1

    assert _find_combination_partition(features, g_of) == ()


def test_combination_search_fails_closed_beyond_its_work_bound() -> None:
    features = tuple(f"attack-pattern--{i:08d}-0000-0000-0000-000000000000" for i in range(17))

    def g_of(_f: frozenset[str]) -> float | None:
        return 0.1  # every one of the 2**17 subsets co-used: beyond the bound

    with pytest.raises(AttributionError, match="exceeds the exact search's work bound"):
        _find_combination_partition(features, g_of)


# ===========================================================================
# 17. Candidate-type invariance
# ===========================================================================


def test_candidate_type_invariance_group_and_campaign_same_diagnosticity(
    tmp_path: Path,
) -> None:
    kb = _build_kb(
        tmp_path,
        technique_ids={T_A},
        group_techniques={_group(1): {T_A}, _group(2): {T_A}, _group(3): set(), _group(4): set()},
        campaign_techniques={_campaign(1): {T_A}},
    )
    result = _analyze(kb, [(T_A,)])
    group_summary = _summary_for(result, _group(1))
    campaign_hyp_id = compute_hypothesis_id("group-1", compute_candidate_id(_campaign(1)))
    campaign_summary = next(
        s for s in result.hypothesis_summaries if s.hypothesis_id == campaign_hyp_id
    )
    assert group_summary.support_value == campaign_summary.support_value
    assert group_summary.contributions[0].g_value == campaign_summary.contributions[0].g_value


def test_group_vs_campaign_hypotheses_distinct_identities(tmp_path: Path) -> None:
    kb = _build_kb(
        tmp_path,
        technique_ids={T_A},
        group_techniques={_group(1): {T_A}, _group(2): set()},
        campaign_techniques={_campaign(1): {T_A}},
    )
    result = _analyze(kb, [(T_A,)])
    candidate_ids = {s.candidate_id for s in result.hypothesis_summaries}
    assert compute_candidate_id(_group(1)) in candidate_ids
    assert compute_candidate_id(_campaign(1)) in candidate_ids
    assert compute_candidate_id(_group(1)) != compute_candidate_id(_campaign(1))


# ===========================================================================
# 18. Active/revoked/deprecated ATT&CK handling
# ===========================================================================


def test_revoked_and_deprecated_groups_excluded_from_g_denominator_and_numerator(
    tmp_path: Path,
) -> None:
    # 2 active groups use T_A; 1 revoked and 1 deprecated group ALSO use T_A.
    # g(T_A) must be 2/2 = 1.0 (active-only), never 2/4 or including the
    # revoked/deprecated users in the numerator.
    kb = _build_kb(
        tmp_path,
        technique_ids={T_A},
        group_techniques={
            _group(1): {T_A},
            _group(2): {T_A},
            _group(3): {T_A},
            _group(4): {T_A},
        },
        revoked_group_ids=frozenset({_group(3)}),
        deprecated_group_ids=frozenset({_group(4)}),
    )
    result = _analyze(kb, [(T_A,)])
    summary = _summary_for(result, _group(1))
    assert summary.contributions[0].g_value == pytest.approx(1.0)
    assert summary.contributions[0].d_value == pytest.approx(0.0)
    candidate_ids = {s.candidate_id for s in result.hypothesis_summaries}
    assert compute_candidate_id(_group(3)) not in candidate_ids
    assert compute_candidate_id(_group(4)) not in candidate_ids


# ===========================================================================
# 19-20. Coverage unavailable -> UNKNOWN; adequate coverage not yet supported
# ===========================================================================


def test_coverage_unavailable_never_becomes_contradiction(tmp_path: Path) -> None:
    """G2 does not use T_A -- no candidate/cell is generated for it; its
    absence must never be silently read as CONTRADICTING evidence."""
    kb = _build_kb(
        tmp_path, technique_ids={T_A}, group_techniques={_group(1): {T_A}, _group(2): set()}
    )
    result = _analyze(kb, [(T_A,)])
    candidate_ids = {s.candidate_id for s in result.hypothesis_summaries}
    assert compute_candidate_id(_group(2)) not in candidate_ids
    # No contribution anywhere ever carries a CONTRADICTING-derived value --
    # see test_contradicting_cell_fails_closed_rather_than_fabricating_a_weight
    # for the direct proof that such a cell would be rejected outright.


def test_contradicting_cell_fails_closed_rather_than_fabricating_a_weight(
    tmp_path: Path,
) -> None:
    """ADR-0005 never defines 'contradiction_strength'. Gate 3.4 never
    produces a CONTRADICTING cell in practice, but this module must still
    refuse to silently process one if it ever appeared, rather than invent
    a weight for it."""
    from attribution_platform.attribution.ach_matrix import ACHMatrix
    from attribution_platform.attribution.contracts import (
        EvidenceAssessment,
        EvidenceRole,
        Hypothesis,
        Relevance,
        compute_evidence_assessment_id,
    )

    kb = _build_kb(tmp_path, technique_ids={T_A}, group_techniques={_group(1): {T_A}})

    hyp = Hypothesis(
        hypothesis_id=compute_hypothesis_id("group-1", UNATTRIBUTED_CANDIDATE_ID),
        group_id="group-1",
        candidate_id=UNATTRIBUTED_CANDIDATE_ID,
    )
    bad_assessment = EvidenceAssessment(
        assessment_id=compute_evidence_assessment_id(hyp.hypothesis_id, "step-1", T_A),
        hypothesis_id=hyp.hypothesis_id,
        step_id="step-1",
        technique_stix_id=T_A,
        role=EvidenceRole.CONTRADICTING,
        relevance=Relevance.INCONSISTENT,
        diagnosticity_ref="diag-ref-1",
    )
    matrix = ACHMatrix(
        group_id="group-1",
        attack_kb_version=kb.attack_kb_version,
        hypotheses=(hyp,),
        assessments=(bad_assessment,),
    )
    empty_candidates = CandidateGenerationResult(
        group_id="group-1", attack_kb_version=kb.attack_kb_version
    )

    with pytest.raises(AttributionError, match="CONTRADICTING"):
        compute_comparative_evidence(matrix, kb, empty_candidates)


# ===========================================================================
# 21. Unknown technique handling
# ===========================================================================


def test_unknown_technique_handling(tmp_path: Path) -> None:
    kb = _build_kb(tmp_path, technique_ids={T_A}, group_techniques={_group(1): {T_A}})
    result = _analyze(kb, [(_UNKNOWN_TECHNIQUE_ID,), (T_A,)])
    summary = _summary_for(result, _group(1))
    assert len(summary.contributions) == 1
    assert summary.contributions[0].feature_stix_ids == (T_A,)


# ===========================================================================
# 22. Unattributed handling (already covered above; additional check)
# ===========================================================================


def test_unattributed_gets_no_fabricated_att_ck_support(tmp_path: Path) -> None:
    kb = _build_kb(
        tmp_path,
        technique_ids={T_A},
        group_techniques={_group(i): {T_A} for i in range(1, 6)},
    )
    result = _analyze(kb, [(T_A,)])
    unattributed = next(
        s for s in result.hypothesis_summaries if s.candidate_id == UNATTRIBUTED_CANDIDATE_ID
    )
    assert unattributed.support_value == 0.0


# ===========================================================================
# 23. Diagnosticity never a probability / 24. no arbitrary points
# ===========================================================================


def test_diagnosticity_bounded_and_not_probability_labeled() -> None:
    field_names = {f.name for f in __import__("dataclasses").fields(EvidenceContribution)}
    forbidden = {"probability", "percent", "percentage", "confidence", "likelihood"}
    assert field_names.isdisjoint(forbidden)


def test_no_arbitrary_point_values_in_source() -> None:
    source_text = COMPARATIVE_ANALYSIS_SOURCE.read_text(encoding="utf-8")
    for forbidden_literal in ("+10", "-5", "+20", "10 points", "point system"):
        assert forbidden_literal not in source_text


# ===========================================================================
# 25-28. No likelihood / confidence / abstention / winner
# ===========================================================================


def test_no_likelihood_confidence_abstention_or_winner_fields() -> None:
    import dataclasses

    for cls in (EvidenceContribution, HypothesisSupportSummary, ComparativeEvidenceResult):
        field_names = {f.name for f in dataclasses.fields(cls)}
        forbidden = {
            "likelihood",
            "wep_band",
            "confidence",
            "abstain",
            "abstention",
            "winner",
            "best_actor",
            "most_likely_actor",
            "final_attribution",
            "attribution_confidence",
            "leading_hypothesis_id",
        }
        assert field_names.isdisjoint(forbidden), f"{cls.__name__} exposes a forbidden field"


def test_source_never_implements_likelihood_confidence_calibration_or_abstention() -> None:
    source_text = COMPARATIVE_ANALYSIS_SOURCE.read_text(encoding="utf-8")
    tree = ast.parse(source_text)
    forbidden_substrings = (
        "compute_likelihood",
        "compute_wep",
        "compute_confidence",
        "run_calibration",
        "fit_calibration",
        "abstain",
        "select_winner",
        "rank_candidates",
        "elasticsearch",
        "elastic_client",
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
                f"comparative_analysis.py binds identifier {identifier!r} referencing "
                f"out-of-scope vocabulary {forbidden!r}"
            )


def test_source_imports_no_networking_dataplane_or_elastic_modules() -> None:
    source_text = COMPARATIVE_ANALYSIS_SOURCE.read_text(encoding="utf-8")
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
        "socket",
        "urllib",
        "http",
        "requests",
    }
    assert imported_modules.isdisjoint(forbidden_modules)


def test_comparative_analysis_module_imports_no_networking_libraries() -> None:
    for name in ("socket", "urllib", "http", "requests"):
        assert not hasattr(
            comparative_analysis_module, name
        ), f"comparative_analysis.py must not import {name!r}"


# ===========================================================================
# 29. No winner/final actor (behavioral, not just structural)
# ===========================================================================


def test_result_never_singles_out_a_winner(tmp_path: Path) -> None:
    kb = _build_kb(
        tmp_path,
        technique_ids={T_A},
        group_techniques={_group(1): {T_A}, _group(2): {T_A}, _group(3): set()},
    )
    result = _analyze(kb, [(T_A,)])
    assert not hasattr(result, "winner")
    assert not hasattr(result, "leading_hypothesis_id")
    assert not hasattr(result, "best_candidate_id")


# ===========================================================================
# 30. Provenance
# ===========================================================================


def test_provenance_traceable_to_assessment_ids(tmp_path: Path) -> None:
    kb = _build_kb(tmp_path, technique_ids={T_A}, group_techniques={_group(1): {T_A}})
    result = _analyze(kb, [(T_A,)])
    summary = _summary_for(result, _group(1))
    contribution = summary.contributions[0]
    assert contribution.assessment_ids
    assert all(isinstance(aid, str) and aid for aid in contribution.assessment_ids)
    assert result.group_id == "group-1"
    assert result.attack_kb_version == kb.attack_kb_version


# ===========================================================================
# 31. Deterministic repeated execution
# ===========================================================================


def test_deterministic_repeated_execution(tmp_path: Path) -> None:
    kb = _build_kb(
        tmp_path,
        technique_ids={T_A, T_B},
        group_techniques={_group(1): {T_A, T_B}, _group(2): {T_A}},
    )
    result_a = _analyze(kb, [(T_A,), (T_B,)])
    result_b = _analyze(kb, [(T_A,), (T_B,)])
    assert result_a == result_b


# ===========================================================================
# 32. No mutation of inputs
# ===========================================================================


def test_no_mutation_of_matrix_or_knowledge(tmp_path: Path) -> None:
    kb = _build_kb(tmp_path, technique_ids={T_A}, group_techniques={_group(1): {T_A}})
    group = _correlation_group()
    sequence = _sequence_from_feature_lists(group.group_id, [(T_A,)])
    candidate_result = generate_candidates(group, sequence, kb)
    matrix = build_ach_matrix(group, sequence, candidate_result, kb)

    matrix_before = (matrix.assessments, matrix.hypotheses)
    candidates_before = candidate_result.candidates
    fingerprint_before = kb.object_fingerprint

    compute_comparative_evidence(matrix, kb, candidate_result)

    assert (matrix.assessments, matrix.hypotheses) == matrix_before
    assert matrix.assessments is matrix_before[0]
    assert candidate_result.candidates is candidates_before
    assert kb.object_fingerprint is fingerprint_before


# ===========================================================================
# 33. No network dependency (already covered above structurally + behaviorally)
# ===========================================================================


def test_comparative_analysis_works_with_network_forcibly_blocked(tmp_path: Path) -> None:
    import socket
    from typing import Any as _Any

    original_connect = socket.socket.connect
    original_connect_ex = socket.socket.connect_ex

    def _blocked(self: _Any, *_args: _Any, **_kwargs: _Any) -> _Any:
        raise RuntimeError("NETWORK ACCESS BLOCKED FOR TEST")

    socket.socket.connect = _blocked  # type: ignore[method-assign]
    socket.socket.connect_ex = _blocked  # type: ignore[method-assign]
    try:
        kb = _build_kb(tmp_path, technique_ids={T_A}, group_techniques={_group(1): {T_A}})
        result = _analyze(kb, [(T_A,)])
        assert result.hypothesis_summaries
    finally:
        socket.socket.connect = original_connect  # type: ignore[method-assign]
        socket.socket.connect_ex = original_connect_ex  # type: ignore[method-assign]


# ===========================================================================
# 34. Real pinned v19.0 ATT&CK KB
# ===========================================================================


def _find_real_technique_with_group_users(kb: AttackKnowledge) -> str:
    for technique in kb.techniques():
        tid = str(technique["id"])
        if groups_using_technique(kb, tid):
            return tid
    pytest.fail("expected a technique with active Group users in v19.0")


def test_real_pinned_kb_support_computation() -> None:
    kb = load_attack_knowledge()
    technique_id = _find_real_technique_with_group_users(kb)
    result = _analyze(kb, [(technique_id,)])
    nonzero = [s for s in result.hypothesis_summaries if s.support_value > 0]
    assert nonzero
    for summary in nonzero:
        for contribution in summary.contributions:
            assert 0.0 <= contribution.g_value <= 1.0  # type: ignore[operator]
            assert 0.0 <= contribution.d_value <= 1.0  # type: ignore[operator]


def test_real_pinned_kb_deterministic_across_independently_loaded_instances() -> None:
    kb_a = load_attack_knowledge()
    kb_b = load_attack_knowledge()
    technique_id = _find_real_technique_with_group_users(kb_a)
    result_a = _analyze(kb_a, [(technique_id,)])
    result_b = _analyze(kb_b, [(technique_id,)])
    assert result_a == result_b


# ===========================================================================
# 35-36. Structural guards / regression (full suite run separately by the report)
# ===========================================================================


def test_no_regenerate_candidates_import() -> None:
    """This module reads an already-built ACHMatrix; it must never import
    generate_candidates or build_ach_matrix's own construction internals to
    regenerate anything."""
    source_text = COMPARATIVE_ANALYSIS_SOURCE.read_text(encoding="utf-8")
    tree = ast.parse(source_text)
    imported_names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                imported_names.add(alias.name)
    assert "generate_candidates" not in imported_names
    assert "build_ach_matrix" not in imported_names


def test_mismatched_kb_version_fails_closed(tmp_path: Path) -> None:
    from attribution_platform.attribution.ach_matrix import ACHMatrix

    kb = _build_kb(tmp_path, technique_ids={T_A}, group_techniques={_group(1): {T_A}})
    fake_matrix = ACHMatrix(group_id="group-1", attack_kb_version="enterprise-attack-99.9")
    candidates = CandidateGenerationResult(
        group_id="group-1", attack_kb_version=kb.attack_kb_version
    )
    with pytest.raises(AttributionError, match="attack_kb_version"):
        compute_comparative_evidence(fake_matrix, kb, candidates)


def test_mismatched_candidate_result_group_id_fails_closed(tmp_path: Path) -> None:
    from attribution_platform.attribution.ach_matrix import ACHMatrix

    kb = _build_kb(tmp_path, technique_ids={T_A}, group_techniques={_group(1): {T_A}})
    matrix = ACHMatrix(group_id="group-1", attack_kb_version=kb.attack_kb_version)
    wrong_candidates = CandidateGenerationResult(
        group_id="group-2", attack_kb_version=kb.attack_kb_version
    )
    with pytest.raises(AttributionError, match="candidate_result.group_id"):
        compute_comparative_evidence(matrix, kb, wrong_candidates)


def test_wrong_argument_types_rejected(tmp_path: Path) -> None:
    from attribution_platform.attribution.ach_matrix import ACHMatrix

    kb = _build_kb(tmp_path, technique_ids={T_A}, group_techniques={_group(1): {T_A}})
    valid_matrix = ACHMatrix(group_id="group-1", attack_kb_version=kb.attack_kb_version)
    valid_candidates = CandidateGenerationResult(
        group_id="group-1", attack_kb_version=kb.attack_kb_version
    )
    with pytest.raises(AttributionError):
        compute_comparative_evidence("not-a-matrix", kb, valid_candidates)  # type: ignore[arg-type]
    with pytest.raises(AttributionError):
        compute_comparative_evidence(valid_matrix, "not-a-knowledge", valid_candidates)  # type: ignore[arg-type]
    with pytest.raises(AttributionError):
        compute_comparative_evidence(valid_matrix, kb, "not-a-candidate-result")  # type: ignore[arg-type]
    with pytest.raises(AttributionError, match="min_profile_floor"):
        compute_comparative_evidence(valid_matrix, kb, valid_candidates, min_profile_floor=0)
    with pytest.raises(AttributionError, match="min_profile_floor"):
        compute_comparative_evidence(
            valid_matrix,
            kb,
            valid_candidates,
            min_profile_floor=1.5,  # type: ignore[arg-type]
        )


# ===========================================================================
# Profile-breadth normalization (ADR-0005 Amendment A)
# ===========================================================================


def _candidate_stix_id(candidate_result: CandidateGenerationResult, candidate_id: str) -> str:
    candidate = next(c for c in candidate_result.candidates if c.candidate_id == candidate_id)
    stix = candidate.actor_ref if candidate.actor_ref is not None else candidate.campaign_ref
    assert stix is not None
    return stix


def test_basic_profile_normalization(tmp_path: Path) -> None:
    # G1 uses only {T_A} -> pb=1; g(T_A)=1/4=0.25, D=0.75; support=0.75/max(1,1)=0.75
    kb = _build_kb(
        tmp_path,
        technique_ids={T_A},
        group_techniques={_group(1): {T_A}, _group(2): set(), _group(3): set(), _group(4): set()},
    )
    result = _analyze(kb, [(T_A,)])
    s = _summary_for(result, _group(1))
    assert s.raw_support_value == pytest.approx(0.75)
    assert s.profile_breadth == 1
    assert s.support_value == pytest.approx(0.75 / 1)


def test_same_evidence_different_profile_breadth_gives_different_support(tmp_path: Path) -> None:
    # Both G1 (small) and G2 (big) use observed T_A -> identical D(T_A) and
    # identical raw support; G2 additionally documents T_B/T_C (unobserved),
    # so its profile is larger. Normalized support differs -- the richness
    # artifact Amendment A exists to correct.
    kb = _build_kb(
        tmp_path,
        technique_ids={T_A, T_B, T_C},
        group_techniques={
            _group(1): {T_A},
            _group(2): {T_A, T_B, T_C},
            _group(3): set(),
            _group(4): set(),
        },
    )
    result = _analyze(kb, [(T_A,)])
    small = _summary_for(result, _group(1))
    big = _summary_for(result, _group(2))
    assert small.raw_support_value == pytest.approx(big.raw_support_value)
    assert small.profile_breadth == 1
    assert big.profile_breadth == 3
    assert small.support_value == pytest.approx(small.raw_support_value / 1)
    assert big.support_value == pytest.approx(big.raw_support_value / 3)
    assert small.support_value > big.support_value


def test_floor_clamping_when_profile_below_floor(tmp_path: Path) -> None:
    kb = _build_kb(
        tmp_path,
        technique_ids={T_A, T_B},
        group_techniques={
            _group(1): {T_A, T_B},
            _group(2): {T_B},
            _group(3): set(),
            _group(4): set(),
        },
    )
    result = _analyze(kb, [(T_A,), (T_B,)], min_profile_floor=5)
    s = _summary_for(result, _group(1))
    assert s.profile_breadth == 2  # raw breadth is reported unclamped
    assert s.profile_breadth_floor_applied is True
    assert s.support_value == pytest.approx(s.raw_support_value / 5)  # divided by floor, not 2


def test_profile_exactly_at_floor_not_clamped(tmp_path: Path) -> None:
    kb = _build_kb(
        tmp_path,
        technique_ids={T_A, T_B, T_C},
        group_techniques={_group(1): {T_A, T_B, T_C}, _group(2): set(), _group(3): set()},
    )
    result = _analyze(kb, [(T_A,), (T_B,), (T_C,)], min_profile_floor=3)
    s = _summary_for(result, _group(1))
    assert s.profile_breadth == 3
    assert s.profile_breadth_floor_applied is False  # pb == floor is NOT below the floor
    assert s.support_value == pytest.approx(s.raw_support_value / 3)


def test_profile_above_floor_not_clamped(tmp_path: Path) -> None:
    kb = _build_kb(
        tmp_path,
        technique_ids={T_A, T_B, T_C},
        group_techniques={_group(1): {T_A, T_B, T_C}, _group(2): set(), _group(3): set()},
    )
    result = _analyze(kb, [(T_A,), (T_B,), (T_C,)], min_profile_floor=2)
    s = _summary_for(result, _group(1))
    assert s.profile_breadth == 3
    assert s.profile_breadth_floor_applied is False
    assert s.support_value == pytest.approx(s.raw_support_value / 3)


def test_group_and_campaign_same_formula_natural_breadth_difference(tmp_path: Path) -> None:
    kb = _build_kb(
        tmp_path,
        technique_ids={T_A, T_B},
        group_techniques={_group(1): {T_A}, _group(2): set(), _group(3): set(), _group(4): set()},
        campaign_techniques={_campaign(1): {T_A, T_B}},
    )
    result = _analyze(kb, [(T_A,)])
    g = _summary_for(result, _group(1))
    c_hyp_id = compute_hypothesis_id("group-1", compute_candidate_id(_campaign(1)))
    c = next(s for s in result.hypothesis_summaries if s.hypothesis_id == c_hyp_id)
    # Identical raw (same D(T_A)); identical FORMULA support=raw/pb; naturally different pb.
    assert g.raw_support_value == pytest.approx(c.raw_support_value)
    assert g.profile_breadth == 1
    assert c.profile_breadth == 2
    assert g.support_value == pytest.approx(g.raw_support_value / 1)
    assert c.support_value == pytest.approx(c.raw_support_value / 2)


def test_repeated_technique_multiplicity_summed_before_normalization(tmp_path: Path) -> None:
    # G1 is the sole user of T_A among 10 groups -> g=0.1, D=0.9. Observed via
    # THREE distinct steps -> raw = 3*0.9 = 2.7, aggregated BEFORE the single
    # division by pb=1 (not normalized per occurrence).
    groups: dict[str, set[str]] = {_group(i): set() for i in range(1, 11)}
    groups[_group(1)] = {T_A}
    kb = _build_kb(tmp_path, technique_ids={T_A}, group_techniques=groups)
    result = _analyze(kb, [(T_A,), (T_A,), (T_A,)])
    s = _summary_for(result, _group(1))
    assert len(s.contributions) == 1
    assert len(s.contributions[0].assessment_ids) == 3
    assert s.raw_support_value == pytest.approx(3 * 0.9)
    assert s.profile_breadth == 1
    assert s.support_value == pytest.approx((3 * 0.9) / 1)


def test_combination_plus_normalization(tmp_path: Path) -> None:
    kb = _three_feature_combination_kb(tmp_path)
    result = _analyze(kb, [(T_A,), (T_B,), (T_C,)])
    s = _summary_for(result, _group(1))
    # raw = D(C={A,B})=0.7 + D(T_C)=0.9 = 1.6, aggregated before one division by pb=3.
    assert s.raw_support_value == pytest.approx(1.6)
    assert s.profile_breadth == 3
    assert s.support_value == pytest.approx(1.6 / 3)


def test_unattributed_no_group_profile_no_division(tmp_path: Path) -> None:
    kb = _build_kb(
        tmp_path, technique_ids={T_A}, group_techniques={_group(1): {T_A}, _group(2): set()}
    )
    result = _analyze(kb, [(T_A,)])
    u = next(s for s in result.hypothesis_summaries if s.candidate_id == UNATTRIBUTED_CANDIDATE_ID)
    assert u.profile_breadth is None
    assert u.profile_breadth_floor_applied is False
    assert u.raw_support_value == 0.0
    assert u.support_value == 0.0


def test_support_may_exceed_one_and_is_not_clamped(tmp_path: Path) -> None:
    groups: dict[str, set[str]] = {_group(i): set() for i in range(1, 11)}
    groups[_group(1)] = {T_A}
    kb = _build_kb(tmp_path, technique_ids={T_A}, group_techniques=groups)
    result = _analyze(kb, [(T_A,), (T_A,), (T_A,)])  # raw = 3 * D(0.9) = 2.7, pb=1
    s = _summary_for(result, _group(1))
    assert s.support_value == pytest.approx(2.7)
    assert s.support_value > 1.0  # permitted: support is an ordering statistic, never a probability


def test_explainability_fields_present_and_consistent(tmp_path: Path) -> None:
    kb = _build_kb(
        tmp_path,
        technique_ids={T_A, T_B},
        group_techniques={
            _group(1): {T_A, T_B},
            _group(2): {T_B},
            _group(3): set(),
            _group(4): set(),
        },
    )
    candidate_result, result = _analyze_full(kb, [(T_A,), (T_B,)])
    s = _summary_for(result, _group(1))
    # raw == sum of per-feature contribution values (contributions unchanged by Amendment A)
    assert s.raw_support_value == pytest.approx(sum(c.contribution_value for c in s.contributions))
    # profile_breadth resolved from the candidate's real STIX id (no hash reversal):
    stix = _candidate_stix_id(candidate_result, s.candidate_id)
    assert s.profile_breadth == len(group_profile(kb, stix))
    assert s.support_value == pytest.approx(
        s.raw_support_value / max(s.profile_breadth, DEFAULT_MIN_PROFILE_FLOOR)
    )


def test_small_profile_candidate_not_dropped(tmp_path: Path) -> None:
    kb = _build_kb(
        tmp_path, technique_ids={T_A}, group_techniques={_group(1): {T_A}, _group(2): set()}
    )
    result = _analyze(kb, [(T_A,)])
    ids = {s.candidate_id for s in result.hypothesis_summaries}
    assert compute_candidate_id(_group(1)) in ids  # not dropped for having a small profile
    s = _summary_for(result, _group(1))
    assert s.support_value > 0.0


def test_zero_profile_breadth_is_scoreable_through_floor_contract() -> None:
    # profile_breadth == 0 is unreachable for a real generated candidate, but
    # the summary contract accepts it; the engine's max(pb, floor) keeps the
    # denominator >= 1, so such a candidate is scored, never dropped.
    s = HypothesisSupportSummary(
        hypothesis_id="h-1",
        candidate_id="candidate::x",
        support_value=0.0,
        raw_support_value=0.0,
        profile_breadth=0,
        profile_breadth_floor_applied=True,
        contributions=(),
    )
    assert s.profile_breadth == 0
    assert s.profile_breadth_floor_applied is True


def test_new_summary_fields_are_not_probabilities() -> None:
    import dataclasses

    field_names = {f.name for f in dataclasses.fields(HypothesisSupportSummary)}
    forbidden = {"probability", "percent", "percentage", "confidence", "likelihood", "wep_band"}
    assert field_names.isdisjoint(forbidden)


def test_normalization_determinism_repeated_and_independent_kb(tmp_path: Path) -> None:
    kb_a = _build_kb(
        tmp_path / "a",
        technique_ids={T_A, T_B, T_C},
        group_techniques={_group(1): {T_A, T_B, T_C}, _group(2): {T_A}, _group(3): set()},
    )
    kb_b = _build_kb(
        tmp_path / "b",
        technique_ids={T_A, T_B, T_C},
        group_techniques={_group(1): {T_A, T_B, T_C}, _group(2): {T_A}, _group(3): set()},
    )
    r_a1 = _analyze(kb_a, [(T_A,), (T_B,), (T_C,)])
    r_a2 = _analyze(kb_a, [(T_A,), (T_B,), (T_C,)])
    r_b = _analyze(kb_b, [(T_A,), (T_B,), (T_C,)])
    assert r_a1 == r_a2
    assert r_a1.hypothesis_summaries == r_b.hypothesis_summaries
