"""Tests for gate G2.4.0: behavioral-sequence domain contracts (ADR-0004).

Covers: :class:`BehavioralStep` (evidence-id/observation grounding shape,
canonicalization, ATT&CK-convenience-field shape, field-set pin);
:class:`OrderingBasis`/:class:`OrderingBasisKind` (exactly two ordering
bases, no third "inferred" tier, no ``TEMPORAL_PROXIMITY``);
:class:`SequenceEdge` (directional identity, self-edge rejection, both
ordering bases); :class:`SequenceGap` (undirected canonicalization,
deterministic identity, distinction from ``SequenceEdge``);
:class:`SequenceParallelGroup` (the accepted branch-partition design —
`>=2` branches, convergence-safety exclusion, order-independent
deterministic identity, delimiter-collision regression); and
:class:`BehavioralSequence` (internal-consistency invariants — duplicate
ids, dangling endpoints, edge/gap conflict, acyclicity, cross-branch
edge/gap conflict — plus the two sanctioned cross-group-validating
constructors :func:`build_behavioral_step`/:func:`build_behavioral_sequence`,
mirroring G2.0's own ``build_correlation_group``). Also covers explicit
negative proof that a contextual (non-structural) link id can never ground
a ``SequenceEdge``/``SequenceGap`` via ``build_behavioral_sequence``, and
guards preserving ADR-0004's boundaries (no attribution/scoring vocabulary,
no ``TEMPORAL_PROXIMITY``, no import of sources/dataplane/replay/api, and —
stronger than G2.1/G2.2 — no import of ``domain`` at all).

This is a G2.4.0 contracts-only gate: no sequence-construction/ordering
algorithm, no ``SHARED_OBSERVATION``-collapse, no branch/convergence
discovery, no replay, no persistence exists to test here.

Does NOT touch any G0.x/G1.x/G2.0-G2.3 source, test, or fixture. Offline,
deterministic, no Elastic/Docker/Windows/network required.
"""

from __future__ import annotations

import ast
import dataclasses
from pathlib import Path

import pytest

from attribution_platform.correlation import (
    BehavioralSequence,
    BehavioralStep,
    CorrelationError,
    CorrelationGroup,
    CorrelationProvenance,
    GapReason,
    OrderingBasis,
    OrderingBasisKind,
    SequenceEdge,
    SequenceGap,
    SequenceParallelGroup,
    build_behavioral_sequence,
    build_behavioral_step,
    compute_sequence_edge_id,
    compute_sequence_gap_id,
    compute_sequence_id,
    compute_sequence_parallel_group_id,
    compute_step_id,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
CORRELATION_DIR = REPO_ROOT / "src" / "attribution_platform" / "correlation"
SEQUENCE_FILE = CORRELATION_DIR / "sequence.py"


# ===========================================================================
# Shared helpers
# ===========================================================================


def _correlation_provenance(**overrides: object) -> CorrelationProvenance:
    kwargs: dict[str, object] = {
        "method": "behavioral-sequence-construction",
        "method_version": "1.0",
        "source_evidence_ids": ("ev-1", "ev-2"),
        "source_observation_ids": ("obs-1", "obs-2"),
    }
    kwargs.update(overrides)
    return CorrelationProvenance(**kwargs)  # type: ignore[arg-type]


def _group(**overrides: object) -> CorrelationGroup:
    kwargs: dict[str, object] = {
        "group_id": "group-1",
        "member_evidence_ids": ("ev-1", "ev-2"),
        "member_observation_ids": ("obs-1", "obs-2"),
        "structural_link_ids": ("link-1",),
        "provenance": _correlation_provenance(),
    }
    kwargs.update(overrides)
    return CorrelationGroup(**kwargs)  # type: ignore[arg-type]


def _step(**overrides: object) -> BehavioralStep:
    kwargs: dict[str, object] = {
        "step_id": compute_step_id("group-1", ["ev-1"]),
        "group_id": "group-1",
        "evidence_ids": ("ev-1",),
        "observation_id": "obs-1",
    }
    kwargs.update(overrides)
    return BehavioralStep(**kwargs)  # type: ignore[arg-type]


def _ordering_basis(**overrides: object) -> OrderingBasis:
    kwargs: dict[str, object] = {
        "basis_kind": OrderingBasisKind.PROCESS_LINEAGE,
        "grounding_link_id": "link-1",
    }
    kwargs.update(overrides)
    return OrderingBasis(**kwargs)  # type: ignore[arg-type]


def _edge(**overrides: object) -> SequenceEdge:
    kwargs: dict[str, object] = {
        "edge_id": compute_sequence_edge_id(
            from_step_id="step-a",
            to_step_id="step-b",
            basis_kind=OrderingBasisKind.PROCESS_LINEAGE,
            grounding_link_id="link-1",
        ),
        "from_step_id": "step-a",
        "to_step_id": "step-b",
        "basis": _ordering_basis(),
    }
    kwargs.update(overrides)
    return SequenceEdge(**kwargs)  # type: ignore[arg-type]


def _gap(**overrides: object) -> SequenceGap:
    kwargs: dict[str, object] = {
        "gap_id": compute_sequence_gap_id(
            step_id_a="step-a",
            step_id_b="step-b",
            reason=GapReason.EQUAL_TIMESTAMPS,
            grounding_link_id="link-1",
        ),
        "step_id_a": "step-a",
        "step_id_b": "step-b",
        "grounding_link_id": "link-1",
        "reason": GapReason.EQUAL_TIMESTAMPS,
    }
    kwargs.update(overrides)
    return SequenceGap(**kwargs)  # type: ignore[arg-type]


def _parallel_group(**overrides: object) -> SequenceParallelGroup:
    branches: tuple[tuple[str, ...], ...] = (("step-a",), ("step-b",))
    kwargs: dict[str, object] = {
        "parallel_group_id": compute_sequence_parallel_group_id("step-p", branches),
        "source_step_id": "step-p",
        "branches": branches,
    }
    kwargs.update(overrides)
    return SequenceParallelGroup(**kwargs)  # type: ignore[arg-type]


def _sequence(**overrides: object) -> BehavioralSequence:
    steps: tuple[BehavioralStep, ...] = (_step(),)
    kwargs: dict[str, object] = {
        "sequence_id": compute_sequence_id("group-1", [s.step_id for s in steps]),
        "group_id": "group-1",
        "steps": steps,
        "provenance": _correlation_provenance(),
    }
    kwargs.update(overrides)
    return BehavioralSequence(**kwargs)  # type: ignore[arg-type]


# ===========================================================================
# 1. BehavioralStep
# ===========================================================================


def test_behavioral_step_valid_construction_preserves_fields() -> None:
    step = _step(technique_stix_ids=("attack-pattern--x",), contextual_annotations=("corr::ctx",))
    assert step.evidence_ids == ("ev-1",)
    assert step.observation_id == "obs-1"
    assert step.technique_stix_ids == ("attack-pattern--x",)
    assert step.contextual_annotations == ("corr::ctx",)


def test_behavioral_step_empty_evidence_ids_rejected() -> None:
    with pytest.raises(CorrelationError, match="evidence_ids must be non-empty"):
        _step(evidence_ids=())


def test_behavioral_step_blank_step_id_rejected() -> None:
    with pytest.raises(CorrelationError, match="non-empty, non-whitespace string"):
        _step(step_id="   ")


def test_behavioral_step_blank_group_id_rejected() -> None:
    with pytest.raises(CorrelationError, match="non-empty, non-whitespace string"):
        _step(group_id="")


def test_behavioral_step_blank_observation_id_rejected() -> None:
    with pytest.raises(CorrelationError, match="non-empty, non-whitespace string"):
        _step(observation_id="")


def test_behavioral_step_duplicate_evidence_ids_silently_deduplicated() -> None:
    step = _step(evidence_ids=("ev-2", "ev-1", "ev-2"))
    assert step.evidence_ids == ("ev-1", "ev-2")


def test_behavioral_step_technique_stix_ids_canonicalized_sorted_unique() -> None:
    step = _step(technique_stix_ids=("attack-pattern--b", "attack-pattern--a", "attack-pattern--a"))
    assert step.technique_stix_ids == ("attack-pattern--a", "attack-pattern--b")


def test_behavioral_step_technique_stix_ids_default_empty() -> None:
    assert _step().technique_stix_ids == ()


def test_behavioral_step_evidence_types_canonicalized_sorted_unique() -> None:
    step = _step(evidence_types=("procedural", "behavioral", "behavioral"))
    assert step.evidence_types == ("behavioral", "procedural")


def test_behavioral_step_evidence_types_default_empty() -> None:
    assert _step().evidence_types == ()


def test_behavioral_step_rejects_empty_evidence_type_value() -> None:
    with pytest.raises(CorrelationError):
        _step(evidence_types=("behavioral", ""))


def test_evidence_types_do_not_participate_in_step_id() -> None:
    # step identity is compute_step_id(group_id, evidence_ids) only; the same
    # (group, evidence) with different evidence_types is the same step_id.
    step_id = compute_step_id("group-1", ["ev-1"])
    a = _step(step_id=step_id, evidence_types=())
    b = _step(step_id=step_id, evidence_types=("behavioral", "procedural"))
    assert a.step_id == b.step_id == compute_step_id("group-1", ["ev-1"])


def test_evidence_types_do_not_participate_in_sequence_id() -> None:
    # sequence identity is compute_sequence_id(group_id, step_ids); since
    # step_ids are invariant to evidence_types, so is sequence_id.
    step_id = compute_step_id("group-1", ["ev-1"])
    a = _step(step_id=step_id, evidence_types=())
    b = _step(step_id=step_id, evidence_types=("behavioral",))
    assert compute_sequence_id("group-1", [a.step_id]) == compute_sequence_id(
        "group-1", [b.step_id]
    )


def test_behavioral_step_contextual_annotations_canonicalized_sorted_unique() -> None:
    step = _step(contextual_annotations=("corr::b", "corr::a", "corr::a"))
    assert step.contextual_annotations == ("corr::a", "corr::b")


def test_behavioral_step_field_set_pinned_no_attribution_fields() -> None:
    """Architectural regression protection: pins the exact field set so a
    future change cannot silently add a likelihood/confidence/actor/
    campaign/score field without this test failing and forcing a
    deliberate architectural decision (ADR-0004 D15/D17)."""
    field_names = {f.name for f in dataclasses.fields(BehavioralStep)}
    assert field_names == {
        "step_id",
        "group_id",
        "evidence_ids",
        "observation_id",
        "technique_stix_ids",
        # B4 (2026-09-21): carry-forward provenance of member Evidence.evidence_type;
        # NOT a likelihood/confidence/actor/score field — the guard's intent holds.
        "evidence_types",
        "contextual_annotations",
        "schema_version",
    }


# ===========================================================================
# 2. build_behavioral_step
# ===========================================================================


def test_build_behavioral_step_valid_path() -> None:
    group = _group()
    step = build_behavioral_step(
        step_id="step-1",
        group=group,
        evidence_ids=["ev-1"],
        observation_id="obs-1",
    )
    assert step.group_id == group.group_id
    assert step.evidence_ids == ("ev-1",)


def test_build_behavioral_step_rejects_evidence_not_in_group() -> None:
    group = _group()
    with pytest.raises(CorrelationError, match="is not a member of"):
        build_behavioral_step(
            step_id="step-1",
            group=group,
            evidence_ids=["ev-not-in-group"],
            observation_id="obs-1",
        )


def test_build_behavioral_step_rejects_observation_not_in_group() -> None:
    group = _group()
    with pytest.raises(CorrelationError, match="is not a member of"):
        build_behavioral_step(
            step_id="step-1",
            group=group,
            evidence_ids=["ev-1"],
            observation_id="obs-not-in-group",
        )


def test_build_behavioral_step_rejects_non_correlation_group() -> None:
    with pytest.raises(CorrelationError, match="must be a CorrelationGroup"):
        build_behavioral_step(
            step_id="step-1",
            group="not-a-group",  # type: ignore[arg-type]
            evidence_ids=["ev-1"],
            observation_id="obs-1",
        )


def test_build_behavioral_step_rejects_empty_evidence_ids() -> None:
    with pytest.raises(CorrelationError, match="evidence_ids must be non-empty"):
        build_behavioral_step(
            step_id="step-1", group=_group(), evidence_ids=[], observation_id="obs-1"
        )


def test_build_behavioral_step_no_longer_accepts_technique_stix_ids_parameter() -> None:
    """G2.4.0 pre-commit audit correction: the sanctioned builder must not
    advertise a caller-supplied mechanism for populating technique_stix_ids
    -- it cannot verify such a value against anything (unlike evidence_ids/
    observation_id, which it genuinely checks against the real group), so
    it must not accept the parameter at all. Passing it must be a
    TypeError (unexpected keyword argument), not a silently-accepted,
    unverified value."""
    with pytest.raises(TypeError, match="technique_stix_ids"):
        build_behavioral_step(  # type: ignore[call-arg]
            step_id="step-1",
            group=_group(),
            evidence_ids=["ev-1"],
            observation_id="obs-1",
            technique_stix_ids=["attack-pattern--fabricated"],
        )


def test_build_behavioral_step_produced_step_always_has_empty_technique_stix_ids() -> None:
    """Direct consequence of the correction above: a step built via the
    sanctioned path can never carry a technique_stix_ids value -- only the
    raw BehavioralStep constructor can, and only as unverified, shape-
    validated, caller-supplied data (see BehavioralStep's own docstring)."""
    step = build_behavioral_step(
        step_id="step-1", group=_group(), evidence_ids=["ev-1"], observation_id="obs-1"
    )
    assert step.technique_stix_ids == ()


def test_raw_behavioral_step_constructor_still_shape_validates_technique_stix_ids() -> None:
    """The raw BehavioralStep contract is unaffected by the builder
    correction -- it still shape-validates (canonicalizes, rejects blank
    entries) whatever technique_stix_ids a caller supplies directly, since
    G2.4.0 does not yet have the Evidence-derived producer (G2.4.1) that
    would call it with a trustworthy value."""
    step = _step(technique_stix_ids=("attack-pattern--b", "attack-pattern--a"))
    assert step.technique_stix_ids == ("attack-pattern--a", "attack-pattern--b")
    with pytest.raises(CorrelationError, match="non-empty, non-whitespace string"):
        _step(technique_stix_ids=("",))


# ===========================================================================
# 3. OrderingBasis / OrderingBasisKind
# ===========================================================================


def test_exactly_two_ordering_bases_no_temporal_proximity() -> None:
    assert {member.name for member in OrderingBasisKind} == {
        "PROCESS_LINEAGE",
        "TEMPORAL_SAME_ENTITY",
    }
    assert len(OrderingBasisKind) == 2


def test_unknown_ordering_basis_kind_rejected() -> None:
    with pytest.raises(ValueError):
        OrderingBasisKind("temporal_proximity")


def test_ordering_basis_valid_construction() -> None:
    basis = _ordering_basis(timestamp_agreement=False, precision_uncertain=True)
    assert basis.basis_kind == OrderingBasisKind.PROCESS_LINEAGE
    assert basis.timestamp_agreement is False
    assert basis.precision_uncertain is True


def test_ordering_basis_blank_grounding_link_id_rejected() -> None:
    with pytest.raises(CorrelationError, match="non-empty, non-whitespace string"):
        _ordering_basis(grounding_link_id="")


def test_ordering_basis_invalid_basis_kind_type_rejected() -> None:
    with pytest.raises(CorrelationError, match="must be an OrderingBasisKind"):
        _ordering_basis(basis_kind="process_lineage")


def test_ordering_basis_timestamp_agreement_defaults_to_none() -> None:
    assert _ordering_basis().timestamp_agreement is None


def test_ordering_basis_field_set_pinned_categorical_only() -> None:
    field_names = {f.name for f in dataclasses.fields(OrderingBasis)}
    assert field_names == {
        "basis_kind",
        "grounding_link_id",
        "timestamp_agreement",
        "precision_uncertain",
    }


# ===========================================================================
# 4. SequenceEdge
# ===========================================================================


def test_sequence_edge_valid_directional_construction() -> None:
    edge = _edge()
    assert edge.from_step_id == "step-a"
    assert edge.to_step_id == "step-b"


@pytest.mark.parametrize(
    "basis_kind", [OrderingBasisKind.PROCESS_LINEAGE, OrderingBasisKind.TEMPORAL_SAME_ENTITY]
)
def test_sequence_edge_accepts_both_ordering_bases(basis_kind: OrderingBasisKind) -> None:
    edge = _edge(basis=_ordering_basis(basis_kind=basis_kind))
    assert edge.basis.basis_kind == basis_kind


def test_sequence_edge_self_edge_rejected() -> None:
    with pytest.raises(CorrelationError, match="must be distinct"):
        _edge(from_step_id="step-a", to_step_id="step-a")


def test_sequence_edge_blank_from_step_id_rejected() -> None:
    with pytest.raises(CorrelationError, match="non-empty, non-whitespace string"):
        _edge(from_step_id="")


def test_sequence_edge_invalid_basis_type_rejected() -> None:
    with pytest.raises(CorrelationError, match="must be an OrderingBasis"):
        _edge(basis="not-a-basis")


def test_sequence_edge_id_deterministic_for_identical_inputs() -> None:
    id_1 = compute_sequence_edge_id(
        from_step_id="step-a",
        to_step_id="step-b",
        basis_kind=OrderingBasisKind.PROCESS_LINEAGE,
        grounding_link_id="link-1",
    )
    id_2 = compute_sequence_edge_id(
        from_step_id="step-a",
        to_step_id="step-b",
        basis_kind=OrderingBasisKind.PROCESS_LINEAGE,
        grounding_link_id="link-1",
    )
    assert id_1 == id_2


def test_sequence_edge_id_differs_when_direction_reversed() -> None:
    forward = compute_sequence_edge_id(
        from_step_id="step-a",
        to_step_id="step-b",
        basis_kind=OrderingBasisKind.PROCESS_LINEAGE,
        grounding_link_id="link-1",
    )
    backward = compute_sequence_edge_id(
        from_step_id="step-b",
        to_step_id="step-a",
        basis_kind=OrderingBasisKind.PROCESS_LINEAGE,
        grounding_link_id="link-1",
    )
    assert forward != backward


def test_compute_sequence_edge_id_requires_distinct_endpoints() -> None:
    with pytest.raises(CorrelationError, match="must be distinct"):
        compute_sequence_edge_id(
            from_step_id="step-a",
            to_step_id="step-a",
            basis_kind=OrderingBasisKind.PROCESS_LINEAGE,
            grounding_link_id="link-1",
        )


def test_sequence_edge_field_set_pinned_no_attribution_fields() -> None:
    field_names = {f.name for f in dataclasses.fields(SequenceEdge)}
    assert field_names == {"edge_id", "from_step_id", "to_step_id", "basis", "schema_version"}


# ===========================================================================
# 5. SequenceGap
# ===========================================================================


def test_sequence_gap_valid_direct_grounded_construction() -> None:
    gap = _gap()
    assert gap.grounding_link_id == "link-1"
    assert gap.reason == GapReason.EQUAL_TIMESTAMPS


def test_sequence_gap_blank_grounding_link_id_rejected() -> None:
    with pytest.raises(CorrelationError, match="non-empty, non-whitespace string"):
        _gap(grounding_link_id="")


def test_sequence_gap_self_gap_rejected() -> None:
    with pytest.raises(CorrelationError, match="must be distinct"):
        _gap(step_id_a="step-a", step_id_b="step-a")


def test_sequence_gap_endpoints_canonicalized_sorted_regardless_of_argument_order() -> None:
    gap_forward = _gap(step_id_a="step-a", step_id_b="step-b")
    gap_backward = _gap(step_id_a="step-b", step_id_b="step-a")
    assert gap_forward.step_id_a == gap_backward.step_id_a == "step-a"
    assert gap_forward.step_id_b == gap_backward.step_id_b == "step-b"


def test_compute_sequence_gap_id_canonicalized_regardless_of_argument_order() -> None:
    id_forward = compute_sequence_gap_id(
        step_id_a="step-a",
        step_id_b="step-b",
        reason=GapReason.EQUAL_TIMESTAMPS,
        grounding_link_id="link-1",
    )
    id_backward = compute_sequence_gap_id(
        step_id_a="step-b",
        step_id_b="step-a",
        reason=GapReason.EQUAL_TIMESTAMPS,
        grounding_link_id="link-1",
    )
    assert id_forward == id_backward


def test_sequence_gap_invalid_reason_type_rejected() -> None:
    with pytest.raises(CorrelationError, match="must be a GapReason"):
        _gap(reason="equal_timestamps")


def test_all_three_gap_reasons_exist() -> None:
    assert {member.name for member in GapReason} == {
        "EQUAL_TIMESTAMPS",
        "COARSE_PRECISION_TIE",
        "MISSING_TIMESTAMP",
    }


def test_sequence_gap_distinct_from_sequence_edge_field_shape() -> None:
    """SequenceGap has no from/to (undirected) -- SequenceEdge has no
    step_id_a/step_id_b/reason (never a gap reason). No overlap that could
    let a gap be mistaken for an edge or vice versa."""
    gap_fields = {f.name for f in dataclasses.fields(SequenceGap)}
    edge_fields = {f.name for f in dataclasses.fields(SequenceEdge)}
    assert "from_step_id" not in gap_fields
    assert "to_step_id" not in gap_fields
    assert "reason" not in edge_fields
    assert "basis" not in gap_fields


def test_sequence_gap_field_set_pinned_no_attribution_fields() -> None:
    field_names = {f.name for f in dataclasses.fields(SequenceGap)}
    assert field_names == {
        "gap_id",
        "step_id_a",
        "step_id_b",
        "grounding_link_id",
        "reason",
        "schema_version",
    }


# ===========================================================================
# 6. SequenceParallelGroup (accepted branch-partition design)
# ===========================================================================


def test_sequence_parallel_group_valid_branch_partition() -> None:
    pg = _parallel_group(branches=(("step-a",), ("step-b", "step-c")))
    assert pg.branches == (("step-a",), ("step-b", "step-c"))


def test_sequence_parallel_group_requires_at_least_two_branches() -> None:
    with pytest.raises(CorrelationError, match="at least two branches"):
        _parallel_group(branches=(("step-a",),))


def test_sequence_parallel_group_rejects_empty_branch() -> None:
    with pytest.raises(CorrelationError, match="must be non-empty"):
        _parallel_group(branches=(("step-a",), ()))


def test_sequence_parallel_group_rejects_duplicate_within_one_branch() -> None:
    with pytest.raises(CorrelationError, match="duplicate step id"):
        _parallel_group(branches=(("step-a", "step-a"), ("step-b",)))


def test_sequence_parallel_group_convergence_exclusion_rejects_step_in_two_branches() -> None:
    """The convergence-safety invariant (ADR-0004 D9): a step reachable
    from more than one branch must never appear in more than one branch
    tuple of the same group -- it must not be falsely claimed parallel."""
    with pytest.raises(CorrelationError, match="belong to at most one branch"):
        _parallel_group(branches=(("step-a", "step-z"), ("step-b", "step-z")))


def test_sequence_parallel_group_not_a_pairwise_representation() -> None:
    """A single SequenceParallelGroup names an entire divergence -- three
    branches of two members each is still exactly one object, never three
    (or more) pairwise objects."""
    pg = _parallel_group(branches=(("a", "d"), ("b", "e"), ("c", "f")))
    assert len(pg.branches) == 3
    assert isinstance(pg, SequenceParallelGroup)


def test_compute_sequence_parallel_group_id_deterministic_for_identical_inputs() -> None:
    branches = (("step-a",), ("step-b", "step-c"))
    assert compute_sequence_parallel_group_id(
        "step-p", branches
    ) == compute_sequence_parallel_group_id("step-p", branches)


def test_compute_sequence_parallel_group_id_independent_of_branch_order() -> None:
    """Which branch is listed first carries no semantic meaning -- swapping
    branch order must not change the id."""
    id_a = compute_sequence_parallel_group_id("step-p", (("step-a",), ("step-b", "step-c")))
    id_b = compute_sequence_parallel_group_id("step-p", (("step-b", "step-c"), ("step-a",)))
    assert id_a == id_b


def test_compute_sequence_parallel_group_id_requires_at_least_two_branches() -> None:
    with pytest.raises(CorrelationError, match="at least two branches"):
        compute_sequence_parallel_group_id("step-p", [["step-a"]])


def test_compute_sequence_parallel_group_id_delimiter_collision_regression() -> None:
    """Real step_id values already contain '::' (see compute_step_id) -- a
    naive raw-text join could let two different branch structures collide.
    Two structures that would collide under a naive '::'-join of raw step
    ids must still produce different parallel_group_ids here."""
    real_step_id_1 = compute_step_id("group-1", ["ev-1"])
    real_step_id_2 = compute_step_id("group-1", ["ev-2"])
    assert "::" in real_step_id_1
    assert "::" in real_step_id_2

    id_one_branch_two_members = compute_sequence_parallel_group_id(
        "step-p", ((real_step_id_1, real_step_id_2), ("step-other",))
    )
    id_two_branches_one_member_each = compute_sequence_parallel_group_id(
        "step-p", ((real_step_id_1,), (real_step_id_2,), ("step-other",))
    )
    assert id_one_branch_two_members != id_two_branches_one_member_each


def test_sequence_parallel_group_field_set_pinned_no_member_step_ids_no_attribution() -> None:
    """Pins the accepted branch-partition shape -- must never revert to a
    flat member_step_ids list (the rejected immediate-children-only draft)
    and must never gain an attribution/scoring field."""
    field_names = {f.name for f in dataclasses.fields(SequenceParallelGroup)}
    assert field_names == {
        "parallel_group_id",
        "source_step_id",
        "branches",
        "schema_version",
    }
    assert "member_step_ids" not in field_names


# ===========================================================================
# 7. BehavioralSequence
# ===========================================================================


def test_behavioral_sequence_valid_minimal_construction() -> None:
    seq = _sequence()
    assert len(seq.steps) == 1
    assert seq.edges == ()
    assert seq.gaps == ()
    assert seq.parallel_groups == ()


def test_behavioral_sequence_requires_at_least_one_step() -> None:
    with pytest.raises(CorrelationError, match="steps must be non-empty"):
        _sequence(steps=())


def test_behavioral_sequence_rejects_step_belonging_to_a_different_group() -> None:
    other_step = _step(
        step_id=compute_step_id("group-2", ["ev-9"]),
        group_id="group-2",
        evidence_ids=("ev-9",),
        observation_id="obs-9",
    )
    with pytest.raises(CorrelationError, match="not this sequence's group"):
        _sequence(steps=(other_step,))


def test_behavioral_sequence_rejects_duplicate_step_id() -> None:
    step = _step()
    with pytest.raises(CorrelationError, match="duplicate step_id"):
        _sequence(steps=(step, step))


def _two_step_sequence_kwargs() -> dict[str, object]:
    step_a = _step(step_id="step-a", evidence_ids=("ev-1",), observation_id="obs-1")
    step_b = _step(step_id="step-b", evidence_ids=("ev-2",), observation_id="obs-2")
    return {
        "sequence_id": compute_sequence_id("group-1", ["step-a", "step-b"]),
        "group_id": "group-1",
        "steps": (step_a, step_b),
        "provenance": _correlation_provenance(),
    }


def test_behavioral_sequence_accepts_valid_edge_between_real_steps() -> None:
    kwargs = _two_step_sequence_kwargs()
    kwargs["edges"] = (_edge(),)
    seq = _sequence(**kwargs)
    assert len(seq.edges) == 1


def test_behavioral_sequence_rejects_edge_with_dangling_from_step() -> None:
    kwargs = _two_step_sequence_kwargs()
    kwargs["edges"] = (_edge(from_step_id="step-does-not-exist"),)
    with pytest.raises(CorrelationError, match="is not a step in this sequence"):
        _sequence(**kwargs)


def test_behavioral_sequence_rejects_edge_with_dangling_to_step() -> None:
    kwargs = _two_step_sequence_kwargs()
    kwargs["edges"] = (_edge(to_step_id="step-does-not-exist"),)
    with pytest.raises(CorrelationError, match="is not a step in this sequence"):
        _sequence(**kwargs)


def test_behavioral_sequence_rejects_gap_with_dangling_endpoint() -> None:
    kwargs = _two_step_sequence_kwargs()
    kwargs["gaps"] = (_gap(step_id_a="step-does-not-exist"),)
    with pytest.raises(CorrelationError, match="is not a step in this sequence"):
        _sequence(**kwargs)


def test_behavioral_sequence_rejects_same_pair_having_both_edge_and_gap() -> None:
    kwargs = _two_step_sequence_kwargs()
    kwargs["edges"] = (_edge(from_step_id="step-a", to_step_id="step-b"),)
    kwargs["gaps"] = (
        _gap(
            step_id_a="step-a",
            step_id_b="step-b",
            gap_id=compute_sequence_gap_id(
                step_id_a="step-a",
                step_id_b="step-b",
                reason=GapReason.EQUAL_TIMESTAMPS,
                grounding_link_id="link-2",
            ),
            grounding_link_id="link-2",
        ),
    )
    with pytest.raises(CorrelationError, match="both a SequenceEdge and a SequenceGap"):
        _sequence(**kwargs)


def test_behavioral_sequence_rejects_duplicate_edge_id() -> None:
    kwargs = _two_step_sequence_kwargs()
    edge = _edge(from_step_id="step-a", to_step_id="step-b")
    kwargs["edges"] = (edge, edge)
    with pytest.raises(CorrelationError, match="duplicate edge_id"):
        _sequence(**kwargs)


def test_behavioral_sequence_accepts_acyclic_chain() -> None:
    step_a = _step(step_id="step-a", evidence_ids=("ev-1",), observation_id="obs-1")
    step_b = _step(step_id="step-b", evidence_ids=("ev-2",), observation_id="obs-2")
    step_c = _step(step_id="step-c", evidence_ids=("ev-3",), observation_id="obs-3")
    edge_ab = _edge(
        edge_id=compute_sequence_edge_id(
            from_step_id="step-a",
            to_step_id="step-b",
            basis_kind=OrderingBasisKind.PROCESS_LINEAGE,
            grounding_link_id="link-1",
        ),
        from_step_id="step-a",
        to_step_id="step-b",
    )
    edge_bc = _edge(
        edge_id=compute_sequence_edge_id(
            from_step_id="step-b",
            to_step_id="step-c",
            basis_kind=OrderingBasisKind.PROCESS_LINEAGE,
            grounding_link_id="link-2",
        ),
        from_step_id="step-b",
        to_step_id="step-c",
    )
    seq = _sequence(
        sequence_id=compute_sequence_id("group-1", ["step-a", "step-b", "step-c"]),
        steps=(step_a, step_b, step_c),
        edges=(edge_ab, edge_bc),
    )
    assert len(seq.edges) == 2


def test_behavioral_sequence_rejects_cyclic_edges() -> None:
    step_a = _step(step_id="step-a", evidence_ids=("ev-1",), observation_id="obs-1")
    step_b = _step(step_id="step-b", evidence_ids=("ev-2",), observation_id="obs-2")
    edge_ab = _edge(
        edge_id=compute_sequence_edge_id(
            from_step_id="step-a",
            to_step_id="step-b",
            basis_kind=OrderingBasisKind.PROCESS_LINEAGE,
            grounding_link_id="link-1",
        ),
        from_step_id="step-a",
        to_step_id="step-b",
    )
    edge_ba = _edge(
        edge_id=compute_sequence_edge_id(
            from_step_id="step-b",
            to_step_id="step-a",
            basis_kind=OrderingBasisKind.TEMPORAL_SAME_ENTITY,
            grounding_link_id="link-2",
        ),
        from_step_id="step-b",
        to_step_id="step-a",
        basis=_ordering_basis(
            basis_kind=OrderingBasisKind.TEMPORAL_SAME_ENTITY, grounding_link_id="link-2"
        ),
    )
    with pytest.raises(CorrelationError, match="forms a cycle"):
        _sequence(
            sequence_id=compute_sequence_id("group-1", ["step-a", "step-b"]),
            steps=(step_a, step_b),
            edges=(edge_ab, edge_ba),
        )


def test_behavioral_sequence_accepts_valid_parallel_group() -> None:
    step_p = _step(step_id="step-p", evidence_ids=("ev-1",), observation_id="obs-1")
    step_a = _step(step_id="step-a", evidence_ids=("ev-2",), observation_id="obs-2")
    step_b = _step(step_id="step-b", evidence_ids=("ev-3",), observation_id="obs-3")
    edge_pa = _edge(
        edge_id=compute_sequence_edge_id(
            from_step_id="step-p",
            to_step_id="step-a",
            basis_kind=OrderingBasisKind.PROCESS_LINEAGE,
            grounding_link_id="link-1",
        ),
        from_step_id="step-p",
        to_step_id="step-a",
    )
    edge_pb = _edge(
        edge_id=compute_sequence_edge_id(
            from_step_id="step-p",
            to_step_id="step-b",
            basis_kind=OrderingBasisKind.PROCESS_LINEAGE,
            grounding_link_id="link-2",
        ),
        from_step_id="step-p",
        to_step_id="step-b",
    )
    pg = _parallel_group(
        parallel_group_id=compute_sequence_parallel_group_id("step-p", (("step-a",), ("step-b",))),
        source_step_id="step-p",
        branches=(("step-a",), ("step-b",)),
    )
    seq = _sequence(
        sequence_id=compute_sequence_id("group-1", ["step-p", "step-a", "step-b"]),
        steps=(step_p, step_a, step_b),
        edges=(edge_pa, edge_pb),
        parallel_groups=(pg,),
    )
    assert len(seq.parallel_groups) == 1


def test_behavioral_sequence_rejects_parallel_group_with_zero_grounding_edges() -> None:
    """The exact exploit found by the G2.4.0 strict pre-commit audit: a
    SequenceParallelGroup naming only real steps, with NO SequenceEdge
    anywhere in the sequence, must be rejected -- otherwise "these branches
    are parallel" is an invented relationship with no grounding at all,
    directly contradicting ADR-0004's own justification for giving
    SequenceParallelGroup no separate grounding field (that its grounding
    is inherited through the real SequenceEdge chain)."""
    step_p = _step(step_id="step-p", evidence_ids=("ev-1",), observation_id="obs-1")
    step_a = _step(step_id="step-a", evidence_ids=("ev-2",), observation_id="obs-2")
    step_b = _step(step_id="step-b", evidence_ids=("ev-3",), observation_id="obs-3")
    pg = _parallel_group(
        parallel_group_id=compute_sequence_parallel_group_id("step-p", (("step-a",), ("step-b",))),
        source_step_id="step-p",
        branches=(("step-a",), ("step-b",)),
    )
    with pytest.raises(CorrelationError, match="has no SequenceEdge from source_step_id"):
        _sequence(
            sequence_id=compute_sequence_id("group-1", ["step-p", "step-a", "step-b"]),
            steps=(step_p, step_a, step_b),
            edges=(),
            parallel_groups=(pg,),
        )


def test_behavioral_sequence_rejects_parallel_group_whose_root_lacks_direct_source_edge() -> None:
    """Merely having *some* real SequenceEdge in the sequence is not
    sufficient grounding -- the edge must actually be
    source_step_id -> branch_root. An unrelated edge elsewhere in the
    sequence must not satisfy the check."""
    step_p = _step(step_id="step-p", evidence_ids=("ev-1",), observation_id="obs-1")
    step_a = _step(step_id="step-a", evidence_ids=("ev-2",), observation_id="obs-2")
    step_b = _step(step_id="step-b", evidence_ids=("ev-3",), observation_id="obs-3")
    step_c = _step(step_id="step-c", evidence_ids=("ev-4",), observation_id="obs-4")
    # A real edge exists in the sequence, but it is C->A, not P->A or P->B --
    # unrelated to the claimed parallel group's own branch points.
    unrelated_edge = _edge(
        edge_id=compute_sequence_edge_id(
            from_step_id="step-c",
            to_step_id="step-a",
            basis_kind=OrderingBasisKind.PROCESS_LINEAGE,
            grounding_link_id="link-1",
        ),
        from_step_id="step-c",
        to_step_id="step-a",
    )
    pg = _parallel_group(
        parallel_group_id=compute_sequence_parallel_group_id("step-p", (("step-a",), ("step-b",))),
        source_step_id="step-p",
        branches=(("step-a",), ("step-b",)),
    )
    with pytest.raises(CorrelationError, match="has no SequenceEdge from source_step_id"):
        _sequence(
            sequence_id=compute_sequence_id("group-1", ["step-p", "step-a", "step-b", "step-c"]),
            steps=(step_p, step_a, step_b, step_c),
            edges=(unrelated_edge,),
            parallel_groups=(pg,),
        )


def test_behavioral_sequence_accepts_parallel_group_with_deeper_chain_grounded_member() -> None:
    """The root of each branch requires a direct source_step_id -> root
    edge, but a *deeper* branch member (branches[i][1:]) is intentionally
    NOT required to have its own direct edge from source_step_id -- it
    remains grounded transitively through its own chain of SequenceEdges
    (root -> deeper member), which is independently validated already."""
    step_p = _step(step_id="step-p", evidence_ids=("ev-1",), observation_id="obs-1")
    step_a = _step(step_id="step-a", evidence_ids=("ev-2",), observation_id="obs-2")
    step_c = _step(step_id="step-c", evidence_ids=("ev-3",), observation_id="obs-3")
    step_b = _step(step_id="step-b", evidence_ids=("ev-4",), observation_id="obs-4")
    edge_pa = _edge(
        edge_id=compute_sequence_edge_id(
            from_step_id="step-p",
            to_step_id="step-a",
            basis_kind=OrderingBasisKind.PROCESS_LINEAGE,
            grounding_link_id="link-1",
        ),
        from_step_id="step-p",
        to_step_id="step-a",
    )
    edge_ac = _edge(
        edge_id=compute_sequence_edge_id(
            from_step_id="step-a",
            to_step_id="step-c",
            basis_kind=OrderingBasisKind.PROCESS_LINEAGE,
            grounding_link_id="link-2",
        ),
        from_step_id="step-a",
        to_step_id="step-c",
    )
    edge_pb = _edge(
        edge_id=compute_sequence_edge_id(
            from_step_id="step-p",
            to_step_id="step-b",
            basis_kind=OrderingBasisKind.PROCESS_LINEAGE,
            grounding_link_id="link-3",
        ),
        from_step_id="step-p",
        to_step_id="step-b",
    )
    branches: tuple[tuple[str, ...], ...] = (("step-a", "step-c"), ("step-b",))
    pg = _parallel_group(
        parallel_group_id=compute_sequence_parallel_group_id("step-p", branches),
        source_step_id="step-p",
        branches=branches,
    )
    seq = _sequence(
        sequence_id=compute_sequence_id("group-1", ["step-p", "step-a", "step-b", "step-c"]),
        steps=(step_p, step_a, step_b, step_c),
        edges=(edge_pa, edge_ac, edge_pb),
        parallel_groups=(pg,),
    )
    assert len(seq.parallel_groups) == 1
    assert seq.parallel_groups[0].branches == branches


def test_behavioral_sequence_rejects_convergent_member_as_branch_member_even_with_grounding() -> (
    None
):
    """A step reachable from more than one branch child must never be
    usable as a branch member, even when both branches are otherwise
    properly grounded by real source->root edges -- the convergence-safety
    exclusion (enforced by SequenceParallelGroup itself) is not bypassed by
    satisfying the new grounding check."""
    branches: tuple[tuple[str, ...], ...] = (("step-a", "step-z"), ("step-b", "step-z"))
    with pytest.raises(CorrelationError, match="belong to at most one branch"):
        _parallel_group(
            parallel_group_id=compute_sequence_parallel_group_id("step-p", branches),
            source_step_id="step-p",
            branches=branches,
        )


def test_behavioral_sequence_rejects_parallel_group_with_dangling_source_step() -> None:
    kwargs = _two_step_sequence_kwargs()
    kwargs["parallel_groups"] = (_parallel_group(source_step_id="step-does-not-exist"),)
    with pytest.raises(CorrelationError, match="is not a step in this sequence"):
        _sequence(**kwargs)


def test_behavioral_sequence_rejects_parallel_group_naming_step_not_in_sequence() -> None:
    kwargs = _two_step_sequence_kwargs()
    branches: tuple[tuple[str, ...], ...] = (("step-a",), ("step-does-not-exist",))
    kwargs["parallel_groups"] = (
        _parallel_group(
            parallel_group_id=compute_sequence_parallel_group_id("step-a", branches),
            source_step_id="step-a",
            branches=branches,
        ),
    )
    with pytest.raises(CorrelationError, match="which is not a step in this sequence"):
        _sequence(**kwargs)


def test_behavioral_sequence_rejects_cross_branch_members_also_directly_connected() -> None:
    """If a SequenceParallelGroup claims two steps (in different branches)
    are parallel, but a real SequenceEdge/SequenceGap also directly
    connects them, that is an internal contradiction -- they cannot be both
    ordered/unresolved and unordered. Both branch roots are properly
    grounded (P->A, P->B) so this test exercises the cross-branch-conflict
    check specifically, not the grounding check."""
    step_p = _step(step_id="step-p", evidence_ids=("ev-1",), observation_id="obs-1")
    step_a = _step(step_id="step-a", evidence_ids=("ev-2",), observation_id="obs-2")
    step_b = _step(step_id="step-b", evidence_ids=("ev-3",), observation_id="obs-3")
    edge_pa = _edge(
        edge_id=compute_sequence_edge_id(
            from_step_id="step-p",
            to_step_id="step-a",
            basis_kind=OrderingBasisKind.PROCESS_LINEAGE,
            grounding_link_id="link-1",
        ),
        from_step_id="step-p",
        to_step_id="step-a",
    )
    edge_pb = _edge(
        edge_id=compute_sequence_edge_id(
            from_step_id="step-p",
            to_step_id="step-b",
            basis_kind=OrderingBasisKind.PROCESS_LINEAGE,
            grounding_link_id="link-2",
        ),
        from_step_id="step-p",
        to_step_id="step-b",
    )
    # An extra, unrelated-looking edge directly between the two "parallel" branch
    # members -- this is the internal contradiction under test.
    edge_ab = _edge(
        edge_id=compute_sequence_edge_id(
            from_step_id="step-a",
            to_step_id="step-b",
            basis_kind=OrderingBasisKind.TEMPORAL_SAME_ENTITY,
            grounding_link_id="link-3",
        ),
        from_step_id="step-a",
        to_step_id="step-b",
        basis=_ordering_basis(
            basis_kind=OrderingBasisKind.TEMPORAL_SAME_ENTITY, grounding_link_id="link-3"
        ),
    )
    pg = _parallel_group(
        parallel_group_id=compute_sequence_parallel_group_id("step-p", (("step-a",), ("step-b",))),
        source_step_id="step-p",
        branches=(("step-a",), ("step-b",)),
    )
    with pytest.raises(CorrelationError, match="directly connected by an edge or gap"):
        _sequence(
            sequence_id=compute_sequence_id("group-1", ["step-p", "step-a", "step-b"]),
            steps=(step_p, step_a, step_b),
            edges=(edge_pa, edge_pb, edge_ab),
            parallel_groups=(pg,),
        )


def test_behavioral_sequence_rejects_non_correlation_provenance() -> None:
    with pytest.raises(CorrelationError, match="must be a CorrelationProvenance"):
        _sequence(provenance="not-provenance")


def test_behavioral_sequence_field_set_pinned_no_cross_sequence_no_attribution() -> None:
    """Pins the exact field set: no field on BehavioralSequence can express
    a cross-sequence/cross-group relationship (mirroring CorrelationGroup's
    own no-group-to-group-relationship-field regression test) and no
    attribution/scoring field exists."""
    field_names = {f.name for f in dataclasses.fields(BehavioralSequence)}
    assert field_names == {
        "sequence_id",
        "group_id",
        "steps",
        "provenance",
        "edges",
        "gaps",
        "parallel_groups",
        "schema_version",
    }


def test_behavioral_sequence_deterministic_identity_for_identical_inputs() -> None:
    id_1 = compute_sequence_id("group-1", ["step-a", "step-b"])
    id_2 = compute_sequence_id("group-1", ["step-b", "step-a"])
    assert id_1 == id_2  # sorted internally -- input order must not matter


# ===========================================================================
# 8. build_behavioral_sequence
# ===========================================================================


def test_build_behavioral_sequence_valid_path_grounds_edge_against_real_group() -> None:
    group = _group(structural_link_ids=("link-1",))
    step_a = _step(
        step_id="step-a",
        group_id=group.group_id,
        evidence_ids=("ev-1",),
        observation_id="obs-1",
    )
    step_b = _step(
        step_id="step-b",
        group_id=group.group_id,
        evidence_ids=("ev-2",),
        observation_id="obs-2",
    )
    edge = _edge(from_step_id="step-a", to_step_id="step-b")
    seq = build_behavioral_sequence(
        sequence_id=compute_sequence_id(group.group_id, ["step-a", "step-b"]),
        group=group,
        steps=(step_a, step_b),
        provenance=_correlation_provenance(),
        edges=(edge,),
    )
    assert seq.group_id == group.group_id
    assert len(seq.edges) == 1


def test_build_behavioral_sequence_rejects_edge_not_grounded_in_group_structural_links() -> None:
    group = _group(structural_link_ids=("link-1",))
    step_a = _step(step_id="step-a", group_id=group.group_id, evidence_ids=("ev-1",))
    step_b = _step(step_id="step-b", group_id=group.group_id, evidence_ids=("ev-2",))
    edge = _edge(
        from_step_id="step-a",
        to_step_id="step-b",
        basis=_ordering_basis(grounding_link_id="link-not-in-group"),
        edge_id=compute_sequence_edge_id(
            from_step_id="step-a",
            to_step_id="step-b",
            basis_kind=OrderingBasisKind.PROCESS_LINEAGE,
            grounding_link_id="link-not-in-group",
        ),
    )
    with pytest.raises(CorrelationError, match="is not a structural link of CorrelationGroup"):
        build_behavioral_sequence(
            sequence_id=compute_sequence_id(group.group_id, ["step-a", "step-b"]),
            group=group,
            steps=(step_a, step_b),
            provenance=_correlation_provenance(),
            edges=(edge,),
        )


def test_build_behavioral_sequence_rejects_gap_not_grounded_in_group_structural_links() -> None:
    group = _group(structural_link_ids=("link-1",))
    step_a = _step(step_id="step-a", group_id=group.group_id, evidence_ids=("ev-1",))
    step_b = _step(step_id="step-b", group_id=group.group_id, evidence_ids=("ev-2",))
    gap = _gap(grounding_link_id="link-not-in-group")
    with pytest.raises(CorrelationError, match="is not a structural link of CorrelationGroup"):
        build_behavioral_sequence(
            sequence_id=compute_sequence_id(group.group_id, ["step-a", "step-b"]),
            group=group,
            steps=(step_a, step_b),
            provenance=_correlation_provenance(),
            gaps=(gap,),
        )


def test_build_behavioral_sequence_rejects_non_correlation_group() -> None:
    with pytest.raises(CorrelationError, match="must be a CorrelationGroup"):
        build_behavioral_sequence(
            sequence_id="seq-1",
            group="not-a-group",  # type: ignore[arg-type]
            steps=(_step(),),
            provenance=_correlation_provenance(),
        )


def test_build_behavioral_sequence_rejects_contextual_link_used_as_grounding() -> None:
    """Explicit negative proof (ADR-0004 D10): a contextual link id -- one
    that is NOT among the group's structural_link_ids -- can never ground a
    SequenceEdge/SequenceGap, i.e. a contextual relationship can never
    enter the sequence-ordering structure. `group.structural_link_ids`
    here deliberately excludes 'contextual-link-1', simulating a group
    whose contextual_link_ids (attached by G2.2, not represented on this
    minimal test double) contains it instead."""
    group = _group(structural_link_ids=("link-1",))  # "contextual-link-1" is NOT structural
    step_a = _step(step_id="step-a", group_id=group.group_id, evidence_ids=("ev-1",))
    step_b = _step(step_id="step-b", group_id=group.group_id, evidence_ids=("ev-2",))
    edge = _edge(
        from_step_id="step-a",
        to_step_id="step-b",
        basis=_ordering_basis(grounding_link_id="contextual-link-1"),
        edge_id=compute_sequence_edge_id(
            from_step_id="step-a",
            to_step_id="step-b",
            basis_kind=OrderingBasisKind.PROCESS_LINEAGE,
            grounding_link_id="contextual-link-1",
        ),
    )
    with pytest.raises(CorrelationError, match="is not a structural link of CorrelationGroup"):
        build_behavioral_sequence(
            sequence_id=compute_sequence_id(group.group_id, ["step-a", "step-b"]),
            group=group,
            steps=(step_a, step_b),
            provenance=_correlation_provenance(),
            edges=(edge,),
        )


# ===========================================================================
# 9. Guards: G2.4.0 stays contracts-only, source-agnostic, ATT&CK-free,
#    TEMPORAL_PROXIMITY-free
# ===========================================================================


def test_sequence_module_never_imports_forbidden_layers() -> None:
    """sequence.py must never depend on sources/dataplane/replay/api, and
    -- stronger than G2.1/G2.2's own guard -- never on attack_knowledge or
    domain either (see the module's own docstring for why: the deeper
    Evidence/Observation grounding check and ATT&CK-derivation are G2.4.1's
    responsibility, not this contract layer's)."""
    forbidden = ("sources", "dataplane", "replay", "api", "attack_knowledge", "domain")
    tree = ast.parse(SEQUENCE_FILE.read_text(encoding="utf-8"), filename=str(SEQUENCE_FILE))
    offending: list[str] = []
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.ImportFrom)
            and node.module
            and any(f"attribution_platform.{layer}" in node.module for layer in forbidden)
        ):
            offending.append(f"from {node.module} import ...")
    assert not offending, f"sequence.py must not import {forbidden}: {offending}"


def test_sequence_module_only_imports_its_own_package_and_stdlib() -> None:
    tree = ast.parse(SEQUENCE_FILE.read_text(encoding="utf-8"), filename=str(SEQUENCE_FILE))
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.ImportFrom)
            and node.module
            and "attribution_platform" in node.module
        ):
            assert node.module.startswith("attribution_platform.correlation"), (
                f"sequence.py must only import from within attribution_platform.correlation, "
                f"found: {node.module}"
            )


def test_sequence_module_contains_no_temporal_proximity_code_reference() -> None:
    """Source-level guard, narrowed to code-shaped identifiers only (the
    module docstring legitimately *discusses* ``TEMPORAL_PROXIMITY`` in
    prose, explaining why it is out of scope -- that is not the concern
    here). No enum member, attribute access, or string literal value named
    ``temporal_proximity``/``TEMPORAL_PROXIMITY`` may appear as an actual
    Python identifier or enum value anywhere in this module's AST."""
    tree = ast.parse(SEQUENCE_FILE.read_text(encoding="utf-8"), filename=str(SEQUENCE_FILE))
    offending: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id == "TEMPORAL_PROXIMITY":
            offending.append("Name(TEMPORAL_PROXIMITY)")
        if isinstance(node, ast.Attribute) and node.attr == "TEMPORAL_PROXIMITY":
            offending.append("Attribute(.TEMPORAL_PROXIMITY)")
        if isinstance(node, ast.Constant) and node.value == "temporal_proximity":
            offending.append("Constant('temporal_proximity')")
    assert not offending, f"TEMPORAL_PROXIMITY referenced as code in sequence.py: {offending}"


def test_sequence_module_contains_no_attribution_or_scoring_identifiers() -> None:
    """Source-level guard mirroring the same discipline already applied to
    correlation/contracts.py, structural.py, and contextual.py -- narrowed
    to actual code identifiers (class/function/attribute/variable names),
    not general prose: this module's own docstrings legitimately *discuss*
    likelihood/confidence/candidate/actor/campaign while explaining that no
    such field or object exists (the field-set-pin tests above already
    prove that precisely). What must never appear is one of these terms
    used as a real Python identifier -- a class, function, or field
    actually named that way."""
    forbidden_terms = (
        "likelihood",
        "confidence",
        "candidate",
        "actor",
        "campaign",
        "calibrat",
        "score",
        "weight",
    )
    tree = ast.parse(SEQUENCE_FILE.read_text(encoding="utf-8"), filename=str(SEQUENCE_FILE))
    offending: list[str] = []
    for node in ast.walk(tree):
        name: str | None = None
        if isinstance(node, ast.Name):
            name = node.id
        elif isinstance(node, ast.Attribute):
            name = node.attr
        elif isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            name = node.name
        elif isinstance(node, ast.arg):
            name = node.arg
        if name is None:
            continue
        lowered = name.lower()
        for term in forbidden_terms:
            if term in lowered:
                offending.append(f"{name!r} contains forbidden term {term!r}")
    assert not offending, f"forbidden attribution/scoring identifiers found: {offending}"


def test_ordering_basis_kind_has_no_temporal_proximity_member() -> None:
    assert "TEMPORAL_PROXIMITY" not in {member.name for member in OrderingBasisKind}
