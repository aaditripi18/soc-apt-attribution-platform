"""Tests for gate G2.4.1: the behavioral-sequence construction engine.

Covers, per section:

- A. Step construction (SHARED_OBSERVATION collapse, mechanical
  ``technique_stix_ids`` derivation from real ``Evidence.attack_ref``,
  ``contextual_annotations`` derivation).
- B. ``PROCESS_LINEAGE`` ordering (directional, from real structural links).
- C. ``TEMPORAL_SAME_ENTITY`` ordering (strict chains, Hasse-reduced).
- D. Lineage-vs-timestamp conflict (ADR-0004 D7 -- disagreement recorded,
  never reverses or drops the edge).
- E. ``SequenceGap`` (exact-equal and coarse-precision ties).
- F. ``SequenceParallelGroup`` construction and convergence-safety exclusion.
- G. Contextual boundary (``contextual_annotations`` never become an edge or
  gap; no ``TEMPORAL_PROXIMITY`` vocabulary anywhere in the engine).
- H. Multi-host / multi-group isolation.
- I. Determinism (shuffle/permutation invariance).
- J. Provenance.
- K. Negative / architecture guards, including the found architectural
  ambiguity this engine handles fail-closed (multiple same-class structural
  ``CorrelationLink``\\ s collapsing onto one step-level relationship after
  ``SHARED_OBSERVATION`` collapse -- ADR-0004 specifies no tie-break, so the
  engine raises ``CorrelationError`` rather than inventing one).

Uses the existing, unmodified ``correlate_structurally``/``contextualize``
(G2.1/G2.2) and ``attribution_platform.extraction.derive_evidence`` to build
real ``CorrelationGroup``/``CorrelationLink`` fixtures -- the same golden-
corpus-in-pure-Python pattern ``test_correlation_structural.py`` already
uses -- rather than hand-constructing correlation objects with matching-by-
hand ids. The two exceptions (K1/K2) deliberately construct the specific,
still-fully-real telemetry shapes that make G2.1's own documented behavior
(the full pairwise ``SAME_PROCESS_ENTITY`` closure; per-child
``PROCESS_LINEAGE`` iteration) produce more than one structural link for a
single step-level relationship -- not synthetic/hand-built correlation
objects.
"""

from __future__ import annotations

import ast
from datetime import UTC, datetime
from pathlib import Path

import pytest

from attribution_platform.attack_knowledge.loader import AttackKnowledge, load_attack_knowledge
from attribution_platform.correlation import (
    SEQUENCE_ENGINE_METHOD,
    SEQUENCE_ENGINE_METHOD_VERSION,
    CorrelationError,
    CorrelationGroup,
    CorrelationLink,
    construct_behavioral_sequence,
    contextualize,
    correlate_structurally,
)
from attribution_platform.correlation.sequence import GapReason, OrderingBasisKind
from attribution_platform.domain import (
    AttackRef,
    Evidence,
    EvidenceType,
    HostRef,
    Observation,
    ProcessRef,
    SourceRef,
    TimePrecision,
    UserRef,
)
from attribution_platform.extraction import RuleRef, derive_evidence

REPO_ROOT = Path(__file__).resolve().parents[1]
CORRELATION_DIR = REPO_ROOT / "src" / "attribution_platform" / "correlation"

T0 = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)


@pytest.fixture(scope="module")
def knowledge() -> AttackKnowledge:
    return load_attack_knowledge()


def _obs(
    observation_id: str,
    *,
    timestamp: datetime = T0,
    timestamp_precision: TimePrecision | None = None,
    host: HostRef | None = None,
    process: ProcessRef | None = None,
    user: UserRef | None = None,
) -> Observation:
    return Observation(
        observation_id=observation_id,
        timestamp=timestamp,
        raw_reference=SourceRef(source_type="synthetic", source_event_id=f"raw-{observation_id}"),
        timestamp_precision=timestamp_precision,
        host=host,
        process=process,
        user=user,
    )


def _evidence(
    evidence_id: str,
    observation: Observation,
    *,
    rule_id: str = "golden-rule",
    rule_version: str = "1.0",
    evidence_type: EvidenceType = EvidenceType.BEHAVIORAL,
    claim: str = "synthetic G2.4.1 golden-corpus evidence",
    attack_ref: AttackRef | None = None,
    knowledge: AttackKnowledge | None = None,
) -> Evidence:
    return derive_evidence(
        evidence_id=evidence_id,
        evidence_type=evidence_type,
        claim=claim,
        observations=(observation,),
        rule_ref=RuleRef(rule_id=rule_id, rule_version=rule_version),
        attack_ref=attack_ref,
        knowledge=knowledge,
    )


def _pair(
    evidence_id: str, observation: Observation, **kwargs: object
) -> tuple[Evidence, Observation]:
    ev = _evidence(evidence_id, observation, **kwargs)  # type: ignore[arg-type]
    return (ev, observation)


def _build(
    items: list[tuple[Evidence, Observation]],
) -> tuple[CorrelationGroup, tuple[CorrelationLink, ...], tuple[CorrelationLink, ...]]:
    """Run the real G2.1/G2.2 pipeline over ``items`` and return the one
    resulting group plus exactly its own structural/contextual links (the
    shape ``construct_behavioral_sequence`` requires). Fails loudly if
    ``items`` does not resolve to exactly one group -- callers that want
    multiple groups must partition ``items`` themselves (see section H)."""
    structural_result = correlate_structurally(items)
    contextual_result = contextualize(structural_result, items)
    assert (
        len(contextual_result.groups) == 1
    ), f"expected exactly one group, got {len(contextual_result.groups)}"
    group = contextual_result.groups[0]
    structural_links = tuple(
        link for link in structural_result.links if link.link_id in group.structural_link_ids
    )
    contextual_links = tuple(
        link
        for link in contextual_result.contextual_links
        if link.link_id in group.contextual_link_ids
    )
    return group, structural_links, contextual_links


# ===========================================================================
# A. Step construction
# ===========================================================================


def test_shared_observation_collapses_into_one_step() -> None:
    obs = _obs("obs-1", host=HostRef(id="H1"), process=ProcessRef(entity_id="{A}"))
    items = [_pair("ev-1", obs), _pair("ev-2", obs)]
    group, structural_links, contextual_links = _build(items)

    sequence = construct_behavioral_sequence(group, items, structural_links, contextual_links)

    assert len(sequence.steps) == 1
    step = sequence.steps[0]
    assert step.evidence_ids == ("ev-1", "ev-2")
    assert step.observation_id == "obs-1"
    assert step.group_id == group.group_id


def test_step_technique_stix_ids_mechanically_derived_and_deduplicated(
    knowledge: AttackKnowledge,
) -> None:
    t1, t2 = knowledge.techniques()[0], knowledge.techniques()[1]
    ref1 = AttackRef(
        stix_id=t1["id"], object_type=t1["type"], attack_kb_version=knowledge.attack_kb_version
    )
    ref2 = AttackRef(
        stix_id=t2["id"], object_type=t2["type"], attack_kb_version=knowledge.attack_kb_version
    )
    obs = _obs("obs-1", host=HostRef(id="H1"), process=ProcessRef(entity_id="{A}"))
    items = [
        _pair("ev-1", obs, attack_ref=ref1, knowledge=knowledge),
        _pair("ev-2", obs, attack_ref=ref2, knowledge=knowledge),
    ]
    group, structural_links, contextual_links = _build(items)

    sequence = construct_behavioral_sequence(group, items, structural_links, contextual_links)

    step = sequence.steps[0]
    assert step.technique_stix_ids == tuple(sorted({t1["id"], t2["id"]}))


def test_step_technique_stix_ids_empty_when_no_attack_ref() -> None:
    obs = _obs("obs-1", host=HostRef(id="H1"), process=ProcessRef(entity_id="{A}"))
    items = [_pair("ev-1", obs)]
    obs_child = _obs(
        "obs-2",
        host=HostRef(id="H1"),
        process=ProcessRef(parent_entity_id="{A}", entity_id="{B}"),
    )
    items.append(_pair("ev-2", obs_child))
    group, structural_links, contextual_links = _build(items)

    sequence = construct_behavioral_sequence(group, items, structural_links, contextual_links)

    assert all(step.technique_stix_ids == () for step in sequence.steps)


def test_step_contextual_annotations_derived_from_contextual_links() -> None:
    host = HostRef(id="H1")
    obs_p = _obs("obs-p", host=host, process=ProcessRef(entity_id="{P}"))
    obs_c = _obs("obs-c", host=host, process=ProcessRef(parent_entity_id="{P}", entity_id="{C}"))
    items = [_pair("ev-p", obs_p), _pair("ev-c", obs_c)]
    group, structural_links, contextual_links = _build(items)
    assert len(contextual_links) >= 1  # SAME_HOST_ID, since both share host H1

    sequence = construct_behavioral_sequence(group, items, structural_links, contextual_links)

    for step in sequence.steps:
        assert step.contextual_annotations != ()
        assert set(step.contextual_annotations) <= {link.link_id for link in contextual_links}


# ===========================================================================
# B. PROCESS_LINEAGE ordering
# ===========================================================================


def test_process_lineage_produces_one_directed_edge() -> None:
    host = HostRef(id="H1")
    obs_p = _obs("obs-p", host=host, process=ProcessRef(entity_id="{P}"), timestamp=T0)
    obs_c = _obs(
        "obs-c",
        host=host,
        process=ProcessRef(parent_entity_id="{P}", entity_id="{C}"),
        timestamp=T0.replace(second=1),
    )
    items = [_pair("ev-p", obs_p), _pair("ev-c", obs_c)]
    group, structural_links, contextual_links = _build(items)

    sequence = construct_behavioral_sequence(group, items, structural_links, contextual_links)

    assert len(sequence.edges) == 1
    edge = sequence.edges[0]
    step_by_evidence = {
        ev_id: step.step_id for step in sequence.steps for ev_id in step.evidence_ids
    }
    assert edge.from_step_id == step_by_evidence["ev-p"]
    assert edge.to_step_id == step_by_evidence["ev-c"]
    assert edge.basis.basis_kind is OrderingBasisKind.PROCESS_LINEAGE
    assert edge.basis.timestamp_agreement is True
    assert sequence.gaps == ()
    assert sequence.parallel_groups == ()


def test_process_lineage_edge_grounded_in_real_structural_link() -> None:
    host = HostRef(id="H1")
    obs_p = _obs("obs-p", host=host, process=ProcessRef(entity_id="{P}"))
    obs_c = _obs("obs-c", host=host, process=ProcessRef(parent_entity_id="{P}", entity_id="{C}"))
    items = [_pair("ev-p", obs_p), _pair("ev-c", obs_c)]
    group, structural_links, contextual_links = _build(items)

    sequence = construct_behavioral_sequence(group, items, structural_links, contextual_links)

    edge = sequence.edges[0]
    assert edge.basis.grounding_link_id in group.structural_link_ids
    assert edge.basis.grounding_link_id in {link.link_id for link in structural_links}


# ===========================================================================
# C. TEMPORAL_SAME_ENTITY ordering (strict chains, Hasse-reduced)
# ===========================================================================


def test_temporal_same_entity_chain_is_hasse_reduced() -> None:
    host = HostRef(id="H1")
    obs0 = _obs("obs-0", host=host, process=ProcessRef(entity_id="{X}"), timestamp=T0)
    obs1 = _obs(
        "obs-1", host=host, process=ProcessRef(entity_id="{X}"), timestamp=T0.replace(second=1)
    )
    obs2 = _obs(
        "obs-2", host=host, process=ProcessRef(entity_id="{X}"), timestamp=T0.replace(second=2)
    )
    items = [_pair("ev-0", obs0), _pair("ev-1", obs1), _pair("ev-2", obs2)]
    group, structural_links, contextual_links = _build(items)

    sequence = construct_behavioral_sequence(group, items, structural_links, contextual_links)

    step_by_evidence = {
        ev_id: step.step_id for step in sequence.steps for ev_id in step.evidence_ids
    }
    edge_pairs = {(e.from_step_id, e.to_step_id) for e in sequence.edges}
    assert edge_pairs == {
        (step_by_evidence["ev-0"], step_by_evidence["ev-1"]),
        (step_by_evidence["ev-1"], step_by_evidence["ev-2"]),
    }
    # never the transitively-implied 0 -> 2 edge
    assert (step_by_evidence["ev-0"], step_by_evidence["ev-2"]) not in edge_pairs
    assert sequence.gaps == ()
    for edge in sequence.edges:
        assert edge.basis.basis_kind is OrderingBasisKind.TEMPORAL_SAME_ENTITY


# ===========================================================================
# D. Lineage-vs-timestamp conflict (ADR-0004 D7)
# ===========================================================================


def test_lineage_timestamp_disagreement_is_recorded_not_reversed() -> None:
    host = HostRef(id="H1")
    # Parent observed *later* than child -- a real-world clock-skew/telemetry
    # anomaly. Lineage direction must still win (parent -> child).
    obs_p = _obs(
        "obs-p", host=host, process=ProcessRef(entity_id="{P}"), timestamp=T0.replace(second=5)
    )
    obs_c = _obs(
        "obs-c",
        host=host,
        process=ProcessRef(parent_entity_id="{P}", entity_id="{C}"),
        timestamp=T0,
    )
    items = [_pair("ev-p", obs_p), _pair("ev-c", obs_c)]
    group, structural_links, contextual_links = _build(items)

    sequence = construct_behavioral_sequence(group, items, structural_links, contextual_links)

    assert len(sequence.edges) == 1
    edge = sequence.edges[0]
    step_by_evidence = {
        ev_id: step.step_id for step in sequence.steps for ev_id in step.evidence_ids
    }
    assert edge.from_step_id == step_by_evidence["ev-p"]
    assert edge.to_step_id == step_by_evidence["ev-c"]
    assert edge.basis.timestamp_agreement is False


# ===========================================================================
# E. SequenceGap
# ===========================================================================


def test_equal_timestamps_produce_a_gap_not_an_edge() -> None:
    host = HostRef(id="H1")
    obs_a = _obs("obs-a", host=host, process=ProcessRef(entity_id="{X}"), timestamp=T0)
    obs_b = _obs("obs-b", host=host, process=ProcessRef(entity_id="{X}"), timestamp=T0)
    items = [_pair("ev-a", obs_a), _pair("ev-b", obs_b)]
    group, structural_links, contextual_links = _build(items)

    sequence = construct_behavioral_sequence(group, items, structural_links, contextual_links)

    assert sequence.edges == ()
    assert len(sequence.gaps) == 1
    gap = sequence.gaps[0]
    assert gap.reason is GapReason.EQUAL_TIMESTAMPS
    assert gap.grounding_link_id in group.structural_link_ids


def test_coarse_precision_tie_produces_a_gap() -> None:
    host = HostRef(id="H1")
    obs_a = _obs(
        "obs-a",
        host=host,
        process=ProcessRef(entity_id="{X}"),
        timestamp=T0.replace(microsecond=100_000),
        timestamp_precision=TimePrecision.SECOND,
    )
    obs_b = _obs(
        "obs-b",
        host=host,
        process=ProcessRef(entity_id="{X}"),
        timestamp=T0.replace(microsecond=900_000),
        timestamp_precision=TimePrecision.SECOND,
    )
    items = [_pair("ev-a", obs_a), _pair("ev-b", obs_b)]
    group, structural_links, contextual_links = _build(items)

    sequence = construct_behavioral_sequence(group, items, structural_links, contextual_links)

    assert sequence.edges == ()
    assert len(sequence.gaps) == 1
    assert sequence.gaps[0].reason is GapReason.COARSE_PRECISION_TIE


def test_unknown_precision_inequality_orders_but_flags_precision_uncertain() -> None:
    host = HostRef(id="H1")
    obs_a = _obs(
        "obs-a",
        host=host,
        process=ProcessRef(entity_id="{X}"),
        timestamp=T0,
        timestamp_precision=TimePrecision.UNKNOWN,
    )
    obs_b = _obs(
        "obs-b",
        host=host,
        process=ProcessRef(entity_id="{X}"),
        timestamp=T0.replace(second=1),
    )
    items = [_pair("ev-a", obs_a), _pair("ev-b", obs_b)]
    group, structural_links, contextual_links = _build(items)

    sequence = construct_behavioral_sequence(group, items, structural_links, contextual_links)

    assert sequence.gaps == ()
    assert len(sequence.edges) == 1
    assert sequence.edges[0].basis.precision_uncertain is True


# ===========================================================================
# F. SequenceParallelGroup construction + convergence-safety exclusion
# ===========================================================================


def test_two_lineage_children_form_one_parallel_group() -> None:
    host = HostRef(id="H1")
    obs_p = _obs("obs-p", host=host, process=ProcessRef(entity_id="{P}"), timestamp=T0)
    obs_a = _obs(
        "obs-a",
        host=host,
        process=ProcessRef(parent_entity_id="{P}", entity_id="{A}"),
        timestamp=T0.replace(second=1),
    )
    obs_b = _obs(
        "obs-b",
        host=host,
        process=ProcessRef(parent_entity_id="{P}", entity_id="{B}"),
        timestamp=T0.replace(second=1),
    )
    items = [_pair("ev-p", obs_p), _pair("ev-a", obs_a), _pair("ev-b", obs_b)]
    group, structural_links, contextual_links = _build(items)

    sequence = construct_behavioral_sequence(group, items, structural_links, contextual_links)

    step_by_evidence = {
        ev_id: step.step_id for step in sequence.steps for ev_id in step.evidence_ids
    }
    assert len(sequence.parallel_groups) == 1
    pg = sequence.parallel_groups[0]
    assert pg.source_step_id == step_by_evidence["ev-p"]
    roots = {branch[0] for branch in pg.branches}
    assert roots == {step_by_evidence["ev-a"], step_by_evidence["ev-b"]}
    # A and B are never directly linked -- no edge/gap between them.
    ab_pair = frozenset((step_by_evidence["ev-a"], step_by_evidence["ev-b"]))
    edge_pairs = {frozenset((e.from_step_id, e.to_step_id)) for e in sequence.edges}
    gap_pairs = {frozenset((g.step_id_a, g.step_id_b)) for g in sequence.gaps}
    assert ab_pair not in edge_pairs
    assert ab_pair not in gap_pairs


def test_mutually_convergent_lineage_children_yield_no_parallel_group() -> None:
    """P spawns A and B (two real PROCESS_LINEAGE children), but A and B
    turn out to be the *same* underlying process entity described at two
    different times (a real, if unusual, telemetry shape -- e.g. duplicate
    or re-registered process records). That makes B reachable both directly
    from P and transitively through A's own TEMPORAL_SAME_ENTITY edge,
    which the convergence-safety rule (ADR-0004 D9) must exclude B from
    every branch; with fewer than two valid branches left, no
    SequenceParallelGroup is built for this branch point at all."""
    host = HostRef(id="H1")
    obs_p = _obs("obs-p", host=host, process=ProcessRef(entity_id="{P}"), timestamp=T0)
    obs_a = _obs(
        "obs-a",
        host=host,
        process=ProcessRef(parent_entity_id="{P}", entity_id="{X}"),
        timestamp=T0.replace(second=1),
    )
    obs_b = _obs(
        "obs-b",
        host=host,
        process=ProcessRef(parent_entity_id="{P}", entity_id="{X}"),
        timestamp=T0.replace(second=2),
    )
    items = [_pair("ev-p", obs_p), _pair("ev-a", obs_a), _pair("ev-b", obs_b)]
    group, structural_links, contextual_links = _build(items)

    sequence = construct_behavioral_sequence(group, items, structural_links, contextual_links)

    assert sequence.parallel_groups == ()


# ===========================================================================
# G. Contextual boundary / no TEMPORAL_PROXIMITY
# ===========================================================================


def test_contextual_links_never_produce_an_edge_or_gap() -> None:
    host = HostRef(id="H1")
    obs_p = _obs("obs-p", host=host, process=ProcessRef(entity_id="{P}"))
    obs_c = _obs("obs-c", host=host, process=ProcessRef(parent_entity_id="{P}", entity_id="{C}"))
    items = [_pair("ev-p", obs_p), _pair("ev-c", obs_c)]
    group, structural_links, contextual_links = _build(items)
    assert len(contextual_links) >= 1

    sequence = construct_behavioral_sequence(group, items, structural_links, contextual_links)

    grounding_ids = {e.basis.grounding_link_id for e in sequence.edges} | {
        g.grounding_link_id for g in sequence.gaps
    }
    contextual_ids = {link.link_id for link in contextual_links}
    assert grounding_ids.isdisjoint(contextual_ids)


def test_engine_module_contains_no_temporal_proximity_code_reference() -> None:
    """Source-level guard, narrowed to code-shaped identifiers only (this
    module's own docstring legitimately *discusses* ``TEMPORAL_PROXIMITY``
    in prose, explaining why it is out of scope -- that is not the concern
    here, mirroring ``test_correlation_sequence.py``'s identical guard for
    ``sequence.py``)."""
    path = CORRELATION_DIR / "sequence_engine.py"
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    offending: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id == "TEMPORAL_PROXIMITY":
            offending.append("Name(TEMPORAL_PROXIMITY)")
        if isinstance(node, ast.Attribute) and node.attr == "TEMPORAL_PROXIMITY":
            offending.append("Attribute(.TEMPORAL_PROXIMITY)")
        if isinstance(node, ast.Constant) and node.value == "temporal_proximity":
            offending.append("Constant('temporal_proximity')")
    assert (
        not offending
    ), f"TEMPORAL_PROXIMITY referenced as code in sequence_engine.py: {offending}"


def test_ordering_basis_kind_is_closed_to_lineage_and_temporal_same_entity() -> None:
    assert {member.name for member in OrderingBasisKind} == {
        "PROCESS_LINEAGE",
        "TEMPORAL_SAME_ENTITY",
    }


# ===========================================================================
# H. Multi-host / multi-group isolation
# ===========================================================================


def test_construct_behavioral_sequence_never_pulls_in_another_hosts_group() -> None:
    host_a = HostRef(id="H1")
    host_b = HostRef(id="H2")
    obs_a1 = _obs("obs-a1", host=host_a, process=ProcessRef(entity_id="{SAME}"), timestamp=T0)
    obs_a2 = _obs(
        "obs-a2",
        host=host_a,
        process=ProcessRef(parent_entity_id="{SAME}", entity_id="{A2}"),
        timestamp=T0.replace(second=1),
    )
    obs_b1 = _obs("obs-b1", host=host_b, process=ProcessRef(entity_id="{SAME}"), timestamp=T0)
    obs_b2 = _obs(
        "obs-b2",
        host=host_b,
        process=ProcessRef(parent_entity_id="{SAME}", entity_id="{B2}"),
        timestamp=T0.replace(second=1),
    )
    all_items = [
        _pair("ev-a1", obs_a1),
        _pair("ev-a2", obs_a2),
        _pair("ev-b1", obs_b1),
        _pair("ev-b2", obs_b2),
    ]
    structural_result = correlate_structurally(all_items)
    contextual_result = contextualize(structural_result, all_items)
    assert len(contextual_result.groups) == 2  # host-scoped: never merged

    for group in contextual_result.groups:
        own_items = [pair for pair in all_items if pair[0].evidence_id in group.member_evidence_ids]
        structural_links = tuple(
            link for link in structural_result.links if link.link_id in group.structural_link_ids
        )
        contextual_links = tuple(
            link
            for link in contextual_result.contextual_links
            if link.link_id in group.contextual_link_ids
        )
        sequence = construct_behavioral_sequence(
            group, own_items, structural_links, contextual_links
        )
        step_evidence_ids = {eid for step in sequence.steps for eid in step.evidence_ids}
        assert step_evidence_ids == set(group.member_evidence_ids)


def test_construct_behavioral_sequence_rejects_items_from_another_group() -> None:
    host_a = HostRef(id="H1")
    host_b = HostRef(id="H2")
    obs_a1 = _obs("obs-a1", host=host_a, process=ProcessRef(entity_id="{A}"))
    obs_a2 = _obs(
        "obs-a2", host=host_a, process=ProcessRef(parent_entity_id="{A}", entity_id="{A2}")
    )
    obs_b1 = _obs("obs-b1", host=host_b, process=ProcessRef(entity_id="{B}"))
    obs_b2 = _obs(
        "obs-b2", host=host_b, process=ProcessRef(parent_entity_id="{B}", entity_id="{B2}")
    )
    all_items = [
        _pair("ev-a1", obs_a1),
        _pair("ev-a2", obs_a2),
        _pair("ev-b1", obs_b1),
        _pair("ev-b2", obs_b2),
    ]
    structural_result = correlate_structurally(all_items)
    contextual_result = contextualize(structural_result, all_items)
    group_a = min(contextual_result.groups, key=lambda g: g.group_id)
    structural_links = tuple(
        link for link in structural_result.links if link.link_id in group_a.structural_link_ids
    )
    contextual_links = tuple(
        link
        for link in contextual_result.contextual_links
        if link.link_id in group_a.contextual_link_ids
    )

    with pytest.raises(CorrelationError, match="correspond exactly"):
        construct_behavioral_sequence(group_a, all_items, structural_links, contextual_links)


# ===========================================================================
# I. Determinism (shuffle/permutation invariance)
# ===========================================================================


def test_construction_is_invariant_to_input_order() -> None:
    host = HostRef(id="H1")
    obs_p = _obs("obs-p", host=host, process=ProcessRef(entity_id="{P}"), timestamp=T0)
    obs_a = _obs(
        "obs-a",
        host=host,
        process=ProcessRef(parent_entity_id="{P}", entity_id="{A}"),
        timestamp=T0.replace(second=1),
    )
    obs_b = _obs(
        "obs-b",
        host=host,
        process=ProcessRef(parent_entity_id="{P}", entity_id="{B}"),
        timestamp=T0.replace(second=1),
    )
    items = [_pair("ev-p", obs_p), _pair("ev-a", obs_a), _pair("ev-b", obs_b)]
    group, structural_links, contextual_links = _build(items)

    forward = construct_behavioral_sequence(group, items, structural_links, contextual_links)
    reversed_result = construct_behavioral_sequence(
        group,
        list(reversed(items)),
        tuple(reversed(structural_links)),
        tuple(reversed(contextual_links)),
    )

    assert forward.sequence_id == reversed_result.sequence_id
    assert forward.steps == reversed_result.steps
    assert forward.edges == reversed_result.edges
    assert forward.gaps == reversed_result.gaps
    assert forward.parallel_groups == reversed_result.parallel_groups


# ===========================================================================
# J. Provenance
# ===========================================================================


def test_provenance_defaults_and_reflects_group_membership() -> None:
    host = HostRef(id="H1")
    obs_p = _obs("obs-p", host=host, process=ProcessRef(entity_id="{P}"))
    obs_c = _obs("obs-c", host=host, process=ProcessRef(parent_entity_id="{P}", entity_id="{C}"))
    items = [_pair("ev-p", obs_p), _pair("ev-c", obs_c)]
    group, structural_links, contextual_links = _build(items)

    sequence = construct_behavioral_sequence(group, items, structural_links, contextual_links)

    assert sequence.provenance.method == SEQUENCE_ENGINE_METHOD
    assert sequence.provenance.method_version == SEQUENCE_ENGINE_METHOD_VERSION
    assert sequence.provenance.source_evidence_ids == group.member_evidence_ids
    assert sequence.provenance.source_observation_ids == group.member_observation_ids


def test_method_content_hash_changes_sequence_id() -> None:
    host = HostRef(id="H1")
    obs_p = _obs("obs-p", host=host, process=ProcessRef(entity_id="{P}"))
    obs_c = _obs("obs-c", host=host, process=ProcessRef(parent_entity_id="{P}", entity_id="{C}"))
    items = [_pair("ev-p", obs_p), _pair("ev-c", obs_c)]
    group, structural_links, contextual_links = _build(items)

    plain = construct_behavioral_sequence(group, items, structural_links, contextual_links)
    hashed = construct_behavioral_sequence(
        group, items, structural_links, contextual_links, method_content_hash="a" * 64
    )

    assert plain.sequence_id != hashed.sequence_id
    assert hashed.provenance.method_content_hash == "a" * 64


# ===========================================================================
# K. Negative / architecture guards
# ===========================================================================


def test_ambiguous_process_lineage_grounding_fails_closed() -> None:
    """O1 matches two rules (E1, E2 -- SHARED_OBSERVATION-collapsed into one
    step) and is the lineage parent of a third Evidence's Observation. G2.1
    independently produces a PROCESS_LINEAGE link from *each* of E1 and E2
    to the child, so after collapse two distinct, equally-real structural
    links resolve to the same directed step-level pair. ADR-0004 specifies
    no tie-break for this -- the engine must fail closed, not guess."""
    host = HostRef(id="H1")
    obs_p = _obs("obs-p", host=host, process=ProcessRef(entity_id="{P}"))
    obs_c = _obs("obs-c", host=host, process=ProcessRef(parent_entity_id="{P}", entity_id="{C}"))
    items = [
        _pair("ev-p1", obs_p, rule_id="rule-a"),
        _pair("ev-p2", obs_p, rule_id="rule-b"),
        _pair("ev-c", obs_c),
    ]
    group, structural_links, contextual_links = _build(items)

    with pytest.raises(CorrelationError, match="ambiguous PROCESS_LINEAGE"):
        construct_behavioral_sequence(group, items, structural_links, contextual_links)


def test_ambiguous_same_process_entity_grounding_fails_closed() -> None:
    """Two Observations (O1, O2) genuinely share one process-entity id (the
    same running process, described twice), and each Observation itself
    matches two rules (SHARED_OBSERVATION-collapsed into one step each).
    G2.1's full pairwise SAME_PROCESS_ENTITY closure then yields four
    distinct structural links, all resolving to the same step-level pair
    after collapse -- another instance of the same found ambiguity."""
    host = HostRef(id="H1")
    obs_1 = _obs("obs-1", host=host, process=ProcessRef(entity_id="{X}"), timestamp=T0)
    obs_2 = _obs(
        "obs-2", host=host, process=ProcessRef(entity_id="{X}"), timestamp=T0.replace(second=1)
    )
    items = [
        _pair("ev-1a", obs_1, rule_id="rule-a"),
        _pair("ev-1b", obs_1, rule_id="rule-b"),
        _pair("ev-2a", obs_2, rule_id="rule-a"),
        _pair("ev-2b", obs_2, rule_id="rule-b"),
    ]
    group, structural_links, contextual_links = _build(items)

    with pytest.raises(CorrelationError, match="ambiguous SAME_PROCESS_ENTITY"):
        construct_behavioral_sequence(group, items, structural_links, contextual_links)


def test_missing_item_is_rejected() -> None:
    host = HostRef(id="H1")
    obs_p = _obs("obs-p", host=host, process=ProcessRef(entity_id="{P}"))
    obs_c = _obs("obs-c", host=host, process=ProcessRef(parent_entity_id="{P}", entity_id="{C}"))
    items = [_pair("ev-p", obs_p), _pair("ev-c", obs_c)]
    group, structural_links, contextual_links = _build(items)

    with pytest.raises(CorrelationError, match="correspond exactly"):
        construct_behavioral_sequence(group, items[:1], structural_links, contextual_links)


def test_extra_item_is_rejected() -> None:
    host = HostRef(id="H1")
    obs_p = _obs("obs-p", host=host, process=ProcessRef(entity_id="{P}"))
    obs_c = _obs("obs-c", host=host, process=ProcessRef(parent_entity_id="{P}", entity_id="{C}"))
    items = [_pair("ev-p", obs_p), _pair("ev-c", obs_c)]
    group, structural_links, contextual_links = _build(items)
    extra_obs = _obs("obs-x", host=host, process=ProcessRef(entity_id="{X}"))
    extra_items = [*items, _pair("ev-x", extra_obs)]

    with pytest.raises(CorrelationError, match="correspond exactly"):
        construct_behavioral_sequence(group, extra_items, structural_links, contextual_links)


def test_mismatched_structural_links_is_rejected() -> None:
    host = HostRef(id="H1")
    obs_p = _obs("obs-p", host=host, process=ProcessRef(entity_id="{P}"))
    obs_c = _obs("obs-c", host=host, process=ProcessRef(parent_entity_id="{P}", entity_id="{C}"))
    items = [_pair("ev-p", obs_p), _pair("ev-c", obs_c)]
    group, structural_links, contextual_links = _build(items)

    with pytest.raises(CorrelationError, match="correspond exactly"):
        construct_behavioral_sequence(group, items, (), contextual_links)


def test_mismatched_contextual_links_is_rejected() -> None:
    host = HostRef(id="H1")
    obs_p = _obs("obs-p", host=host, process=ProcessRef(entity_id="{P}"))
    obs_c = _obs("obs-c", host=host, process=ProcessRef(parent_entity_id="{P}", entity_id="{C}"))
    items = [_pair("ev-p", obs_p), _pair("ev-c", obs_c)]
    group, structural_links, contextual_links = _build(items)
    assert contextual_links  # SAME_HOST_ID should be present

    with pytest.raises(CorrelationError, match="correspond exactly"):
        construct_behavioral_sequence(group, items, structural_links, ())


def test_group_type_is_checked() -> None:
    with pytest.raises(CorrelationError, match="CorrelationGroup"):
        construct_behavioral_sequence("not-a-group", [], (), ())  # type: ignore[arg-type]


def test_engine_module_never_imports_attack_knowledge_sources_or_dataplane() -> None:
    """G2.4.1 must not read ATT&CK knowledge (technique ids are read only
    off already-resolved ``Evidence.attack_ref``) and must stay as source-
    agnostic as G2.1/G2.2 already established for the package."""
    forbidden = ("attack_knowledge", "sources", "dataplane", "replay", "api")
    path = CORRELATION_DIR / "sequence_engine.py"
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    offending: list[str] = []
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.ImportFrom)
            and node.module
            and any(f"attribution_platform.{layer}" in node.module for layer in forbidden)
        ):
            offending.append(f"from {node.module} import ...")
    assert not offending, f"sequence_engine.py must not import {forbidden}: {offending}"


def test_engine_module_imports_only_stdlib_and_own_layers() -> None:
    """The engine legitimately needs ``domain`` (Evidence/Observation) and
    its own package (``contracts``/``errors``/``sequence``) -- unlike
    ``sequence.py``'s stricter contracts-only boundary -- but nothing else."""
    allowed_prefixes = (
        "attribution_platform.correlation",
        "attribution_platform.domain",
    )
    path = CORRELATION_DIR / "sequence_engine.py"
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    offending: list[str] = []
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.ImportFrom)
            and node.module
            and node.module.startswith("attribution_platform")
            and not any(node.module.startswith(prefix) for prefix in allowed_prefixes)
        ):
            offending.append(f"from {node.module} import ...")
    assert not offending, f"sequence_engine.py imports outside its layer: {offending}"


def test_engine_module_contains_no_attribution_or_scoring_identifiers() -> None:
    """Source-level guard mirroring ``test_correlation_sequence.py``'s
    identical guard for ``sequence.py`` -- narrowed to actual code
    identifiers (class/function/attribute/variable names), not general
    prose: this module's own docstring legitimately *discusses*
    likelihood/confidence/scoring while explaining that none of it exists
    here. What must never appear is one of these terms used as a real
    Python identifier."""
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
    path = CORRELATION_DIR / "sequence_engine.py"
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
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
