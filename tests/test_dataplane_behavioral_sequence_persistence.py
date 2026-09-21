"""Tests for gate G2.4.2: BehavioralSequence persistence.

Covers: write->read round trip for a real, engine-produced
``BehavioralSequence`` (steps, edges, a gap, provenance, and — the one
concrete nested-reconstruction risk this gate identified — a
``SequenceParallelGroup`` with a *multi-element* branch, proving
``branches`` round-trips as ``tuple[tuple[str, ...], ...]`` and never
silently degrades to a tuple of lists); idempotent writes keyed by
``sequence_id``; the pinned, schema-version-derived index name/mapping;
fail-closed rejection of non-``BehavioralSequence`` input, a
write-before-``ensure_index``, an unrecognized stored ``schema_version``,
and a malformed stored document; ``load_behavioral_sequence`` returning
``None`` for an absent id.

Builds its ``BehavioralSequence`` fixtures via the real, unmodified G2.1/
G2.2/G2.4.1 engines (the same ``_obs``/``_evidence``/``_pair`` pattern
``test_correlation_sequence_engine.py`` already established) rather than
hand-authoring correlation/sequence objects with matching-by-hand ids.

Does NOT touch fixtures/phase2_correlation_scenarios.json, G2.4.0's
``sequence.py``, or G2.4.1's ``sequence_engine.py``. Offline, deterministic.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from attribution_platform.attack_knowledge.loader import AttackKnowledge, load_attack_knowledge
from attribution_platform.correlation import (
    BehavioralSequence,
    CorrelationGroup,
    CorrelationLink,
    construct_behavioral_sequence,
    contextualize,
    correlate_structurally,
)
from attribution_platform.correlation.sequence import GapReason
from attribution_platform.dataplane import (
    BEHAVIORAL_SEQUENCES_INDEX,
    BEHAVIORAL_SEQUENCES_MAPPING,
    ElasticIntegrationError,
    FakeElasticClient,
    PersistResult,
    load_behavioral_sequence,
    persist_behavioral_sequence,
)
from attribution_platform.domain import (
    AttackRef,
    Evidence,
    EvidenceType,
    HostRef,
    Observation,
    ProcessRef,
    SourceRef,
)
from attribution_platform.extraction import RuleRef, derive_evidence

T0 = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)


@pytest.fixture(scope="module")
def knowledge() -> AttackKnowledge:
    return load_attack_knowledge()


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
    evidence_id: str,
    observation: Observation,
    *,
    rule_id: str = "golden-rule",
    attack_ref: AttackRef | None = None,
    knowledge: AttackKnowledge | None = None,
) -> Evidence:
    return derive_evidence(
        evidence_id=evidence_id,
        evidence_type=EvidenceType.BEHAVIORAL,
        claim="synthetic G2.4.2 persistence-test evidence",
        observations=(observation,),
        rule_ref=RuleRef(rule_id=rule_id, rule_version="1.0"),
        attack_ref=attack_ref,
        knowledge=knowledge,
    )


def _pair(
    evidence_id: str, observation: Observation, **kwargs: object
) -> tuple[Evidence, Observation]:
    return (_evidence(evidence_id, observation, **kwargs), observation)  # type: ignore[arg-type]


def _build(
    items: list[tuple[Evidence, Observation]],
) -> tuple[CorrelationGroup, tuple[CorrelationLink, ...], tuple[CorrelationLink, ...]]:
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
    return group, structural_links, contextual_links


def _branching_sequence(knowledge: AttackKnowledge) -> BehavioralSequence:
    """P -> A (leaf), P -> B -> C: a deeper branch, so
    SequenceParallelGroup.branches has one two-element inner tuple -- the
    exact shape whose round-trip reconstruction this gate must get right."""
    technique = knowledge.techniques()[0]
    ref = AttackRef(
        stix_id=technique["id"],
        object_type=technique["type"],
        attack_kb_version=knowledge.attack_kb_version,
    )
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
    items = [
        _pair("ev-p", obs_p, attack_ref=ref, knowledge=knowledge),
        _pair("ev-a", obs_a),
        _pair("ev-b", obs_b),
        _pair("ev-c", obs_c),
    ]
    group, structural_links, contextual_links = _build(items)
    return construct_behavioral_sequence(group, items, structural_links, contextual_links)


def _gap_sequence() -> BehavioralSequence:
    """Two observations sharing one process entity, identical timestamps --
    a SequenceGap, never an edge."""
    host = HostRef(id="H1")
    obs_a = _obs("obs-a", host=host, process=ProcessRef(entity_id="{X}"), timestamp=T0)
    obs_b = _obs("obs-b", host=host, process=ProcessRef(entity_id="{X}"), timestamp=T0)
    items = [_pair("ev-a", obs_a), _pair("ev-b", obs_b)]
    group, structural_links, contextual_links = _build(items)
    return construct_behavioral_sequence(group, items, structural_links, contextual_links)


# ===========================================================================
# 1. Write -> read round trip
# ===========================================================================


def test_branching_sequence_round_trip_preserves_every_field(knowledge: AttackKnowledge) -> None:
    client = FakeElasticClient()
    original = _branching_sequence(knowledge)
    persist_behavioral_sequence(client, original)
    loaded = load_behavioral_sequence(client, original.sequence_id)
    assert loaded == original


def test_round_trip_preserves_step_evidence_types(knowledge: AttackKnowledge) -> None:
    # B4: every engine-built step carries its member Evidence.evidence_type
    # (default BEHAVIORAL here); the write->read round trip preserves it.
    client = FakeElasticClient()
    original = _branching_sequence(knowledge)
    assert original.steps and all(step.evidence_types == ("behavioral",) for step in original.steps)
    persist_behavioral_sequence(client, original)
    loaded = load_behavioral_sequence(client, original.sequence_id)
    assert loaded is not None
    assert [s.evidence_types for s in loaded.steps] == [s.evidence_types for s in original.steps]


def test_legacy_step_document_without_evidence_types_loads_as_empty_tuple(
    knowledge: AttackKnowledge,
) -> None:
    # A pre-``behavioral-step/2`` document has no evidence_types key on its
    # steps; it must load with evidence_types == () (tolerant default, no
    # migration) rather than failing.
    client = FakeElasticClient()
    original = _branching_sequence(knowledge)
    persist_behavioral_sequence(client, original)
    stored = client.get_document(BEHAVIORAL_SEQUENCES_INDEX, original.sequence_id)
    assert stored is not None
    legacy = {
        **stored,
        "steps": [
            {k: v for k, v in step.items() if k != "evidence_types"} for step in stored["steps"]
        ],
    }
    client.index_document(BEHAVIORAL_SEQUENCES_INDEX, original.sequence_id, legacy)
    loaded = load_behavioral_sequence(client, original.sequence_id)
    assert loaded is not None
    assert loaded.steps and all(step.evidence_types == () for step in loaded.steps)


def test_nested_parallel_group_branches_round_trip_as_tuple_of_tuples(
    knowledge: AttackKnowledge,
) -> None:
    """The dedicated regression test for the identified risk: to_serializable
    turns tuple[tuple[str, ...], ...] into list[list[str]]; a shallow
    outer-only conversion would silently degrade equality (a tuple of lists
    is never equal to a tuple of tuples)."""
    client = FakeElasticClient()
    original = _branching_sequence(knowledge)
    assert len(original.parallel_groups) == 1
    pg = original.parallel_groups[0]
    assert any(
        len(branch) == 2 for branch in pg.branches
    ), "fixture must produce a multi-element branch to exercise the nested-tuple risk"

    persist_behavioral_sequence(client, original)
    loaded = load_behavioral_sequence(client, original.sequence_id)

    assert loaded is not None
    loaded_pg = loaded.parallel_groups[0]
    assert loaded_pg.branches == pg.branches
    for branch in loaded_pg.branches:
        assert isinstance(branch, tuple)
    assert isinstance(loaded_pg.branches, tuple)


def test_gap_sequence_round_trip_preserves_gap_reason() -> None:
    client = FakeElasticClient()
    original = _gap_sequence()
    assert original.edges == ()
    assert len(original.gaps) == 1
    assert original.gaps[0].reason is GapReason.EQUAL_TIMESTAMPS

    persist_behavioral_sequence(client, original)
    loaded = load_behavioral_sequence(client, original.sequence_id)

    assert loaded == original
    assert loaded is not None
    assert loaded.gaps[0].reason is GapReason.EQUAL_TIMESTAMPS


def test_load_missing_sequence_returns_none() -> None:
    client = FakeElasticClient()
    assert load_behavioral_sequence(client, "does-not-exist") is None


# ===========================================================================
# 2. Idempotent, deterministic writes keyed by sequence_id
# ===========================================================================


def test_persist_behavioral_sequence_is_idempotent_and_uses_domain_id(
    knowledge: AttackKnowledge,
) -> None:
    client = FakeElasticClient()
    sequence = _branching_sequence(knowledge)
    result_1 = persist_behavioral_sequence(client, sequence)
    result_2 = persist_behavioral_sequence(client, sequence)
    assert (
        result_1
        == result_2
        == PersistResult(index=BEHAVIORAL_SEQUENCES_INDEX, document_id=sequence.sequence_id)
    )
    assert client.document_count(BEHAVIORAL_SEQUENCES_INDEX) == 1


# ===========================================================================
# 3. Pinned, deterministic index name/mapping
# ===========================================================================


def test_behavioral_sequences_index_is_pinned_and_schema_derived() -> None:
    assert BEHAVIORAL_SEQUENCES_INDEX == "attribution-platform-behavioral-sequences-v1"


def test_behavioral_sequences_mapping_has_required_top_level_fields() -> None:
    for field in (
        "sequence_id",
        "group_id",
        "schema_version",
        "steps",
        "edges",
        "gaps",
        "parallel_groups",
        "provenance",
    ):
        assert field in BEHAVIORAL_SEQUENCES_MAPPING
    assert BEHAVIORAL_SEQUENCES_MAPPING["sequence_id"] == {"type": "keyword"}
    assert BEHAVIORAL_SEQUENCES_MAPPING["provenance"]["properties"]["method"] == {"type": "keyword"}


def test_ensure_index_is_idempotent_for_behavioral_sequences() -> None:
    client = FakeElasticClient()
    client.ensure_index(BEHAVIORAL_SEQUENCES_INDEX, BEHAVIORAL_SEQUENCES_MAPPING)
    client.ensure_index(BEHAVIORAL_SEQUENCES_INDEX, BEHAVIORAL_SEQUENCES_MAPPING)
    assert client.mappings_for(BEHAVIORAL_SEQUENCES_INDEX) == BEHAVIORAL_SEQUENCES_MAPPING


# ===========================================================================
# 4. Fail closed
# ===========================================================================


def test_persist_behavioral_sequence_rejects_non_sequence() -> None:
    client = FakeElasticClient()
    with pytest.raises(ElasticIntegrationError, match="requires a BehavioralSequence"):
        persist_behavioral_sequence(client, "not-a-sequence")  # type: ignore[arg-type]


def test_index_document_before_ensure_index_fails_closed() -> None:
    client = FakeElasticClient()
    with pytest.raises(ElasticIntegrationError, match="does not exist"):
        client.index_document(BEHAVIORAL_SEQUENCES_INDEX, "seq-1", {"sequence_id": "seq-1"})


def test_load_rejects_unrecognized_schema_version() -> None:
    client = FakeElasticClient()
    client.ensure_index(BEHAVIORAL_SEQUENCES_INDEX, BEHAVIORAL_SEQUENCES_MAPPING)
    stale_document = {
        "sequence_id": "seq-1",
        "group_id": "group-1",
        "steps": [],
        "provenance": {"method": "m", "method_version": "1"},
        "schema_version": "behavioral-sequence/999",
    }
    client.index_document(BEHAVIORAL_SEQUENCES_INDEX, "seq-1", stale_document)
    with pytest.raises(ElasticIntegrationError, match="schema_version"):
        load_behavioral_sequence(client, "seq-1")


def test_load_rejects_malformed_stored_document() -> None:
    client = FakeElasticClient()
    client.ensure_index(BEHAVIORAL_SEQUENCES_INDEX, BEHAVIORAL_SEQUENCES_MAPPING)
    # Missing required 'steps' entirely.
    client.index_document(
        BEHAVIORAL_SEQUENCES_INDEX,
        "seq-1",
        {
            "sequence_id": "seq-1",
            "group_id": "group-1",
            "provenance": {"method": "m", "method_version": "1"},
            "schema_version": "behavioral-sequence/1",
        },
    )
    with pytest.raises(ElasticIntegrationError, match="could not be reconstructed"):
        load_behavioral_sequence(client, "seq-1")


def test_load_rejects_document_with_invalid_nested_enum() -> None:
    client = FakeElasticClient()
    client.ensure_index(BEHAVIORAL_SEQUENCES_INDEX, BEHAVIORAL_SEQUENCES_MAPPING)
    document = {
        "sequence_id": "seq-1",
        "group_id": "group-1",
        "provenance": {"method": "m", "method_version": "1"},
        "schema_version": "behavioral-sequence/1",
        "steps": [
            {
                "step_id": "step-1",
                "group_id": "group-1",
                "evidence_ids": ["ev-1"],
                "observation_id": "obs-1",
                "schema_version": "behavioral-step/1",
            }
        ],
        "edges": [
            {
                "edge_id": "edge-1",
                "from_step_id": "step-1",
                "to_step_id": "step-2",
                "basis": {
                    "basis_kind": "not_a_real_basis_kind",
                    "grounding_link_id": "link-1",
                },
                "schema_version": "sequence-edge/1",
            }
        ],
    }
    client.index_document(BEHAVIORAL_SEQUENCES_INDEX, "seq-1", document)
    with pytest.raises(ElasticIntegrationError, match="could not be reconstructed"):
        load_behavioral_sequence(client, "seq-1")
