"""Replaying a raw-telemetry fixture through detection, correlation, *and*
behavioral-sequence reconstruction (gate G2.4.2).

Target flow, built entirely on unmodified earlier gates:

    DetectionReplayFixture -> replay_fixture_through_correlation (G2.3)
    -> CorrelationReplayResult (detection results + structural/contextual
       results, already persisted CorrelationLink/CorrelationGroup)
    -> for each resulting CorrelationGroup: filter that group's own
       (Evidence, Observation) pairs and structural/contextual links
    -> construct_behavioral_sequence (G2.4.1, pure, unmodified)
    -> persist_behavioral_sequence (G2.4.2)

This module adds **no new normalization, detection, correlation, or
sequence-ordering logic of its own** — it is a thin orchestrator, exactly
like G2.3's ``correlation_pipeline`` is over G1.2/G2.1/G2.2, and like
``detection_pipeline`` is over G0.4/G0.5/G0.8/G1.0. Concretely:

1. **G2.3** — :func:`attribution_platform.replay.replay_fixture_through_correlation`
   runs, completely unchanged. Every ``CorrelationGroup`` this module builds
   a sequence for, and every ``(Evidence, Observation)``/``CorrelationLink``
   fed into that construction, comes from that call's own
   ``CorrelationReplayResult`` — this module never constructs a
   ``CorrelationGroup``, ``CorrelationLink``, or ``Evidence`` itself
   (mirroring ``correlation_pipeline.py``'s own no-fabrication guarantee,
   checked the same way: an AST guard test in
   ``tests/test_replay_behavioral_sequence.py``).
2. **Group-scoped filtering** — for each ``CorrelationGroup`` in
   ``correlation_result.contextual_result.groups``, this module selects
   *exactly* the ``(Evidence, Observation)`` pairs whose evidence id is in
   ``group.member_evidence_ids``, *exactly* the structural links named by
   ``group.structural_link_ids``, and *exactly* the contextual links named
   by ``group.contextual_link_ids`` — no cross-group material ever reaches
   one group's sequence construction. ``construct_behavioral_sequence``
   itself re-verifies this exact correspondence and fails closed
   (``CorrelationError``) if it does not hold, so this filtering is checked
   twice, not merely assumed once.
3. **G2.4.1** — :func:`attribution_platform.correlation.construct_behavioral_sequence`
   runs, unchanged, once per group. This module never catches or suppresses
   the ``CorrelationError`` it may raise (in particular the G2.4.1-audited
   multi-link-grounding-ambiguity case) — a raised error propagates to the
   caller exactly as ``correlate_structurally``/``contextualize`` errors
   already do, uncaught, in ``correlation_pipeline.py``.
4. **G2.4.2** — every resulting ``BehavioralSequence`` is persisted via
   :func:`attribution_platform.dataplane.persist_behavioral_sequence` — the
   new, additive G2.4.2 extension of G0.8/G2.3's persistence pattern (no
   second persistence architecture; see that module's docstring).

Deterministic by construction, transitively: every function this module
calls is pure or idempotent-by-own-id (G1.2, G2.1, G2.2, G2.4.1, and
G0.8/G2.3/G2.4.2 persistence all already guarantee this individually — see
their own docstrings). Replaying the same fixture against the same rule pack
and client twice is therefore idempotent: identical sequences, identical
persisted documents.

Deliberately NOT here (forbidden this gate): a second replay, correlation,
or persistence framework (G2.3's own pipeline/persistence functions are
reused verbatim); the G2.4.1 ordering engine itself (called, never
reimplemented or modified); ``TEMPORAL_PROXIMITY``/G2.4.3 (out of scope,
sequenced after this gate); ATT&CK-knowledge-base access of any kind (this
module never imports ``attack_knowledge`` for sequence purposes — the
``AttackKnowledge`` it takes is passed straight through to G1.2's detection
replay via G2.3's own pipeline, unchanged from that gate;
``BehavioralStep.technique_stix_ids`` is already fully derived by G2.4.1
from real ``Evidence.attack_ref`` before this module ever sees it);
attribution, scoring, candidate generation, or confidence of any kind.
"""

from __future__ import annotations

from dataclasses import dataclass

from attribution_platform.attack_knowledge.loader import AttackKnowledge
from attribution_platform.correlation import (
    BehavioralSequence,
    CorrelationLink,
    construct_behavioral_sequence,
)
from attribution_platform.dataplane import ElasticClient, PersistResult, persist_behavioral_sequence
from attribution_platform.detection import DetectionEngine
from attribution_platform.domain import Evidence, Observation
from attribution_platform.replay.correlation_pipeline import (
    CorrelationReplayResult,
    replay_fixture_through_correlation,
)
from attribution_platform.replay.detection_fixtures import DetectionReplayFixture
from attribution_platform.sources.adapter import SourceAdapter


@dataclass(frozen=True)
class BehavioralSequenceReplayResult:
    """What replaying ``fixture`` through detection, correlation, and
    behavioral-sequence reconstruction produced — for tests and for a future
    caller to report on.

    ``correlation_result`` is G2.3's own unmodified return value (every
    sequence built below is grounded in one of its
    ``contextual_result.groups``). ``sequences``/``sequence_persists`` are
    in the same order as ``correlation_result.contextual_result.groups``
    (already sorted by ``group_id`` — see that result's own docstring) — one
    ``BehavioralSequence`` per group, never fewer, never merged across
    groups (ADR-0004 D1).
    """

    correlation_result: CorrelationReplayResult
    sequences: tuple[BehavioralSequence, ...]
    sequence_persists: tuple[PersistResult, ...]


def replay_fixture_through_behavioral_sequences(
    fixture: DetectionReplayFixture,
    *,
    client: ElasticClient,
    engine: DetectionEngine,
    knowledge: AttackKnowledge,
    adapter: SourceAdapter | None = None,
) -> BehavioralSequenceReplayResult:
    """Replay every scenario in ``fixture`` through the real G1.0 detection
    engine and G2.1/G2.2 correlation engines (via G2.3's
    ``replay_fixture_through_correlation``, unchanged), then reconstruct and
    persist one real ``BehavioralSequence`` per resulting ``CorrelationGroup``
    via the real, unmodified G2.4.1 ``construct_behavioral_sequence``.

    Every ``BehavioralSequence`` built is grounded only in its own
    ``CorrelationGroup``'s own material — this function never hand-authors a
    ``BehavioralSequence`` or any of its nested contracts, and never lets one
    group's Evidence or links leak into another group's sequence.
    """
    correlation_result = replay_fixture_through_correlation(
        fixture, client=client, engine=engine, knowledge=knowledge, adapter=adapter
    )

    items_by_evidence_id: dict[str, tuple[Evidence, Observation]] = {}
    for result in correlation_result.detection_results:
        for evidence in result.evidences:
            items_by_evidence_id[evidence.evidence_id] = (evidence, result.observation)

    structural_by_id: dict[str, CorrelationLink] = {
        link.link_id: link for link in correlation_result.structural_result.links
    }
    contextual_by_id: dict[str, CorrelationLink] = {
        link.link_id: link for link in correlation_result.contextual_result.contextual_links
    }

    sequences: list[BehavioralSequence] = []
    sequence_persists: list[PersistResult] = []
    for group in correlation_result.contextual_result.groups:
        group_items = tuple(
            items_by_evidence_id[evidence_id] for evidence_id in group.member_evidence_ids
        )
        group_structural_links = tuple(
            structural_by_id[link_id] for link_id in group.structural_link_ids
        )
        group_contextual_links = tuple(
            contextual_by_id[link_id] for link_id in group.contextual_link_ids
        )
        sequence = construct_behavioral_sequence(
            group, group_items, group_structural_links, group_contextual_links
        )
        sequences.append(sequence)
        sequence_persists.append(persist_behavioral_sequence(client, sequence))

    return BehavioralSequenceReplayResult(
        correlation_result=correlation_result,
        sequences=tuple(sequences),
        sequence_persists=tuple(sequence_persists),
    )
