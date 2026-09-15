"""Replaying a raw-telemetry fixture through detection, correlation, and
TEMPORAL_PROXIMITY enrichment (gate G2.4.3).

Target flow, built entirely on unmodified earlier gates:

    DetectionReplayFixture -> replay_fixture_through_correlation (G2.3)
    -> CorrelationReplayResult (detection results + structural/contextual
       results, already persisted CorrelationLink/CorrelationGroup)
    -> compute_temporal_proximity (G2.4.3, pure, unmodified elsewhere)
    -> persist_correlation_link / persist_correlation_group (G2.3 persistence,
       reused unchanged -- both are already generic over LinkClass)
    -> for each updated CorrelationGroup: filter that group's own
       (Evidence, Observation) pairs and structural/contextual links
    -> construct_behavioral_sequence (G2.4.1, pure, unmodified)
    -> persist_behavioral_sequence (G2.4.2 persistence, reused unchanged)

This module adds **no new normalization, detection, correlation, or
temporal-matching logic of its own** — it is a thin orchestrator, exactly
like G2.4.2's ``behavioral_sequence_pipeline`` is over G2.3/G2.4.1, and like
G2.3's ``correlation_pipeline`` is over G1.2/G2.1/G2.2. Concretely:

1. **G2.3** — :func:`attribution_platform.replay.replay_fixture_through_correlation`
   runs, completely unchanged. Every ``(Evidence, Observation)`` pair, every
   structural link, and every already-computed group this module enriches
   comes from that call's own ``CorrelationReplayResult`` — this module
   never constructs a ``CorrelationGroup``, ``CorrelationLink``, or
   ``Evidence`` itself (mirroring ``correlation_pipeline.py``'s/
   ``behavioral_sequence_pipeline.py``'s own no-fabrication guarantee,
   checked the same way: an AST guard test in
   ``tests/test_replay_temporal_proximity.py``).
2. **G2.4.3** — :func:`attribution_platform.correlation.compute_temporal_proximity`
   runs, unchanged, once over the full flattened item list, producing new
   ``TEMPORAL_PROXIMITY`` links and the *union*-enriched groups (never a
   replacement of a group's existing ``contextual_link_ids``).
3. **G2.3 persistence, reused verbatim** — every new ``TEMPORAL_PROXIMITY``
   link is persisted via :func:`attribution_platform.dataplane.persist_correlation_link`
   (already generic over ``LinkClass``, no changes needed); every enriched
   group is persisted via :func:`attribution_platform.dataplane.persist_correlation_group`
   under its own **unchanged** ``group_id`` — an idempotent upsert that
   replaces the G2.3-persisted document in place with the larger
   ``contextual_link_ids`` set, never a new document, never a new id.
4. **G2.4.1** — :func:`attribution_platform.correlation.construct_behavioral_sequence`
   runs, unchanged, once per *enriched* group (not the pre-enrichment
   groups — the whole point of this pipeline is that the resulting
   ``BehavioralSequence``s carry the ``TEMPORAL_PROXIMITY`` annotations).
   This module never catches or suppresses the ``CorrelationError`` it may
   raise, uncaught, exactly as ``behavioral_sequence_pipeline.py`` already
   does not catch it.
5. **G2.4.2 persistence, reused verbatim** — every resulting
   ``BehavioralSequence`` is persisted via
   :func:`attribution_platform.dataplane.persist_behavioral_sequence` — no
   second persistence architecture.

**Why this does not call** ``replay_fixture_through_behavioral_sequences``
**(G2.4.2's own orchestrator):** that function recomputes its own
``CorrelationReplayResult`` internally and has no parameter for injecting
temporal-proximity-enriched groups. This module instead composes the same
*lower-level*, already-public, already-generic functions that function
itself is built from (``construct_behavioral_sequence``,
``persist_behavioral_sequence``) directly — the identical relationship
``behavioral_sequence_pipeline.py`` already has to
``correlation_pipeline.py`` (a new orchestrator composing frozen building
blocks, never wrapping or modifying the prior one).
``replay_fixture_through_behavioral_sequences`` remains a fully valid,
unmodified, standalone entry point for callers who do not want
temporal-proximity enrichment; ``correlation_pipeline.py`` and
``behavioral_sequence_pipeline.py`` are both untouched by this gate.

Deterministic by construction, transitively: every function this module
calls is pure or idempotent-by-own-id (G1.2, G2.1, G2.2, G2.4.1, G2.4.3, and
G0.8/G2.3/G2.4.2 persistence all already guarantee this individually — see
their own docstrings). Replaying the same fixture against the same rule
pack, window configuration, and client twice is therefore idempotent:
identical links, identical enriched groups, identical sequences, identical
persisted documents.

Deliberately NOT here (forbidden this gate): a second replay, correlation,
sequence-construction, or persistence framework (G2.3's/G2.4.1's/G2.4.2's
own functions are reused verbatim); modification of
``correlation_pipeline.py``/``behavioral_sequence_pipeline.py`` (both
untouched); ATT&CK-knowledge-base access of any kind beyond the pass-through
already required by G1.2's detection replay (this module never imports
``attack_knowledge`` for temporal-proximity purposes); attribution, scoring,
candidate generation, or confidence of any kind.
"""

from __future__ import annotations

from dataclasses import dataclass

from attribution_platform.attack_knowledge.loader import AttackKnowledge
from attribution_platform.correlation import (
    BehavioralSequence,
    CorrelationGroup,
    CorrelationLink,
    TemporalProximityConfig,
    compute_temporal_proximity,
    construct_behavioral_sequence,
)
from attribution_platform.dataplane import (
    ElasticClient,
    PersistResult,
    persist_behavioral_sequence,
    persist_correlation_group,
    persist_correlation_link,
)
from attribution_platform.detection import DetectionEngine
from attribution_platform.domain import Evidence, Observation
from attribution_platform.replay.correlation_pipeline import (
    CorrelationReplayResult,
    replay_fixture_through_correlation,
)
from attribution_platform.replay.detection_fixtures import DetectionReplayFixture
from attribution_platform.sources.adapter import SourceAdapter


@dataclass(frozen=True)
class TemporalProximityReplayResult:
    """What replaying ``fixture`` through detection, correlation,
    TEMPORAL_PROXIMITY enrichment, and behavioral-sequence reconstruction
    produced — for tests and for a future caller to report on.

    ``correlation_result`` is G2.3's own unmodified return value.
    ``temporal_proximity_links``/``enriched_groups`` are G2.4.3's own
    unmodified return values (``enriched_groups`` carries the *union* of
    each group's pre-existing ``contextual_link_ids`` and any newly-touching
    ``TEMPORAL_PROXIMITY`` link ids — never a replacement).
    ``sequences``/``sequence_persists`` are built from the *enriched* groups,
    in the same order as ``enriched_groups`` (already sorted by ``group_id``)
    — one ``BehavioralSequence`` per group, never fewer, never merged across
    groups (ADR-0004 D1).
    """

    correlation_result: CorrelationReplayResult
    temporal_proximity_links: tuple[CorrelationLink, ...]
    temporal_proximity_link_persists: tuple[PersistResult, ...]
    enriched_groups: tuple[CorrelationGroup, ...]
    group_persists: tuple[PersistResult, ...]
    sequences: tuple[BehavioralSequence, ...]
    sequence_persists: tuple[PersistResult, ...]


def replay_fixture_through_temporal_proximity(
    fixture: DetectionReplayFixture,
    *,
    client: ElasticClient,
    engine: DetectionEngine,
    knowledge: AttackKnowledge,
    config: TemporalProximityConfig,
    adapter: SourceAdapter | None = None,
) -> TemporalProximityReplayResult:
    """Replay every scenario in ``fixture`` through the real G1.0 detection
    engine and G2.1/G2.2 correlation engines (via G2.3's
    ``replay_fixture_through_correlation``, unchanged), enrich the resulting
    groups with the real, unmodified G2.4.3
    :func:`~attribution_platform.correlation.compute_temporal_proximity`,
    persist every new ``TEMPORAL_PROXIMITY`` link and every enriched group
    via G2.3's own persistence functions (unchanged), then reconstruct and
    persist one real ``BehavioralSequence`` per *enriched* group via the
    real, unmodified G2.4.1 ``construct_behavioral_sequence`` and G2.4.2
    ``persist_behavioral_sequence``.

    Every ``BehavioralSequence`` built is grounded only in its own,
    already-enriched ``CorrelationGroup``'s own material — this function
    never hand-authors a ``CorrelationLink``, ``CorrelationGroup``, or
    ``BehavioralSequence``, and never lets one group's Evidence or links
    leak into another group's sequence.
    """
    correlation_result = replay_fixture_through_correlation(
        fixture, client=client, engine=engine, knowledge=knowledge, adapter=adapter
    )

    items_by_evidence_id: dict[str, tuple[Evidence, Observation]] = {}
    items: list[tuple[Evidence, Observation]] = []
    for result in correlation_result.detection_results:
        for evidence in result.evidences:
            pair = (evidence, result.observation)
            items_by_evidence_id[evidence.evidence_id] = pair
            items.append(pair)

    temporal_proximity_result = compute_temporal_proximity(
        correlation_result.structural_result,
        correlation_result.contextual_result,
        items,
        config,
    )

    temporal_proximity_link_persists = tuple(
        persist_correlation_link(client, link)
        for link in temporal_proximity_result.temporal_proximity_links
    )
    group_persists = tuple(
        persist_correlation_group(client, group) for group in temporal_proximity_result.groups
    )

    structural_by_id: dict[str, CorrelationLink] = {
        link.link_id: link for link in correlation_result.structural_result.links
    }
    contextual_by_id: dict[str, CorrelationLink] = {
        link.link_id: link for link in correlation_result.contextual_result.contextual_links
    }
    for link in temporal_proximity_result.temporal_proximity_links:
        contextual_by_id[link.link_id] = link

    sequences: list[BehavioralSequence] = []
    sequence_persists: list[PersistResult] = []
    for group in temporal_proximity_result.groups:
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

    return TemporalProximityReplayResult(
        correlation_result=correlation_result,
        temporal_proximity_links=temporal_proximity_result.temporal_proximity_links,
        temporal_proximity_link_persists=temporal_proximity_link_persists,
        enriched_groups=temporal_proximity_result.groups,
        group_persists=group_persists,
        sequences=tuple(sequences),
        sequence_persists=tuple(sequence_persists),
    )
