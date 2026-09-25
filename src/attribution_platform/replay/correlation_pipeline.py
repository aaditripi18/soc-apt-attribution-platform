"""Replaying a raw-telemetry fixture through detection *and* correlation
(gate G2.3).

Target flow, built entirely on unmodified earlier gates:

    DetectionReplayFixture -> replay_fixture_through_detection_engine (G1.2)
    -> (Evidence, Observation) pairs -> correlate_structurally (G2.1)
    -> contextualize (G2.2) -> persist_correlation_link/persist_correlation_group (G2.3)

This module adds **no new normalization, detection, or correlation logic of
its own** — it is a thin orchestrator, exactly like G1.2's
``detection_pipeline`` is over G0.4/G0.5/G0.8/G1.0. Concretely:

1. **G1.2** — :func:`attribution_platform.replay.replay_fixture_through_detection_engine`
   runs, completely unchanged. Every ``(Evidence, Observation)`` pair this
   module correlates comes from that call's own
   ``DetectionReplayResult.evidences``/``.observation`` — this module never
   constructs a ``DetectionResult`` or ``Evidence`` itself (mirroring
   ``detection_pipeline.py``'s own no-fabrication guarantee, checked the same
   way: a guard test in ``tests/test_replay_correlation.py``).
2. **G2.1** — :func:`attribution_platform.correlation.correlate_structurally`
   runs, unchanged, over every pair collected in step 1.
3. **G2.2** — :func:`attribution_platform.correlation.contextualize` runs,
   unchanged, over the structural result from step 2 and the same pairs.
4. **G2.3** — every resulting ``CorrelationLink`` (structural and
   contextual) and every ``CorrelationGroup`` is persisted via
   :func:`attribution_platform.dataplane.persist_correlation_link`/
   :func:`~attribution_platform.dataplane.persist_correlation_group` — the
   new, additive G2.3 extension of G0.8's persistence pattern (no second
   persistence architecture; see that module's docstring).

Deterministic by construction, transitively: every function this module
calls is pure or idempotent-by-own-id (G1.2, G2.1, G2.2, and G0.8/G2.3
persistence all already guarantee this individually — see their own
docstrings). Replaying the same fixture against the same rule pack and
client twice is therefore idempotent: identical links, identical groups,
identical persisted documents.

Deliberately NOT here (forbidden this gate): a second replay or persistence
framework (G1.2's pipeline and G0.8/G2.3's persistence functions are reused
verbatim); ``BehavioralSequence``/temporal correlation (G2.4); ATT&CK-aware
correlation of any kind (structural.py/contextual.py remain ATT&CK-free;
this module never imports ``attack_knowledge`` for correlation purposes —
the ``AttackKnowledge`` it does take is passed straight through to G1.2's
detection replay, unchanged from that gate); attribution, scoring,
candidate generation, or confidence of any kind.
"""

from __future__ import annotations

from dataclasses import dataclass

from attribution_platform.attack_knowledge.loader import AttackKnowledge
from attribution_platform.correlation import (
    ContextualCorrelationResult,
    StructuralCorrelationResult,
    contextualize,
    correlate_structurally,
)
from attribution_platform.dataplane import (
    ElasticClient,
    PersistResult,
    persist_correlation_group,
    persist_correlation_link,
)
from attribution_platform.detection import DetectionEngine
from attribution_platform.domain import Evidence, Observation
from attribution_platform.replay.detection_fixtures import DetectionReplayFixture
from attribution_platform.replay.detection_pipeline import (
    DetectionReplayResult,
    replay_fixture_through_detection_engine,
)
from attribution_platform.sources.adapter import SourceAdapter


@dataclass(frozen=True)
class CorrelationReplayResult:
    """What replaying ``fixture`` through detection and correlation
    produced — for tests and for a future caller to report on.

    ``detection_results`` is G1.2's own unmodified return value (every
    Evidence correlated below came from here). ``structural_result``/
    ``contextual_result`` are G2.1/G2.2's own unmodified return values.
    ``link_persists``/``group_persists`` record where each correlation
    object was written, in the same order as
    ``contextual_result.contextual_links + structural_result.links`` is
    persisted (structural links, then contextual links, then groups) --
    see :func:`replay_fixture_through_correlation` for the exact order.
    """

    detection_results: tuple[DetectionReplayResult, ...]
    structural_result: StructuralCorrelationResult
    contextual_result: ContextualCorrelationResult
    link_persists: tuple[PersistResult, ...]
    group_persists: tuple[PersistResult, ...]


def replay_fixture_through_correlation(
    fixture: DetectionReplayFixture,
    *,
    client: ElasticClient,
    engine: DetectionEngine,
    knowledge: AttackKnowledge,
    adapter: SourceAdapter | None = None,
) -> CorrelationReplayResult:
    """Replay every scenario in ``fixture`` through the real G1.0
    ``DetectionEngine`` (via G1.2's ``replay_fixture_through_detection_engine``,
    unchanged), then through the real G2.1 structural and G2.2 contextual
    correlation engines (unchanged), then persist every resulting
    ``CorrelationLink``/``CorrelationGroup`` against ``client``.

    Every ``(Evidence, Observation)`` pair correlated is taken directly from
    the G1.2 replay's own output — this function never hand-authors a
    ``CorrelationGroup`` or a ``CorrelationLink``; both come entirely from
    calling the real G2.1/G2.2 engines against real replayed Evidence.
    """
    detection_results = replay_fixture_through_detection_engine(
        fixture, client=client, engine=engine, knowledge=knowledge, adapter=adapter
    )

    items: list[tuple[Evidence, Observation]] = []
    for result in detection_results:
        for evidence in result.evidences:
            items.append((evidence, result.observation))

    # Observations no rule fired on are still telemetry: they are passed as
    # witnesses only (ADR-0003 Amendment A7 -- e.g. a remote-thread event
    # attesting an injection between two instances that do carry Evidence).
    context_observations = tuple(r.observation for r in detection_results if not r.evidences)
    structural_result = correlate_structurally(items, context_observations=context_observations)
    contextual_result = contextualize(
        structural_result, items, context_observations=context_observations
    )

    link_persists = tuple(
        persist_correlation_link(client, link)
        for link in (*structural_result.links, *contextual_result.contextual_links)
    )
    group_persists = tuple(
        persist_correlation_group(client, group) for group in contextual_result.groups
    )

    return CorrelationReplayResult(
        detection_results=detection_results,
        structural_result=structural_result,
        contextual_result=contextual_result,
        link_persists=link_persists,
        group_persists=group_persists,
    )
