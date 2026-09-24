"""Replaying raw-telemetry fixture scenarios through the real G1.0
DetectionEngine (gate G1.2).

Target flow (unchanged from the accepted G1.2 requirement):

    synthetic fixture -> SourceAdapter -> Observation -> DetectionEngine ->
    DetectionResult -> derive_evidence_from_detection -> Evidence

Like G0.9's :mod:`attribution_platform.replay.pipeline`, this module adds
**no new normalization or derivation logic of its own** — it is a thin
orchestrator over functions earlier gates already built:

1. **G0.4** — :func:`attribution_platform.sources.adapter.convert` with the
   unmodified :class:`~attribution_platform.sources.synthetic.SyntheticSourceAdapter`
   turns the scenario's raw record into an ``Observation``. Identical hop to
   G0.9's.
2. **G0.5** — exactly as G0.9's ``pipeline.py`` explains for its own
   ``dataset_ref``-stamping ("why the G0.5 hop, not just the G0.4 Observation
   directly"): the G0.4-stage Observation is sparse (the reference synthetic
   adapter carries no entity data — see that module's docstring), so the
   canonical Observation is re-derived via
   :func:`attribution_platform.extraction.extract_observations`, which both
   stamps ``fixture.dataset_ref`` into provenance *and* attaches this
   scenario's entity data (``process``/``event``/...) — the fields the real
   rule engine actually evaluates. The ``RuleRef`` this hop requires is a
   fixed, documented placeholder (see :data:`_RAW_TELEMETRY_RULE_REF`
   below): per the G0.5 contract's own docstring, it is "not consumed into
   Observations" — used only for extractor error-message context — so using
   a placeholder here fabricates nothing that reaches any output.
3. **G0.8** — the canonical Observation is persisted
   (:func:`attribution_platform.dataplane.persist_observation`), exactly as
   G0.9 does.
4. **G1.0** — the canonical Observation is evaluated by the caller-supplied,
   real :class:`~attribution_platform.detection.DetectionEngine` (loaded, in
   the ordinary case, from the existing ``fixtures/phase1_core_rules.json``
   rule pack via :func:`attribution_platform.detection.load_rule_pack`) —
   **this is the one thing that fundamentally distinguishes this module from
   G0.9's**: no fixture field anywhere asserts a rule id or ATT&CK mapping;
   whether anything fires, and what it maps to, is a fact the engine
   determines from the Observation's actual field values, never trusted or
   pre-declared by fixture content. A non-matching Observation legitimately
   produces zero ``DetectionResult``s.
5. **G1.0** — each ``DetectionResult`` the engine returns is fanned out into
   Evidence via the existing, unmodified
   :func:`attribution_platform.detection.derive_evidence_from_detection` —
   the exact same function gate G1.1's Elastic adapter feeds into. This
   module does not construct a ``DetectionResult`` or ``Evidence`` directly
   anywhere (enforced by a guard test — see
   ``tests/test_replay_detection.py``): every one that exists came from the
   real engine and the real evidence-derivation fan-out.
6. **G0.8** — each derived Evidence is persisted
   (:func:`attribution_platform.dataplane.persist_evidence`), exactly as
   G0.9 does. No DetectionResult persistence is introduced — none exists
   anywhere yet (G1.0/G1.1 never added one), and inventing one here would be
   new persistence architecture this gate does not call for; a
   ``DetectionResult`` is an in-memory intermediate, returned to the caller
   on :class:`DetectionReplayResult` for inspection, exactly as it already is
   in the G1.0/G1.1 flow.

Deterministic by construction, transitively: :meth:`DetectionEngine.evaluate`
and :func:`derive_evidence_from_detection` are pure, and every id/timestamp
here still comes from the fixture or the rule pack's own content hash, never
generated. Replaying the same fixture against the same rule pack twice into
one client is idempotent (``persist_observation``/``persist_evidence`` key
by the domain object's own id — see :mod:`attribution_platform.dataplane.persistence`)
and, across independent runs, byte-for-byte reproducible.

Deliberately NOT here (forbidden this gate): Elastic Detection Engine
integration (unchanged from G1.1), correlation/multi-event detection,
attribution/candidate-generation/scoring, Sigma, any Sysmon-specific logic,
API/frontend work, and no G0.9 ``pipeline.py``/``fixtures.py`` behavior is
touched — that module still replays its own fixture format completely
unchanged.
"""

from __future__ import annotations

from dataclasses import dataclass

from attribution_platform.attack_knowledge.loader import AttackKnowledge
from attribution_platform.dataplane import (
    ElasticClient,
    PersistResult,
    persist_evidence,
    persist_observation,
)
from attribution_platform.detection import (
    DetectionEngine,
    DetectionResult,
    derive_evidence_from_detection,
)
from attribution_platform.domain import Evidence, Observation, SourceRef
from attribution_platform.extraction import DetectionMatchRecord, MatchedEvent, extract_observations
from attribution_platform.extraction.detection_match import RuleRef
from attribution_platform.replay.detection_fixtures import (
    DetectionReplayFixture,
    DetectionReplayScenario,
)
from attribution_platform.sources.adapter import SourceAdapter, convert
from attribution_platform.sources.synthetic import SyntheticSourceAdapter

#: Structural placeholder for the G0.5 ``DetectionMatchRecord.rule_ref`` this
#: hop requires. Never fabricated data: the G0.5 contract's own docstring
#: states this field is "not consumed into Observations" (used only for
#: extractor error-message context) -- which rule, if any, actually matched
#: is decided afterward by the real DetectionEngine and carried on
#: ``DetectionResult.rule_ref`` instead. This constant never reaches any
#: Observation, DetectionResult, or Evidence field.
_RAW_TELEMETRY_RULE_REF = RuleRef(rule_id="replay-raw-telemetry", rule_version="n/a")


@dataclass(frozen=True)
class DetectionReplayResult:
    """What replaying one raw-telemetry scenario through the real
    DetectionEngine produced — for tests and for a future caller to report
    on, not a new persisted object. ``detections``/``evidences`` may
    legitimately be empty (a non-matching Observation)."""

    scenario_id: str
    observation: Observation
    observation_persist: PersistResult
    detections: tuple[DetectionResult, ...]
    evidences: tuple[Evidence, ...]
    evidence_persists: tuple[PersistResult, ...]


def replay_fixture_through_detection_engine(
    fixture: DetectionReplayFixture,
    *,
    client: ElasticClient,
    engine: DetectionEngine,
    knowledge: AttackKnowledge,
    adapter: SourceAdapter | None = None,
) -> tuple[DetectionReplayResult, ...]:
    """Replay every scenario in ``fixture``, in file order, through
    ``engine`` (a real :class:`~attribution_platform.detection.DetectionEngine`,
    typically built from :func:`attribution_platform.detection.load_rule_pack`
    against ``fixtures/phase1_core_rules.json``) and persist the results
    against ``client``.

    ``knowledge`` is required (not optional): it is the pinned ATT&CK KB
    :func:`~attribution_platform.detection.derive_evidence_from_detection`
    validates every technique mapping against — the same requirement that
    function already enforces, not duplicated here. ``adapter`` defaults to
    the reference :class:`SyntheticSourceAdapter`; a parameter exists only so
    a test can substitute a probe/fake without patching a module global,
    exactly like G0.9's ``replay_fixture``.
    """
    source_adapter = adapter if adapter is not None else SyntheticSourceAdapter()
    return tuple(
        _replay_scenario_through_engine(
            scenario,
            fixture=fixture,
            client=client,
            engine=engine,
            knowledge=knowledge,
            adapter=source_adapter,
        )
        for scenario in fixture.scenarios
    )


def _replay_scenario_through_engine(
    scenario: DetectionReplayScenario,
    *,
    fixture: DetectionReplayFixture,
    client: ElasticClient,
    engine: DetectionEngine,
    knowledge: AttackKnowledge,
    adapter: SourceAdapter,
) -> DetectionReplayResult:
    # 1. G0.4: raw record -> Observation via the SourceAdapter boundary.
    (adapter_observation,) = convert(adapter, scenario.raw_record)

    # 2. G0.5: re-derive the canonical Observation, stamping dataset
    #    provenance and attaching this scenario's entity data (see module
    #    docstring). rule_ref here is a non-consumed structural placeholder.
    matched_event = MatchedEvent(
        observation_id=adapter_observation.observation_id,
        source_ref=SourceRef(
            source_type=adapter_observation.raw_reference.source_type,
            source_event_id=adapter_observation.raw_reference.source_event_id,
            dataset_ref=fixture.dataset_ref,
        ),
        timestamp=adapter_observation.timestamp,
        timestamp_precision=adapter_observation.timestamp_precision,
        event=scenario.event,
        host=scenario.host,
        user=scenario.user,
        process=scenario.process,
        network=scenario.network,
        file=scenario.file,
        dll=scenario.dll,
        registry=scenario.registry,
    )
    record = DetectionMatchRecord(rule_ref=_RAW_TELEMETRY_RULE_REF, matched_events=(matched_event,))
    (observation,) = extract_observations(record)

    # 3. G0.8: persist the canonical Observation.
    observation_persist = persist_observation(client, observation)

    # 4. G1.0: the real DetectionEngine decides whether/which rule(s) fire.
    #    Zero, one, or several DetectionResults may come back for one
    #    Observation -- never asserted by the fixture.
    detections = engine.evaluate([observation])

    # 5-6. G1.0's existing fan-out + G0.8 persistence, per DetectionResult.
    evidences: list[Evidence] = []
    evidence_persists: list[PersistResult] = []
    for detection in detections:
        for evidence in derive_evidence_from_detection(detection, observation, knowledge=knowledge):
            evidences.append(evidence)
            evidence_persists.append(persist_evidence(client, evidence))

    return DetectionReplayResult(
        scenario_id=scenario.scenario_id,
        observation=observation,
        observation_persist=observation_persist,
        detections=detections,
        evidences=tuple(evidences),
        evidence_persists=tuple(evidence_persists),
    )
