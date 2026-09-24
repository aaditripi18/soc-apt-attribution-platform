"""Replaying a loaded fixture's scenarios through the existing pipeline
(gate G0.9).

Per doc 13 G0.9's objective ("hand-authored synthetic fixtures -> the
identical downstream pipeline") and docs/architecture/03-system-data-flow.md
("live and replay modes converge immediately after ingestion"): this module
adds **no new normalization or derivation logic**. Each scenario is pushed
through exactly the functions earlier gates already built, in the order
those gates defined:

1. **G0.4** — :func:`attribution_platform.sources.adapter.convert` with the
   unmodified :class:`~attribution_platform.sources.synthetic.SyntheticSourceAdapter`
   turns the scenario's raw record into an ``Observation``. This is the
   literal "raw record -> SourceAdapter -> Observation" hop.
2. **G0.5** — that Observation's own fields are re-expressed as one
   :class:`~attribution_platform.extraction.detection_match.MatchedEvent`
   under the scenario's :class:`~attribution_platform.extraction.detection_match.RuleRef`,
   and :func:`attribution_platform.extraction.extract_observations` produces
   the canonical ``Observation`` that is actually persisted and carried
   forward. Doing this (rather than persisting the G0.4-stage Observation
   directly) exercises the *other* Observation-producing boundary this gate
   was told to use, and is where the fixture's dataset content-hash is
   stamped into provenance — see the module-level note below.
3. **G0.8** — the canonical Observation is persisted
   (:func:`attribution_platform.dataplane.persist_observation`).
4. **G0.6** — :func:`attribution_platform.extraction.derive_evidence` derives
   the scenario's Evidence from that Observation (+ its ``RuleRef`` +
   optional ``AttackRef``, validated against the loaded KB exactly as G0.6
   defined).
5. **G0.8** — the Evidence is persisted
   (:func:`attribution_platform.dataplane.persist_evidence`).

**Why the G0.5 hop, not just the G0.4 Observation directly:** G0.4's
``SyntheticSourceAdapter`` is deliberately sparse (no ``dataset_ref`` on the
``SourceRef`` it builds — see that module's docstring) and this gate must
record the fixture's content-hash as replay-dataset provenance. Rather than
modifying the unmodified G0.4 adapter (forbidden — G0.1-G0.8 behavior must
not change), the G0.5 extraction boundary is used to reconstruct the same
Observation content with an enriched ``SourceRef`` (same ``source_type``,
same ``source_event_id``, ``dataset_ref`` added). This uses two real,
already-accepted seams for what they are for, rather than inventing a third.

Nothing here fabricates an id, a timestamp, or a value not present in the
fixture — every field placed on an ``Observation``/``Evidence`` traces back
to something the fixture (or the pipeline functions it calls) supplied.
Fail-closed: a well-formed fixture that a pipeline stage rejects (e.g. an
``attack_ref`` absent from the loaded KB) raises that stage's own existing
typed error — nothing here swallows or re-wraps it.

Deliberately NOT here (forbidden this gate): a real Sysmon/Windows adapter,
detection-rule content, ATT&CK candidate generation, correlation,
attack-chain logic, attribution, API work, or live adversary emulation.
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
from attribution_platform.domain import Evidence, Observation, SourceRef
from attribution_platform.extraction import (
    DetectionMatchRecord,
    MatchedEvent,
    derive_evidence,
    extract_observations,
)
from attribution_platform.replay.fixtures import Fixture, ReplayScenario
from attribution_platform.sources.adapter import SourceAdapter, convert
from attribution_platform.sources.synthetic import SyntheticSourceAdapter


@dataclass(frozen=True)
class ScenarioResult:
    """What replaying one fixture scenario produced — for tests and for a
    future caller (e.g. a CLI) to report on, not a new persisted object."""

    scenario_id: str
    observation: Observation
    evidence: Evidence
    observation_persist: PersistResult
    evidence_persist: PersistResult


def replay_fixture(
    fixture: Fixture,
    *,
    client: ElasticClient,
    knowledge: AttackKnowledge | None = None,
    adapter: SourceAdapter | None = None,
) -> tuple[ScenarioResult, ...]:
    """Replay every scenario in ``fixture``, in file order, against ``client``.

    ``knowledge`` is required only if some scenario's Evidence declares an
    ``attack_ref`` (the same requirement :func:`derive_evidence` already
    enforces — this function does not duplicate that check). ``adapter``
    defaults to the reference :class:`SyntheticSourceAdapter`; a parameter
    exists only so a test can substitute a probe/fake without patching a
    module global.
    """
    source_adapter = adapter if adapter is not None else SyntheticSourceAdapter()
    return tuple(
        _replay_scenario(
            scenario, fixture=fixture, client=client, knowledge=knowledge, adapter=source_adapter
        )
        for scenario in fixture.scenarios
    )


def _replay_scenario(
    scenario: ReplayScenario,
    *,
    fixture: Fixture,
    client: ElasticClient,
    knowledge: AttackKnowledge | None,
    adapter: SourceAdapter,
) -> ScenarioResult:
    # 1. G0.4: raw record -> Observation via the SourceAdapter boundary.
    adapter_observations = convert(adapter, scenario.raw_record)

    # 2. G0.5: re-derive the canonical Observation via the detection-match
    #    extraction boundary, stamping the fixture's content-hash into
    #    provenance (see module docstring for why).
    matched_events = tuple(
        MatchedEvent(
            observation_id=obs.observation_id,
            source_ref=SourceRef(
                source_type=obs.raw_reference.source_type,
                source_event_id=obs.raw_reference.source_event_id,
                dataset_ref=fixture.dataset_ref,
            ),
            timestamp=obs.timestamp,
            timestamp_precision=obs.timestamp_precision,
            event=obs.event,
            host=obs.host,
            user=obs.user,
            process=obs.process,
            network=obs.network,
            file=obs.file,
            dll=obs.dll,
            registry=obs.registry,
        )
        for obs in adapter_observations
    )
    record = DetectionMatchRecord(rule_ref=scenario.rule_ref, matched_events=matched_events)
    observations = extract_observations(record)

    # 3. G0.8: persist the canonical Observation(s). This fixture format
    #    always produces exactly one per scenario.
    (observation,) = observations
    observation_persist = persist_observation(client, observation)

    # 4. G0.6: derive Evidence from it.
    evidence = derive_evidence(
        evidence_id=scenario.evidence_spec.evidence_id,
        evidence_type=scenario.evidence_spec.evidence_type,
        claim=scenario.evidence_spec.claim,
        observations=observations,
        rule_ref=scenario.rule_ref,
        attack_ref=scenario.evidence_spec.attack_ref,
        knowledge=knowledge,
    )

    # 5. G0.8: persist the Evidence.
    evidence_persist = persist_evidence(client, evidence)

    return ScenarioResult(
        scenario_id=scenario.scenario_id,
        observation=observation,
        evidence=evidence,
        observation_persist=observation_persist,
        evidence_persist=evidence_persist,
    )
