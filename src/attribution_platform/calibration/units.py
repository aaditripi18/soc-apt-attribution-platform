"""Attribution units of a corpus source, whatever its kind (doc 15 DC-3/DC-4).

A corpus family's telemetry comes either from a synthetic replay fixture (a
:class:`~attribution_platform.replay.DetectionReplayFixture`) or from a real
recording (a :class:`~attribution_platform.replay.recording_pipeline.RecordingSource`).
The corpus builder and the decision-input harness need the same three things
from either: the correlation groups, their behavioral sequences, and a way to
resolve an authored **anchor** to Observations —

- fixture: an anchor is a *scenario id* (its Observations);
- recording: an anchor is an *Observation id* (itself) — a specific telemetry
  record the author identified from the dataset's documented procedure.

A recording's analysis is expensive (a full pipeline over tens of thousands of
events), so it is computed once per (archive digest, engine, knowledge) in this
process and shared by the builder and the harness.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from attribution_platform.attack_knowledge.loader import AttackKnowledge
from attribution_platform.correlation import BehavioralSequence, CorrelationGroup
from attribution_platform.dataplane import ElasticClient
from attribution_platform.detection import DetectionEngine
from attribution_platform.replay import (
    DetectionReplayFixture,
    replay_fixture_through_behavioral_sequences,
)
from attribution_platform.replay.recording_pipeline import (
    RecordingAnalysis,
    RecordingSource,
    analyze_recording,
)

CorpusSource = DetectionReplayFixture | RecordingSource


@dataclass(frozen=True)
class UnitAnalysis:
    """What one corpus source replays to."""

    source_id: str
    groups: tuple[CorrelationGroup, ...]
    sequences: tuple[BehavioralSequence, ...]
    anchor_observations: Mapping[str, frozenset[str]]


_RECORDING_CACHE: dict[tuple[str, int, str], tuple[DetectionEngine, RecordingAnalysis]] = {}


def source_id(source: CorpusSource) -> str:
    return source.fixture_id if isinstance(source, DetectionReplayFixture) else source.recording_id


def analyze_recording_cached(
    source: RecordingSource, *, engine: DetectionEngine, knowledge: AttackKnowledge
) -> RecordingAnalysis:
    """:func:`analyze_recording`, once per (digest, engine, knowledge) here."""
    key = (source.sha256, id(engine), knowledge.attack_kb_version)
    hit = _RECORDING_CACHE.get(key)
    if hit is not None and hit[0] is engine:
        return hit[1]
    analysis = analyze_recording(source, engine=engine, knowledge=knowledge)
    _RECORDING_CACHE[key] = (engine, analysis)  # the engine is held so its id stays unique
    return analysis


def analyze_source(
    source: CorpusSource,
    *,
    client: ElasticClient,
    engine: DetectionEngine,
    knowledge: AttackKnowledge,
) -> UnitAnalysis:
    """The attribution units ``source`` produces (module docstring)."""
    if isinstance(source, DetectionReplayFixture):
        result = replay_fixture_through_behavioral_sequences(
            source, client=client, engine=engine, knowledge=knowledge
        )
        anchors: dict[str, set[str]] = {}
        for detection in result.correlation_result.detection_results:
            anchors.setdefault(detection.scenario_id, set()).add(
                detection.observation.observation_id
            )
        return UnitAnalysis(
            source_id=source.fixture_id,
            groups=result.correlation_result.contextual_result.groups,
            sequences=result.sequences,
            anchor_observations={k: frozenset(v) for k, v in anchors.items()},
        )
    analysis = analyze_recording_cached(source, engine=engine, knowledge=knowledge)
    observation_ids = {observation.observation_id for _, observation in analysis.items.values()}
    return UnitAnalysis(
        source_id=source.recording_id,
        groups=analysis.groups,
        sequences=analysis.sequences,
        anchor_observations={oid: frozenset({oid}) for oid in observation_ids},
    )


__all__ = [
    "CorpusSource",
    "UnitAnalysis",
    "analyze_recording_cached",
    "analyze_source",
    "source_id",
]
