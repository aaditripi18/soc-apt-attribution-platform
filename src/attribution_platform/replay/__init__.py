"""Synthetic/replay ingestion: hand-authored fixtures through the same
source-agnostic pipeline a real telemetry source will use (gate G0.9).

Per docs/architecture/03-system-data-flow.md ("live and replay modes
converge immediately after ingestion") and
docs/architecture/12-deployment-and-endpoint-scope.md §G (synthetic
telemetry is the primary mode for tests/validation/calibration because it is
deterministic and reproducible): this package adds **no new normalization or
derivation logic**. It only loads a small hand-authored fixture file and
drives it through the pipeline functions G0.4-G0.8 already defined — the
same functions a real Sysmon/Windows adapter (a later gate) will call.

Gate status:

- **G0.9 (implemented):** ``errors`` — ``ReplayError`` for malformed
  fixtures; ``fixtures`` — ``load_fixture_file()``, parsing a small,
  specific JSON fixture format (documented in that module and in
  ``fixtures/README.md`` at the repo root) into typed scenarios, with a
  SHA-256 content hash for deterministic dataset provenance; ``pipeline`` —
  ``replay_fixture()``, which pushes each scenario through
  ``SourceAdapter`` (G0.4) -> ``extract_observations`` (G0.5) ->
  ``persist_observation`` (G0.8) -> ``derive_evidence`` (G0.6) ->
  ``persist_evidence`` (G0.8), in that order. Each scenario *asserts* its own
  Evidence (an "externally produced detection" fixture) — see G1.2 below for
  why this stays completely unchanged rather than being extended.
- **G1.2 (implemented):** ``detection_fixtures`` — ``load_detection_replay_fixture_file()``,
  a second, deliberately separate small JSON fixture format carrying only raw
  telemetry (no rule/evidence assertion at all — see that module's
  docstring for why this is a distinct type from G0.9's ``Fixture``, not an
  extension of it); ``detection_pipeline`` — ``replay_fixture_through_detection_engine()``,
  which pushes each scenario through ``SourceAdapter`` (G0.4) ->
  ``extract_observations`` (G0.5) -> ``persist_observation`` (G0.8) -> the
  real G1.0 ``DetectionEngine`` -> ``derive_evidence_from_detection`` (G1.0) ->
  ``persist_evidence`` (G0.8). This is the "derived-detection replay" path:
  no fixture field anywhere asserts a rule id or ATT&CK mapping — the engine
  decides. G0.9's ``fixtures``/``pipeline`` modules are untouched by this
  gate.
- **G2.3 (implemented):** ``correlation_pipeline`` —
  ``replay_fixture_through_correlation()``, which reuses G1.2's
  ``replay_fixture_through_detection_engine`` unchanged to obtain
  ``(Evidence, Observation)`` pairs, feeds them through the real G2.1
  ``correlate_structurally`` and G2.2 ``contextualize`` engines (unchanged),
  and persists every resulting ``CorrelationLink``/``CorrelationGroup`` via
  the new G2.3 ``dataplane.persist_correlation_link``/
  ``persist_correlation_group``. This module hand-authors no
  ``CorrelationGroup``/``CorrelationLink`` and no ``DetectionResult``/
  ``Evidence`` — every one comes from calling the real, unmodified engines.
- **Not yet implemented:** replaying a real telemetry-source adapter's
  output through this package (the Sysmon adapter itself was added at
  G0.11, but reads live/real telemetry, not fixtures — unrelated to and
  untouched by this package); ``BehavioralSequence``/temporal correlation
  (G2.4); ATT&CK-aware correlation, attack-chain logic, or attribution; the
  read-model API (G0.10); live adversary emulation (never automated — see
  docs/architecture/12-deployment-and-endpoint-scope.md §J).
"""

from __future__ import annotations

from attribution_platform.replay.correlation_pipeline import (
    CorrelationReplayResult,
    replay_fixture_through_correlation,
)
from attribution_platform.replay.detection_fixtures import (
    DetectionReplayFixture,
    DetectionReplayScenario,
    load_detection_replay_fixture_file,
)
from attribution_platform.replay.detection_pipeline import (
    DetectionReplayResult,
    replay_fixture_through_detection_engine,
)
from attribution_platform.replay.errors import ReplayError
from attribution_platform.replay.fixtures import (
    EvidenceSpec,
    Fixture,
    ReplayScenario,
    load_fixture_file,
)
from attribution_platform.replay.pipeline import ScenarioResult, replay_fixture

__all__ = [
    "ReplayError",
    "Fixture",
    "ReplayScenario",
    "EvidenceSpec",
    "load_fixture_file",
    "ScenarioResult",
    "replay_fixture",
    "DetectionReplayFixture",
    "DetectionReplayScenario",
    "load_detection_replay_fixture_file",
    "DetectionReplayResult",
    "replay_fixture_through_detection_engine",
    "CorrelationReplayResult",
    "replay_fixture_through_correlation",
]
