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
  ``persist_evidence`` (G0.8), in that order.
- **Not yet implemented:** a real telemetry-source adapter (Sysmon/Windows
  Event Log — a later gate); detection-rule content; ATT&CK candidate
  generation, correlation, attack-chain logic, or attribution; the
  read-model API (G0.10); live adversary emulation (never automated — see
  docs/architecture/12-deployment-and-endpoint-scope.md §J).
"""

from __future__ import annotations

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
]
