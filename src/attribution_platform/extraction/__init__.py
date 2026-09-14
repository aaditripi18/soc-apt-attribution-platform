"""Detection-match record -> Observation extraction boundary.

Per docs/architecture/04-component-boundaries.md and
docs/architecture/06-evidence-model.md: turns a detection match (rule id,
matched fields, entities, source event references) into provenance-carrying
normalized ``Observation`` objects. Deterministic and source-agnostic — it
consumes the generic detection-match record contract and the G0.3 domain
types, and knows nothing about where the telemetry originated.

Gate status:

- **G0.5 (implemented):** the ``DetectionMatchRecord`` contract
  (``RuleRef`` + ``MatchedEvent``s + optional ``matched_fields``) and
  ``extract_observations()`` — the deterministic, fail-closed function
  producing one ``Observation`` per matched event with intact
  ``SourceRef`` provenance.
- **G0.6 (implemented):** ``derive_evidence()`` — deterministic
  ``Observation`` + rule-context -> ``Evidence`` derivation, with optional
  ATT&CK-technique linkage validated against the pinned KB. No standalone
  ``TechniqueAssertion`` object (the ATT&CK link is the G0.3 ``AttackRef`` on
  ``Evidence``); no scoring/likelihood/confidence/attribution.
- **Not yet implemented (later gates):** correlation, attack chains,
  candidate generation, attribution, Elastic. A real detection *engine* now
  exists — see ``attribution_platform.detection`` (gate G1.0) — but it
  consumes this package's ``derive_evidence()`` unchanged rather than
  replacing anything here.
"""

from __future__ import annotations

from attribution_platform.extraction.detection_match import (
    DetectionMatchRecord,
    MatchedEvent,
    RuleRef,
)
from attribution_platform.extraction.errors import ExtractionError
from attribution_platform.extraction.evidence_derivation import (
    EvidenceDerivationError,
    derive_evidence,
)
from attribution_platform.extraction.extractor import extract_observations

__all__ = [
    "DetectionMatchRecord",
    "MatchedEvent",
    "RuleRef",
    "ExtractionError",
    "extract_observations",
    "EvidenceDerivationError",
    "derive_evidence",
]
