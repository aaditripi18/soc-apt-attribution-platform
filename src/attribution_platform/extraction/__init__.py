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
- **Not yet implemented (later gates):** technique mapping / ATT&CK matching,
  Evidence creation (G0.6), correlation, any real detection engine, Elastic.
"""

from __future__ import annotations

from attribution_platform.extraction.detection_match import (
    DetectionMatchRecord,
    MatchedEvent,
    RuleRef,
)
from attribution_platform.extraction.errors import ExtractionError
from attribution_platform.extraction.extractor import extract_observations

__all__ = [
    "DetectionMatchRecord",
    "MatchedEvent",
    "RuleRef",
    "ExtractionError",
    "extract_observations",
]
