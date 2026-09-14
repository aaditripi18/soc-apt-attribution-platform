"""Deterministic detection: Observation -> DetectionResult -> Evidence (gate G1.0).

Phase 1's first gate. Fills the one gap Phase 0 deliberately left open
(``extraction``'s own docstring: "no real detection engine" — G0.5/G0.6 took
a caller-supplied ``rule_ref``/``attack_ref`` on faith): this package is the
logic that actually *decides* a detection fired and *why*, and maps that
decision to a pinned-KB-validated ATT&CK technique — nothing upstream or
downstream changes to accommodate it.

Source-agnostic and Elastic-free: this package depends only on ``domain``,
``extraction`` (reuses ``RuleRef`` and ``derive_evidence`` unchanged), and
``attack_knowledge`` (reuses ``resolve_attack_ref`` unchanged) — never on
``sources``, ``dataplane``, ``replay``, or ``api``. Sysmon (or any other
source) never appears here: a rule references only the G0.3 ECS-aligned
Observation fields, so the same rule pack applies unchanged no matter which
adapter produced the Observations it evaluates.

Gate status:

- **G1.0 (implemented):** ``errors`` — ``DetectionError``; ``contracts`` —
  ``MatchedField``/``MatchBasis`` (the *why*), ``TechniqueMapping`` (a single
  validated rule-to-technique link, kept structurally distinct from
  ``DetectionResult.rule_ref``), ``DetectionResult`` (one rule firing against
  one supporting Observation — strictly single-Observation scope);
  ``rules`` — ``FieldCondition``/``DetectionRule`` (deterministic, data-only
  predicates — no ML), ``RulePack``/``load_rule_pack()`` (a content-hashed
  JSON rule pack, every technique mapping validated against the pinned KB at
  load time), ``DetectionEngine.evaluate()`` (pure, KB-free rule evaluation);
  ``evidence`` — ``derive_evidence_from_detection()``, a thin fan-out into
  the existing, unmodified G0.6 ``derive_evidence()`` (one Evidence per
  technique mapping, or one unmapped).
- **G1.1 (implemented, elsewhere):** an Elastic Detection Engine alert
  adapter now exists — see
  :mod:`attribution_platform.elastic_detections` — normalizing an Elastic
  alert into the exact same ``DetectionResult`` this package defines. This
  package itself is untouched: the adapter depends on ``detection``, never
  the reverse (a guard test enforces this).
- **Not yet implemented:** multi-Observation/sequence rules (Phase 2
  correlation); a Sysmon/Windows-specific detection path (none is needed —
  rules are source-agnostic by construction); any attribution, candidate
  generation, scoring, or attack-chain logic (out of scope for the entire
  detection layer, not just this gate).
"""

from __future__ import annotations

from attribution_platform.detection.contracts import (
    DETECTION_RESULT_SCHEMA_VERSION,
    MATCH_OPERATORS,
    DetectionResult,
    MatchBasis,
    MatchedField,
    TechniqueMapping,
)
from attribution_platform.detection.errors import DetectionError
from attribution_platform.detection.evidence import derive_evidence_from_detection
from attribution_platform.detection.rules import (
    DetectionEngine,
    DetectionRule,
    FieldCondition,
    RulePack,
    load_rule_pack,
)

__all__ = [
    "DetectionError",
    "MatchedField",
    "MatchBasis",
    "TechniqueMapping",
    "DetectionResult",
    "DETECTION_RESULT_SCHEMA_VERSION",
    "MATCH_OPERATORS",
    "FieldCondition",
    "DetectionRule",
    "RulePack",
    "load_rule_pack",
    "DetectionEngine",
    "derive_evidence_from_detection",
]
