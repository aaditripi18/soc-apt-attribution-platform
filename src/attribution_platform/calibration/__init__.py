"""Calibration corpus & versioning layer (Phase 3 prerequisite B1,
ADR-0006 — docs/architecture/adr/0006-calibration-corpus-and-versioning.md).

Per accepted ADR-0006 this package is the **corpus / schema / versioning**
foundation the later parameter-fitting gate builds on. It exists to make a
trustworthy, versioned, leakage-controlled calibration corpus possible — it
does **not** itself fit any parameter, choose any numeric threshold, or
produce a ``calibration_version``.

This package deliberately performs **none** of the following, and depends on
none of them at this stage: attribution scoring, likelihood, confidence,
ranking, abstention, a combined score (ADR-0005 Amendment B is frozen and only
referenced, never re-decided); ``g(x)``/``D(x)`` or any change to ATT&CK
relationships/aliases/candidate universe; ATT&CK knowledge traversal, Elastic,
the replay pipeline, correlation, or telemetry ingestion. It reuses the
existing deterministic-serialization convention
(:func:`attribution_platform.domain.serialization.to_canonical_json`) and the
existing SHA-256 / ``content_hash`` conventions rather than introducing a new
hashing algorithm or serialization format.

Gate status:

- **B1.1 (implemented):** ``errors`` —
  :class:`~attribution_platform.calibration.errors.CalibrationError`, the
  per-layer fail-closed error, plus this importable package foundation.
  Following the nearest-sibling convention (``attribution``/``correlation``),
  the layer-local deterministic helpers (``_sha256_hex`` / ``_require_*`` /
  ``_canonical_tuple``) are **inlined per contracts module** rather than placed
  in a shared helpers module.
- **B1.2 (implemented — this gate):** ``contracts`` — the frozen
  :class:`~attribution_platform.calibration.contracts.CalibrationCase` and its
  value objects/enums (:class:`~attribution_platform.calibration.contracts.GroundTruth`,
  :class:`~attribution_platform.calibration.contracts.ExpectedOutputShape`,
  :class:`~attribution_platform.calibration.contracts.SourceKind`,
  :class:`~attribution_platform.calibration.contracts.ActorLabelSource`,
  :class:`~attribution_platform.calibration.contracts.LabelSemantics`,
  :class:`~attribution_platform.calibration.contracts.LabelConfidence`,
  :class:`~attribution_platform.calibration.contracts.CaseRole`,
  :class:`~attribution_platform.calibration.contracts.ExpectedOutcome`), plus
  the deterministic-id function
  :func:`~attribution_platform.calibration.contracts.compute_calibration_case_id`.
  **Contract only** — no corpus, no versioning, no scoring.
- **B1.3+ (deferred, not implemented):** the corpus manifest and
  ``calibration_corpus_version``; scenario-family split / leakage validation;
  provenance / license validation; the read-only corpus validation harness. No
  corpus data, no manifest, no ``calibration_version``, and no fitting exist yet.
"""

from __future__ import annotations

from attribution_platform.calibration.contracts import (
    CALIBRATION_CASE_SCHEMA_VERSION,
    CASE_ID_INPUT_FIELDS,
    ActorLabelSource,
    CalibrationCase,
    CaseRole,
    ExpectedOutcome,
    ExpectedOutputShape,
    GroundTruth,
    LabelConfidence,
    LabelSemantics,
    SourceKind,
    compute_calibration_case_id,
)
from attribution_platform.calibration.errors import CalibrationError

__all__ = [
    "CalibrationError",
    "CalibrationCase",
    "GroundTruth",
    "ExpectedOutputShape",
    "SourceKind",
    "ActorLabelSource",
    "LabelSemantics",
    "LabelConfidence",
    "CaseRole",
    "ExpectedOutcome",
    "compute_calibration_case_id",
    "CALIBRATION_CASE_SCHEMA_VERSION",
    "CASE_ID_INPUT_FIELDS",
]
