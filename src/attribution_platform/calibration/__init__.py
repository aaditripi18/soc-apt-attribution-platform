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
- **B1.3 (implemented — this gate):** ``manifest`` — the frozen
  :class:`~attribution_platform.calibration.manifest.CalibrationCorpusManifest`
  and its entries
  (:class:`~attribution_platform.calibration.manifest.CorpusCaseEntry`,
  :class:`~attribution_platform.calibration.manifest.CorpusSourceEntry`), plus
  the deterministic corpus identity
  :func:`~attribution_platform.calibration.manifest.compute_calibration_corpus_version`.
  **Corpus identity only** — this gate creates ``calibration_corpus_version``
  and **no** ``calibration_version``, **no** fitting, **no** split/leakage
  validation, **no** scoring.
- **B1.4 (implemented — this gate):** ``split_validation`` — the read-only
  :func:`~attribution_platform.calibration.split_validation.validate_split`
  (and :func:`~attribution_platform.calibration.split_validation.require_valid_split`)
  producing a deterministic
  :class:`~attribution_platform.calibration.split_validation.SplitValidationReport`
  of :class:`~attribution_platform.calibration.split_validation.SplitValidationViolation`
  objects (:class:`~attribution_platform.calibration.split_validation.SplitViolationType`).
  Enforces scenario-family -> single-role disjointness and blind-actor-holdout
  readiness (§D9/§D10). **Read-only, no ATT&CK, no ablation, no fitting, no
  ``calibration_version``.**
- **B1.5 (implemented — this gate):** ``provenance_validation`` — the read-only
  :func:`~attribution_platform.calibration.provenance_validation.validate_provenance`
  (and :func:`~attribution_platform.calibration.provenance_validation.require_valid_provenance`)
  producing a deterministic
  :class:`~attribution_platform.calibration.provenance_validation.ProvenanceValidationReport`
  of ``ProvenanceValidationViolation`` objects (``ProvenanceViolationType``).
  Validates, over the manifest alone, the correctness layer above B1.3: SPDX
  license membership (``SPDX_LICENSE_ALLOWLIST``), orphan-source detection, and
  structural provenance adequacy (§D13/§D15).
  **Read-only, manifest-only, no ATT&CK, no network, no redistribution field, no
  ``calibration_version``.**
- **B1.6 (implemented — this gate):** ``composition`` — the read-only,
  descriptive
  :func:`~attribution_platform.calibration.composition.describe_corpus_composition`
  producing a deterministic
  :class:`~attribution_platform.calibration.composition.CorpusCompositionReport`
  of raw, canonically-sorted counts over ``(manifest, cases)``. **Descriptive
  only — no ``is_valid``, no violations, no pass/fail, no score/ratio/
  concentration/threshold, no ATT&CK, no new identity, no
  ``calibration_version``.**
- **B1.7+ (deferred, not implemented):** the later blind-actor ATT&CK
  identity-ablation evaluation; and — much later — parameter fitting and
  ``calibration_version``. No ``calibration_version`` and no fitting exist yet.
"""

from __future__ import annotations

from attribution_platform.calibration.composition import (
    COMPOSITION_SCHEMA_VERSION,
    CorpusCompositionReport,
    describe_corpus_composition,
)
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
from attribution_platform.calibration.manifest import (
    CALIBRATION_CORPUS_VERSION_PREFIX,
    CALIBRATION_MANIFEST_SCHEMA_VERSION,
    CORPUS_VERSION_INPUT_FIELDS,
    CalibrationCorpusManifest,
    CorpusCaseEntry,
    CorpusSourceEntry,
    compute_calibration_corpus_version,
)
from attribution_platform.calibration.provenance_validation import (
    PROVENANCE_VALIDATION_SCHEMA_VERSION,
    SPDX_LICENSE_ALLOWLIST,
    ProvenanceValidationReport,
    ProvenanceValidationViolation,
    ProvenanceViolationType,
    require_valid_provenance,
    validate_provenance,
)
from attribution_platform.calibration.split_validation import (
    NO_MANIFEST_CORPUS_VERSION,
    SPLIT_VALIDATION_SCHEMA_VERSION,
    SplitValidationReport,
    SplitValidationViolation,
    SplitViolationType,
    require_valid_split,
    validate_split,
)

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
    "CalibrationCorpusManifest",
    "CorpusCaseEntry",
    "CorpusSourceEntry",
    "compute_calibration_corpus_version",
    "CALIBRATION_MANIFEST_SCHEMA_VERSION",
    "CALIBRATION_CORPUS_VERSION_PREFIX",
    "CORPUS_VERSION_INPUT_FIELDS",
    "validate_split",
    "require_valid_split",
    "SplitValidationReport",
    "SplitValidationViolation",
    "SplitViolationType",
    "SPLIT_VALIDATION_SCHEMA_VERSION",
    "NO_MANIFEST_CORPUS_VERSION",
    "validate_provenance",
    "require_valid_provenance",
    "ProvenanceValidationReport",
    "ProvenanceValidationViolation",
    "ProvenanceViolationType",
    "PROVENANCE_VALIDATION_SCHEMA_VERSION",
    "SPDX_LICENSE_ALLOWLIST",
    "describe_corpus_composition",
    "CorpusCompositionReport",
    "COMPOSITION_SCHEMA_VERSION",
]
