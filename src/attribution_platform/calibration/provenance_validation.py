"""Calibration provenance / license correctness validation (gate B1.5,
ADR-0006 §D13/§D15).

**Read-only correctness validator over an already-structurally-valid manifest —
no scoring, no fitting, no ATT&CK, no mutation, no new identity.** This module
validates the *correctness* layer that sits **above** the structural integrity
:class:`~attribution_platform.calibration.manifest.CalibrationCorpusManifest`
construction already guarantees. It consumes **only** the manifest (never
:class:`~attribution_platform.calibration.contracts.CalibrationCase` objects —
all provenance/license metadata lives on the manifest's
:class:`~attribution_platform.calibration.manifest.CorpusSourceEntry` /
:class:`~attribution_platform.calibration.manifest.CorpusCaseEntry`), and it
produces a deterministic, explainable :class:`ProvenanceValidationReport`.

**B1.3 already owns (NOT re-checked here):** source-registry uniqueness; every
case's ``source_ref`` is registered; case/source ``license`` and ``source_kind``
agreement; non-empty ``acquisition_provenance`` / ``transformation_provenance`` /
``license``. B1.5 assumes a valid manifest and does not duplicate any of these.

**B1.5 owns (this gate):**

1. **Deterministic license-identifier validation** — every registered source's
   ``license`` must be one of the project's fixed, documented SPDX identifiers
   (:data:`SPDX_LICENSE_ALLOWLIST`), else :attr:`ProvenanceViolationType.INVALID_SPDX_LICENSE`.
   Because B1.3 already forces case ``license`` == source ``license``, validating
   the *source* registry covers every case without duplicating B1.3.
2. **Orphan-source detection** — every :class:`CorpusSourceEntry` must be
   referenced by at least one :class:`CorpusCaseEntry`, else
   :attr:`ProvenanceViolationType.ORPHAN_SOURCE_ENTRY` (source-traceability
   integrity, **not** corpus-quality analysis).
3. **Minimal structural provenance adequacy** — ``acquisition_provenance`` /
   ``transformation_provenance`` must not be an obvious placeholder token
   (``n/a``/``none``/``unknown``/``todo``/``tbd``/… case-insensitively after
   stripping), else :attr:`INADEQUATE_ACQUISITION_PROVENANCE` /
   :attr:`INADEQUATE_TRANSFORMATION_PROVENANCE`. **Structural only** — it never
   determines whether provenance is *truthful*, never fetches a URL, never
   inspects an external source, and makes **no** legal/redistribution claim.

**Explicitly out of scope / deferred:** the ``redistribution_constraint`` field
(§D15, deferred — not added, no redistribution violation type); SPDX legal-text
verification and legal-compatibility conclusions; source reachability /
network / filesystem access; B1.4 split/leakage/blind-actor logic; B1.6 corpus
quality/coverage/sufficiency; ``calibration_version`` / fitting / thresholds /
scoring / likelihood / confidence; any ATT&CK dependency.

**Reuse, never re-invent.** Imports only its own package
(:mod:`~attribution_platform.calibration.manifest` / ``.errors``) and the
standard library. Report/violation objects follow the frozen-dataclass +
closed-enum + canonical sorted-tuple discipline B1.4 established; all output is
deterministic and ``PYTHONHASHSEED``-independent. The report **echoes**
``manifest.calibration_corpus_version`` unchanged and computes **no** new hash.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from attribution_platform.calibration.errors import CalibrationError
from attribution_platform.calibration.manifest import CalibrationCorpusManifest

#: Schema version of the B1.5 provenance-validation report contract.
PROVENANCE_VALIDATION_SCHEMA_VERSION = "calibration-provenance-validation/1"

#: The project's fixed, documented, version-controlled SPDX license allowlist.
#: Derived **only** from the datasets research actually documented as relevant to
#: this project (``docs/research/07-datasets-and-synthetic-telemetry.md``):
#:
#: - ``MIT`` — OTRF Security-Datasets; Atomic Red Team.
#: - ``Apache-2.0`` — MITRE CALDERA.
#: - ``GPL-3.0`` — ``sbousseaden/EVTX-ATTACK-SAMPLES`` (local-only; redistribution
#:   handling is deferred with the ``redistribution_constraint`` field, §D15).
#:
#: Matching is **exact** (canonical SPDX identifiers are case-sensitive) — a
#: non-canonical spelling (e.g. ``"mit"``, ``"apache 2.0"``) is not allowlisted.
#: This is **membership only**: it asserts nothing about legal compatibility and
#: is never fetched from an external SPDX database.
SPDX_LICENSE_ALLOWLIST: frozenset[str] = frozenset({"MIT", "Apache-2.0", "GPL-3.0"})

#: Obvious structural placeholder tokens rejected as inadequate provenance,
#: compared case-insensitively after stripping surrounding whitespace. This is a
#: purely structural adequacy check — it does not judge truthfulness.
_PLACEHOLDER_TOKENS: frozenset[str] = frozenset(
    {"", "n/a", "na", "none", "unknown", "todo", "tbd", "-", "?"}
)


class ProvenanceViolationType(Enum):
    """Closed set of provenance/license correctness violation kinds (ADR-0006
    §D13/§D15). Deliberately excludes any redistribution-related kind —
    ``redistribution_constraint`` is a deferred field (§D15)."""

    INVALID_SPDX_LICENSE = "invalid_spdx_license"
    ORPHAN_SOURCE_ENTRY = "orphan_source_entry"
    INADEQUATE_ACQUISITION_PROVENANCE = "inadequate_acquisition_provenance"
    INADEQUATE_TRANSFORMATION_PROVENANCE = "inadequate_transformation_provenance"


def _canonical_source_refs(values: object, field_name: str) -> tuple[str, ...]:
    """Canonicalize to a sorted-unique tuple of non-empty strings (the exact
    discipline every prior calibration contract applies)."""
    if not isinstance(values, tuple | list | set | frozenset):
        raise CalibrationError(f"{field_name} must be an iterable of str, got {values!r}")
    canonical = tuple(sorted({str(v) for v in values}))
    for element in canonical:
        if not element.strip():
            raise CalibrationError(f"{field_name}[] must be non-empty, got {element!r}")
    return canonical


def _is_placeholder(value: str) -> bool:
    """True iff ``value`` is an obvious structural placeholder (case-insensitive,
    stripped) — never a truthfulness judgement."""
    return value.strip().casefold() in _PLACEHOLDER_TOKENS


@dataclass(frozen=True)
class ProvenanceValidationViolation:
    """One deterministic, explainable provenance/license violation. ``source_refs``
    is canonicalized (sorted-unique); ``license`` is set only for
    ``INVALID_SPDX_LICENSE`` (else ``None``)."""

    violation_type: ProvenanceViolationType
    source_refs: tuple[str, ...]
    reason: str
    license: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.violation_type, ProvenanceViolationType):
            raise CalibrationError(
                "ProvenanceValidationViolation.violation_type must be a ProvenanceViolationType, "
                f"got {type(self.violation_type).__name__}"
            )
        object.__setattr__(
            self,
            "source_refs",
            _canonical_source_refs(self.source_refs, "ProvenanceValidationViolation.source_refs"),
        )
        if not isinstance(self.reason, str) or not self.reason.strip():
            raise CalibrationError(
                "ProvenanceValidationViolation.reason must be a non-empty string"
            )
        if self.license is not None and not isinstance(self.license, str):
            raise CalibrationError(
                "ProvenanceValidationViolation.license must be a str or None, "
                f"got {type(self.license).__name__}"
            )

    def _sort_key(self) -> tuple[str, tuple[str, ...], str]:
        return (self.violation_type.value, self.source_refs, self.license or "")


@dataclass(frozen=True)
class ProvenanceValidationReport:
    """The read-only result of :func:`validate_provenance` (ADR-0006 §D13/§D15) —
    an explainable report, never a bare boolean, never a score.

    ``calibration_corpus_version`` echoes the supplied manifest's value
    **unchanged** (never recomputed). ``violations`` is canonically sorted."""

    is_valid: bool
    calibration_corpus_version: str
    violations: tuple[ProvenanceValidationViolation, ...] = ()
    validation_schema_version: str = field(default=PROVENANCE_VALIDATION_SCHEMA_VERSION)

    def __post_init__(self) -> None:
        for v in self.violations:
            if not isinstance(v, ProvenanceValidationViolation):
                raise CalibrationError(
                    "ProvenanceValidationReport.violations must contain only "
                    f"ProvenanceValidationViolation objects, got {type(v).__name__}"
                )
        object.__setattr__(
            self, "violations", tuple(sorted(self.violations, key=lambda v: v._sort_key()))
        )
        computed_valid = len(self.violations) == 0
        if self.is_valid != computed_valid:
            raise CalibrationError(
                f"ProvenanceValidationReport.is_valid ({self.is_valid}) is inconsistent with "
                f"{len(self.violations)} violation(s)"
            )
        if not isinstance(self.calibration_corpus_version, str) or not (
            self.calibration_corpus_version.strip()
        ):
            raise CalibrationError(
                "ProvenanceValidationReport.calibration_corpus_version must be a non-empty string"
            )
        if not isinstance(self.validation_schema_version, str) or not (
            self.validation_schema_version.strip()
        ):
            raise CalibrationError(
                "ProvenanceValidationReport.validation_schema_version must be a non-empty string"
            )


def validate_provenance(
    manifest: CalibrationCorpusManifest,
) -> ProvenanceValidationReport:
    """Read-only provenance/license correctness validation over an
    already-structurally-valid :class:`CalibrationCorpusManifest` (ADR-0006
    §D13/§D15). Never mutates the manifest, never consults ATT&CK, never
    accesses the network/filesystem, never computes a new hash/version, and
    introduces no threshold/score.

    Checks (over ``manifest.source_entries`` / ``manifest.case_entries``):
    per-source SPDX-license membership; obvious-placeholder acquisition/
    transformation provenance; and orphan sources (registered but referenced by
    no case). An **empty manifest is valid** (no sources, no violations).
    """
    if not isinstance(manifest, CalibrationCorpusManifest):
        raise CalibrationError(
            "validate_provenance: manifest must be a CalibrationCorpusManifest, "
            f"got {type(manifest).__name__}"
        )

    used_source_refs = {entry.source_ref for entry in manifest.case_entries}
    violations: list[ProvenanceValidationViolation] = []

    for source in manifest.source_entries:
        if source.license not in SPDX_LICENSE_ALLOWLIST:
            violations.append(
                ProvenanceValidationViolation(
                    violation_type=ProvenanceViolationType.INVALID_SPDX_LICENSE,
                    source_refs=(source.source_ref,),
                    reason=(
                        f"source {source.source_ref!r} declares license {source.license!r}, which "
                        "is not a documented allowlisted SPDX identifier "
                        f"({', '.join(sorted(SPDX_LICENSE_ALLOWLIST))})"
                    ),
                    license=source.license,
                )
            )
        if _is_placeholder(source.acquisition_provenance):
            violations.append(
                ProvenanceValidationViolation(
                    violation_type=ProvenanceViolationType.INADEQUATE_ACQUISITION_PROVENANCE,
                    source_refs=(source.source_ref,),
                    reason=(
                        f"source {source.source_ref!r} has placeholder acquisition_provenance "
                        f"{source.acquisition_provenance!r} (structural adequacy only; no "
                        "truthfulness judged)"
                    ),
                )
            )
        if _is_placeholder(source.transformation_provenance):
            violations.append(
                ProvenanceValidationViolation(
                    violation_type=ProvenanceViolationType.INADEQUATE_TRANSFORMATION_PROVENANCE,
                    source_refs=(source.source_ref,),
                    reason=(
                        f"source {source.source_ref!r} has placeholder transformation_provenance "
                        f"{source.transformation_provenance!r} (structural adequacy only; no "
                        "truthfulness judged)"
                    ),
                )
            )
        if source.source_ref not in used_source_refs:
            violations.append(
                ProvenanceValidationViolation(
                    violation_type=ProvenanceViolationType.ORPHAN_SOURCE_ENTRY,
                    source_refs=(source.source_ref,),
                    reason=(
                        f"registered source {source.source_ref!r} is referenced by no case entry "
                        "(orphan source; source-traceability integrity)"
                    ),
                )
            )

    return ProvenanceValidationReport(
        is_valid=len(violations) == 0,
        calibration_corpus_version=manifest.calibration_corpus_version,
        violations=tuple(violations),
    )


def require_valid_provenance(
    manifest: CalibrationCorpusManifest,
) -> ProvenanceValidationReport:
    """Convenience wrapper around :func:`validate_provenance` that **raises**
    :class:`CalibrationError` when the corpus provenance/licensing is invalid
    (fail-closed call site), returning the report otherwise. The
    report-returning :func:`validate_provenance` remains the primary,
    explainable API."""
    report = validate_provenance(manifest)
    if not report.is_valid:
        summary = "; ".join(v.reason for v in report.violations)
        raise CalibrationError(
            f"require_valid_provenance: corpus provenance/licensing is invalid "
            f"({len(report.violations)} violation(s)): {summary}"
        )
    return report
