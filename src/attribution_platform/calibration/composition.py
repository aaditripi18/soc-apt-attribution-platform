"""Calibration corpus composition description (gate B1.6, ADR-0006).

**Descriptive only — raw counts, never a judgement.** :func:`describe_corpus_composition`
reports *what a corpus contains* as deterministic, canonically-sorted raw
counts. It is **not** a validator: no ``is_valid``, no violations, no
``require_valid_*``, no pass/fail gate, no minimum-size check, no threshold, no
quality/coverage score, no ratio/percentage/concentration statistic, and no
weighted/normalized/composite value of any kind. B1.4 (split/leakage) and B1.5
(provenance/license) own the validation layers; this gate never duplicates them.

**Anti-circularity boundary.** Only fields already fixed by the case's own
dataset-authored metadata are counted (role, source kind, label semantics,
expected outcome, scenario family, source, license, and — for ``ATTRIBUTABLE``
cases only — the authored actor label verbatim). ``discriminating_evidence``,
``expected_contradiction``, ``expected_next_evidence``, ``campaign_context``,
``label_confidence`` and ``actor_label_source`` are deliberately **never**
counted. Actor labels are never alias-resolved or normalized and ATT&CK is
never consulted.

**Cross-identity guard.** The supplied ``cases`` must carry exactly the
``case_id`` set of ``manifest.case_entries``; any difference fails closed with
:class:`CalibrationError`. Neither input is mutated, the manifest's
``calibration_corpus_version`` is echoed unchanged (never recomputed), and no
new identity/hash is introduced. An empty corpus is valid and simply describes
as all-zero / empty distributions.

Imports only ``calibration.contracts`` / ``calibration.manifest`` /
``calibration.errors`` and the standard library. Deterministic and
``PYTHONHASHSEED``-independent (every distribution is sorted by its key before
the report is built; no RNG/UUID/timestamp).
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field

from attribution_platform.calibration.contracts import CalibrationCase, LabelSemantics
from attribution_platform.calibration.errors import CalibrationError
from attribution_platform.calibration.manifest import CalibrationCorpusManifest

#: Schema version of the B1.6 composition-report contract.
COMPOSITION_SCHEMA_VERSION = "calibration-composition/1"

#: A canonical distribution: ``(key, raw_count)`` pairs sorted by key.
Distribution = tuple[tuple[str, int], ...]


def _canonical_distribution(values: Iterable[str]) -> Distribution:
    """Raw counts of ``values`` as a key-sorted tuple of ``(key, count)``."""
    return tuple(sorted(Counter(values).items()))


def _validate_distribution(value: object, field_name: str) -> Distribution:
    """Require a tuple of ``(non-empty str, positive int)`` pairs with unique
    keys, and return it canonically key-sorted."""
    if not isinstance(value, tuple):
        raise CalibrationError(f"{field_name} must be a tuple of (str, int) pairs, got {value!r}")
    seen: set[str] = set()
    for pair in value:
        if not (isinstance(pair, tuple) and len(pair) == 2):
            raise CalibrationError(f"{field_name} entries must be (str, int) pairs, got {pair!r}")
        key, count = pair
        if not isinstance(key, str) or not key.strip():
            raise CalibrationError(f"{field_name} keys must be non-empty strings, got {key!r}")
        if isinstance(count, bool) or not isinstance(count, int) or count < 1:
            raise CalibrationError(f"{field_name} counts must be positive ints, got {count!r}")
        if key in seen:
            raise CalibrationError(f"{field_name} has duplicate key {key!r}")
        seen.add(key)
    return tuple(sorted(value))


def _require_count(value: object, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise CalibrationError(f"{field_name} must be a non-negative int, got {value!r}")
    return value


@dataclass(frozen=True)
class CorpusCompositionReport:
    """Raw-count description of one calibration corpus (ADR-0006) — descriptive
    only, never a verdict. Every distribution is a canonically key-sorted,
    hashable ``tuple[tuple[str, int], ...]`` of raw counts. There is no
    validity flag, violation list, ratio, percentage, concentration statistic,
    score, threshold, or ``calibration_version``.

    ``calibration_corpus_version`` echoes the manifest's value unchanged.
    """

    calibration_corpus_version: str
    total_cases: int
    distinct_sources: int
    distinct_scenario_families: int
    role_distribution: Distribution
    source_kind_distribution: Distribution
    label_semantics_distribution: Distribution
    expected_outcome_distribution: Distribution
    attributable_actor_distribution: Distribution
    license_distribution: Distribution
    cases_per_scenario_family: Distribution
    cases_per_source_ref: Distribution
    composition_schema_version: str = field(default=COMPOSITION_SCHEMA_VERSION)

    def __post_init__(self) -> None:
        for name in ("calibration_corpus_version", "composition_schema_version"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise CalibrationError(
                    f"CorpusCompositionReport.{name} must be a non-empty string, got {value!r}"
                )
        _require_count(self.total_cases, "CorpusCompositionReport.total_cases")
        _require_count(self.distinct_sources, "CorpusCompositionReport.distinct_sources")
        _require_count(
            self.distinct_scenario_families, "CorpusCompositionReport.distinct_scenario_families"
        )
        for name in (
            "role_distribution",
            "source_kind_distribution",
            "label_semantics_distribution",
            "expected_outcome_distribution",
            "attributable_actor_distribution",
            "license_distribution",
            "cases_per_scenario_family",
            "cases_per_source_ref",
        ):
            object.__setattr__(
                self,
                name,
                _validate_distribution(getattr(self, name), f"CorpusCompositionReport.{name}"),
            )


def describe_corpus_composition(
    manifest: CalibrationCorpusManifest,
    cases: tuple[CalibrationCase, ...],
) -> CorpusCompositionReport:
    """Describe the composition of a calibration corpus as raw, canonically
    sorted counts (ADR-0006). Descriptive only: never validates, scores,
    thresholds, or interprets. Fails closed with :class:`CalibrationError` if
    ``cases``' ``case_id`` set differs from ``manifest.case_entries``'.
    """
    if not isinstance(manifest, CalibrationCorpusManifest):
        raise CalibrationError(
            "describe_corpus_composition: manifest must be a CalibrationCorpusManifest, "
            f"got {type(manifest).__name__}"
        )
    if not isinstance(cases, tuple):
        raise CalibrationError(
            f"describe_corpus_composition: cases must be a tuple, got {type(cases).__name__}"
        )
    for case in cases:
        if not isinstance(case, CalibrationCase):
            raise CalibrationError(
                "describe_corpus_composition: cases must contain only CalibrationCase objects, "
                f"got {type(case).__name__}"
            )

    case_ids = {case.case_id for case in cases}
    manifest_case_ids = {entry.case_id for entry in manifest.case_entries}
    if case_ids != manifest_case_ids:
        only_cases = sorted(case_ids - manifest_case_ids)
        only_manifest = sorted(manifest_case_ids - case_ids)
        raise CalibrationError(
            "describe_corpus_composition: cases do not match manifest.case_entries "
            f"(in cases only: {only_cases}; in manifest only: {only_manifest})"
        )

    return CorpusCompositionReport(
        calibration_corpus_version=manifest.calibration_corpus_version,
        total_cases=len(cases),
        distinct_sources=len({case.source_ref for case in cases}),
        distinct_scenario_families=len({case.scenario_family_id for case in cases}),
        role_distribution=_canonical_distribution(case.case_role.value for case in cases),
        source_kind_distribution=_canonical_distribution(case.source_kind.value for case in cases),
        label_semantics_distribution=_canonical_distribution(
            case.ground_truth.label_semantics.value for case in cases
        ),
        expected_outcome_distribution=_canonical_distribution(
            case.expected_output_shape.outcome.value for case in cases
        ),
        attributable_actor_distribution=_canonical_distribution(
            case.ground_truth.actor_label
            for case in cases
            if case.ground_truth.label_semantics is LabelSemantics.ATTRIBUTABLE
            and case.ground_truth.actor_label is not None
        ),
        license_distribution=_canonical_distribution(case.license for case in cases),
        cases_per_scenario_family=_canonical_distribution(
            case.scenario_family_id for case in cases
        ),
        cases_per_source_ref=_canonical_distribution(case.source_ref for case in cases),
    )
