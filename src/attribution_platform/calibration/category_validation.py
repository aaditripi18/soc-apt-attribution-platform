"""Calibration corpus category-completeness validation (C3.2 Stage 3,
ADR-0006 §D8/§D19).

**Read-only validator — no scoring, no fitting, no ATT&CK, no mutation, no new
corpus identity.** This module mechanically checks that a calibration corpus
exercises every category ADR-0006 §D19 requires the corpus to cover, that all
four :class:`~attribution_platform.domain.enums.EvidenceType` values are
reachable somewhere in it, that it contains both a coverage-present and a
coverage-absent case, that every required
:class:`~attribution_platform.calibration.contracts.CaseRole` population is
non-empty, and that the required categories are present in both the
``CALIBRATION`` and ``HELD_OUT_VALIDATION`` populations specifically. It
produces a deterministic, explainable :class:`CategoryCompletenessReport` —
never a bare boolean, never a score.

**Contract discrepancy discovered and reported, not silently resolved (per
explicit instruction).** Nothing in
:class:`~attribution_platform.calibration.contracts.CalibrationCase`,
:class:`~attribution_platform.calibration.contracts.GroundTruth`,
:class:`~attribution_platform.calibration.contracts.ExpectedOutputShape`,
:class:`~attribution_platform.calibration.manifest.CorpusCaseEntry`, or the
manifest carries a repetition-sub-type / correlated-detection /
genuinely-distinct / deliberate-imitation / campaign-contextualization tag, or
a per-case :class:`~attribution_platform.domain.enums.EvidenceType` set — the
frozen ``CalibrationCase`` intentionally carries only Phase 0-2 *id references*
(``correlation_group_id`` / ``sequence_id`` / ``telemetry_provenance``), never a
copy of ``BehavioralStep.evidence_types``. Two of the nine requested "category
presence" checks *are* directly derivable from the existing frozen contract and
this module derives them **without any new metadata**:

- The four :attr:`~attribution_platform.calibration.contracts.LabelSemantics`
  values (``ATTRIBUTABLE`` / ``UNATTRIBUTABLE_BY_DESIGN`` / ``DISPUTED`` /
  ``UNKNOWN``) are read directly from ``case.ground_truth.label_semantics``.
- "Coverage-present" / "coverage-absent" is read directly from whether
  ``case.coverage_assumptions`` (§D6: "declared data-source availability, feeds
  ``CoverageProfile``") is non-empty or empty, respectively.

The remaining nine categories (the five repetition sub-types + correlated-
detection + genuinely-distinct-evidence + deliberate-imitation +
campaign-contextualization, per §D19's own list) and per-case
:class:`~attribution_platform.domain.enums.EvidenceType` coverage have **no**
home anywhere in the frozen contract chain. Rather than add a field to
``CalibrationCase`` (which this task explicitly gates on first reporting the
discrepancy — done above — and only if the contract "genuinely requires it"; it
does not, since a validator input can carry this instead), this module accepts
them as a **new, additively-authored, separate** :class:`CaseCategoryRecord`
per case — mirroring the exact anti-circularity separation the C3.2 corpus
builder already established between raw telemetry and its
:class:`~attribution_platform.calibration.corpus_builder.CorpusScenarioAnnotation`
(labels kept apart from evidence so authorship stays independent of inference).
A record is a *declaration of an already-observed fact* about a real,
already-built case (which categories it was authored to exercise; which
``EvidenceType`` values its real replay is recorded to have produced) — never a
computation this module performs itself, and never an ATT&CK-derived value.

**Cross-identity guard.** ``cases``' ``case_id`` set, ``manifest.case_entries``'
``case_id`` set, and ``category_records``' ``case_id`` set must all agree
exactly, else this fails closed with :class:`CalibrationError` — the same
"never validate a mismatched pair" discipline B1.4/B1.6 already established,
extended here to three inputs since all three are mandatory.

**What this module does NOT do** (out of scope / deferred): split/leakage or
blind-actor-holdout-readiness checking
(B1.4's :func:`~attribution_platform.calibration.split_validation.validate_split`
owns that — not duplicated here); provenance/license correctness (B1.5's
:func:`~attribution_platform.calibration.provenance_validation.validate_provenance`
owns that); corpus composition counting (B1.6's
:func:`~attribution_platform.calibration.composition.describe_corpus_composition`
owns that); authoring/persisting real :class:`CaseCategoryRecord` values for the
actual seed/golden corpus (a later Stage 4 concern); any fitting,
``calibration_version``, scoring, likelihood, confidence, WEP, abstention, or
G3.6 logic; any ATT&CK traversal or ``Group -> uses`` inference of any kind.

**Reuse, never re-invent.** Report/violation objects follow the frozen-
dataclass + closed-enum + canonical sorted-tuple discipline every prior
calibration validator uses; all output is deterministic and
``PYTHONHASHSEED``-independent (every collection is sorted before it is
returned). Imports only its own package
(:mod:`~attribution_platform.calibration.contracts` /
:mod:`~attribution_platform.calibration.manifest` /
:mod:`~attribution_platform.calibration.errors`), the real, unmodified
:class:`~attribution_platform.domain.enums.EvidenceType` (needed to validate —
never fabricate — evidence-type coverage), and the standard library.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from attribution_platform.calibration.contracts import (
    CalibrationCase,
    CaseRole,
    LabelSemantics,
)
from attribution_platform.calibration.errors import CalibrationError
from attribution_platform.calibration.manifest import CalibrationCorpusManifest
from attribution_platform.domain.enums import EvidenceType

#: Schema version of the C3.2 Stage 3 category-completeness report contract.
CATEGORY_VALIDATION_SCHEMA_VERSION = "calibration-category-validation/1"


class CaseCategoryTag(Enum):
    """The nine ADR-0006 §D19 corpus-diversity categories that have **no**
    home in the frozen :class:`~attribution_platform.calibration.contracts.CalibrationCase`
    (see the module docstring). Authored per case via :class:`CaseCategoryRecord`
    — never inferred by this module."""

    ONE_OBSERVATION = "one_observation"
    REPEATED_BEHAVIOR = "repeated_behavior"
    REPEATED_DETECTION = "repeated_detection"
    MULTIPLE_DISTINCT_OBSERVATION = "multiple_distinct_observation"
    MULTIPLE_EVIDENCE_TYPE = "multiple_evidence_type"
    CORRELATED_DETECTION = "correlated_detection"
    GENUINELY_DISTINCT_EVIDENCE = "genuinely_distinct_evidence"
    DELIBERATE_IMITATION = "deliberate_imitation"
    CAMPAIGN_CONTEXTUALIZATION = "campaign_contextualization"


#: Every required :class:`CaseCategoryTag`, in declaration order — the "Category
#: presence" set this module checks against the whole corpus and, separately,
#: against the CALIBRATION and HELD_OUT_VALIDATION populations.
REQUIRED_CATEGORY_TAGS: tuple[CaseCategoryTag, ...] = tuple(CaseCategoryTag)

#: Every required :class:`~attribution_platform.calibration.contracts.LabelSemantics`
#: value — the remaining four "Category presence" items (derived directly from
#: ``ground_truth.label_semantics``, never from an authored tag).
REQUIRED_LABEL_SEMANTICS: tuple[LabelSemantics, ...] = tuple(LabelSemantics)

#: Every required :class:`~attribution_platform.domain.enums.EvidenceType`
#: value — checked once, over the whole corpus (not per-population).
REQUIRED_EVIDENCE_TYPES: tuple[EvidenceType, ...] = tuple(EvidenceType)

#: The four :class:`~attribution_platform.calibration.contracts.CaseRole`
#: populations this module requires to be non-empty. ``EXCLUDED`` is the
#: documented final-test-reserved population (ADR-0006 §D9's "FINAL TEST" set) —
#: per the accepted C3.2 Stage 2 D2 decision, represented by the existing
#: ``EXCLUDED`` role rather than a new ``FINAL_TEST`` enum member.
#: ``TIER1_STRUCTURAL`` is a real ``CaseRole`` member but is not required
#: non-empty by this module (not requested by this gate's locked scope).
REQUIRED_NONEMPTY_POPULATIONS: tuple[CaseRole, ...] = (
    CaseRole.CALIBRATION,
    CaseRole.HELD_OUT_VALIDATION,
    CaseRole.BLIND_ACTOR_HOLDOUT,
    CaseRole.EXCLUDED,
)

#: The two populations every required category (all thirteen "Category
#: presence" items — the nine :class:`CaseCategoryTag` values plus the four
#: :class:`~attribution_platform.calibration.contracts.LabelSemantics` values)
#: must independently appear in.
_CATEGORY_REQUIRED_POPULATIONS: tuple[CaseRole, ...] = (
    CaseRole.CALIBRATION,
    CaseRole.HELD_OUT_VALIDATION,
)


class CategoryViolationType(Enum):
    """Closed set of category-completeness violation kinds (ADR-0006 §D19)."""

    MISSING_CATEGORY = "missing_category"
    MISSING_LABEL_SEMANTICS = "missing_label_semantics"
    MISSING_EVIDENCE_TYPE = "missing_evidence_type"
    NO_COVERAGE_PRESENT_CASE = "no_coverage_present_case"
    NO_COVERAGE_ABSENT_CASE = "no_coverage_absent_case"
    EMPTY_POPULATION = "empty_population"
    CATEGORY_MISSING_FROM_POPULATION = "category_missing_from_population"


def _canonical_case_ids(values: object, field_name: str) -> tuple[str, ...]:
    """Canonicalize to a sorted-unique tuple of non-empty strings (the exact
    discipline every prior calibration contract applies)."""
    if not isinstance(values, tuple | list | set | frozenset):
        raise CalibrationError(f"{field_name} must be an iterable of str, got {values!r}")
    canonical = tuple(sorted({str(v) for v in values}))
    for element in canonical:
        if not element.strip():
            raise CalibrationError(f"{field_name}[] must be non-empty, got {element!r}")
    return canonical


@dataclass(frozen=True)
class CaseCategoryRecord:
    """The separately-authored declaration, for one case, of which
    :class:`CaseCategoryTag` values it was authored to exercise and which real
    :class:`~attribution_platform.domain.enums.EvidenceType` values its actual
    replay is recorded to have produced.

    Kept apart from :class:`~attribution_platform.calibration.contracts.CalibrationCase`
    (see the module docstring's discrepancy note) — this is authored metadata
    about an already-built case, never fabricated or inferred by this module,
    and never from ATT&CK. Both fields may be empty (a case need not exercise
    any category tag or have any known evidence type)."""

    case_id: str
    categories: tuple[CaseCategoryTag, ...] = ()
    evidence_types: tuple[EvidenceType, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.case_id, str) or not self.case_id.strip():
            raise CalibrationError("CaseCategoryRecord.case_id must be a non-empty string")
        for category in self.categories:
            if not isinstance(category, CaseCategoryTag):
                raise CalibrationError(
                    "CaseCategoryRecord.categories must contain only CaseCategoryTag objects, "
                    f"got {type(category).__name__}"
                )
        object.__setattr__(
            self, "categories", tuple(sorted(set(self.categories), key=lambda c: c.value))
        )
        for evidence_type in self.evidence_types:
            if not isinstance(evidence_type, EvidenceType):
                raise CalibrationError(
                    "CaseCategoryRecord.evidence_types must contain only EvidenceType objects, "
                    f"got {type(evidence_type).__name__}"
                )
        object.__setattr__(
            self,
            "evidence_types",
            tuple(sorted(set(self.evidence_types), key=lambda e: e.value)),
        )


@dataclass(frozen=True)
class CategoryCompletenessViolation:
    """One deterministic, explainable category-completeness violation.
    ``case_ids`` is canonicalized (sorted-unique, may be empty for a
    corpus-wide absence with no specific offending case). ``category`` /
    ``label_semantics`` / ``evidence_type`` / ``population`` are set only when
    relevant to ``violation_type``, else ``None``."""

    violation_type: CategoryViolationType
    reason: str
    case_ids: tuple[str, ...] = ()
    category: CaseCategoryTag | None = None
    label_semantics: LabelSemantics | None = None
    evidence_type: EvidenceType | None = None
    population: CaseRole | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.violation_type, CategoryViolationType):
            raise CalibrationError(
                "CategoryCompletenessViolation.violation_type must be a CategoryViolationType, "
                f"got {type(self.violation_type).__name__}"
            )
        if not isinstance(self.reason, str) or not self.reason.strip():
            raise CalibrationError(
                "CategoryCompletenessViolation.reason must be a non-empty string"
            )
        object.__setattr__(
            self,
            "case_ids",
            _canonical_case_ids(self.case_ids, "CategoryCompletenessViolation.case_ids"),
        )
        for value, expected, name in (
            (self.category, CaseCategoryTag, "category"),
            (self.label_semantics, LabelSemantics, "label_semantics"),
            (self.evidence_type, EvidenceType, "evidence_type"),
            (self.population, CaseRole, "population"),
        ):
            if value is not None and not isinstance(value, expected):
                raise CalibrationError(
                    f"CategoryCompletenessViolation.{name} must be a {expected.__name__} or None, "
                    f"got {type(value).__name__}"
                )

    def _sort_key(self) -> tuple[str, str, str, str, str, tuple[str, ...]]:
        return (
            self.violation_type.value,
            self.category.value if self.category is not None else "",
            self.label_semantics.value if self.label_semantics is not None else "",
            self.evidence_type.value if self.evidence_type is not None else "",
            self.population.value if self.population is not None else "",
            self.case_ids,
        )


@dataclass(frozen=True)
class CategoryCompletenessReport:
    """The read-only result of :func:`validate_category_completeness`
    (ADR-0006 §D19) — an explainable report, never a bare boolean, never a
    score.

    ``calibration_corpus_version`` echoes the supplied manifest's value
    **unchanged**. ``violations`` is canonically sorted."""

    is_valid: bool
    calibration_corpus_version: str
    violations: tuple[CategoryCompletenessViolation, ...] = ()
    validation_schema_version: str = field(default=CATEGORY_VALIDATION_SCHEMA_VERSION)

    def __post_init__(self) -> None:
        for v in self.violations:
            if not isinstance(v, CategoryCompletenessViolation):
                raise CalibrationError(
                    "CategoryCompletenessReport.violations must contain only "
                    f"CategoryCompletenessViolation objects, got {type(v).__name__}"
                )
        object.__setattr__(
            self,
            "violations",
            tuple(sorted(self.violations, key=lambda v: v._sort_key())),
        )
        computed_valid = len(self.violations) == 0
        if self.is_valid != computed_valid:
            raise CalibrationError(
                f"CategoryCompletenessReport.is_valid ({self.is_valid}) is inconsistent with "
                f"{len(self.violations)} violation(s)"
            )
        if not isinstance(self.calibration_corpus_version, str) or not (
            self.calibration_corpus_version.strip()
        ):
            raise CalibrationError(
                "CategoryCompletenessReport.calibration_corpus_version must be a non-empty string"
            )
        if not isinstance(self.validation_schema_version, str) or not (
            self.validation_schema_version.strip()
        ):
            raise CalibrationError(
                "CategoryCompletenessReport.validation_schema_version must be a non-empty string"
            )


def _cases_by_role(
    cases: tuple[CalibrationCase, ...],
) -> dict[CaseRole, tuple[CalibrationCase, ...]]:
    by_role: dict[CaseRole, list[CalibrationCase]] = {role: [] for role in CaseRole}
    for case in cases:
        by_role[case.case_role].append(case)
    return {role: tuple(members) for role, members in by_role.items()}


def _population_violations(
    by_role: dict[CaseRole, tuple[CalibrationCase, ...]],
) -> tuple[CategoryCompletenessViolation, ...]:
    violations: list[CategoryCompletenessViolation] = []
    for role in REQUIRED_NONEMPTY_POPULATIONS:
        if not by_role[role]:
            violations.append(
                CategoryCompletenessViolation(
                    violation_type=CategoryViolationType.EMPTY_POPULATION,
                    population=role,
                    reason=(
                        f"required population {role.value!r} has no cases (ADR-0006 §D8/§D9 "
                        "requires each population to be populated)"
                    ),
                )
            )
    return tuple(violations)


def _coverage_diversity_violations(
    cases: tuple[CalibrationCase, ...],
) -> tuple[CategoryCompletenessViolation, ...]:
    has_present = any(len(c.coverage_assumptions) > 0 for c in cases)
    has_absent = any(len(c.coverage_assumptions) == 0 for c in cases)
    violations: list[CategoryCompletenessViolation] = []
    if not has_present:
        violations.append(
            CategoryCompletenessViolation(
                violation_type=CategoryViolationType.NO_COVERAGE_PRESENT_CASE,
                reason=(
                    "no case declares any coverage_assumptions (a non-empty declared "
                    "data-source-availability set); the corpus needs at least one "
                    "coverage-present case (ADR-0006 §D19)"
                ),
            )
        )
    if not has_absent:
        violations.append(
            CategoryCompletenessViolation(
                violation_type=CategoryViolationType.NO_COVERAGE_ABSENT_CASE,
                reason=(
                    "every case declares a non-empty coverage_assumptions set; the corpus needs "
                    "at least one coverage-absent case (empty coverage_assumptions, ADR-0006 §D19)"
                ),
            )
        )
    return tuple(violations)


def _evidence_type_violations(
    records_by_case: dict[str, CaseCategoryRecord],
) -> tuple[CategoryCompletenessViolation, ...]:
    present = {et for record in records_by_case.values() for et in record.evidence_types}
    violations = []
    for evidence_type in REQUIRED_EVIDENCE_TYPES:
        if evidence_type not in present:
            violations.append(
                CategoryCompletenessViolation(
                    violation_type=CategoryViolationType.MISSING_EVIDENCE_TYPE,
                    evidence_type=evidence_type,
                    reason=(
                        f"no case's category record reports EvidenceType {evidence_type.value!r}; "
                        "the corpus must reach every EvidenceType (ADR-0006 §D19)"
                    ),
                )
            )
    return tuple(violations)


def _category_and_label_semantics_violations(
    cases: tuple[CalibrationCase, ...],
    records_by_case: dict[str, CaseCategoryRecord],
) -> tuple[CategoryCompletenessViolation, ...]:
    violations: list[CategoryCompletenessViolation] = []

    tags_present: set[CaseCategoryTag] = set()
    tags_by_population: dict[CaseRole, set[CaseCategoryTag]] = {
        role: set() for role in _CATEGORY_REQUIRED_POPULATIONS
    }
    semantics_present: set[LabelSemantics] = set()
    semantics_by_population: dict[CaseRole, set[LabelSemantics]] = {
        role: set() for role in _CATEGORY_REQUIRED_POPULATIONS
    }

    for case in cases:
        record = records_by_case.get(case.case_id)
        case_tags = record.categories if record is not None else ()
        tags_present.update(case_tags)
        semantics_present.add(case.ground_truth.label_semantics)
        if case.case_role in tags_by_population:
            tags_by_population[case.case_role].update(case_tags)
            semantics_by_population[case.case_role].add(case.ground_truth.label_semantics)

    for tag in REQUIRED_CATEGORY_TAGS:
        if tag not in tags_present:
            violations.append(
                CategoryCompletenessViolation(
                    violation_type=CategoryViolationType.MISSING_CATEGORY,
                    category=tag,
                    reason=(
                        f"no case's category record carries the required category {tag.value!r} "
                        "(ADR-0006 §D19)"
                    ),
                )
            )
            continue
        for role in _CATEGORY_REQUIRED_POPULATIONS:
            if tag not in tags_by_population[role]:
                violations.append(
                    CategoryCompletenessViolation(
                        violation_type=CategoryViolationType.CATEGORY_MISSING_FROM_POPULATION,
                        category=tag,
                        population=role,
                        reason=(
                            f"required category {tag.value!r} is present in the corpus but absent "
                            f"from the {role.value!r} population (ADR-0006 §D19)"
                        ),
                    )
                )

    for semantics in REQUIRED_LABEL_SEMANTICS:
        if semantics not in semantics_present:
            violations.append(
                CategoryCompletenessViolation(
                    violation_type=CategoryViolationType.MISSING_LABEL_SEMANTICS,
                    label_semantics=semantics,
                    reason=(
                        f"no case has ground_truth.label_semantics == {semantics.value!r} "
                        "(ADR-0006 §D7/§D19)"
                    ),
                )
            )
            continue
        for role in _CATEGORY_REQUIRED_POPULATIONS:
            if semantics not in semantics_by_population[role]:
                violations.append(
                    CategoryCompletenessViolation(
                        violation_type=CategoryViolationType.CATEGORY_MISSING_FROM_POPULATION,
                        label_semantics=semantics,
                        population=role,
                        reason=(
                            f"required label_semantics {semantics.value!r} is present in the "
                            f"corpus but absent from the {role.value!r} population "
                            "(ADR-0006 §D7/§D19)"
                        ),
                    )
                )

    return tuple(violations)


def validate_category_completeness(
    manifest: CalibrationCorpusManifest,
    cases: tuple[CalibrationCase, ...],
    category_records: tuple[CaseCategoryRecord, ...],
) -> CategoryCompletenessReport:
    """Read-only category-completeness validation over a manifest, its cases,
    and their separately-authored :class:`CaseCategoryRecord` declarations
    (ADR-0006 §D19). Never mutates any input, never consults ATT&CK, never
    computes a new corpus hash, and introduces no threshold/score.

    All three of ``manifest.case_entries``, ``cases``, and ``category_records``
    must carry exactly the same ``case_id`` set — a mismatched combination
    fails closed with :class:`CalibrationError` rather than being silently
    validated against a subset.

    An **empty corpus is structurally valid input** — it simply reports every
    required category/population/evidence-type as missing rather than raising
    (the same "never a minimum-size gate here" discipline every prior
    calibration validator uses); this module's populated-corpus checks are
    what makes an empty corpus report invalid.
    """
    if not isinstance(manifest, CalibrationCorpusManifest):
        raise CalibrationError(
            "validate_category_completeness: manifest must be a CalibrationCorpusManifest, "
            f"got {type(manifest).__name__}"
        )
    if not isinstance(cases, tuple):
        raise CalibrationError(
            "validate_category_completeness: cases must be a tuple of CalibrationCase, "
            f"got {type(cases).__name__}"
        )
    for case in cases:
        if not isinstance(case, CalibrationCase):
            raise CalibrationError(
                "validate_category_completeness: cases must contain only CalibrationCase "
                f"objects, got {type(case).__name__}"
            )
    if not isinstance(category_records, tuple):
        raise CalibrationError(
            "validate_category_completeness: category_records must be a tuple of "
            f"CaseCategoryRecord, got {type(category_records).__name__}"
        )
    for record in category_records:
        if not isinstance(record, CaseCategoryRecord):
            raise CalibrationError(
                "validate_category_completeness: category_records must contain only "
                f"CaseCategoryRecord objects, got {type(record).__name__}"
            )

    case_ids = frozenset(c.case_id for c in cases)
    manifest_ids = frozenset(e.case_id for e in manifest.case_entries)
    record_ids: set[str] = set()
    for record in category_records:
        if record.case_id in record_ids:
            raise CalibrationError(
                f"validate_category_completeness: duplicate case_id {record.case_id!r} in "
                "category_records — exactly one record per case is required"
            )
        record_ids.add(record.case_id)
    if not (case_ids == manifest_ids == frozenset(record_ids)):
        raise CalibrationError(
            "validate_category_completeness: the supplied cases, manifest.case_entries, and "
            "category_records do not all reference exactly the same case_id set — refusing to "
            "validate a mismatched triple"
        )

    records_by_case = {record.case_id: record for record in category_records}
    by_role = _cases_by_role(cases)

    violations = (
        _population_violations(by_role)
        + _coverage_diversity_violations(cases)
        + _evidence_type_violations(records_by_case)
        + _category_and_label_semantics_violations(cases, records_by_case)
    )
    return CategoryCompletenessReport(
        is_valid=len(violations) == 0,
        calibration_corpus_version=manifest.calibration_corpus_version,
        violations=violations,
    )


def require_valid_category_completeness(
    manifest: CalibrationCorpusManifest,
    cases: tuple[CalibrationCase, ...],
    category_records: tuple[CaseCategoryRecord, ...],
) -> CategoryCompletenessReport:
    """Convenience wrapper around :func:`validate_category_completeness` that
    **raises** :class:`CalibrationError` when the corpus is category-
    incomplete (fail-closed call site), returning the report otherwise. The
    report-returning :func:`validate_category_completeness` remains the
    primary, explainable API."""
    report = validate_category_completeness(manifest, cases, category_records)
    if not report.is_valid:
        summary = "; ".join(v.reason for v in report.violations)
        raise CalibrationError(
            f"require_valid_category_completeness: corpus is category-incomplete "
            f"({len(report.violations)} violation(s)): {summary}"
        )
    return report


__all__ = [
    "CATEGORY_VALIDATION_SCHEMA_VERSION",
    "CaseCategoryTag",
    "REQUIRED_CATEGORY_TAGS",
    "REQUIRED_LABEL_SEMANTICS",
    "REQUIRED_EVIDENCE_TYPES",
    "REQUIRED_NONEMPTY_POPULATIONS",
    "CategoryViolationType",
    "CaseCategoryRecord",
    "CategoryCompletenessViolation",
    "CategoryCompletenessReport",
    "validate_category_completeness",
    "require_valid_category_completeness",
]
