"""C3.2 Stage 3 — category-completeness validator tests (ADR-0006 §D19).

Covers only the Stage 3 descriptive/validation surface: category, evidence-
type, coverage-diversity, and population-non-emptiness completeness over a
manifest + cases + separately-authored ``CaseCategoryRecord`` declarations.
Does not duplicate B1.4 (split/leakage/blind-actor readiness) or B1.5
(provenance/license correctness). No fitting, ``calibration_version``,
scoring, WEP, abstention, or G3.6 is exercised (none exists here). No ATT&CK
knowledge is consulted — offline, deterministic.
"""

from __future__ import annotations

import ast
import copy
import dataclasses
import itertools
import subprocess
import sys
from pathlib import Path

import pytest

from attribution_platform.calibration.category_validation import (
    CATEGORY_VALIDATION_SCHEMA_VERSION,
    REQUIRED_CATEGORY_TAGS,
    REQUIRED_EVIDENCE_TYPES,
    REQUIRED_LABEL_SEMANTICS,
    REQUIRED_NONEMPTY_POPULATIONS,
    CaseCategoryRecord,
    CaseCategoryTag,
    CategoryCompletenessReport,
    CategoryViolationType,
    require_valid_category_completeness,
    validate_category_completeness,
)
from attribution_platform.calibration.contracts import (
    ActorLabelSource,
    CalibrationCase,
    CaseRole,
    ExpectedOutcome,
    ExpectedOutputShape,
    GroundTruth,
    LabelConfidence,
    LabelSemantics,
    SourceKind,
)
from attribution_platform.calibration.errors import CalibrationError
from attribution_platform.calibration.manifest import (
    CalibrationCorpusManifest,
    CorpusSourceEntry,
)
from attribution_platform.domain.enums import EvidenceType

_KB = "enterprise-attack-19.0"
_counter = itertools.count()

module_path = Path(__file__).resolve().parents[1] / (
    "src/attribution_platform/calibration/category_validation.py"
)


def _truth(semantics: LabelSemantics, actor: str | None) -> GroundTruth:
    if semantics is LabelSemantics.UNATTRIBUTABLE_BY_DESIGN:
        actor = None
    return GroundTruth(
        actor_label_source=(
            ActorLabelSource.UNKNOWN
            if semantics is LabelSemantics.UNKNOWN
            else ActorLabelSource.EMULATION_PLAN
        ),
        label_semantics=semantics,
        label_confidence=LabelConfidence.MODERATE,
        actor_label=actor,
    )


def _shape(semantics: LabelSemantics) -> ExpectedOutputShape:
    outcome = (
        ExpectedOutcome.INSUFFICIENT_EVIDENCE
        if semantics is LabelSemantics.UNATTRIBUTABLE_BY_DESIGN
        else ExpectedOutcome.LEADING_HYPOTHESIS
    )
    return ExpectedOutputShape(
        outcome=outcome,
        authorship_provenance="analyst",
        expected_likelihood_band=(
            "likely" if outcome is ExpectedOutcome.LEADING_HYPOTHESIS else None
        ),
    )


def _case(
    *,
    role: CaseRole,
    semantics: LabelSemantics = LabelSemantics.ATTRIBUTABLE,
    coverage: bool = True,
    family: str | None = None,
    source_ref: str = "a@1",
) -> CalibrationCase:
    family = family or f"fam-{next(_counter)}"
    return CalibrationCase(
        scenario_family_id=family,
        source_kind=SourceKind.EMULATED,
        source_ref=source_ref,
        license="MIT",
        attack_kb_version=_KB,
        correlation_group_id="correlation-group::abc",
        sequence_id="behavioral-sequence::def",
        telemetry_provenance=(f"observation::o{next(_counter)}",),
        ground_truth=_truth(semantics, "APT-X" if semantics != LabelSemantics.UNKNOWN else None),
        expected_output_shape=_shape(semantics),
        case_role=role,
        coverage_assumptions=("data-component::process-creation",) if coverage else (),
    )


def _manifest(cases: tuple[CalibrationCase, ...]) -> CalibrationCorpusManifest:
    sources = {
        c.source_ref: CorpusSourceEntry(
            source_ref=c.source_ref,
            source_kind=c.source_kind,
            license=c.license,
            acquisition_provenance="downloaded from the upstream repository tag",
            transformation_provenance="replayed through the deterministic pipeline",
        )
        for c in cases
    }
    return CalibrationCorpusManifest.from_cases(
        cases, list(sources.values()), attack_kb_version=_KB
    )


def _full_corpus() -> (
    tuple[CalibrationCorpusManifest, tuple[CalibrationCase, ...], tuple[CaseCategoryRecord, ...]]
):
    """A corpus satisfying every Stage 3 requirement: all nine
    ``CaseCategoryTag`` values and all four ``LabelSemantics`` values present
    in both CALIBRATION and HELD_OUT_VALIDATION; all four ``EvidenceType``
    values reachable; both a coverage-present and coverage-absent case; every
    required population non-empty."""
    semantics_cycle = list(LabelSemantics)
    evidence_cycle = list(EvidenceType)
    cases: list[CalibrationCase] = []
    records: list[CaseCategoryRecord] = []

    for role in (CaseRole.CALIBRATION, CaseRole.HELD_OUT_VALIDATION):
        for i, tag in enumerate(CaseCategoryTag):
            semantics = semantics_cycle[i % len(semantics_cycle)]
            case = _case(role=role, semantics=semantics, coverage=(i % 2 == 0))
            cases.append(case)
            records.append(
                CaseCategoryRecord(
                    case_id=case.case_id,
                    categories=(tag,),
                    evidence_types=(evidence_cycle[i % len(evidence_cycle)],),
                )
            )

    blind = _case(role=CaseRole.BLIND_ACTOR_HOLDOUT, semantics=LabelSemantics.ATTRIBUTABLE)
    excluded = _case(role=CaseRole.EXCLUDED, semantics=LabelSemantics.ATTRIBUTABLE)
    for extra in (blind, excluded):
        cases.append(extra)
        records.append(CaseCategoryRecord(case_id=extra.case_id))

    cases_t = tuple(cases)
    return _manifest(cases_t), cases_t, tuple(records)


# ===========================================================================
# 1. Full corpus passes
# ===========================================================================


def test_full_corpus_is_category_complete() -> None:
    manifest, cases, records = _full_corpus()
    report = validate_category_completeness(manifest, cases, records)
    assert report.is_valid
    assert report.violations == ()
    assert report.calibration_corpus_version == manifest.calibration_corpus_version
    assert report.validation_schema_version == CATEGORY_VALIDATION_SCHEMA_VERSION
    # sanity on the fixture itself
    assert set(REQUIRED_CATEGORY_TAGS) == set(CaseCategoryTag)
    assert set(REQUIRED_LABEL_SEMANTICS) == set(LabelSemantics)
    assert set(REQUIRED_EVIDENCE_TYPES) == set(EvidenceType)


def test_require_valid_category_completeness_returns_when_valid() -> None:
    manifest, cases, records = _full_corpus()
    report = require_valid_category_completeness(manifest, cases, records)
    assert report.is_valid


# ===========================================================================
# 2. Each required category missing -> fail closed
# ===========================================================================


@pytest.mark.parametrize("missing_tag", list(CaseCategoryTag))
def test_each_required_category_missing_fails_closed(missing_tag: CaseCategoryTag) -> None:
    manifest, cases, records = _full_corpus()
    stripped = tuple(
        dataclasses.replace(r, categories=tuple(t for t in r.categories if t is not missing_tag))
        for r in records
    )
    report = validate_category_completeness(manifest, cases, stripped)
    assert not report.is_valid
    matches = [
        v
        for v in report.violations
        if v.violation_type is CategoryViolationType.MISSING_CATEGORY and v.category is missing_tag
    ]
    assert len(matches) == 1


# ===========================================================================
# 3. Each EvidenceType missing -> fail closed
# ===========================================================================


@pytest.mark.parametrize("missing_type", list(EvidenceType))
def test_each_evidence_type_missing_fails_closed(missing_type: EvidenceType) -> None:
    manifest, cases, records = _full_corpus()
    stripped = tuple(
        dataclasses.replace(
            r, evidence_types=tuple(e for e in r.evidence_types if e is not missing_type)
        )
        for r in records
    )
    report = validate_category_completeness(manifest, cases, stripped)
    assert not report.is_valid
    matches = [
        v
        for v in report.violations
        if v.violation_type is CategoryViolationType.MISSING_EVIDENCE_TYPE
        and v.evidence_type is missing_type
    ]
    assert len(matches) == 1


# ===========================================================================
# 4-5. Coverage diversity
# ===========================================================================


def _retarget_records(
    old_cases: tuple[CalibrationCase, ...],
    new_cases: tuple[CalibrationCase, ...],
    records: tuple[CaseCategoryRecord, ...],
) -> tuple[CaseCategoryRecord, ...]:
    """Re-key ``records`` (by position) onto ``new_cases``' possibly-changed
    ``case_id``s — needed because changing a case-identity field (e.g.
    ``coverage_assumptions``) changes ``case_id``."""
    by_old_id = {c.case_id: r for c, r in zip(old_cases, records, strict=True)}
    return tuple(
        dataclasses.replace(by_old_id[old.case_id], case_id=new.case_id)
        for old, new in zip(old_cases, new_cases, strict=True)
    )


def test_no_coverage_present_case_fails() -> None:
    manifest, cases, records = _full_corpus()
    absent_cases = tuple(dataclasses.replace(c, coverage_assumptions=()) for c in cases)
    absent_records = _retarget_records(cases, absent_cases, records)
    manifest2 = _manifest(absent_cases)
    report = validate_category_completeness(manifest2, absent_cases, absent_records)
    assert not report.is_valid
    assert any(
        v.violation_type is CategoryViolationType.NO_COVERAGE_PRESENT_CASE
        for v in report.violations
    )


def test_no_coverage_absent_case_fails() -> None:
    manifest, cases, records = _full_corpus()
    present_cases = tuple(
        dataclasses.replace(c, coverage_assumptions=("data-component::process-creation",))
        for c in cases
    )
    present_records = _retarget_records(cases, present_cases, records)
    manifest2 = _manifest(present_cases)
    report = validate_category_completeness(manifest2, present_cases, present_records)
    assert not report.is_valid
    assert any(
        v.violation_type is CategoryViolationType.NO_COVERAGE_ABSENT_CASE for v in report.violations
    )


# ===========================================================================
# 6. Each required population missing -> fail
# ===========================================================================


@pytest.mark.parametrize("missing_role", list(REQUIRED_NONEMPTY_POPULATIONS))
def test_each_required_population_missing_fails(missing_role: CaseRole) -> None:
    manifest, cases, records = _full_corpus()
    keep_cases = tuple(c for c in cases if c.case_role is not missing_role)
    keep_ids = {c.case_id for c in keep_cases}
    keep_records = tuple(r for r in records if r.case_id in keep_ids)
    manifest2 = _manifest(keep_cases)
    report = validate_category_completeness(manifest2, keep_cases, keep_records)
    assert not report.is_valid
    matches = [
        v
        for v in report.violations
        if v.violation_type is CategoryViolationType.EMPTY_POPULATION
        and v.population is missing_role
    ]
    assert len(matches) == 1


def test_excluded_accepted_as_final_test_reserved_population() -> None:
    # No FINAL_TEST role exists; EXCLUDED satisfies the population-non-emptiness
    # requirement on its own.
    assert not hasattr(CaseRole, "FINAL_TEST")
    manifest, cases, records = _full_corpus()
    assert any(c.case_role is CaseRole.EXCLUDED for c in cases)
    report = validate_category_completeness(manifest, cases, records)
    assert not any(
        v.violation_type is CategoryViolationType.EMPTY_POPULATION
        and v.population is CaseRole.EXCLUDED
        for v in report.violations
    )


# ===========================================================================
# 7-8. Required category absent from CALIBRATION / HELD_OUT_VALIDATION
# ===========================================================================


def test_category_absent_from_calibration_fails() -> None:
    manifest, cases, records = _full_corpus()
    target_tag = next(iter(CaseCategoryTag))
    target_case_id = next(
        c.case_id
        for c, r in zip(cases, records, strict=True)
        if c.case_role is CaseRole.CALIBRATION and target_tag in r.categories
    )
    stripped = tuple(
        dataclasses.replace(r, categories=()) if r.case_id == target_case_id else r for r in records
    )
    report = validate_category_completeness(manifest, cases, stripped)
    assert not report.is_valid
    matches = [
        v
        for v in report.violations
        if v.violation_type is CategoryViolationType.CATEGORY_MISSING_FROM_POPULATION
        and v.category is target_tag
        and v.population is CaseRole.CALIBRATION
    ]
    assert len(matches) == 1
    # the tag is still globally present (via HELD_OUT_VALIDATION), so it must
    # NOT also be reported as entirely MISSING_CATEGORY
    assert not any(
        v.violation_type is CategoryViolationType.MISSING_CATEGORY and v.category is target_tag
        for v in report.violations
    )


def test_category_absent_from_held_out_validation_fails() -> None:
    manifest, cases, records = _full_corpus()
    target_tag = next(iter(CaseCategoryTag))
    target_case_id = next(
        c.case_id
        for c, r in zip(cases, records, strict=True)
        if c.case_role is CaseRole.HELD_OUT_VALIDATION and target_tag in r.categories
    )
    stripped = tuple(
        dataclasses.replace(r, categories=()) if r.case_id == target_case_id else r for r in records
    )
    report = validate_category_completeness(manifest, cases, stripped)
    assert not report.is_valid
    matches = [
        v
        for v in report.violations
        if v.violation_type is CategoryViolationType.CATEGORY_MISSING_FROM_POPULATION
        and v.category is target_tag
        and v.population is CaseRole.HELD_OUT_VALIDATION
    ]
    assert len(matches) == 1


def test_label_semantics_absent_from_calibration_fails() -> None:
    manifest, cases, records = _full_corpus()
    target = LabelSemantics.UNATTRIBUTABLE_BY_DESIGN
    demoted = tuple(
        dataclasses.replace(c, case_role=CaseRole.EXCLUDED)
        if c.case_role is CaseRole.CALIBRATION and c.ground_truth.label_semantics is target
        else c
        for c in cases
    )
    manifest2 = _manifest(demoted)
    report = validate_category_completeness(manifest2, demoted, records)
    assert not report.is_valid
    assert any(
        v.violation_type is CategoryViolationType.CATEGORY_MISSING_FROM_POPULATION
        and v.label_semantics is target
        and v.population is CaseRole.CALIBRATION
        for v in report.violations
    )


# ===========================================================================
# 9. Non-mutation
# ===========================================================================


def test_validator_does_not_mutate_inputs() -> None:
    manifest, cases, records = _full_corpus()
    cases_before = copy.deepcopy(cases)
    records_before = copy.deepcopy(records)
    version_before = manifest.calibration_corpus_version
    entries_before = copy.deepcopy(manifest.case_entries)

    validate_category_completeness(manifest, cases, records)

    assert cases == cases_before
    assert records == records_before
    assert manifest.calibration_corpus_version == version_before
    assert manifest.case_entries == entries_before


# ===========================================================================
# 10. No ATT&CK inference
# ===========================================================================


def test_validator_never_consults_attack_knowledge() -> None:
    tree = ast.parse(module_path.read_text(encoding="utf-8"))
    imports = [
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module is not None
    ]
    assert not any("attack_knowledge" in m for m in imports)
    assert not any(
        m == "attribution_platform.attribution" or m.startswith("attribution_platform.attribution.")
        for m in imports
    )


# ===========================================================================
# 11-12. Determinism
# ===========================================================================


def test_repeated_calls_are_identical() -> None:
    manifest, cases, records = _full_corpus()
    first = validate_category_completeness(manifest, cases, records)
    second = validate_category_completeness(manifest, cases, records)
    assert first == second


def test_input_order_independence() -> None:
    manifest, cases, records = _full_corpus()
    by_id = {r.case_id: r for r in records}
    shuffled_cases = tuple(reversed(cases))
    shuffled_records = tuple(by_id[c.case_id] for c in shuffled_cases)
    forward = validate_category_completeness(manifest, cases, records)
    backward = validate_category_completeness(manifest, shuffled_cases, shuffled_records)
    assert forward == backward


_SUBPROCESS = """
from attribution_platform.calibration.category_validation import (
    CaseCategoryRecord, CaseCategoryTag, validate_category_completeness)
from attribution_platform.calibration.contracts import (
    ActorLabelSource, CalibrationCase, CaseRole, ExpectedOutcome,
    ExpectedOutputShape, GroundTruth, LabelConfidence, LabelSemantics, SourceKind)
from attribution_platform.calibration.manifest import CalibrationCorpusManifest, CorpusSourceEntry
from attribution_platform.domain.enums import EvidenceType

def case(i, role, semantics, tag):
    gt = GroundTruth(
        actor_label_source=ActorLabelSource.EMULATION_PLAN,
        label_semantics=semantics, label_confidence=LabelConfidence.MODERATE,
        actor_label=None if semantics == LabelSemantics.UNATTRIBUTABLE_BY_DESIGN else "APT-X")
    outcome = (ExpectedOutcome.INSUFFICIENT_EVIDENCE
               if semantics == LabelSemantics.UNATTRIBUTABLE_BY_DESIGN
               else ExpectedOutcome.LEADING_HYPOTHESIS)
    band = None if outcome == ExpectedOutcome.INSUFFICIENT_EVIDENCE else "likely"
    shape = ExpectedOutputShape(outcome=outcome, authorship_provenance="a",
        expected_likelihood_band=band)
    return CalibrationCase(
        scenario_family_id="fam-%d" % i, source_kind=SourceKind.EMULATED, source_ref="a@1",
        license="MIT", attack_kb_version="enterprise-attack-19.0",
        correlation_group_id="correlation-group::abc", sequence_id="behavioral-sequence::def",
        telemetry_provenance=("observation::o%d" % i,), ground_truth=gt,
        expected_output_shape=shape, case_role=role,
        coverage_assumptions=("dc",) if i % 2 == 0 else ())

semantics = list(LabelSemantics)
evidence = list(EvidenceType)
cases = []
records = []
n = 0
for role in (CaseRole.CALIBRATION, CaseRole.HELD_OUT_VALIDATION):
    for i, tag in enumerate(CaseCategoryTag):
        c = case(n, role, semantics[i % 4], tag)
        n += 1
        cases.append(c)
        records.append(CaseCategoryRecord(case_id=c.case_id, categories=(tag,),
                                           evidence_types=(evidence[i % 4],)))
blind = case(99, CaseRole.BLIND_ACTOR_HOLDOUT, LabelSemantics.ATTRIBUTABLE, None)
excluded = case(100, CaseRole.EXCLUDED, LabelSemantics.ATTRIBUTABLE, None)
cases += [blind, excluded]
records += [CaseCategoryRecord(case_id=blind.case_id), CaseCategoryRecord(case_id=excluded.case_id)]

source = CorpusSourceEntry(source_ref="a@1", source_kind=SourceKind.EMULATED, license="MIT",
    acquisition_provenance="a", transformation_provenance="t")
manifest = CalibrationCorpusManifest.from_cases(tuple(cases), [source],
    attack_kb_version="enterprise-attack-19.0")
report = validate_category_completeness(manifest, tuple(cases), tuple(records))
print(report.is_valid, len(report.violations), report.calibration_corpus_version)
"""


def _run_under_seed(seed: str) -> str:
    return subprocess.run(
        [sys.executable, "-c", _SUBPROCESS],
        capture_output=True,
        text=True,
        env={"PYTHONHASHSEED": seed, "PYTHONPATH": "src"},
        check=True,
    ).stdout.strip()


def test_pythonhashseed_independent() -> None:
    first = _run_under_seed("0")
    assert first
    assert first == _run_under_seed("1") == _run_under_seed("424242")


# ===========================================================================
# 13. Cross-identity guard / fail-closed
# ===========================================================================


def test_cases_manifest_mismatch_fails_closed() -> None:
    manifest, cases, records = _full_corpus()
    with pytest.raises(CalibrationError, match="mismatched triple"):
        validate_category_completeness(manifest, cases[:-1], records)


def test_cases_records_mismatch_fails_closed() -> None:
    manifest, cases, records = _full_corpus()
    with pytest.raises(CalibrationError, match="mismatched triple"):
        validate_category_completeness(manifest, cases, records[:-1])


def test_duplicate_record_case_id_fails_closed() -> None:
    manifest, cases, records = _full_corpus()
    with pytest.raises(CalibrationError, match="duplicate case_id"):
        validate_category_completeness(manifest, cases, records + (records[0],))


def test_wrong_argument_types_fail_closed() -> None:
    manifest, cases, records = _full_corpus()
    with pytest.raises(CalibrationError):
        validate_category_completeness("not-a-manifest", cases, records)  # type: ignore[arg-type]
    with pytest.raises(CalibrationError):
        validate_category_completeness(manifest, list(cases), records)  # type: ignore[arg-type]
    with pytest.raises(CalibrationError):
        validate_category_completeness(manifest, cases, list(records))  # type: ignore[arg-type]
    with pytest.raises(CalibrationError):
        bad_records: tuple[CaseCategoryRecord, ...] = (*records, "not-a-record")  # type: ignore[arg-type]
        validate_category_completeness(manifest, cases, bad_records)


def test_require_valid_category_completeness_raises_on_invalid() -> None:
    manifest, cases, records = _full_corpus()
    stripped = tuple(dataclasses.replace(r, categories=()) for r in records)
    with pytest.raises(CalibrationError, match="category-incomplete"):
        require_valid_category_completeness(manifest, cases, stripped)


# ===========================================================================
# 14. Empty corpus is structurally valid input but reports everything missing
# ===========================================================================


def test_empty_corpus_reports_every_requirement_missing_without_raising() -> None:
    manifest = _manifest(())
    report = validate_category_completeness(manifest, (), ())
    assert not report.is_valid
    assert report.calibration_corpus_version == manifest.calibration_corpus_version
    violation_types = {v.violation_type for v in report.violations}
    assert CategoryViolationType.EMPTY_POPULATION in violation_types
    assert CategoryViolationType.MISSING_CATEGORY in violation_types
    assert CategoryViolationType.MISSING_LABEL_SEMANTICS in violation_types
    assert CategoryViolationType.MISSING_EVIDENCE_TYPE in violation_types
    assert CategoryViolationType.NO_COVERAGE_PRESENT_CASE in violation_types
    assert CategoryViolationType.NO_COVERAGE_ABSENT_CASE in violation_types


# ===========================================================================
# 15. Frozen / immutable outputs
# ===========================================================================


def test_report_and_violation_and_record_are_frozen() -> None:
    manifest, cases, records = _full_corpus()
    report = validate_category_completeness(manifest, cases, records)
    with pytest.raises(dataclasses.FrozenInstanceError):
        report.is_valid = False  # type: ignore[misc]
    with pytest.raises(dataclasses.FrozenInstanceError):
        records[0].case_id = "x"  # type: ignore[misc]
    if report.violations:
        with pytest.raises(dataclasses.FrozenInstanceError):
            report.violations[0].reason = "y"  # type: ignore[misc]


def test_report_is_hashable() -> None:
    manifest, cases, records = _full_corpus()
    report = validate_category_completeness(manifest, cases, records)
    assert isinstance(hash(report), int)


# ===========================================================================
# 16. No fitting / scoring / calibration_version vocabulary
# ===========================================================================


def test_no_fitting_or_scoring_vocabulary() -> None:
    # Structural guard on BOUND IDENTIFIERS only (never prose): the module
    # docstring legitimately *discusses* calibration_version/likelihood/WEP as
    # explicit non-goals, so a text substring check would false-positive on its
    # own disclaimers. Mirrors the traversal-module precedent
    # (test_traversal_module_never_references_scoring_or_calibration_vocabulary).
    tree = ast.parse(module_path.read_text(encoding="utf-8"))
    identifiers = (
        {node.id.lower() for node in ast.walk(tree) if isinstance(node, ast.Name)}
        | {node.attr.lower() for node in ast.walk(tree) if isinstance(node, ast.Attribute)}
        | {
            node.name.lower()
            for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef | ast.ClassDef)
        }
    )
    forbidden_substrings = (
        "calibration_version",
        "likelihood",
        "confidence_band",
        "wep",
        "decision_support",
        "fitted_parameter",
        "fitting",
    )
    for identifier in identifiers:
        for forbidden in forbidden_substrings:
            assert forbidden not in identifier, (
                f"category_validation.py binds identifier {identifier!r} referencing "
                f"out-of-scope vocabulary {forbidden!r}"
            )


def test_no_calibration_version_field_anywhere() -> None:
    for cls in (CategoryCompletenessReport, CaseCategoryRecord):
        names = {f.name for f in dataclasses.fields(cls)}
        assert "calibration_version" not in names
