"""B1.6 — corpus composition description tests (ADR-0006).

Covers only the B1.6 descriptive surface: raw canonically-sorted counts over
``(manifest, cases)``. B1.6 is not a validator, so nothing here exercises
validity, violations, scores, thresholds, ATT&CK, or ``calibration_version``
(none exists in B1.6).
"""

from __future__ import annotations

import copy
import dataclasses
import itertools
import subprocess
import sys

import pytest

import attribution_platform.calibration as calibration
from attribution_platform.calibration.composition import (
    COMPOSITION_SCHEMA_VERSION,
    CorpusCompositionReport,
    describe_corpus_composition,
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

_KB = "enterprise-attack-19.0"
_counter = itertools.count()


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


def _shape(outcome: ExpectedOutcome) -> ExpectedOutputShape:
    return ExpectedOutputShape(
        outcome=outcome,
        authorship_provenance="analyst",
        expected_likelihood_band=(
            "likely" if outcome is ExpectedOutcome.LEADING_HYPOTHESIS else None
        ),
    )


def _case(
    *,
    role: CaseRole = CaseRole.CALIBRATION,
    kind: SourceKind = SourceKind.EMULATED,
    semantics: LabelSemantics = LabelSemantics.ATTRIBUTABLE,
    outcome: ExpectedOutcome = ExpectedOutcome.LEADING_HYPOTHESIS,
    actor: str | None = "APT-X",
    family: str = "fam-1",
    source_ref: str = "a@1",
    license: str = "MIT",
) -> CalibrationCase:
    if semantics is LabelSemantics.UNATTRIBUTABLE_BY_DESIGN:
        outcome = ExpectedOutcome.INSUFFICIENT_EVIDENCE
    return CalibrationCase(
        scenario_family_id=family,
        source_kind=kind,
        source_ref=source_ref,
        license=license,
        attack_kb_version=_KB,
        correlation_group_id="correlation-group::abc",
        sequence_id="behavioral-sequence::def",
        telemetry_provenance=(f"observation::o{next(_counter)}",),
        ground_truth=_truth(semantics, actor),
        expected_output_shape=_shape(outcome),
        case_role=role,
    )


def _manifest(cases: tuple[CalibrationCase, ...]) -> CalibrationCorpusManifest:
    sources = {
        (c.source_ref, c.source_kind, c.license): CorpusSourceEntry(
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


def _describe(*cases: CalibrationCase) -> CorpusCompositionReport:
    return describe_corpus_composition(_manifest(cases), cases)


# --- 1. valid composition report -------------------------------------------


def test_valid_composition_report() -> None:
    cases = (
        _case(family="f1", source_ref="a@1"),
        _case(family="f1", source_ref="a@1", role=CaseRole.HELD_OUT_VALIDATION),
        _case(family="f2", source_ref="b@1", license="Apache-2.0", kind=SourceKind.SYNTHETIC),
    )
    manifest = _manifest(cases)
    report = describe_corpus_composition(manifest, cases)
    assert isinstance(report, CorpusCompositionReport)
    assert report.total_cases == 3
    assert report.distinct_sources == 2
    assert report.distinct_scenario_families == 2
    assert report.composition_schema_version == COMPOSITION_SCHEMA_VERSION
    assert report.calibration_corpus_version == manifest.calibration_corpus_version


# --- 2. empty corpus --------------------------------------------------------


def test_empty_corpus_is_valid_and_descriptive() -> None:
    manifest = _manifest(())
    report = describe_corpus_composition(manifest, ())
    assert report.total_cases == 0
    assert report.distinct_sources == 0
    assert report.distinct_scenario_families == 0
    for f in dataclasses.fields(report):
        if f.name.endswith("_distribution") or f.name.startswith("cases_per_"):
            assert getattr(report, f.name) == ()
    assert report.calibration_corpus_version == manifest.calibration_corpus_version


# --- 3-6. every enum value --------------------------------------------------


def test_all_case_roles_counted() -> None:
    report = _describe(*(_case(role=r) for r in CaseRole))
    assert report.role_distribution == tuple(sorted((r.value, 1) for r in CaseRole))


def test_all_source_kinds_counted() -> None:
    report = _describe(*(_case(kind=k, source_ref=f"s-{k.value}@1") for k in SourceKind))
    assert report.source_kind_distribution == tuple(sorted((k.value, 1) for k in SourceKind))


def test_all_label_semantics_counted() -> None:
    report = _describe(*(_case(semantics=s) for s in LabelSemantics))
    assert report.label_semantics_distribution == tuple(
        sorted((s.value, 1) for s in LabelSemantics)
    )


def test_both_expected_outcomes_counted() -> None:
    report = _describe(
        _case(outcome=ExpectedOutcome.LEADING_HYPOTHESIS),
        _case(outcome=ExpectedOutcome.LEADING_HYPOTHESIS),
        _case(outcome=ExpectedOutcome.INSUFFICIENT_EVIDENCE),
    )
    assert report.expected_outcome_distribution == (
        ("insufficient_evidence", 1),
        ("leading_hypothesis", 2),
    )


# --- 7-8. attributable-actor counting only ---------------------------------


def test_attributable_actor_counting_only() -> None:
    report = _describe(
        _case(actor="APT-X"),
        _case(actor="APT-X"),
        _case(actor="APT-Y"),
        _case(semantics=LabelSemantics.DISPUTED, actor="APT-Z"),
        _case(semantics=LabelSemantics.UNKNOWN, actor="APT-Q"),
        _case(semantics=LabelSemantics.UNATTRIBUTABLE_BY_DESIGN),
    )
    assert report.attributable_actor_distribution == (("APT-X", 2), ("APT-Y", 1))


def test_non_attributable_actors_excluded() -> None:
    report = _describe(
        _case(semantics=LabelSemantics.DISPUTED, actor="APT-Z"),
        _case(semantics=LabelSemantics.UNKNOWN, actor="APT-Q"),
        _case(semantics=LabelSemantics.UNATTRIBUTABLE_BY_DESIGN),
    )
    assert report.attributable_actor_distribution == ()


def test_actor_labels_not_normalized_or_alias_resolved() -> None:
    report = _describe(_case(actor="APT-X"), _case(actor="apt-x"), _case(actor="APT X"))
    assert report.attributable_actor_distribution == (("APT X", 1), ("APT-X", 1), ("apt-x", 1))


# --- 9-12. source / family / license / outcome counts ----------------------


def test_source_counts() -> None:
    report = _describe(_case(source_ref="a@1"), _case(source_ref="a@1"), _case(source_ref="b@1"))
    assert report.distinct_sources == 2
    assert report.cases_per_source_ref == (("a@1", 2), ("b@1", 1))


def test_family_counts() -> None:
    report = _describe(_case(family="f1"), _case(family="f1"), _case(family="f2"))
    assert report.distinct_scenario_families == 2
    assert report.cases_per_scenario_family == (("f1", 2), ("f2", 1))


def test_license_counts() -> None:
    report = _describe(
        _case(license="MIT", source_ref="a@1"),
        _case(license="MIT", source_ref="a@1"),
        _case(license="GPL-3.0", source_ref="g@1"),
    )
    assert report.license_distribution == (("GPL-3.0", 1), ("MIT", 2))


# --- 13-15. determinism -----------------------------------------------------


def test_distribution_ordering_is_canonical() -> None:
    report = _describe(
        _case(family="zeta", source_ref="z@1", license="MIT"),
        _case(family="alpha", source_ref="a@1", license="MIT"),
        _case(family="mid", source_ref="m@1", license="MIT"),
    )
    for f in dataclasses.fields(report):
        value = getattr(report, f.name)
        if isinstance(value, tuple):
            assert list(value) == sorted(value)
    assert [k for k, _ in report.cases_per_scenario_family] == ["alpha", "mid", "zeta"]


def test_input_order_independence() -> None:
    cases = (
        _case(family="f1", source_ref="a@1", actor="APT-X"),
        _case(family="f2", source_ref="b@1", actor="APT-Y", role=CaseRole.EXCLUDED),
        _case(family="f3", source_ref="c@1", semantics=LabelSemantics.DISPUTED),
    )
    manifest = _manifest(cases)
    forward = describe_corpus_composition(manifest, cases)
    backward = describe_corpus_composition(manifest, tuple(reversed(cases)))
    assert forward == backward


def test_repeated_call_determinism() -> None:
    cases = (_case(family="f1"), _case(family="f2", source_ref="b@1"))
    manifest = _manifest(cases)
    first = describe_corpus_composition(manifest, cases)
    assert first == describe_corpus_composition(manifest, cases)
    assert hash(first) == hash(describe_corpus_composition(manifest, cases))


_SUBPROCESS = """
from attribution_platform.calibration.contracts import *
from attribution_platform.calibration.manifest import *
from attribution_platform.calibration.composition import describe_corpus_composition

def case(i, fam, sref, actor):
    return CalibrationCase(
        scenario_family_id=fam, source_kind=SourceKind.EMULATED, source_ref=sref,
        license="MIT", attack_kb_version="enterprise-attack-19.0",
        correlation_group_id="correlation-group::abc", sequence_id="behavioral-sequence::def",
        telemetry_provenance=("observation::o%d" % i,),
        ground_truth=GroundTruth(
            actor_label_source=ActorLabelSource.EMULATION_PLAN,
            label_semantics=LabelSemantics.ATTRIBUTABLE,
            label_confidence=LabelConfidence.MODERATE, actor_label=actor),
        expected_output_shape=ExpectedOutputShape(
            outcome=ExpectedOutcome.LEADING_HYPOTHESIS,
            authorship_provenance="a", expected_likelihood_band="likely"),
        case_role=CaseRole.CALIBRATION)

def src(sref):
    return CorpusSourceEntry(source_ref=sref, source_kind=SourceKind.EMULATED,
        license="MIT", acquisition_provenance="a", transformation_provenance="t")

cases = tuple(case(i, "fam-%d" % (i % 3), "s%d@1" % (i % 2), "APT-%d" % (i % 4))
              for i in range(12))
m = CalibrationCorpusManifest.from_cases(
    cases, [src("s0@1"), src("s1@1")], attack_kb_version="enterprise-attack-19.0")
print(describe_corpus_composition(m, cases))
"""


def _report_under_seed(seed: str) -> str:
    out = subprocess.run(
        [sys.executable, "-c", _SUBPROCESS],
        capture_output=True,
        text=True,
        env={"PYTHONHASHSEED": seed, "PYTHONPATH": "src"},
        check=True,
    )
    return out.stdout.strip()


def test_pythonhashseed_independent() -> None:
    assert _report_under_seed("0") == _report_under_seed("1") == _report_under_seed("424242")


# --- 16-17. cross-identity guard / echoed version --------------------------


def test_case_missing_from_cases_fails_closed() -> None:
    cases = (_case(family="f1"), _case(family="f2"))
    manifest = _manifest(cases)
    with pytest.raises(CalibrationError, match="do not match"):
        describe_corpus_composition(manifest, cases[:1])


def test_extra_case_not_in_manifest_fails_closed() -> None:
    in_manifest = (_case(family="f1"),)
    manifest = _manifest(in_manifest)
    with pytest.raises(CalibrationError, match="do not match"):
        describe_corpus_composition(manifest, (*in_manifest, _case(family="f2")))


def test_empty_cases_against_nonempty_manifest_fails_closed() -> None:
    manifest = _manifest((_case(),))
    with pytest.raises(CalibrationError, match="do not match"):
        describe_corpus_composition(manifest, ())


def test_wrong_argument_types_fail_closed() -> None:
    cases = (_case(),)
    manifest = _manifest(cases)
    with pytest.raises(CalibrationError):
        describe_corpus_composition("not-a-manifest", cases)  # type: ignore[arg-type]
    with pytest.raises(CalibrationError):
        describe_corpus_composition(manifest, [cases[0]])  # type: ignore[arg-type]
    with pytest.raises(CalibrationError):
        describe_corpus_composition(manifest, ("not-a-case",))  # type: ignore[arg-type]


def test_both_arguments_are_mandatory() -> None:
    with pytest.raises(TypeError):
        describe_corpus_composition(_manifest(()))  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        describe_corpus_composition()  # type: ignore[call-arg]


def test_corpus_version_echoed_unchanged() -> None:
    cases = (_case(),)
    manifest = _manifest(cases)
    before = manifest.calibration_corpus_version
    report = describe_corpus_composition(manifest, cases)
    assert report.calibration_corpus_version == before == manifest.calibration_corpus_version


# --- 18-19. immutability ----------------------------------------------------


def test_inputs_not_mutated() -> None:
    cases = (_case(family="f1"), _case(family="f2", source_ref="b@1"))
    manifest = _manifest(cases)
    cases_before = copy.deepcopy(cases)
    entries_before = copy.deepcopy(manifest.case_entries)
    version_before = manifest.calibration_corpus_version
    describe_corpus_composition(manifest, cases)
    assert cases == cases_before
    assert manifest.case_entries == entries_before
    assert manifest.calibration_corpus_version == version_before


def test_report_is_frozen_and_hashable() -> None:
    report = _describe(_case())
    with pytest.raises(dataclasses.FrozenInstanceError):
        report.total_cases = 99  # type: ignore[misc]
    assert isinstance(hash(report), int)
    for f in dataclasses.fields(report):
        assert not isinstance(getattr(report, f.name), dict | list | set)


def test_report_rejects_malformed_distribution() -> None:
    base = dataclasses.asdict(_describe(_case()))
    base["role_distribution"] = (("calibration", 0),)
    with pytest.raises(CalibrationError):
        CorpusCompositionReport(**base)
    base["role_distribution"] = (("calibration", 1), ("calibration", 2))
    with pytest.raises(CalibrationError):
        CorpusCompositionReport(**base)


# --- 20-24. boundaries ------------------------------------------------------


def test_report_has_exactly_the_locked_fields() -> None:
    assert {f.name for f in dataclasses.fields(CorpusCompositionReport)} == {
        "calibration_corpus_version",
        "composition_schema_version",
        "total_cases",
        "distinct_sources",
        "distinct_scenario_families",
        "role_distribution",
        "source_kind_distribution",
        "label_semantics_distribution",
        "expected_outcome_distribution",
        "attributable_actor_distribution",
        "license_distribution",
        "cases_per_scenario_family",
        "cases_per_source_ref",
    }


def test_no_calibration_version_or_numeric_parameters() -> None:
    names = {f.name for f in dataclasses.fields(CorpusCompositionReport)}
    assert "calibration_version" not in names
    report = _describe(_case(), _case(family="f2"))
    for f in dataclasses.fields(report):
        value = getattr(report, f.name)
        assert not isinstance(value, float)
        if isinstance(value, tuple):
            for _key, count in value:
                assert isinstance(count, int) and not isinstance(count, bool)


def test_no_score_ratio_percentage_or_concentration_fields() -> None:
    forbidden = (
        "score",
        "ratio",
        "percent",
        "concentration",
        "gini",
        "herfindahl",
        "weight",
        "threshold",
        "quality",
        "coverage",
        "is_valid",
        "violation",
        "confidence",
        "likelihood",
    )
    for f in dataclasses.fields(CorpusCompositionReport):
        assert not set(f.name.split("_")) & set(forbidden)


def test_no_attack_or_scoring_dependency() -> None:
    import attribution_platform.calibration.composition as mod

    with open(mod.__file__, encoding="utf-8") as fh:
        text = fh.read()
    imports = [ln for ln in text.splitlines() if ln.startswith(("import ", "from "))]
    joined = "\n".join(imports)
    assert "attack_knowledge" not in joined
    assert "attribution_platform.attribution" not in joined
    for allowed_only in imports:
        assert "attribution_platform.calibration." in allowed_only or allowed_only.startswith(
            ("from __future__", "from collections", "from dataclasses")
        )


def test_not_counted_fields_do_not_influence_report() -> None:
    # Cases differing only in fields B1.6 must never count yield equal reports.
    a = _case()
    b = dataclasses.replace(
        a,
        ground_truth=dataclasses.replace(
            a.ground_truth,
            label_confidence=LabelConfidence.LOW,
            actor_label_source=ActorLabelSource.INCIDENT_REPORT,
            campaign_context=("campaign-1",),
        ),
        expected_output_shape=dataclasses.replace(
            a.expected_output_shape,
            discriminating_evidence=("T1059",),
            expected_contradiction=("T1003",),
            expected_next_evidence=("T1078",),
        ),
    )
    report_a = describe_corpus_composition(_manifest((a,)), (a,))
    report_b = describe_corpus_composition(_manifest((b,)), (b,))
    for f in dataclasses.fields(CorpusCompositionReport):
        if f.name != "calibration_corpus_version":
            assert getattr(report_a, f.name) == getattr(report_b, f.name)


# --- 25. exports / no require_valid_* --------------------------------------


def test_public_exports() -> None:
    for name in (
        "describe_corpus_composition",
        "CorpusCompositionReport",
        "COMPOSITION_SCHEMA_VERSION",
    ):
        assert name in calibration.__all__
        assert getattr(calibration, name) is not None


def test_no_require_valid_composition_exists() -> None:
    import attribution_platform.calibration.composition as mod

    assert not hasattr(mod, "require_valid_composition")
    assert not hasattr(mod, "validate_composition")
    assert not hasattr(calibration, "require_valid_composition")
    assert not any(n.startswith("require_valid_") and "compos" in n for n in dir(calibration))
