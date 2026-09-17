"""B1.4 — split/leakage validation + blind-actor holdout readiness tests
(ADR-0006 §D9/§D10).

Covers only the B1.4 read-only validator: strict family->single-role
disjointness, blind-actor readiness/exclusion, label-semantics handling (no
silent negatives), determinism, empty-corpus, manifest interaction, and
boundary confirmations (no ATT&CK, no similarity, no calibration_version). No
scoring/fitting/ablation is exercised (none exists).
"""

from __future__ import annotations

import copy
import dataclasses
import subprocess
import sys

import pytest

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
from attribution_platform.calibration.split_validation import (
    NO_MANIFEST_CORPUS_VERSION,
    SPLIT_VALIDATION_SCHEMA_VERSION,
    SplitValidationReport,
    SplitValidationViolation,
    SplitViolationType,
    require_valid_split,
    validate_split,
)

_KB = "enterprise-attack-19.0"


def _shape(*, insufficient: bool = False) -> ExpectedOutputShape:
    if insufficient:
        return ExpectedOutputShape(
            outcome=ExpectedOutcome.INSUFFICIENT_EVIDENCE,
            authorship_provenance="analyst",
        )
    return ExpectedOutputShape(
        outcome=ExpectedOutcome.LEADING_HYPOTHESIS,
        authorship_provenance="analyst",
        expected_likelihood_band="likely",
    )


def _gt(
    *,
    semantics: LabelSemantics = LabelSemantics.ATTRIBUTABLE,
    actor: str | None = "APT-X",
    source: ActorLabelSource = ActorLabelSource.EMULATION_PLAN,
) -> GroundTruth:
    return GroundTruth(
        actor_label_source=source,
        label_semantics=semantics,
        label_confidence=LabelConfidence.MODERATE,
        actor_label=actor,
    )


def _case(
    *,
    family: str = "fam-1",
    role: CaseRole = CaseRole.CALIBRATION,
    telemetry: tuple[str, ...] = ("observation::o1",),
    ground_truth: GroundTruth | None = None,
    expected: ExpectedOutputShape | None = None,
) -> CalibrationCase:
    return CalibrationCase(
        scenario_family_id=family,
        source_kind=SourceKind.EMULATED,
        source_ref="s@1",
        license="Apache-2.0",
        attack_kb_version=_KB,
        correlation_group_id="correlation-group::abc",
        sequence_id="behavioral-sequence::def",
        telemetry_provenance=telemetry,
        ground_truth=ground_truth if ground_truth is not None else _gt(),
        expected_output_shape=expected if expected is not None else _shape(),
        case_role=role,
    )


# --- A. basic validity -----------------------------------------------------


def test_valid_split_is_valid() -> None:
    cases = (
        _case(family="fam-cal", role=CaseRole.CALIBRATION, telemetry=("observation::o1",)),
        _case(
            family="fam-val", role=CaseRole.HELD_OUT_VALIDATION, telemetry=("observation::o2",)
        ),
    )
    report = validate_split(cases)
    assert report.is_valid
    assert report.violations == ()
    assert report.validation_schema_version == SPLIT_VALIDATION_SCHEMA_VERSION
    assert report.calibration_corpus_version == NO_MANIFEST_CORPUS_VERSION


def test_empty_corpus_is_valid() -> None:
    report = validate_split(())
    assert report.is_valid
    assert report.violations == ()


def test_one_family_multiple_cases_same_role_is_valid() -> None:
    cases = (
        _case(family="fam-1", role=CaseRole.CALIBRATION, telemetry=("observation::o1",)),
        _case(family="fam-1", role=CaseRole.CALIBRATION, telemetry=("observation::o2",)),
    )
    assert validate_split(cases).is_valid


# --- B. family leakage -----------------------------------------------------


@pytest.mark.parametrize(
    ("role_a", "role_b"),
    [
        (CaseRole.CALIBRATION, CaseRole.HELD_OUT_VALIDATION),
        (CaseRole.CALIBRATION, CaseRole.BLIND_ACTOR_HOLDOUT),
        (CaseRole.HELD_OUT_VALIDATION, CaseRole.BLIND_ACTOR_HOLDOUT),
        (CaseRole.TIER1_STRUCTURAL, CaseRole.CALIBRATION),
        (CaseRole.EXCLUDED, CaseRole.CALIBRATION),
    ],
)
def test_family_split_across_roles_violates(role_a: CaseRole, role_b: CaseRole) -> None:
    cases = (
        _case(family="fam-x", role=role_a, telemetry=("observation::o1",)),
        _case(family="fam-x", role=role_b, telemetry=("observation::o2",)),
    )
    report = validate_split(cases)
    assert not report.is_valid
    types = {v.violation_type for v in report.violations}
    assert SplitViolationType.FAMILY_ROLE_LEAKAGE in types
    fam_violation = next(
        v
        for v in report.violations
        if v.violation_type is SplitViolationType.FAMILY_ROLE_LEAKAGE
    )
    assert fam_violation.scenario_family_ids == ("fam-x",)
    assert set(fam_violation.roles) == {role_a.value, role_b.value}


# --- C. blind actor --------------------------------------------------------


def test_valid_blind_actor_case() -> None:
    cases = (
        _case(
            family="fam-blind",
            role=CaseRole.BLIND_ACTOR_HOLDOUT,
            ground_truth=_gt(actor="APT-B"),
        ),
        _case(family="fam-cal", role=CaseRole.CALIBRATION, ground_truth=_gt(actor="APT-CAL")),
    )
    assert validate_split(cases).is_valid


def test_blind_actor_missing_label_violates() -> None:
    cases = (
        _case(
            family="fam-blind",
            role=CaseRole.BLIND_ACTOR_HOLDOUT,
            ground_truth=_gt(
                semantics=LabelSemantics.UNKNOWN, actor=None, source=ActorLabelSource.UNKNOWN
            ),
            expected=_shape(insufficient=True),
        ),
    )
    report = validate_split(cases)
    assert not report.is_valid
    assert any(
        v.violation_type is SplitViolationType.BLIND_ACTOR_HOLDOUT_NOT_ATTRIBUTABLE
        for v in report.violations
    )


def test_blind_actor_non_attributable_semantics_violates() -> None:
    cases = (
        _case(
            family="fam-blind",
            role=CaseRole.BLIND_ACTOR_HOLDOUT,
            ground_truth=_gt(semantics=LabelSemantics.DISPUTED, actor="APT-D"),
        ),
    )
    report = validate_split(cases)
    assert not report.is_valid
    assert any(
        v.violation_type is SplitViolationType.BLIND_ACTOR_HOLDOUT_NOT_ATTRIBUTABLE
        for v in report.violations
    )


def test_blind_actor_label_in_calibration_violates() -> None:
    cases = (
        _case(
            family="fam-blind",
            role=CaseRole.BLIND_ACTOR_HOLDOUT,
            ground_truth=_gt(actor="APT-B"),
        ),
        _case(family="fam-cal", role=CaseRole.CALIBRATION, ground_truth=_gt(actor="APT-B")),
    )
    report = validate_split(cases)
    assert not report.is_valid
    leak = [
        v
        for v in report.violations
        if v.violation_type is SplitViolationType.BLIND_ACTOR_IN_CALIBRATION
    ]
    assert len(leak) == 1
    assert leak[0].actor_label == "APT-B"
    assert leak[0].case_ids  # names the offending calibration case


def test_blind_actor_family_in_calibration_caught_by_family_rule() -> None:
    # Same family under BLIND_ACTOR_HOLDOUT and CALIBRATION -> family-role leakage.
    cases = (
        _case(
            family="fam-shared",
            role=CaseRole.BLIND_ACTOR_HOLDOUT,
            ground_truth=_gt(actor="APT-B"),
        ),
        _case(
            family="fam-shared",
            role=CaseRole.CALIBRATION,
            telemetry=("observation::o2",),
            ground_truth=_gt(actor="APT-B"),
        ),
    )
    report = validate_split(cases)
    assert not report.is_valid
    assert any(
        v.violation_type is SplitViolationType.FAMILY_ROLE_LEAKAGE for v in report.violations
    )


def test_multiple_blind_cases_same_actor_single_identity() -> None:
    cases = (
        _case(
            family="fam-b1",
            role=CaseRole.BLIND_ACTOR_HOLDOUT,
            telemetry=("observation::o1",),
            ground_truth=_gt(actor="APT-B"),
        ),
        _case(
            family="fam-b2",
            role=CaseRole.BLIND_ACTOR_HOLDOUT,
            telemetry=("observation::o2",),
            ground_truth=_gt(actor="APT-B"),
        ),
        _case(family="fam-cal", role=CaseRole.CALIBRATION, ground_truth=_gt(actor="APT-B")),
    )
    report = validate_split(cases)
    leak = [
        v
        for v in report.violations
        if v.violation_type is SplitViolationType.BLIND_ACTOR_IN_CALIBRATION
    ]
    assert len(leak) == 1  # one violation per actor, not per case
    assert leak[0].actor_label == "APT-B"


def test_two_distinct_actor_labels_are_distinct_identities() -> None:
    cases = (
        _case(family="fam-b", role=CaseRole.BLIND_ACTOR_HOLDOUT, ground_truth=_gt(actor="APT-B")),
        _case(family="fam-cal", role=CaseRole.CALIBRATION, ground_truth=_gt(actor="APT-OTHER")),
    )
    # APT-OTHER is not held out -> no blind-actor-in-calibration violation.
    assert validate_split(cases).is_valid


# --- D. label semantics (no silent negatives) ------------------------------


@pytest.mark.parametrize(
    ("semantics", "actor", "expected"),
    [
        (LabelSemantics.DISPUTED, "APT-D", _shape()),
        (LabelSemantics.UNKNOWN, None, _shape(insufficient=True)),
        (LabelSemantics.UNATTRIBUTABLE_BY_DESIGN, None, _shape(insufficient=True)),
    ],
)
def test_non_attributable_calibration_cases_allowed(
    semantics: LabelSemantics, actor: str | None, expected: ExpectedOutputShape
) -> None:
    source = ActorLabelSource.UNKNOWN if actor is None else ActorLabelSource.DATASET_ANNOTATION
    case = _case(
        family="fam-cal",
        role=CaseRole.CALIBRATION,
        ground_truth=_gt(semantics=semantics, actor=actor, source=source),
        expected=expected,
    )
    assert validate_split((case,)).is_valid


# --- E. determinism --------------------------------------------------------


def test_input_order_does_not_change_report() -> None:
    a = _case(family="fam-cal", role=CaseRole.CALIBRATION, telemetry=("observation::o1",))
    b = _case(
        family="fam-val", role=CaseRole.HELD_OUT_VALIDATION, telemetry=("observation::o2",)
    )
    r1 = validate_split((a, b))
    r2 = validate_split((b, a))
    assert r1 == r2


def test_violation_ordering_is_deterministic() -> None:
    cases = (
        _case(family="z-fam", role=CaseRole.CALIBRATION, telemetry=("observation::o1",)),
        _case(family="z-fam", role=CaseRole.EXCLUDED, telemetry=("observation::o2",)),
        _case(family="a-fam", role=CaseRole.CALIBRATION, telemetry=("observation::o3",)),
        _case(family="a-fam", role=CaseRole.HELD_OUT_VALIDATION, telemetry=("observation::o4",)),
    )
    report = validate_split(cases)
    keys = [v._sort_key() for v in report.violations]
    assert keys == sorted(keys)


def test_repeated_validation_identical() -> None:
    cases = (
        _case(family="fam-cal", role=CaseRole.CALIBRATION),
        _case(family="fam-cal", role=CaseRole.EXCLUDED, telemetry=("observation::o2",)),
    )
    assert validate_split(cases) == validate_split(cases)


_SUBPROCESS = """
from attribution_platform.calibration.contracts import (
    ActorLabelSource, CalibrationCase, CaseRole, ExpectedOutcome,
    ExpectedOutputShape, GroundTruth, LabelConfidence, LabelSemantics, SourceKind,
)
from attribution_platform.calibration.split_validation import validate_split

def mk(fam, role, o):
    return CalibrationCase(
        scenario_family_id=fam, source_kind=SourceKind.EMULATED, source_ref="s@1",
        license="Apache-2.0", attack_kb_version="enterprise-attack-19.0",
        correlation_group_id="correlation-group::abc", sequence_id="behavioral-sequence::def",
        telemetry_provenance=(o,),
        ground_truth=GroundTruth(
            actor_label_source=ActorLabelSource.EMULATION_PLAN,
            label_semantics=LabelSemantics.ATTRIBUTABLE,
            label_confidence=LabelConfidence.MODERATE, actor_label="APT-B"),
        expected_output_shape=ExpectedOutputShape(
            outcome=ExpectedOutcome.LEADING_HYPOTHESIS,
            authorship_provenance="a", expected_likelihood_band="likely"),
        case_role=role)

cases = (mk("z", CaseRole.CALIBRATION, "observation::o1"),
         mk("z", CaseRole.EXCLUDED, "observation::o2"),
         mk("cal", CaseRole.CALIBRATION, "observation::o3"))
r = validate_split(cases)
print("|".join(v.violation_type.value + ":" + ",".join(v.scenario_family_ids)
      for v in r.violations))
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
    assert _report_under_seed("0") == _report_under_seed("1") == _report_under_seed("98765")


# --- F. manifest interaction ----------------------------------------------


def _manifest_for(cases: tuple[CalibrationCase, ...]) -> CalibrationCorpusManifest:
    source = CorpusSourceEntry(
        source_ref="s@1",
        source_kind=SourceKind.EMULATED,
        license="Apache-2.0",
        acquisition_provenance="a",
        transformation_provenance="t",
    )
    return CalibrationCorpusManifest.from_cases(list(cases), [source], attack_kb_version=_KB)


def test_manifest_version_echoed_unchanged() -> None:
    cases = (_case(family="fam-cal", role=CaseRole.CALIBRATION),)
    manifest = _manifest_for(cases)
    report = validate_split(cases, manifest)
    assert report.calibration_corpus_version == manifest.calibration_corpus_version


def test_manifest_case_mismatch_fails_closed() -> None:
    cases = (_case(family="fam-cal", role=CaseRole.CALIBRATION),)
    manifest = _manifest_for(cases)
    other = (_case(family="fam-cal", role=CaseRole.CALIBRATION, telemetry=("observation::oX",)),)
    with pytest.raises(CalibrationError, match="do not correspond to the manifest"):
        validate_split(other, manifest)


def test_no_corpus_mutation() -> None:
    cases = (
        _case(family="fam-cal", role=CaseRole.CALIBRATION),
        _case(family="fam-cal", role=CaseRole.EXCLUDED, telemetry=("observation::o2",)),
    )
    manifest = _manifest_for(cases)
    before_cases = copy.deepcopy(cases)
    before_version = manifest.calibration_corpus_version
    validate_split(cases, manifest)
    assert cases == before_cases
    assert manifest.calibration_corpus_version == before_version


# --- G. boundaries ---------------------------------------------------------


def test_no_attack_dependency() -> None:
    import attribution_platform.calibration.split_validation as mod

    src = mod.__file__
    with open(src, encoding="utf-8") as f:
        text = f.read()
    assert "attack_knowledge" not in text
    assert "import attribution_platform.attribution" not in text


def test_no_calibration_version_or_numeric_fields() -> None:
    for cls in (SplitValidationReport, SplitValidationViolation):
        names = {f.name for f in dataclasses.fields(cls)}
        assert "calibration_version" not in names
        for f in dataclasses.fields(cls):
            assert f.type not in ("float", "int")


# --- H. immutability -------------------------------------------------------


def test_report_and_violation_frozen() -> None:
    report = validate_split(())
    with pytest.raises(dataclasses.FrozenInstanceError):
        report.is_valid = False  # type: ignore[misc]
    v = SplitValidationViolation(
        violation_type=SplitViolationType.FAMILY_ROLE_LEAKAGE,
        scenario_family_ids=("f",),
        case_ids=("c",),
        roles=("calibration",),
        reason="x",
    )
    with pytest.raises(dataclasses.FrozenInstanceError):
        v.reason = "y"  # type: ignore[misc]


# --- require_valid_split ---------------------------------------------------


def test_require_valid_split_raises_on_violation() -> None:
    cases = (
        _case(family="fam-x", role=CaseRole.CALIBRATION),
        _case(family="fam-x", role=CaseRole.HELD_OUT_VALIDATION, telemetry=("observation::o2",)),
    )
    with pytest.raises(CalibrationError, match="corpus split is invalid"):
        require_valid_split(cases)


def test_require_valid_split_returns_report_when_valid() -> None:
    report = require_valid_split((_case(),))
    assert report.is_valid


# --- I. public exports -----------------------------------------------------


def test_public_exports() -> None:
    import attribution_platform.calibration as calibration

    for name in (
        "validate_split",
        "require_valid_split",
        "SplitValidationReport",
        "SplitValidationViolation",
        "SplitViolationType",
        "SPLIT_VALIDATION_SCHEMA_VERSION",
        "NO_MANIFEST_CORPUS_VERSION",
    ):
        assert name in calibration.__all__
        assert getattr(calibration, name) is not None
