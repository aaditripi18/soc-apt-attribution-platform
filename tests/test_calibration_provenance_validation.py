"""B1.5 — provenance / license correctness validation tests (ADR-0006
§D13/§D15).

Covers only the B1.5 correctness surface (SPDX-license membership, orphan
sources, structural provenance adequacy) over a B1.3-structurally-valid
manifest. Does not duplicate B1.3 (chain integrity) or B1.4 (split/actor). No
scoring/fitting/ATT&CK/redistribution/calibration_version is exercised (none
exists).
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
from attribution_platform.calibration.provenance_validation import (
    PROVENANCE_VALIDATION_SCHEMA_VERSION,
    SPDX_LICENSE_ALLOWLIST,
    ProvenanceValidationReport,
    ProvenanceValidationViolation,
    ProvenanceViolationType,
    require_valid_provenance,
    validate_provenance,
)

_KB = "enterprise-attack-19.0"


def _case(
    *,
    source_ref: str = "a@1",
    license: str = "MIT",
    source_kind: SourceKind = SourceKind.EMULATED,
    family: str = "fam-1",
    telemetry: tuple[str, ...] = ("observation::o1",),
) -> CalibrationCase:
    return CalibrationCase(
        scenario_family_id=family,
        source_kind=source_kind,
        source_ref=source_ref,
        license=license,
        attack_kb_version=_KB,
        correlation_group_id="correlation-group::abc",
        sequence_id="behavioral-sequence::def",
        telemetry_provenance=telemetry,
        ground_truth=GroundTruth(
            actor_label_source=ActorLabelSource.EMULATION_PLAN,
            label_semantics=LabelSemantics.ATTRIBUTABLE,
            label_confidence=LabelConfidence.MODERATE,
            actor_label="APT-X",
        ),
        expected_output_shape=ExpectedOutputShape(
            outcome=ExpectedOutcome.LEADING_HYPOTHESIS,
            authorship_provenance="analyst",
            expected_likelihood_band="likely",
        ),
        case_role=CaseRole.CALIBRATION,
    )


def _source(
    *,
    source_ref: str = "a@1",
    license: str = "MIT",
    source_kind: SourceKind = SourceKind.EMULATED,
    acquisition_provenance: str = "downloaded from the caldera repo tag v4.2",
    transformation_provenance: str = "replayed through the deterministic pipeline",
) -> CorpusSourceEntry:
    return CorpusSourceEntry(
        source_ref=source_ref,
        source_kind=source_kind,
        license=license,
        acquisition_provenance=acquisition_provenance,
        transformation_provenance=transformation_provenance,
    )


def _manifest(
    cases: list[CalibrationCase], sources: list[CorpusSourceEntry]
) -> CalibrationCorpusManifest:
    return CalibrationCorpusManifest.from_cases(cases, sources, attack_kb_version=_KB)


# --- 1-2. valid + allowlist ------------------------------------------------


def test_valid_manifest_is_valid() -> None:
    report = validate_provenance(_manifest([_case()], [_source()]))
    assert report.is_valid
    assert report.violations == ()
    assert report.validation_schema_version == PROVENANCE_VALIDATION_SCHEMA_VERSION


@pytest.mark.parametrize("spdx", sorted(SPDX_LICENSE_ALLOWLIST))
def test_each_allowlisted_license_passes(spdx: str) -> None:
    manifest = _manifest(
        [_case(license=spdx)],
        [_source(license=spdx)],
    )
    assert validate_provenance(manifest).is_valid


def test_allowlist_is_the_documented_set() -> None:
    assert sorted(SPDX_LICENSE_ALLOWLIST) == ["Apache-2.0", "GPL-3.0", "MIT"]


# --- 3. invalid / non-allowlisted license ----------------------------------


@pytest.mark.parametrize("bad", ["proprietary", "mit", "apache-2.0", "GPL", "open-source"])
def test_non_allowlisted_license_violates(bad: str) -> None:
    # case + source agree (B1.3 passes), but the license is not an allowlisted SPDX id.
    manifest = _manifest([_case(license=bad)], [_source(license=bad)])
    report = validate_provenance(manifest)
    assert not report.is_valid
    v = next(
        x
        for x in report.violations
        if x.violation_type is ProvenanceViolationType.INVALID_SPDX_LICENSE
    )
    assert v.source_refs == ("a@1",)
    assert v.license == bad


# --- 4-5. placeholder provenance -------------------------------------------


@pytest.mark.parametrize("placeholder", ["n/a", "N/A", " none ", "UNKNOWN", "todo", "TBD", "-"])
def test_placeholder_acquisition_violates(placeholder: str) -> None:
    manifest = _manifest([_case()], [_source(acquisition_provenance=placeholder)])
    report = validate_provenance(manifest)
    assert any(
        v.violation_type is ProvenanceViolationType.INADEQUATE_ACQUISITION_PROVENANCE
        for v in report.violations
    )


@pytest.mark.parametrize("placeholder", ["n/a", "None", "tbd"])
def test_placeholder_transformation_violates(placeholder: str) -> None:
    manifest = _manifest([_case()], [_source(transformation_provenance=placeholder)])
    report = validate_provenance(manifest)
    assert any(
        v.violation_type is ProvenanceViolationType.INADEQUATE_TRANSFORMATION_PROVENANCE
        for v in report.violations
    )


# --- 6. orphan source ------------------------------------------------------


def test_orphan_source_violates() -> None:
    # "a@1" is used; "orphan@1" is registered but referenced by no case.
    manifest = _manifest(
        [_case(source_ref="a@1")],
        [_source(source_ref="a@1"), _source(source_ref="orphan@1")],
    )
    report = validate_provenance(manifest)
    orphans = [
        v
        for v in report.violations
        if v.violation_type is ProvenanceViolationType.ORPHAN_SOURCE_ENTRY
    ]
    assert len(orphans) == 1
    assert orphans[0].source_refs == ("orphan@1",)


# --- 7-8. sharing / full coverage ------------------------------------------


def test_multiple_cases_share_one_source_valid() -> None:
    manifest = _manifest(
        [_case(telemetry=("observation::o1",)), _case(telemetry=("observation::o2",))],
        [_source()],
    )
    assert validate_provenance(manifest).is_valid


def test_source_used_by_every_case_no_orphan() -> None:
    manifest = _manifest(
        [_case(source_ref="a@1"), _case(source_ref="b@1", telemetry=("observation::o2",))],
        [_source(source_ref="a@1"), _source(source_ref="b@1")],
    )
    report = validate_provenance(manifest)
    assert not any(
        v.violation_type is ProvenanceViolationType.ORPHAN_SOURCE_ENTRY for v in report.violations
    )


# --- 9. empty ---------------------------------------------------------------


def test_empty_manifest_is_valid() -> None:
    manifest = _manifest([], [])
    report = validate_provenance(manifest)
    assert report.is_valid
    assert report.violations == ()


# --- 10. multiple simultaneous violation types -----------------------------


def test_multiple_violation_types() -> None:
    manifest = _manifest(
        [_case(source_ref="a@1", license="proprietary")],
        [
            _source(source_ref="a@1", license="proprietary", acquisition_provenance="n/a"),
            _source(source_ref="orphan@1"),
        ],
    )
    report = validate_provenance(manifest)
    types = {v.violation_type for v in report.violations}
    assert ProvenanceViolationType.INVALID_SPDX_LICENSE in types
    assert ProvenanceViolationType.INADEQUATE_ACQUISITION_PROVENANCE in types
    assert ProvenanceViolationType.ORPHAN_SOURCE_ENTRY in types


# --- 11-13. determinism ----------------------------------------------------


def test_violation_ordering_deterministic() -> None:
    manifest = _manifest(
        [_case(source_ref="a@1", license="proprietary")],
        [
            _source(source_ref="z@1"),
            _source(source_ref="a@1", license="proprietary", transformation_provenance="tbd"),
        ],
    )
    report = validate_provenance(manifest)
    keys = [v._sort_key() for v in report.violations]
    assert keys == sorted(keys)


def test_repeated_validation_identical() -> None:
    manifest = _manifest([_case(license="proprietary")], [_source(license="proprietary")])
    assert validate_provenance(manifest) == validate_provenance(manifest)


def test_input_independent_source_order() -> None:
    # Source entries are canonicalized by the manifest, so validation is stable.
    m1 = _manifest(
        [_case(source_ref="a@1")], [_source(source_ref="a@1"), _source(source_ref="z@1")]
    )
    m2 = _manifest(
        [_case(source_ref="a@1")], [_source(source_ref="z@1"), _source(source_ref="a@1")]
    )
    assert validate_provenance(m1) == validate_provenance(m2)


_SUBPROCESS = """
from attribution_platform.calibration.contracts import (
    ActorLabelSource, CalibrationCase, CaseRole, ExpectedOutcome,
    ExpectedOutputShape, GroundTruth, LabelConfidence, LabelSemantics, SourceKind,
)
from attribution_platform.calibration.manifest import (
    CalibrationCorpusManifest, CorpusSourceEntry,
)
from attribution_platform.calibration.provenance_validation import validate_provenance

def case(sref, lic):
    return CalibrationCase(
        scenario_family_id="fam", source_kind=SourceKind.EMULATED, source_ref=sref,
        license=lic, attack_kb_version="enterprise-attack-19.0",
        correlation_group_id="correlation-group::abc", sequence_id="behavioral-sequence::def",
        telemetry_provenance=("observation::o1",),
        ground_truth=GroundTruth(
            actor_label_source=ActorLabelSource.EMULATION_PLAN,
            label_semantics=LabelSemantics.ATTRIBUTABLE,
            label_confidence=LabelConfidence.MODERATE, actor_label="APT-X"),
        expected_output_shape=ExpectedOutputShape(
            outcome=ExpectedOutcome.LEADING_HYPOTHESIS,
            authorship_provenance="a", expected_likelihood_band="likely"),
        case_role=CaseRole.CALIBRATION)

def src(sref, lic="MIT", acq="a", trans="t"):
    return CorpusSourceEntry(source_ref=sref, source_kind=SourceKind.EMULATED,
        license=lic, acquisition_provenance=acq, transformation_provenance=trans)

m = CalibrationCorpusManifest.from_cases(
    [case("a@1", "proprietary")],
    [src("a@1", "proprietary", acq="n/a"), src("z@1")],
    attack_kb_version="enterprise-attack-19.0")
r = validate_provenance(m)
print("|".join(v.violation_type.value + ":" + ",".join(v.source_refs) for v in r.violations))
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


# --- 15-16. immutability ---------------------------------------------------


def test_manifest_not_mutated() -> None:
    manifest = _manifest([_case(license="proprietary")], [_source(license="proprietary")])
    before_version = manifest.calibration_corpus_version
    before_sources = copy.deepcopy(manifest.source_entries)
    validate_provenance(manifest)
    assert manifest.calibration_corpus_version == before_version
    assert manifest.source_entries == before_sources


def test_report_and_violation_frozen() -> None:
    report = validate_provenance(_manifest([], []))
    with pytest.raises(dataclasses.FrozenInstanceError):
        report.is_valid = False  # type: ignore[misc]
    v = ProvenanceValidationViolation(
        violation_type=ProvenanceViolationType.ORPHAN_SOURCE_ENTRY,
        source_refs=("s",),
        reason="x",
    )
    with pytest.raises(dataclasses.FrozenInstanceError):
        v.reason = "y"  # type: ignore[misc]


# --- 17. corpus version echoed ---------------------------------------------


def test_corpus_version_echoed_unchanged() -> None:
    manifest = _manifest([_case()], [_source()])
    report = validate_provenance(manifest)
    assert report.calibration_corpus_version == manifest.calibration_corpus_version


# --- 18-21. boundaries -----------------------------------------------------


def test_no_calibration_version_or_numeric_fields() -> None:
    for cls in (ProvenanceValidationReport, ProvenanceValidationViolation):
        names = {f.name for f in dataclasses.fields(cls)}
        assert "calibration_version" not in names
        for f in dataclasses.fields(cls):
            assert f.type not in ("float", "int")


def test_no_attack_dependency_and_no_redistribution() -> None:
    import attribution_platform.calibration.provenance_validation as mod

    with open(mod.__file__, encoding="utf-8") as f:
        text = f.read()
    assert "attack_knowledge" not in text
    assert "import attribution_platform.attribution" not in text
    # redistribution_constraint remains deferred: no field, no violation type.
    assert not any("redistribution" in v.value for v in ProvenanceViolationType)


# --- 22-23. require_valid_provenance ---------------------------------------


def test_require_valid_provenance_returns_when_valid() -> None:
    assert require_valid_provenance(_manifest([_case()], [_source()])).is_valid


def test_require_valid_provenance_raises_on_invalid() -> None:
    manifest = _manifest([_case(license="proprietary")], [_source(license="proprietary")])
    with pytest.raises(CalibrationError, match="provenance/licensing is invalid"):
        require_valid_provenance(manifest)


# --- B1.3 non-duplication --------------------------------------------------


def test_b13_valid_manifest_can_still_be_b15_invalid() -> None:
    # A manifest that is fully valid by B1.3 (case/source license agree, provenance
    # non-empty, sources registered) can still be B1.5-invalid on the correctness
    # surface B1.3 does not own (non-SPDX license) -- proving B1.5 adds a distinct
    # layer rather than duplicating B1.3.
    manifest = _manifest([_case(license="proprietary")], [_source(license="proprietary")])
    assert manifest.calibration_corpus_version  # B1.3 constructed it successfully
    assert not validate_provenance(manifest).is_valid


# --- 24. public exports ----------------------------------------------------


def test_public_exports() -> None:
    import attribution_platform.calibration as calibration

    for name in (
        "validate_provenance",
        "require_valid_provenance",
        "ProvenanceValidationReport",
        "ProvenanceValidationViolation",
        "ProvenanceViolationType",
        "PROVENANCE_VALIDATION_SCHEMA_VERSION",
        "SPDX_LICENSE_ALLOWLIST",
    ):
        assert name in calibration.__all__
        assert getattr(calibration, name) is not None
