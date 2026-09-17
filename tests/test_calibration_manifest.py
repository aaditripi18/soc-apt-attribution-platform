"""B1.3 — calibration corpus manifest + ``calibration_corpus_version`` tests
(ADR-0006 §D12/§D13).

Covers only the B1.3 corpus-identity contract: manifest construction, the
deterministic ``calibration_corpus_version`` and its self-excluded hash
boundary, canonical ordering, fail-closed consistency (duplicate case ids,
mixed KB, source mismatch, mixed corpus schema), split-assignment derivation,
empty-corpus semantics, immutability, and ``PYTHONHASHSEED`` independence. No
split/leakage validation, no ``calibration_version``, no fitting, no scoring
(none exists).
"""

from __future__ import annotations

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
    CALIBRATION_CORPUS_VERSION_PREFIX,
    CALIBRATION_MANIFEST_SCHEMA_VERSION,
    CORPUS_VERSION_INPUT_FIELDS,
    CalibrationCorpusManifest,
    CorpusCaseEntry,
    CorpusSourceEntry,
    compute_calibration_corpus_version,
)
from attribution_platform.domain.serialization import to_canonical_json

_KB = "enterprise-attack-19.0"


def _shape() -> ExpectedOutputShape:
    return ExpectedOutputShape(
        outcome=ExpectedOutcome.LEADING_HYPOTHESIS,
        authorship_provenance="emulation-plan#1: analyst-authored",
        expected_likelihood_band="likely",
        discriminating_evidence=("distinctive-combo-A",),
    )


def _case(
    *,
    source_ref: str = "caldera@4.2:run-7",
    source_kind: SourceKind = SourceKind.EMULATED,
    license: str = "Apache-2.0",
    attack_kb_version: str = _KB,
    scenario_family_id: str = "family-001",
    case_role: CaseRole = CaseRole.CALIBRATION,
    telemetry: tuple[str, ...] = ("observation::o1", "evidence::e1"),
    corpus_schema_version: str | None = None,
    actor_label: str = "APT-X",
) -> CalibrationCase:
    kwargs: dict[str, object] = {
        "scenario_family_id": scenario_family_id,
        "source_kind": source_kind,
        "source_ref": source_ref,
        "license": license,
        "attack_kb_version": attack_kb_version,
        "correlation_group_id": "correlation-group::abc",
        "sequence_id": "behavioral-sequence::def",
        "telemetry_provenance": telemetry,
        "ground_truth": GroundTruth(
            actor_label_source=ActorLabelSource.EMULATION_PLAN,
            label_semantics=LabelSemantics.ATTRIBUTABLE,
            label_confidence=LabelConfidence.MODERATE,
            actor_label=actor_label,
        ),
        "expected_output_shape": _shape(),
        "case_role": case_role,
    }
    if corpus_schema_version is not None:
        kwargs["corpus_schema_version"] = corpus_schema_version
    return CalibrationCase(**kwargs)  # type: ignore[arg-type]


def _source(
    *,
    source_ref: str = "caldera@4.2:run-7",
    source_kind: SourceKind = SourceKind.EMULATED,
    license: str = "Apache-2.0",
    acquisition_provenance: str = "downloaded from caldera repo tag v4.2",
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
    cases: list[CalibrationCase] | None = None,
    sources: list[CorpusSourceEntry] | None = None,
    *,
    attack_kb_version: str = _KB,
) -> CalibrationCorpusManifest:
    if cases is None:
        cases = [_case()]
    if sources is None:
        sources = [_source()]
    return CalibrationCorpusManifest.from_cases(
        cases, sources, attack_kb_version=attack_kb_version
    )


# --- construction + version shape -----------------------------------------


def test_valid_manifest_and_version_shape() -> None:
    m = _manifest()
    assert m.calibration_corpus_version.startswith(f"{CALIBRATION_CORPUS_VERSION_PREFIX}::")
    assert len(m.calibration_corpus_version.split("::")[1]) == 64
    assert m.manifest_schema_version == CALIBRATION_MANIFEST_SCHEMA_VERSION
    assert m.corpus_schema_version == "calibration-case/1"
    assert len(m.case_entries) == 1


def test_version_is_field_init_false() -> None:
    fields = {f.name: f for f in dataclasses.fields(CalibrationCorpusManifest)}
    assert fields["calibration_corpus_version"].init is False
    assert fields["split_assignment"].init is False


# --- determinism / ordering independence -----------------------------------


def test_identical_corpus_same_version() -> None:
    assert _manifest().calibration_corpus_version == _manifest().calibration_corpus_version


def test_case_input_order_independent() -> None:
    a = _case(source_ref="caldera@4.2:run-7", telemetry=("observation::o1",))
    b = _case(source_ref="caldera@4.2:run-8", telemetry=("observation::o2",))
    sources = [_source(source_ref="caldera@4.2:run-7"), _source(source_ref="caldera@4.2:run-8")]
    m1 = CalibrationCorpusManifest.from_cases([a, b], sources, attack_kb_version=_KB)
    m2 = CalibrationCorpusManifest.from_cases(
        [b, a], list(reversed(sources)), attack_kb_version=_KB
    )
    assert m1.calibration_corpus_version == m2.calibration_corpus_version


def test_case_entries_sorted_by_case_id() -> None:
    a = _case(source_ref="caldera@4.2:run-7")
    b = _case(source_ref="caldera@4.2:run-8")
    sources = [_source(source_ref="caldera@4.2:run-7"), _source(source_ref="caldera@4.2:run-8")]
    m = CalibrationCorpusManifest.from_cases([b, a], sources, attack_kb_version=_KB)
    ids = [e.case_id for e in m.case_entries]
    assert ids == sorted(ids)


def test_source_entries_sorted_by_source_ref() -> None:
    m = CalibrationCorpusManifest.from_cases(
        [_case(source_ref="z@1"), _case(source_ref="a@1")],
        [_source(source_ref="z@1"), _source(source_ref="a@1")],
        attack_kb_version=_KB,
    )
    refs = [s.source_ref for s in m.source_entries]
    assert refs == sorted(refs)


def test_split_assignment_ordering_deterministic() -> None:
    m = _manifest()
    # tuple of (role, sorted-unique families); roles sorted
    roles = [role for role, _ in m.split_assignment]
    assert roles == sorted(roles)
    for _role, families in m.split_assignment:
        assert list(families) == sorted(set(families))


# --- content change -> different version -----------------------------------


def test_case_content_change_changes_version() -> None:
    base = _manifest().calibration_corpus_version
    changed = _manifest([_case(telemetry=("observation::o9",))]).calibration_corpus_version
    assert changed != base


def test_source_provenance_change_changes_version() -> None:
    base = _manifest().calibration_corpus_version
    changed = _manifest(
        sources=[_source(transformation_provenance="a DIFFERENT transformation")]
    ).calibration_corpus_version
    assert changed != base
    # acquisition provenance too
    changed2 = _manifest(
        sources=[_source(acquisition_provenance="acquired differently")]
    ).calibration_corpus_version
    assert changed2 != base


def test_attack_kb_version_change_changes_version() -> None:
    base = _manifest().calibration_corpus_version
    other = _manifest(
        [_case(attack_kb_version="enterprise-attack-18.1")],
        attack_kb_version="enterprise-attack-18.1",
    ).calibration_corpus_version
    assert other != base


def test_manifest_schema_version_change_changes_version() -> None:
    base = _manifest()
    other = CalibrationCorpusManifest(
        corpus_schema_version=base.corpus_schema_version,
        attack_kb_version=base.attack_kb_version,
        case_entries=base.case_entries,
        source_entries=base.source_entries,
        manifest_schema_version="calibration-corpus-manifest/999",
    )
    assert other.calibration_corpus_version != base.calibration_corpus_version


def test_corpus_schema_version_change_changes_version() -> None:
    base = _manifest().calibration_corpus_version
    other = CalibrationCorpusManifest.from_cases(
        [_case(corpus_schema_version="calibration-case/2")],
        [_source()],
        attack_kb_version=_KB,
        corpus_schema_version="calibration-case/2",
    ).calibration_corpus_version
    assert other != base


def test_equivalent_manifests_identical_version_different_differ() -> None:
    assert _manifest().calibration_corpus_version == _manifest().calibration_corpus_version
    assert (
        _manifest([_case(actor_label="APT-Y")]).calibration_corpus_version
        != _manifest().calibration_corpus_version
    )


# --- self-hash exclusion / acyclicity --------------------------------------


def test_self_hash_exclusion_and_recompute_matches() -> None:
    m = _manifest()
    recomputed = compute_calibration_corpus_version(
        manifest_schema_version=m.manifest_schema_version,
        corpus_schema_version=m.corpus_schema_version,
        attack_kb_version=m.attack_kb_version,
        case_entries=m.case_entries,
        source_entries=m.source_entries,
        split_assignment=m.split_assignment,
    )
    assert recomputed == m.calibration_corpus_version


def test_version_input_boundary_excludes_self_and_calibration_version() -> None:
    assert "calibration_corpus_version" not in CORPUS_VERSION_INPUT_FIELDS
    assert "calibration_version" not in CORPUS_VERSION_INPUT_FIELDS
    for forbidden in ("timestamp", "uuid", "fitted_parameter_set", "threshold"):
        assert forbidden not in CORPUS_VERSION_INPUT_FIELDS


# --- fail-closed consistency -----------------------------------------------


def test_duplicate_case_id_rejected() -> None:
    entry = CorpusCaseEntry.from_case(_case())
    with pytest.raises(CalibrationError, match="duplicate case_id"):
        CalibrationCorpusManifest(
            corpus_schema_version="calibration-case/1",
            attack_kb_version=_KB,
            case_entries=(entry, entry),
            source_entries=(_source(),),
        )


def test_mixed_attack_kb_version_rejected() -> None:
    with pytest.raises(CalibrationError, match="mixed-KB corpus is rejected"):
        CalibrationCorpusManifest.from_cases(
            [_case(attack_kb_version="enterprise-attack-18.1")],
            [_source()],
            attack_kb_version=_KB,
        )


def test_mixed_corpus_schema_version_rejected() -> None:
    with pytest.raises(CalibrationError, match="all cases must share one corpus schema"):
        CalibrationCorpusManifest.from_cases(
            [
                _case(source_ref="a@1"),
                _case(source_ref="b@1", corpus_schema_version="calibration-case/2"),
            ],
            [_source(source_ref="a@1"), _source(source_ref="b@1")],
            attack_kb_version=_KB,
        )


def test_source_license_mismatch_rejected() -> None:
    with pytest.raises(CalibrationError, match="license .* disagrees with the source registry"):
        CalibrationCorpusManifest.from_cases(
            [_case(license="MIT")],
            [_source(license="Apache-2.0")],
            attack_kb_version=_KB,
        )


def test_source_kind_mismatch_rejected() -> None:
    with pytest.raises(CalibrationError, match="source_kind .* disagrees"):
        CalibrationCorpusManifest.from_cases(
            [_case(source_kind=SourceKind.REPLAY)],
            [_source(source_kind=SourceKind.EMULATED)],
            attack_kb_version=_KB,
        )


def test_missing_source_registry_entry_rejected() -> None:
    with pytest.raises(CalibrationError, match="no matching CorpusSourceEntry"):
        CalibrationCorpusManifest.from_cases(
            [_case(source_ref="unregistered@1")],
            [_source(source_ref="other@1")],
            attack_kb_version=_KB,
        )


def test_duplicate_source_ref_rejected() -> None:
    with pytest.raises(CalibrationError, match="duplicate source_ref"):
        CalibrationCorpusManifest.from_cases(
            [_case()],
            [_source(), _source()],
            attack_kb_version=_KB,
        )


def test_provenance_required_nonempty() -> None:
    with pytest.raises(CalibrationError, match="acquisition_provenance"):
        _source(acquisition_provenance="")
    with pytest.raises(CalibrationError, match="transformation_provenance"):
        _source(transformation_provenance="")


# --- split assignment reflects case metadata -------------------------------


def test_split_assignment_reflects_case_metadata() -> None:
    cases = [
        _case(source_ref="a@1", scenario_family_id="fam-cal", case_role=CaseRole.CALIBRATION),
        _case(
            source_ref="b@1",
            scenario_family_id="fam-val",
            case_role=CaseRole.HELD_OUT_VALIDATION,
        ),
    ]
    sources = [_source(source_ref="a@1"), _source(source_ref="b@1")]
    m = CalibrationCorpusManifest.from_cases(cases, sources, attack_kb_version=_KB)
    assignment = dict(m.split_assignment)
    assert assignment[CaseRole.CALIBRATION.value] == ("fam-cal",)
    assert assignment[CaseRole.HELD_OUT_VALIDATION.value] == ("fam-val",)


# --- empty corpus ----------------------------------------------------------


def test_empty_corpus_is_structurally_valid_and_versioned() -> None:
    m = CalibrationCorpusManifest.from_cases([], [], attack_kb_version=_KB)
    assert m.case_entries == ()
    assert m.calibration_corpus_version.startswith(f"{CALIBRATION_CORPUS_VERSION_PREFIX}::")
    # deterministic and stable
    m2 = CalibrationCorpusManifest.from_cases([], [], attack_kb_version=_KB)
    assert m.calibration_corpus_version == m2.calibration_corpus_version
    # empty corpora on different KBs differ
    m3 = CalibrationCorpusManifest.from_cases([], [], attack_kb_version="enterprise-attack-18.1")
    assert m3.calibration_corpus_version != m.calibration_corpus_version


# --- immutability / no calibration_version / no numerics -------------------


def test_manifest_is_frozen() -> None:
    m = _manifest()
    with pytest.raises(dataclasses.FrozenInstanceError):
        m.attack_kb_version = "mutated"  # type: ignore[misc]


def test_no_calibration_version_or_numeric_fields() -> None:
    for cls in (CalibrationCorpusManifest, CorpusCaseEntry, CorpusSourceEntry):
        names = {f.name for f in dataclasses.fields(cls)}
        assert "calibration_version" not in names
        for f in dataclasses.fields(cls):
            assert f.type not in ("float", "int")


def test_serialization_is_deterministic() -> None:
    m = _manifest()
    assert to_canonical_json(m) == to_canonical_json(m)


# --- PYTHONHASHSEED independence -------------------------------------------

_SUBPROCESS = """
from attribution_platform.calibration.contracts import (
    ActorLabelSource, CalibrationCase, CaseRole, ExpectedOutcome,
    ExpectedOutputShape, GroundTruth, LabelConfidence, LabelSemantics, SourceKind,
)
from attribution_platform.calibration.manifest import (
    CalibrationCorpusManifest, CorpusSourceEntry,
)
case = CalibrationCase(
    scenario_family_id="fam", source_kind=SourceKind.EMULATED, source_ref="s@1",
    license="Apache-2.0", attack_kb_version="enterprise-attack-19.0",
    correlation_group_id="correlation-group::abc", sequence_id="behavioral-sequence::def",
    telemetry_provenance=("observation::o1", "evidence::e1"),
    ground_truth=GroundTruth(
        actor_label_source=ActorLabelSource.EMULATION_PLAN,
        label_semantics=LabelSemantics.ATTRIBUTABLE,
        label_confidence=LabelConfidence.MODERATE, actor_label="APT-X"),
    expected_output_shape=ExpectedOutputShape(
        outcome=ExpectedOutcome.LEADING_HYPOTHESIS,
        authorship_provenance="p", expected_likelihood_band="likely",
        discriminating_evidence=("c",)),
    case_role=CaseRole.CALIBRATION,
)
src = CorpusSourceEntry(source_ref="s@1", source_kind=SourceKind.EMULATED,
    license="Apache-2.0", acquisition_provenance="a", transformation_provenance="t")
m = CalibrationCorpusManifest.from_cases([case], [src], attack_kb_version="enterprise-attack-19.0")
print(m.calibration_corpus_version)
"""


def _version_under_seed(seed: str) -> str:
    out = subprocess.run(
        [sys.executable, "-c", _SUBPROCESS],
        capture_output=True,
        text=True,
        env={"PYTHONHASHSEED": seed, "PYTHONPATH": "src"},
        check=True,
    )
    return out.stdout.strip()


def test_pythonhashseed_independent() -> None:
    v0 = _version_under_seed("0")
    v1 = _version_under_seed("1")
    v2 = _version_under_seed("12345")
    assert v0 == v1 == v2
    assert v0.startswith(f"{CALIBRATION_CORPUS_VERSION_PREFIX}::")


# --- public exports --------------------------------------------------------


def test_public_exports() -> None:
    import attribution_platform.calibration as calibration

    for name in (
        "CalibrationCorpusManifest",
        "CorpusCaseEntry",
        "CorpusSourceEntry",
        "compute_calibration_corpus_version",
        "CALIBRATION_MANIFEST_SCHEMA_VERSION",
        "CALIBRATION_CORPUS_VERSION_PREFIX",
        "CORPUS_VERSION_INPUT_FIELDS",
    ):
        assert name in calibration.__all__
        assert getattr(calibration, name) is not None
