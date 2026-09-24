"""B1.2 — CalibrationCase contract tests (ADR-0006 §D6/§D7).

Covers only the B1.2 contract: schema validation, fail-closed invariants,
the anti-circular authorship requirement, deterministic ``case_id`` and its
documented input boundary, immutability, and serialization determinism. No
corpus/manifest/``calibration_version``/split/scoring is exercised (none
exists yet).
"""

from __future__ import annotations

import dataclasses

import pytest

from attribution_platform.calibration.contracts import (
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
from attribution_platform.domain.serialization import to_canonical_json


def _ground_truth(**overrides: object) -> GroundTruth:
    kwargs: dict[str, object] = {
        "actor_label_source": ActorLabelSource.EMULATION_PLAN,
        "label_semantics": LabelSemantics.ATTRIBUTABLE,
        "label_confidence": LabelConfidence.MODERATE,
        "actor_label": "APT-EXAMPLE",
        "campaign_context": (),
    }
    kwargs.update(overrides)
    return GroundTruth(**kwargs)  # type: ignore[arg-type]


def _expected_shape(**overrides: object) -> ExpectedOutputShape:
    kwargs: dict[str, object] = {
        "outcome": ExpectedOutcome.LEADING_HYPOTHESIS,
        "authorship_provenance": "emulation-plan#2026-01: analyst-authored",
        "expected_likelihood_band": "likely",
        "expected_confidence_band": "moderate",
        "discriminating_evidence": ("distinctive-combo-A",),
    }
    kwargs.update(overrides)
    return ExpectedOutputShape(**kwargs)  # type: ignore[arg-type]


def _case(**overrides: object) -> CalibrationCase:
    kwargs: dict[str, object] = {
        "scenario_family_id": "family-001",
        "source_kind": SourceKind.EMULATED,
        "source_ref": "caldera@4.2:run-7",
        "license": "Apache-2.0",
        "attack_kb_version": "enterprise-attack-19.0",
        "correlation_group_id": "correlation-group::abc",
        "sequence_id": "behavioral-sequence::def",
        "telemetry_provenance": ("observation::o1", "evidence::e1"),
        "ground_truth": _ground_truth(),
        "expected_output_shape": _expected_shape(),
        "case_role": CaseRole.CALIBRATION,
    }
    kwargs.update(overrides)
    return CalibrationCase(**kwargs)  # type: ignore[arg-type]


# --- valid construction + case_id shape -----------------------------------


def test_valid_case_constructs_and_computes_case_id() -> None:
    case = _case()
    assert case.case_id.startswith("calibration-case::")
    assert len(case.case_id.split("::")[1]) == 64  # sha256 hex
    assert case.corpus_schema_version == "calibration-case/1"


def test_case_id_is_field_init_false_and_not_passable() -> None:
    fields = {f.name: f for f in dataclasses.fields(CalibrationCase)}
    assert "case_id" in fields
    assert fields["case_id"].init is False


# --- required fields fail closed ------------------------------------------


@pytest.mark.parametrize(
    "override",
    [
        {"scenario_family_id": ""},
        {"scenario_family_id": "   "},
        {"source_ref": ""},
        {"license": ""},
        {"attack_kb_version": ""},
        {"correlation_group_id": ""},
        {"sequence_id": ""},
        {"corpus_schema_version": ""},
    ],
)
def test_required_identifier_fields_reject_empty(override: dict[str, object]) -> None:
    with pytest.raises(CalibrationError):
        _case(**override)


def test_telemetry_provenance_required_nonempty() -> None:
    with pytest.raises(CalibrationError, match="telemetry_provenance must be non-empty"):
        _case(telemetry_provenance=())


def test_invalid_source_kind_rejected() -> None:
    with pytest.raises(CalibrationError, match="source_kind must be a SourceKind"):
        _case(source_kind="emulated")


def test_invalid_case_role_rejected() -> None:
    with pytest.raises(CalibrationError, match="case_role must be a CaseRole"):
        _case(case_role="calibration")


# --- ground-truth semantics ------------------------------------------------


def test_attributable_requires_actor_label() -> None:
    with pytest.raises(CalibrationError, match="ATTRIBUTABLE requires a non-empty actor_label"):
        _ground_truth(label_semantics=LabelSemantics.ATTRIBUTABLE, actor_label=None)


def test_attributable_requires_known_source() -> None:
    with pytest.raises(CalibrationError, match="requires a known actor_label_source"):
        _ground_truth(
            label_semantics=LabelSemantics.ATTRIBUTABLE,
            actor_label_source=ActorLabelSource.UNKNOWN,
        )


def test_unattributable_by_design_forbids_actor_label() -> None:
    with pytest.raises(CalibrationError, match="must have actor_label=None"):
        _ground_truth(label_semantics=LabelSemantics.UNATTRIBUTABLE_BY_DESIGN, actor_label="APT-X")


def test_disputed_and_unknown_do_not_coerce_to_negative() -> None:
    # DISPUTED/UNKNOWN may carry or omit an actor_label; the contract stores the
    # semantics without turning them into a negative (ADR-0006 D7).
    gt_present = _ground_truth(
        label_semantics=LabelSemantics.DISPUTED,
        actor_label="APT-DISPUTED",
        label_confidence=LabelConfidence.LOW,
    )
    gt_absent = _ground_truth(
        label_semantics=LabelSemantics.UNKNOWN,
        actor_label=None,
        actor_label_source=ActorLabelSource.UNKNOWN,
        label_confidence=LabelConfidence.UNKNOWN,
    )
    assert gt_present.label_semantics is LabelSemantics.DISPUTED
    assert gt_absent.actor_label is None


def test_ground_truth_enum_type_checks() -> None:
    with pytest.raises(CalibrationError, match="label_confidence must be a LabelConfidence"):
        _ground_truth(label_confidence="moderate")


# --- expected-output-shape authorship + band invariants --------------------


def test_expected_shape_requires_authorship_provenance() -> None:
    with pytest.raises(CalibrationError, match="authorship_provenance"):
        _expected_shape(authorship_provenance="")


def test_insufficient_outcome_forbids_likelihood_band() -> None:
    with pytest.raises(CalibrationError, match="INSUFFICIENT_EVIDENCE must have"):
        _expected_shape(
            outcome=ExpectedOutcome.INSUFFICIENT_EVIDENCE, expected_likelihood_band="likely"
        )


def test_leading_hypothesis_requires_likelihood_band() -> None:
    with pytest.raises(CalibrationError, match="LEADING_HYPOTHESIS requires"):
        _expected_shape(outcome=ExpectedOutcome.LEADING_HYPOTHESIS, expected_likelihood_band=None)


def test_insufficient_outcome_shape_is_valid_without_band() -> None:
    shape = _expected_shape(
        outcome=ExpectedOutcome.INSUFFICIENT_EVIDENCE,
        expected_likelihood_band=None,
        discriminating_evidence=(),
    )
    assert shape.outcome is ExpectedOutcome.INSUFFICIENT_EVIDENCE
    assert shape.expected_likelihood_band is None


# --- case-level consistency ------------------------------------------------


def test_designed_negative_must_expect_insufficient() -> None:
    with pytest.raises(CalibrationError, match="UNATTRIBUTABLE_BY_DESIGN ground truth requires"):
        _case(
            ground_truth=_ground_truth(
                label_semantics=LabelSemantics.UNATTRIBUTABLE_BY_DESIGN, actor_label=None
            ),
            expected_output_shape=_expected_shape(outcome=ExpectedOutcome.LEADING_HYPOTHESIS),
        )


def test_designed_negative_with_insufficient_is_valid() -> None:
    case = _case(
        ground_truth=_ground_truth(
            label_semantics=LabelSemantics.UNATTRIBUTABLE_BY_DESIGN, actor_label=None
        ),
        expected_output_shape=_expected_shape(
            outcome=ExpectedOutcome.INSUFFICIENT_EVIDENCE,
            expected_likelihood_band=None,
            discriminating_evidence=(),
        ),
    )
    assert case.ground_truth.label_semantics is LabelSemantics.UNATTRIBUTABLE_BY_DESIGN


# --- determinism -----------------------------------------------------------


def test_case_id_deterministic_for_identical_inputs() -> None:
    assert _case().case_id == _case().case_id


def test_case_id_changes_when_case_defining_input_changes() -> None:
    base = _case().case_id
    assert _case(source_ref="caldera@4.2:run-8").case_id != base
    assert _case(attack_kb_version="enterprise-attack-18.1").case_id != base
    assert _case(correlation_group_id="correlation-group::other").case_id != base
    assert _case(telemetry_provenance=("observation::o2",)).case_id != base
    assert _case(ground_truth=_ground_truth(actor_label="APT-OTHER")).case_id != base


def test_case_id_ignores_corpus_assignment_metadata() -> None:
    # scenario_family_id and case_role are corpus-assignment metadata,
    # deliberately excluded from case_id (documented input boundary).
    base = _case().case_id
    assert _case(scenario_family_id="family-999").case_id == base
    assert _case(case_role=CaseRole.HELD_OUT_VALIDATION).case_id == base


def test_case_id_order_independent_over_canonicalized_collections() -> None:
    a = _case(telemetry_provenance=("evidence::e1", "observation::o1"))
    b = _case(telemetry_provenance=("observation::o1", "evidence::e1", "observation::o1"))
    assert a.case_id == b.case_id


def test_compute_function_matches_stored_case_id() -> None:
    case = _case()
    recomputed = compute_calibration_case_id(
        corpus_schema_version=case.corpus_schema_version,
        source_kind=case.source_kind,
        source_ref=case.source_ref,
        license=case.license,
        attack_kb_version=case.attack_kb_version,
        correlation_group_id=case.correlation_group_id,
        sequence_id=case.sequence_id,
        telemetry_provenance=case.telemetry_provenance,
        coverage_assumptions=case.coverage_assumptions,
        ground_truth=case.ground_truth,
        expected_output_shape=case.expected_output_shape,
    )
    assert recomputed == case.case_id


def test_case_id_input_boundary_excludes_assignment_and_volatile_fields() -> None:
    assert "scenario_family_id" not in CASE_ID_INPUT_FIELDS
    assert "case_role" not in CASE_ID_INPUT_FIELDS
    assert "case_id" not in CASE_ID_INPUT_FIELDS
    # nothing volatile / calibration-version-ish is in the boundary
    for forbidden in ("calibration_version", "manifest_hash", "timestamp", "uuid"):
        assert forbidden not in CASE_ID_INPUT_FIELDS


# --- immutability + serialization ------------------------------------------


def test_case_is_frozen() -> None:
    case = _case()
    with pytest.raises(dataclasses.FrozenInstanceError):
        case.scenario_family_id = "mutated"  # type: ignore[misc]


def test_serialization_is_deterministic() -> None:
    case = _case()
    assert to_canonical_json(case) == to_canonical_json(case)
    # equivalent canonical ordering yields identical serialization
    reordered = _case(telemetry_provenance=("evidence::e1", "observation::o1"))
    assert to_canonical_json(case) == to_canonical_json(reordered)


def test_no_calibration_version_field_exists() -> None:
    names = {f.name for f in dataclasses.fields(CalibrationCase)}
    assert "calibration_version" not in names
    assert "calibration_corpus_version" not in names
    # and no numeric threshold/score field leaked in
    for f in dataclasses.fields(CalibrationCase):
        assert f.type not in ("float", "int")


def test_attack_kb_and_schema_version_required() -> None:
    with pytest.raises(CalibrationError, match="attack_kb_version"):
        _case(attack_kb_version="")
    with pytest.raises(CalibrationError, match="corpus_schema_version"):
        _case(corpus_schema_version="")
