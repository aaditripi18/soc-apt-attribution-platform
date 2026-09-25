"""Fitting-readiness gate (doc 15 DC-5, T5; ADR-0006 F-3 "insufficient data →
fail closed").

A read-only validator run on a built corpus plus its Stage-5 decision inputs
**before** fitting. Fitting must refuse to start unless the report is ready.
It checks that the corpus can actually support fitting — the four Stage-5
findings (doc 14 F5-1..F5-4) are each a check here:

- **Population size** — calibration families ≥ 12 whose attributable ones span
  ≥ 4 distinct resolved actors; held-out families ≥ 8.
- **Hard negatives (F5-4)** — designed-negative (``UNATTRIBUTABLE_BY_DESIGN``)
  families: ≥ 3 in calibration and ≥ 2 held-out, a family counting only if
  *every* unit has ≥ 2 observed decision features (an empty negative is not
  hard).
- **Multi-feature units** — ≥ 30 % of attributable calibration units have ≥ 3
  distinct observed decision features.
- **Concentration spread (F5-2)** — the top candidate's ``concentration`` is not
  constant across calibration units (at least two defined, differing values).
- **Cross-split evidence identity (F5-3)** — no calibration unit has exactly the
  observed decision-feature set of a held-out or blind-actor unit, unless one of
  the two belongs to a family declared ``DELIBERATE_IMITATION``.
- **Label resolution (F5-1)** — every attributable label resolves, by ATT&CK
  alias lookup only (never ``uses``), to exactly one active Group.
- **Existing validators** — the category-completeness, split/leakage and
  provenance reports must each be valid (they are inputs, not re-derived).

**Thresholds** are the doc 15 DC-5 minimums the owner accepted (2026-09-24),
held in :class:`ReadinessThresholds` and echoed in the report. **Definitions:**
a unit's observed decision features are
:attr:`~attribution_platform.calibration.decision_inputs.CaseDecisionInput.observed_features`
(candidate-independent); the top candidate is the non-``Unattributed``
hypothesis with the greatest ``decision_support`` (floor-independent; ties
broken by ``hypothesis_id``), and its concentration is evaluated at an explicit
``min_profile_floor`` (default the structural lower bound 1 — never a fitted
value chosen here).

Fits nothing, chooses no parameter, emits no attribution decision; measurements
in the report are counts/fractions for explanation only.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from enum import Enum

from attribution_platform.attack_knowledge.loader import AttackKnowledge
from attribution_platform.attack_knowledge.traversal import (
    AmbiguousAliasError,
    UnknownAttackEntityError,
    resolve_alias,
)
from attribution_platform.attribution.contracts import UNATTRIBUTED_CANDIDATE_ID
from attribution_platform.calibration.category_validation import (
    CaseCategoryRecord,
    CaseCategoryTag,
    CategoryCompletenessReport,
)
from attribution_platform.calibration.contracts import CalibrationCase, CaseRole, LabelSemantics
from attribution_platform.calibration.corpus_builder import CorpusBuildResult
from attribution_platform.calibration.decision_inputs import (
    CaseDecisionInput,
    CorpusDecisionInputs,
    compute_case_decision_quantities,
)
from attribution_platform.calibration.errors import CalibrationError
from attribution_platform.calibration.provenance_validation import ProvenanceValidationReport
from attribution_platform.calibration.split_validation import SplitValidationReport

READINESS_SCHEMA_VERSION = "fitting-readiness/1"

#: The populations the gate needs decision inputs for (EXCLUDED is never read).
_EVALUATED_ROLES = (
    CaseRole.CALIBRATION,
    CaseRole.HELD_OUT_VALIDATION,
    CaseRole.BLIND_ACTOR_HOLDOUT,
)
_GROUP_TYPES = frozenset({"intrusion-set"})


@dataclass(frozen=True)
class ReadinessThresholds:
    """Doc 15 DC-5 minimums (owner-accepted 2026-09-24)."""

    min_calibration_families: int = 12
    min_calibration_actors: int = 4
    min_held_out_families: int = 8
    min_calibration_hard_negative_families: int = 3
    min_held_out_hard_negative_families: int = 2
    min_hard_negative_features: int = 2
    multi_feature_min_features: int = 3
    min_multi_feature_unit_fraction: float = 0.30


class ReadinessViolationType(Enum):
    """Closed set of fitting-readiness violation kinds."""

    MISSING_DECISION_INPUT = "missing_decision_input"
    CALIBRATION_FAMILIES = "calibration_families"
    CALIBRATION_ACTORS = "calibration_actors"
    HELD_OUT_FAMILIES = "held_out_families"
    CALIBRATION_HARD_NEGATIVES = "calibration_hard_negatives"
    HELD_OUT_HARD_NEGATIVES = "held_out_hard_negatives"
    MULTI_FEATURE_UNITS = "multi_feature_units"
    CONSTANT_CONCENTRATION = "constant_concentration"
    CROSS_SPLIT_IDENTICAL_FEATURES = "cross_split_identical_features"
    UNRESOLVED_LABEL = "unresolved_label"
    EXISTING_VALIDATOR_INVALID = "existing_validator_invalid"


@dataclass(frozen=True)
class ReadinessViolation:
    """One failed check: its kind, a plain-language detail, and the cases it
    concerns (sorted; may be empty for a population-level check)."""

    violation_type: ReadinessViolationType
    detail: str
    case_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "case_ids", tuple(sorted(set(self.case_ids))))


@dataclass(frozen=True)
class FittingReadinessReport:
    """The gate's explainable result. ``is_ready`` iff there are no violations;
    ``measurements`` are the observed counts/fractions (explanation only);
    ``resolved_labels`` maps each attributable label to its resolved Group id."""

    is_ready: bool
    calibration_corpus_version: str
    thresholds: ReadinessThresholds
    min_profile_floor: int
    violations: tuple[ReadinessViolation, ...] = ()
    measurements: tuple[tuple[str, float], ...] = ()
    resolved_labels: tuple[tuple[str, str], ...] = ()
    schema_version: str = field(default=READINESS_SCHEMA_VERSION)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "violations",
            tuple(
                sorted(
                    self.violations, key=lambda v: (v.violation_type.value, v.case_ids, v.detail)
                )
            ),
        )
        if self.is_ready != (not self.violations):
            raise CalibrationError(
                f"FittingReadinessReport.is_ready ({self.is_ready}) is inconsistent with "
                f"{len(self.violations)} violation(s)"
            )


def _families(cases: Iterable[CalibrationCase], role: CaseRole) -> dict[str, list[CalibrationCase]]:
    out: dict[str, list[CalibrationCase]] = {}
    for case in cases:
        if case.case_role is role:
            out.setdefault(case.scenario_family_id, []).append(case)
    return out


def _top_concentration(case_input: CaseDecisionInput, min_profile_floor: int) -> float | None:
    quantities = compute_case_decision_quantities(case_input, min_profile_floor=min_profile_floor)
    real = [h for h in quantities.hypotheses if h.candidate_id != UNATTRIBUTED_CANDIDATE_ID]
    if not real:
        return None
    top = min(real, key=lambda h: (-h.decision_support, h.hypothesis_id))
    return top.concentration


def validate_fitting_readiness(
    corpus: CorpusBuildResult,
    decision_inputs: CorpusDecisionInputs,
    *,
    knowledge: AttackKnowledge,
    category_records: Sequence[CaseCategoryRecord],
    category_report: CategoryCompletenessReport,
    split_report: SplitValidationReport,
    provenance_report: ProvenanceValidationReport,
    thresholds: ReadinessThresholds | None = None,
    min_profile_floor: int = 1,
) -> FittingReadinessReport:
    """Run every DC-5 check (module docstring). Read-only and deterministic."""
    limits = thresholds if thresholds is not None else ReadinessThresholds()
    version = corpus.calibration_corpus_version
    if decision_inputs.calibration_corpus_version != version:
        raise CalibrationError(
            f"validate_fitting_readiness: decision inputs are for corpus "
            f"{decision_inputs.calibration_corpus_version!r}, not {version!r}"
        )
    for name, report_version in (
        ("split", split_report.calibration_corpus_version),
        ("provenance", provenance_report.calibration_corpus_version),
        ("category", category_report.calibration_corpus_version),
    ):
        if report_version != version:  # a report without this manifest is not evidence
            raise CalibrationError(
                f"validate_fitting_readiness: the {name} report is for corpus "
                f"{report_version!r}, not {version!r}"
            )

    violations: list[ReadinessViolation] = []
    measurements: dict[str, float] = {}
    add = violations.append

    # Existing validators are inputs; each must already be valid.
    for name, valid in (
        ("category completeness", category_report.is_valid),
        ("split/leakage", split_report.is_valid),
        ("provenance", provenance_report.is_valid),
    ):
        if not valid:
            add(
                ReadinessViolation(
                    ReadinessViolationType.EXISTING_VALIDATOR_INVALID,
                    f"the {name} report has violations",
                )
            )

    inputs = {ci.case_id: ci for ci in decision_inputs.cases}
    missing = [
        c.case_id
        for c in corpus.cases
        if c.case_role in _EVALUATED_ROLES and c.case_id not in inputs
    ]
    if missing:
        add(
            ReadinessViolation(
                ReadinessViolationType.MISSING_DECISION_INPUT,
                "cases in calibration/held-out/blind populations have no decision input",
                tuple(missing),
            )
        )

    # Label resolution: alias identity only (doc 15 DC-2).
    resolved: dict[str, str] = {}
    for case in corpus.cases:
        if case.ground_truth.label_semantics is not LabelSemantics.ATTRIBUTABLE:
            continue
        label = case.ground_truth.actor_label or ""
        if label in resolved:
            continue
        try:
            resolved[label] = resolve_alias(knowledge, label, object_types=_GROUP_TYPES)
        except (UnknownAttackEntityError, AmbiguousAliasError) as exc:
            add(
                ReadinessViolation(
                    ReadinessViolationType.UNRESOLVED_LABEL,
                    f"actor label {label!r} does not resolve to exactly one active Group: {exc}",
                    (case.case_id,),
                )
            )

    calibration = _families(corpus.cases, CaseRole.CALIBRATION)
    held_out = _families(corpus.cases, CaseRole.HELD_OUT_VALIDATION)
    measurements["calibration_families"] = len(calibration)
    measurements["held_out_families"] = len(held_out)
    if len(calibration) < limits.min_calibration_families:
        add(
            ReadinessViolation(
                ReadinessViolationType.CALIBRATION_FAMILIES,
                f"{len(calibration)} calibration families < {limits.min_calibration_families}",
            )
        )
    if len(held_out) < limits.min_held_out_families:
        add(
            ReadinessViolation(
                ReadinessViolationType.HELD_OUT_FAMILIES,
                f"{len(held_out)} held-out families < {limits.min_held_out_families}",
            )
        )
    actors = {
        resolved[c.ground_truth.actor_label]
        for family in calibration.values()
        for c in family
        if c.ground_truth.label_semantics is LabelSemantics.ATTRIBUTABLE
        and c.ground_truth.actor_label in resolved
    }
    measurements["calibration_actors"] = len(actors)
    if len(actors) < limits.min_calibration_actors:
        add(
            ReadinessViolation(
                ReadinessViolationType.CALIBRATION_ACTORS,
                f"attributable calibration families span {len(actors)} resolved actors "
                f"< {limits.min_calibration_actors}",
            )
        )

    # Hard negatives (F5-4).
    def hard_negative_families(families: dict[str, list[CalibrationCase]]) -> int:
        count = 0
        for family in families.values():
            if (
                family[0].ground_truth.label_semantics
                is not LabelSemantics.UNATTRIBUTABLE_BY_DESIGN
            ):
                continue
            if all(
                c.case_id in inputs
                and len(inputs[c.case_id].observed_features) >= limits.min_hard_negative_features
                for c in family
            ):
                count += 1
        return count

    for role_name, families, minimum, kind in (
        (
            "calibration",
            calibration,
            limits.min_calibration_hard_negative_families,
            ReadinessViolationType.CALIBRATION_HARD_NEGATIVES,
        ),
        (
            "held-out",
            held_out,
            limits.min_held_out_hard_negative_families,
            ReadinessViolationType.HELD_OUT_HARD_NEGATIVES,
        ),
    ):
        count = hard_negative_families(families)
        measurements[f"{role_name}_hard_negative_families"] = count
        if count < minimum:
            add(
                ReadinessViolation(
                    kind,
                    f"{count} {role_name} hard-negative families (every unit with ≥ "
                    f"{limits.min_hard_negative_features} observed features) < {minimum}",
                )
            )

    # Multi-feature attributable calibration units.
    attributable_units = [
        inputs[c.case_id]
        for family in calibration.values()
        for c in family
        if c.ground_truth.label_semantics is LabelSemantics.ATTRIBUTABLE and c.case_id in inputs
    ]
    multi = sum(
        1
        for u in attributable_units
        if len(u.observed_features) >= limits.multi_feature_min_features
    )
    fraction = multi / len(attributable_units) if attributable_units else 0.0
    measurements["multi_feature_unit_fraction"] = fraction
    if fraction < limits.min_multi_feature_unit_fraction:
        add(
            ReadinessViolation(
                ReadinessViolationType.MULTI_FEATURE_UNITS,
                f"{multi} of {len(attributable_units)} attributable calibration units have ≥ "
                f"{limits.multi_feature_min_features} observed features ({fraction:.2f} < "
                f"{limits.min_multi_feature_unit_fraction:.2f})",
            )
        )

    # Concentration spread (F5-2).
    concentrations = sorted(
        {
            value
            for family in calibration.values()
            for c in family
            if c.case_id in inputs
            and (value := _top_concentration(inputs[c.case_id], min_profile_floor)) is not None
        }
    )
    measurements["distinct_top_concentrations"] = len(concentrations)
    if len(concentrations) < 2:
        add(
            ReadinessViolation(
                ReadinessViolationType.CONSTANT_CONCENTRATION,
                f"top-candidate concentration takes {len(concentrations)} distinct value(s) "
                "across calibration units; fitting needs variation",
            )
        )

    # Cross-split evidence identity (F5-3), except declared imitation.
    imitation_cases = {
        r.case_id for r in category_records if CaseCategoryTag.DELIBERATE_IMITATION in r.categories
    }
    by_case = {c.case_id: c for c in corpus.cases}
    imitation_families = {
        by_case[cid].scenario_family_id for cid in imitation_cases if cid in by_case
    }
    other: dict[tuple[str, ...], list[str]] = {}
    for case in corpus.cases:
        if (
            case.case_role in (CaseRole.HELD_OUT_VALIDATION, CaseRole.BLIND_ACTOR_HOLDOUT)
            and case.case_id in inputs
        ):
            other.setdefault(inputs[case.case_id].observed_features, []).append(case.case_id)
    for family in calibration.values():
        for case in family:
            if case.case_id not in inputs:
                continue
            for twin in other.get(inputs[case.case_id].observed_features, ()):
                if (
                    case.scenario_family_id in imitation_families
                    or by_case[twin].scenario_family_id in imitation_families
                ):
                    continue
                add(
                    ReadinessViolation(
                        ReadinessViolationType.CROSS_SPLIT_IDENTICAL_FEATURES,
                        "a calibration unit and a held-out/blind unit have exactly the same "
                        "observed decision-feature set (the held-out gate would not be "
                        "independent)",
                        (case.case_id, twin),
                    )
                )

    return FittingReadinessReport(
        is_ready=not violations,
        calibration_corpus_version=version,
        thresholds=limits,
        min_profile_floor=min_profile_floor,
        violations=tuple(violations),
        measurements=tuple(sorted(measurements.items())),
        resolved_labels=tuple(sorted(resolved.items())),
    )


def require_fitting_ready(report: FittingReadinessReport) -> FittingReadinessReport:
    """Fail closed: raise unless ``report`` is ready (fitting must not start)."""
    if not report.is_ready:
        summary = "; ".join(f"{v.violation_type.value}: {v.detail}" for v in report.violations)
        raise CalibrationError(f"corpus is not ready for fitting — {summary}")
    return report


__all__ = [
    "READINESS_SCHEMA_VERSION",
    "FittingReadinessReport",
    "ReadinessThresholds",
    "ReadinessViolation",
    "ReadinessViolationType",
    "require_fitting_ready",
    "validate_fitting_readiness",
]
