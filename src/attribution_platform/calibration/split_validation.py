"""Calibration split / leakage validation + blind-actor holdout readiness
(gate B1.4, ADR-0006 §D5/§D9/§D10).

**Read-only validator — no scoring, no fitting, no ATT&CK, no mutation.** This
module mechanically checks that a calibration corpus can be partitioned without
leakage and that its blind-actor-holdout metadata is structurally valid. It
operates **only** at :class:`~attribution_platform.calibration.contracts.CalibrationCase`
granularity (never observations/evidence/links), consumes the authoring-time
``scenario_family_id`` as the **trusted** grouping key (ADR-0006 §D5 folds
incident/host/session/template/seed/near-duplicate/technique-combination lineage
into it), and produces a deterministic, explainable
:class:`SplitValidationReport`.

**What B1.4 does (and only this):**

- **Family -> single role (NB-1, strict).** Every ``scenario_family_id`` must map
  to exactly one :class:`~attribution_platform.calibration.contracts.CaseRole`;
  a family that appears under more than one role is a ``FAMILY_ROLE_LEAKAGE``
  violation. This is stronger than ADR-0006 §D9's literal "the four populations
  are disjoint by ``scenario_family_id``" minimum, and it subsumes the required
  pairwise disjointness of CALIBRATION / HELD_OUT_VALIDATION / BLIND_ACTOR_HOLDOUT
  (and also prevents TIER1_STRUCTURAL / EXCLUDED overlapping any of them).
- **Blind-actor holdout readiness (§D10).** A held-out actor set is *derived*
  from cases whose ``case_role == BLIND_ACTOR_HOLDOUT`` using the
  dataset-authored ``ground_truth.actor_label`` (never ATT&CK). Each such case
  must be genuinely attributable (``label_semantics == ATTRIBUTABLE`` and a
  present ``actor_label``) else ``BLIND_ACTOR_HOLDOUT_NOT_ATTRIBUTABLE``. No
  held-out actor's ``actor_label`` may appear in a CALIBRATION case, else
  ``BLIND_ACTOR_IN_CALIBRATION``.

**What B1.4 explicitly does NOT do** (deferred / out of scope): near-duplicate
or similarity computation of any kind; deriving incident/host/session/template/
campaign grouping (all folded into ``scenario_family_id`` upstream); alias
normalization; ATT&CK identity ablation / candidate-universe / ``g``/``D`` /
breadth / null recomputation (later blind-actor evaluation); provenance/license
correctness (B1.5); corpus quality/coverage orchestration (B1.6); any
``calibration_version`` / fitting / threshold / score / likelihood / ranking /
abstention. It imports **no** ATT&CK knowledge and never relabels a case (a
``DISPUTED``/``UNKNOWN``/``UNATTRIBUTABLE_BY_DESIGN`` case is never coerced into
a negative).

**Reuse, never re-invent.** Imports only its own package
(:mod:`~attribution_platform.calibration.contracts` /
:mod:`~attribution_platform.calibration.manifest` /
:mod:`~attribution_platform.calibration.errors`) and the standard library. The
report/violation objects follow the frozen-dataclass + closed-enum + canonical
sorted-tuple discipline every prior contract uses; all output is deterministic
and ``PYTHONHASHSEED``-independent (every collection is sorted before it is
returned).
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

#: Schema version of the B1.4 split-validation report contract.
SPLIT_VALIDATION_SCHEMA_VERSION = "calibration-split-validation/1"

#: The deterministic corpus-version value reported when no manifest is supplied
#: (B1.4 never computes a corpus hash — that is B1.3's sole responsibility, and
#: recomputing one here would duplicate ownership). It is a fixed sentinel, not
#: a second corpus identity.
NO_MANIFEST_CORPUS_VERSION = "calibration-corpus-version::unset"


class SplitViolationType(Enum):
    """Closed set of split/leakage violation kinds (ADR-0006 §D9/§D10). Kept
    minimal and non-overlapping: the strict family->single-role rule
    (``FAMILY_ROLE_LEAKAGE``) subsumes population disjointness, and the two
    blind-actor kinds cover the §D10 readiness checks."""

    FAMILY_ROLE_LEAKAGE = "family_role_leakage"
    BLIND_ACTOR_IN_CALIBRATION = "blind_actor_in_calibration"
    BLIND_ACTOR_HOLDOUT_NOT_ATTRIBUTABLE = "blind_actor_holdout_not_attributable"


def _canonical_tuple(values: object, field_name: str) -> tuple[str, ...]:
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
class SplitValidationViolation:
    """One deterministic, explainable split/leakage violation. All id/role
    collections are canonicalized (sorted-unique) so equality and serialization
    are order-independent.

    - ``violation_type``: closed :class:`SplitViolationType`.
    - ``scenario_family_ids`` / ``case_ids`` / ``roles``: the affected families,
      cases, and role values, each sorted-unique.
    - ``actor_label``: set only for actor-level violations, else ``None``.
    - ``reason``: human-readable explanation (no scores/thresholds).
    """

    violation_type: SplitViolationType
    scenario_family_ids: tuple[str, ...]
    case_ids: tuple[str, ...]
    roles: tuple[str, ...]
    reason: str
    actor_label: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.violation_type, SplitViolationType):
            raise CalibrationError(
                "SplitValidationViolation.violation_type must be a SplitViolationType, "
                f"got {type(self.violation_type).__name__}"
            )
        object.__setattr__(
            self,
            "scenario_family_ids",
            _canonical_tuple(
                self.scenario_family_ids, "SplitValidationViolation.scenario_family_ids"
            ),
        )
        object.__setattr__(
            self,
            "case_ids",
            _canonical_tuple(self.case_ids, "SplitValidationViolation.case_ids"),
        )
        object.__setattr__(
            self, "roles", _canonical_tuple(self.roles, "SplitValidationViolation.roles")
        )
        if not isinstance(self.reason, str) or not self.reason.strip():
            raise CalibrationError("SplitValidationViolation.reason must be a non-empty string")
        if self.actor_label is not None and (
            not isinstance(self.actor_label, str) or not self.actor_label.strip()
        ):
            raise CalibrationError(
                "SplitValidationViolation.actor_label must be a non-empty string or None"
            )

    def _sort_key(self) -> tuple[str, tuple[str, ...], tuple[str, ...], tuple[str, ...], str]:
        return (
            self.violation_type.value,
            self.scenario_family_ids,
            self.case_ids,
            self.roles,
            self.actor_label or "",
        )


@dataclass(frozen=True)
class SplitValidationReport:
    """The read-only result of :func:`validate_split` (ADR-0006 §D9/§D10) — an
    explainable report, never a bare boolean, never a score.

    - ``is_valid``: ``True`` iff ``violations`` is empty.
    - ``violations``: canonically sorted tuple of :class:`SplitValidationViolation`.
    - ``calibration_corpus_version``: echoed unchanged from the supplied manifest,
      or :data:`NO_MANIFEST_CORPUS_VERSION` when no manifest is given. **Never
      recomputed here.**
    - ``validation_schema_version``: this report contract's schema version.
    """

    is_valid: bool
    calibration_corpus_version: str
    violations: tuple[SplitValidationViolation, ...] = ()
    validation_schema_version: str = field(default=SPLIT_VALIDATION_SCHEMA_VERSION)

    def __post_init__(self) -> None:
        for v in self.violations:
            if not isinstance(v, SplitValidationViolation):
                raise CalibrationError(
                    "SplitValidationReport.violations must contain only "
                    f"SplitValidationViolation objects, got {type(v).__name__}"
                )
        object.__setattr__(
            self,
            "violations",
            tuple(sorted(self.violations, key=lambda v: v._sort_key())),
        )
        computed_valid = len(self.violations) == 0
        if self.is_valid != computed_valid:
            raise CalibrationError(
                f"SplitValidationReport.is_valid ({self.is_valid}) is inconsistent with "
                f"{len(self.violations)} violation(s)"
            )
        if not isinstance(self.calibration_corpus_version, str) or not (
            self.calibration_corpus_version.strip()
        ):
            raise CalibrationError(
                "SplitValidationReport.calibration_corpus_version must be a non-empty string"
            )
        if not isinstance(self.validation_schema_version, str) or not (
            self.validation_schema_version.strip()
        ):
            raise CalibrationError(
                "SplitValidationReport.validation_schema_version must be a non-empty string"
            )


def _families_by_role(
    cases: tuple[CalibrationCase, ...],
) -> tuple[SplitValidationViolation, ...]:
    """Strict NB-1: every scenario_family_id maps to exactly one CaseRole.
    Returns one ``FAMILY_ROLE_LEAKAGE`` violation per offending family."""
    roles_by_family: dict[str, set[str]] = {}
    cases_by_family: dict[str, set[str]] = {}
    for case in cases:
        roles_by_family.setdefault(case.scenario_family_id, set()).add(case.case_role.value)
        cases_by_family.setdefault(case.scenario_family_id, set()).add(case.case_id)

    violations: list[SplitValidationViolation] = []
    for family in sorted(roles_by_family):
        roles = roles_by_family[family]
        if len(roles) > 1:
            violations.append(
                SplitValidationViolation(
                    violation_type=SplitViolationType.FAMILY_ROLE_LEAKAGE,
                    scenario_family_ids=(family,),
                    case_ids=tuple(cases_by_family[family]),
                    roles=tuple(roles),
                    reason=(
                        f"scenario_family_id {family!r} appears under more than one case_role "
                        f"({', '.join(sorted(roles))}); each scenario family must map to exactly "
                        "one role (ADR-0006 §D9)"
                    ),
                )
            )
    return tuple(violations)


def _blind_actor_violations(
    cases: tuple[CalibrationCase, ...],
) -> tuple[SplitValidationViolation, ...]:
    """Blind-actor holdout readiness (ADR-0006 §D10): every BLIND_ACTOR_HOLDOUT
    case must be genuinely attributable; and no derived held-out actor may
    appear in a CALIBRATION case."""
    violations: list[SplitValidationViolation] = []

    # Each BLIND_ACTOR_HOLDOUT case must be attributable with a present actor.
    holdout_actors: set[str] = set()
    for case in cases:
        if case.case_role is not CaseRole.BLIND_ACTOR_HOLDOUT:
            continue
        gt = case.ground_truth
        if gt.label_semantics is not LabelSemantics.ATTRIBUTABLE or gt.actor_label is None:
            violations.append(
                SplitValidationViolation(
                    violation_type=SplitViolationType.BLIND_ACTOR_HOLDOUT_NOT_ATTRIBUTABLE,
                    scenario_family_ids=(case.scenario_family_id,),
                    case_ids=(case.case_id,),
                    roles=(CaseRole.BLIND_ACTOR_HOLDOUT.value,),
                    reason=(
                        f"BLIND_ACTOR_HOLDOUT case {case.case_id!r} is not genuinely attributable "
                        f"(label_semantics={gt.label_semantics.value}, "
                        f"actor_label={gt.actor_label!r}); a blind-actor holdout must name a known "
                        "actor (ADR-0006 §D10)"
                    ),
                    actor_label=gt.actor_label,
                )
            )
        else:
            holdout_actors.add(gt.actor_label)

    # No held-out actor's authored label may appear in a CALIBRATION case.
    # Grouped into one violation per offending actor (deterministic, no duplicates).
    calib_families_by_actor: dict[str, set[str]] = {}
    calib_cases_by_actor: dict[str, set[str]] = {}
    for case in cases:
        if case.case_role is not CaseRole.CALIBRATION:
            continue
        label = case.ground_truth.actor_label
        if label is not None and label in holdout_actors:
            calib_families_by_actor.setdefault(label, set()).add(case.scenario_family_id)
            calib_cases_by_actor.setdefault(label, set()).add(case.case_id)

    for actor in sorted(calib_cases_by_actor):
        violations.append(
            SplitValidationViolation(
                violation_type=SplitViolationType.BLIND_ACTOR_IN_CALIBRATION,
                scenario_family_ids=tuple(calib_families_by_actor[actor]),
                case_ids=tuple(calib_cases_by_actor[actor]),
                roles=(CaseRole.CALIBRATION.value, CaseRole.BLIND_ACTOR_HOLDOUT.value),
                reason=(
                    f"held-out actor {actor!r} (a BLIND_ACTOR_HOLDOUT actor) also appears in "
                    "CALIBRATION case(s); a held-out actor must be excluded from all parameter "
                    "fitting (ADR-0006 §D10)"
                ),
                actor_label=actor,
            )
        )
    return tuple(violations)


def validate_split(
    cases: tuple[CalibrationCase, ...],
    manifest: CalibrationCorpusManifest | None = None,
) -> SplitValidationReport:
    """Read-only split/leakage + blind-actor-holdout validation over a set of
    :class:`~attribution_platform.calibration.contracts.CalibrationCase`
    objects (ADR-0006 §D9/§D10). Never mutates its inputs, never consults
    ATT&CK, never computes a corpus hash, and introduces no threshold/score.

    ``cases`` are authoritative (they carry ``ground_truth``/``case_role``/
    ``scenario_family_id``). ``manifest`` is optional and used only as a
    cross-identity reference: when supplied, its
    ``calibration_corpus_version`` is echoed **unchanged**, and the set of
    ``case_id``s must match the manifest's ``case_entries`` exactly (else fail
    closed with :class:`CalibrationError` — a mismatched pair is not silently
    validated). B1.4 does **not** re-run B1.3's manifest validation.

    An **empty corpus is structurally valid** and yields a valid report with no
    violations (no minimum case count / sufficiency logic here).
    """
    if not isinstance(cases, tuple):
        raise CalibrationError(
            f"validate_split: cases must be a tuple of CalibrationCase, got {type(cases).__name__}"
        )
    for case in cases:
        if not isinstance(case, CalibrationCase):
            raise CalibrationError(
                "validate_split: cases must contain only CalibrationCase objects, "
                f"got {type(case).__name__}"
            )

    corpus_version = NO_MANIFEST_CORPUS_VERSION
    if manifest is not None:
        if not isinstance(manifest, CalibrationCorpusManifest):
            raise CalibrationError(
                "validate_split: manifest must be a CalibrationCorpusManifest or None, "
                f"got {type(manifest).__name__}"
            )
        # Cross-identity: the supplied cases must be exactly the manifest's cases.
        case_ids = frozenset(c.case_id for c in cases)
        manifest_ids = frozenset(e.case_id for e in manifest.case_entries)
        if case_ids != manifest_ids:
            raise CalibrationError(
                "validate_split: the supplied cases do not correspond to the manifest's "
                "case_entries (case_id sets differ) — refusing to validate a mismatched "
                "(cases, manifest) pair"
            )
        corpus_version = manifest.calibration_corpus_version

    violations = _families_by_role(cases) + _blind_actor_violations(cases)
    return SplitValidationReport(
        is_valid=len(violations) == 0,
        calibration_corpus_version=corpus_version,
        violations=violations,
    )


def require_valid_split(
    cases: tuple[CalibrationCase, ...],
    manifest: CalibrationCorpusManifest | None = None,
) -> SplitValidationReport:
    """Convenience wrapper around :func:`validate_split` that **raises**
    :class:`CalibrationError` when the corpus is invalid (fail-closed call
    site), returning the report otherwise. The report-returning
    :func:`validate_split` remains the primary, explainable API."""
    report = validate_split(cases, manifest)
    if not report.is_valid:
        summary = "; ".join(v.reason for v in report.violations)
        raise CalibrationError(
            f"require_valid_split: corpus split is invalid ({len(report.violations)} "
            f"violation(s)): {summary}"
        )
    return report
