"""Calibration case contract (gate B1.2, ADR-0006 §D6/§D7).

**Contract only — no corpus, no versioning, no fitting, no scoring.** This
module defines what a single :class:`CalibrationCase` *is*: the typed,
frozen, deterministically-identified record of one calibration/validation
case (one attribution unit + its dataset-authored ground truth + its
dataset-authored expected-output *shape* + its corpus-role metadata). It
contains **no** corpus manifest, **no** ``calibration_corpus_version``, **no**
``calibration_version``, **no** scenario-family split / leakage engine, **no**
provenance-validation engine, **no** blind-actor-holdout / ATT&CK-ablation
logic, and **no** attribution scoring, likelihood, confidence, ranking, or
abstention. Those are later, separately-gated pieces (B1.3+ / the fitting
sub-gate / Phase 3) built *around* this contract, never inside it — mirroring
how ``correlation.contracts`` / ``attribution.contracts`` precede their own
engines.

**No ATT&CK dependency, no scoring dependency.** This module imports only its
own package (``calibration.errors``), the already-shared, framework-free
:func:`attribution_platform.domain.serialization.to_canonical_json`, and the
standard library. It never loads ATT&CK, never traverses the KB, never
computes ``g(x)``/``D(x)``, and holds **no** numeric threshold, weight,
score, or percentage of any kind.

**Anti-circular ground truth (ADR-0006 §D6/§D9), enforced at the type level.**
A case's actor label originates from dataset/incident/emulation provenance,
never from ATT&CK ``uses`` inference — enforced structurally: the only legal
:class:`ActorLabelSource` values are ``EMULATION_PLAN``/``INCIDENT_REPORT``/
``DATASET_ANNOTATION``/``UNKNOWN``; there is no "ATT&CK-derived" source, so a
label cannot even *declare* itself KB-derived. Likewise the
:class:`ExpectedOutputShape` carries a required, non-empty
``authorship_provenance`` string making its dataset-authorship explicit (esp.
its discriminating-evidence set), so it can never be *silently* ATT&CK-derived
(§D6 / accepted NB-2). Whether the author honored that remains an authorial
assertion — the contract makes it non-silent, not mechanically provable.

**Deterministic identity (ADR-0006 §D6 "deterministic content hash of the
case's frozen inputs"; §D17 determinism).** ``case_id`` is **computed**, not
supplied — a ``field(init=False)`` set in ``__post_init__`` via
:func:`compute_calibration_case_id`, mirroring
:class:`attribution_platform.correlation.temporal_proximity.TemporalProximityConfig`'s
own ``content_hash`` precedent. Its input boundary is fixed and documented in
:func:`compute_calibration_case_id`. It reuses the existing
``to_canonical_json`` (sorted-key, ``PYTHONHASHSEED``-independent) +
SHA-256/``"::"``-join conventions — never a new serializer or hash scheme.

**No numeric fields.** ``label_confidence`` and every "band" are **categorical
strings / closed enums**, never numbers — so serialization is byte-stable and
no threshold/score leaks in (ADR-0006 §D3/§D6; the fitting boundary is a later
gate).

**Deeply immutable, canonicalized collections.** Every contract is a
``@dataclass(frozen=True)``; every semantically-unordered id collection is
canonicalized to a sorted-unique ``tuple`` on construction (the exact
``tuple(sorted(set(...)))`` discipline every Phase 0–2 contract already uses),
so equality and ``case_id`` are order-independent.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import Enum

from attribution_platform.calibration.errors import CalibrationError
from attribution_platform.domain.serialization import to_canonical_json

#: Schema version of the B1.2 calibration-case contract, mirroring every prior
#: gate's ``"<slug>/<version>"`` convention.
CALIBRATION_CASE_SCHEMA_VERSION = "calibration-case/1"


def _sha256_hex(value: str) -> str:
    """SHA-256 hex digest of one caller-supplied string — a local copy of the
    identical helper every prior contracts layer owns independently (never a
    new hashing algorithm)."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _require_nonempty_str(value: object, field_name: str) -> str:
    """Calibration-layer non-empty-string check (raises
    :class:`CalibrationError`) — a local copy of the identical check every
    other layer owns, never imported across a package boundary."""
    if not isinstance(value, str) or not value.strip():
        raise CalibrationError(
            f"{field_name} must be a non-empty, non-whitespace string, got {value!r}"
        )
    return value


def _canonical_tuple(values: Iterable[str], field_name: str) -> tuple[str, ...]:
    """Validate every element non-empty, then canonicalize to a sorted-unique
    tuple — the exact ``tuple(sorted(set(...)))`` pattern every prior layer's
    tuple-of-ids field applies, so equality and hashing are order-independent."""
    canonical = tuple(sorted(set(values)))
    for element in canonical:
        _require_nonempty_str(element, field_name)
    return canonical


def _require_optional_str(value: object, field_name: str) -> str | None:
    """Return ``None`` unchanged, else require a non-empty string. Used for
    optional-but-must-be-meaningful-if-present fields (never numeric)."""
    if value is None:
        return None
    return _require_nonempty_str(value, field_name)


# ===========================================================================
# Closed enums (ADR-0006 §D6/§D7)
# ===========================================================================


class SourceKind(Enum):
    """How a case's telemetry was produced (ADR-0006 §D6). Closed set; a
    case is exactly one of these."""

    SYNTHETIC = "synthetic"
    REPLAY = "replay"
    EMULATED = "emulated"
    REAL_INCIDENT = "real_incident"


class ActorLabelSource(Enum):
    """Where a case's ground-truth actor label came from (ADR-0006 §D6/§D9).
    Deliberately has **no** "ATT&CK-derived" member — a label can never
    declare itself derived from the KB ``uses`` relationships the engine
    scores against (anti-circular, §D9)."""

    EMULATION_PLAN = "emulation-plan"
    INCIDENT_REPORT = "incident-report"
    DATASET_ANNOTATION = "dataset-annotation"
    UNKNOWN = "unknown"


class LabelSemantics(Enum):
    """The closed four-value label semantics ADR-0006 §D7 requires. A
    ``DISPUTED``/``UNKNOWN`` case must never silently become a negative
    example — that is enforced by corpus-use gates (B1.4+), never by
    fabricating an ``UNATTRIBUTABLE_BY_DESIGN`` here."""

    ATTRIBUTABLE = "attributable"
    UNATTRIBUTABLE_BY_DESIGN = "unattributable_by_design"
    DISPUTED = "disputed"
    UNKNOWN = "unknown"


class LabelConfidence(Enum):
    """The dataset's own **categorical** confidence in its actor label
    (ADR-0006 §D6). ADR-0006 does not enumerate a vocabulary; B1.2 adopts the
    minimal closed categorical set consistent with this codebase's own
    band shape (mirroring ``ConfidenceBand`` plus an explicit ``UNKNOWN``),
    **never a numeric score** — see the module docstring / the B1.2 report's
    recorded interpretation."""

    HIGH = "high"
    MODERATE = "moderate"
    LOW = "low"
    UNKNOWN = "unknown"


class CaseRole(Enum):
    """The corpus role of a case (ADR-0006 §D6/§D8). Assignment metadata:
    deliberately **not** part of ``case_id`` (a case's evidential+ground-truth
    identity is stable across a role reassignment — see
    :func:`compute_calibration_case_id`)."""

    CALIBRATION = "calibration"
    HELD_OUT_VALIDATION = "held_out_validation"
    BLIND_ACTOR_HOLDOUT = "blind_actor_holdout"
    TIER1_STRUCTURAL = "tier1_structural"
    EXCLUDED = "excluded"


class ExpectedOutcome(Enum):
    """Whether the case's expected output is a named leading hypothesis or an
    explicit "insufficient evidence" abstention (ADR-0006 §D6). Never a score
    — only which *shape* of outcome the dataset author expects."""

    LEADING_HYPOTHESIS = "leading_hypothesis"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"


# ===========================================================================
# Value objects (ADR-0006 §D6)
# ===========================================================================


@dataclass(frozen=True)
class GroundTruth:
    """Dataset/provenance-authored ground truth for one case (ADR-0006 §D6/§D7).

    ``actor_label`` is an actor identity **as authored by the dataset/incident/
    emulation source** (a name or id string) — never inferred from ATT&CK
    ``uses`` (§D9). Consistency invariants (fail closed):

    - ``ATTRIBUTABLE`` ⇒ ``actor_label`` present and ``actor_label_source`` is
      not ``UNKNOWN`` (a legitimately-sourced label must actually exist).
    - ``UNATTRIBUTABLE_BY_DESIGN`` ⇒ ``actor_label`` is ``None`` (a *designed*
      negative names no actor).
    - ``DISPUTED``/``UNKNOWN`` place no presence constraint on ``actor_label``
      (it may be present-but-uncertain or absent) — and this contract never
      coerces them into a negative; corpus-use gates (B1.4+) decide which
      operation may include them.
    """

    actor_label_source: ActorLabelSource
    label_semantics: LabelSemantics
    label_confidence: LabelConfidence
    actor_label: str | None = None
    campaign_context: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.actor_label_source, ActorLabelSource):
            raise CalibrationError(
                "GroundTruth.actor_label_source must be an ActorLabelSource, "
                f"got {type(self.actor_label_source).__name__}"
            )
        if not isinstance(self.label_semantics, LabelSemantics):
            raise CalibrationError(
                "GroundTruth.label_semantics must be a LabelSemantics, "
                f"got {type(self.label_semantics).__name__}"
            )
        if not isinstance(self.label_confidence, LabelConfidence):
            raise CalibrationError(
                "GroundTruth.label_confidence must be a LabelConfidence, "
                f"got {type(self.label_confidence).__name__}"
            )
        object.__setattr__(
            self, "actor_label", _require_optional_str(self.actor_label, "GroundTruth.actor_label")
        )
        object.__setattr__(
            self,
            "campaign_context",
            _canonical_tuple(self.campaign_context, "GroundTruth.campaign_context[]"),
        )

        if self.label_semantics is LabelSemantics.ATTRIBUTABLE:
            if self.actor_label is None:
                raise CalibrationError(
                    "GroundTruth: label_semantics ATTRIBUTABLE requires a non-empty actor_label"
                )
            if self.actor_label_source is ActorLabelSource.UNKNOWN:
                raise CalibrationError(
                    "GroundTruth: label_semantics ATTRIBUTABLE requires a known actor_label_source "
                    "(not UNKNOWN) — a legitimately-sourced label must have a real provenance"
                )
        if (
            self.label_semantics is LabelSemantics.UNATTRIBUTABLE_BY_DESIGN
            and self.actor_label is not None
        ):
            raise CalibrationError(
                "GroundTruth: label_semantics UNATTRIBUTABLE_BY_DESIGN must have actor_label=None "
                "(a designed negative names no actor)"
            )


@dataclass(frozen=True)
class ExpectedOutputShape:
    """The dataset-authored expected-output **shape** for one case (ADR-0006
    §D6). A *shape* — bands and evidence structure — never a model prediction,
    never a numeric score/percentage.

    - ``outcome``: named leading hypothesis vs explicit insufficient-evidence.
    - ``expected_likelihood_band`` / ``expected_confidence_band``: categorical
      band **name** strings (never numbers); the WEP/confidence vocabularies
      are themselves calibration-defined, so they are represented as authored
      tokens, not a fixed enum here. Required/forbidden per ``outcome`` below.
    - ``discriminating_evidence`` / ``expected_contradiction`` /
      ``expected_next_evidence``: dataset-authored reference tuples (may be
      empty).
    - ``authorship_provenance``: **required, non-empty** — the explicit,
      non-silent indication that this shape (especially
      ``discriminating_evidence``) was **authored from the case's own
      ground-truth/dataset provenance, not mechanically derived from ATT&CK**
      (§D6 / NB-2).

    Invariants (fail closed): ``INSUFFICIENT_EVIDENCE`` ⇒
    ``expected_likelihood_band`` is ``None`` (an abstention names no leading
    band); ``LEADING_HYPOTHESIS`` ⇒ ``expected_likelihood_band`` is present.
    """

    outcome: ExpectedOutcome
    authorship_provenance: str
    expected_likelihood_band: str | None = None
    expected_confidence_band: str | None = None
    discriminating_evidence: tuple[str, ...] = ()
    expected_contradiction: tuple[str, ...] = ()
    expected_next_evidence: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.outcome, ExpectedOutcome):
            raise CalibrationError(
                f"ExpectedOutputShape.outcome must be an ExpectedOutcome, "
                f"got {type(self.outcome).__name__}"
            )
        _require_nonempty_str(
            self.authorship_provenance, "ExpectedOutputShape.authorship_provenance"
        )
        object.__setattr__(
            self,
            "expected_likelihood_band",
            _require_optional_str(
                self.expected_likelihood_band, "ExpectedOutputShape.expected_likelihood_band"
            ),
        )
        object.__setattr__(
            self,
            "expected_confidence_band",
            _require_optional_str(
                self.expected_confidence_band, "ExpectedOutputShape.expected_confidence_band"
            ),
        )
        object.__setattr__(
            self,
            "discriminating_evidence",
            _canonical_tuple(
                self.discriminating_evidence, "ExpectedOutputShape.discriminating_evidence[]"
            ),
        )
        object.__setattr__(
            self,
            "expected_contradiction",
            _canonical_tuple(
                self.expected_contradiction, "ExpectedOutputShape.expected_contradiction[]"
            ),
        )
        object.__setattr__(
            self,
            "expected_next_evidence",
            _canonical_tuple(
                self.expected_next_evidence, "ExpectedOutputShape.expected_next_evidence[]"
            ),
        )

        if self.outcome is ExpectedOutcome.INSUFFICIENT_EVIDENCE:
            if self.expected_likelihood_band is not None:
                raise CalibrationError(
                    "ExpectedOutputShape: outcome INSUFFICIENT_EVIDENCE must have "
                    "expected_likelihood_band=None (an abstention names no leading band)"
                )
        elif self.expected_likelihood_band is None:
            raise CalibrationError(
                "ExpectedOutputShape: outcome LEADING_HYPOTHESIS requires a non-empty "
                "expected_likelihood_band"
            )


# ===========================================================================
# Deterministic case identity (ADR-0006 §D6/§D17)
# ===========================================================================

#: Fixed, documented ``case_id`` input boundary. ``case_id`` is a SHA-256 over
#: the canonical JSON of exactly these **stable, case-defining** inputs, in a
#: fixed key set (``to_canonical_json`` sorts keys, so key order is irrelevant
#: and the result is ``PYTHONHASHSEED``-independent):
#:
#:   corpus_schema_version, source_kind, source_ref, license, attack_kb_version,
#:   correlation_group_id, sequence_id, telemetry_provenance (canonical),
#:   coverage_assumptions (canonical), ground_truth, expected_output_shape.
#:
#: **Deliberately EXCLUDED** (so a case keeps its identity across a corpus
#: re-assignment): ``scenario_family_id`` and ``case_role`` — both are
#: corpus-assignment metadata (a case is "the same case" if its evidence +
#: ground truth + expected shape are the same, regardless of which fold/role a
#: later split places it in). Also excluded, by construction: any volatile
#: timestamp, memory address, filesystem path not part of ``source_ref``,
#: random UUID, calibration parameter, ``calibration_version``, manifest hash,
#: or runtime ordering — none appears in the input set above.
CASE_ID_INPUT_FIELDS: tuple[str, ...] = (
    "corpus_schema_version",
    "source_kind",
    "source_ref",
    "license",
    "attack_kb_version",
    "correlation_group_id",
    "sequence_id",
    "telemetry_provenance",
    "coverage_assumptions",
    "ground_truth",
    "expected_output_shape",
)


def compute_calibration_case_id(
    *,
    corpus_schema_version: str,
    source_kind: SourceKind,
    source_ref: str,
    license: str,
    attack_kb_version: str,
    correlation_group_id: str,
    sequence_id: str,
    telemetry_provenance: tuple[str, ...],
    coverage_assumptions: tuple[str, ...],
    ground_truth: GroundTruth,
    expected_output_shape: ExpectedOutputShape,
) -> str:
    """Deterministically compose a ``CalibrationCase.case_id`` from the fixed,
    documented stable-input boundary (:data:`CASE_ID_INPUT_FIELDS`) — never a
    random id, never dependent on ``scenario_family_id``/``case_role`` or any
    volatile value. Reuses ``to_canonical_json`` (sorted-key, byte-stable,
    ``PYTHONHASHSEED``-independent) and the SHA-256/``"::"``-join convention.

    Callers normally do not call this directly: :class:`CalibrationCase`
    computes and stores ``case_id`` itself. It is exposed for tests and for a
    later corpus builder.
    """
    identity: dict[str, object] = {
        "corpus_schema_version": corpus_schema_version,
        "source_kind": source_kind.value,
        "source_ref": source_ref,
        "license": license,
        "attack_kb_version": attack_kb_version,
        "correlation_group_id": correlation_group_id,
        "sequence_id": sequence_id,
        "telemetry_provenance": list(telemetry_provenance),
        "coverage_assumptions": list(coverage_assumptions),
        "ground_truth": ground_truth,
        "expected_output_shape": expected_output_shape,
    }
    return "::".join(["calibration-case", _sha256_hex(to_canonical_json(identity))])


# ===========================================================================
# CalibrationCase (ADR-0006 §D6)
# ===========================================================================


@dataclass(frozen=True)
class CalibrationCase:
    """One calibration/validation case (ADR-0006 §D6) — one attribution unit
    (``correlation_group_id`` + ``sequence_id``) plus its dataset-authored
    ground truth and expected-output shape and its corpus-role metadata.
    References the Phase 0–2 attribution unit **by id only** (never a copy of a
    ``CorrelationGroup``/``BehavioralSequence`` object, and never a
    reconstruction of one — this module imports neither).

    ``case_id`` is **computed** (``field(init=False)``), not supplied — a
    deterministic content hash of the stable inputs
    (:func:`compute_calibration_case_id` / :data:`CASE_ID_INPUT_FIELDS`), set in
    ``__post_init__`` after every collection is canonicalized, so it is
    order-independent. ``scenario_family_id`` and ``case_role`` are required and
    validated but are **not** part of ``case_id`` (corpus-assignment metadata).

    Field order places every required, non-default field before the defaulted
    ones (Python dataclass ordering) — not ADR-0006's own prose order.
    """

    scenario_family_id: str
    source_kind: SourceKind
    source_ref: str
    license: str
    attack_kb_version: str
    correlation_group_id: str
    sequence_id: str
    telemetry_provenance: tuple[str, ...]
    ground_truth: GroundTruth
    expected_output_shape: ExpectedOutputShape
    case_role: CaseRole
    coverage_assumptions: tuple[str, ...] = ()
    corpus_schema_version: str = field(default=CALIBRATION_CASE_SCHEMA_VERSION)
    case_id: str = field(init=False)

    def __post_init__(self) -> None:
        _require_nonempty_str(self.scenario_family_id, "CalibrationCase.scenario_family_id")
        if not isinstance(self.source_kind, SourceKind):
            raise CalibrationError(
                f"CalibrationCase.source_kind must be a SourceKind, "
                f"got {type(self.source_kind).__name__}"
            )
        _require_nonempty_str(self.source_ref, "CalibrationCase.source_ref")
        _require_nonempty_str(self.license, "CalibrationCase.license")
        _require_nonempty_str(self.attack_kb_version, "CalibrationCase.attack_kb_version")
        _require_nonempty_str(self.correlation_group_id, "CalibrationCase.correlation_group_id")
        _require_nonempty_str(self.sequence_id, "CalibrationCase.sequence_id")

        if not self.telemetry_provenance:
            raise CalibrationError(
                "CalibrationCase.telemetry_provenance must be non-empty: a case must trace to at "
                "least one Observation/Evidence provenance reference"
            )
        object.__setattr__(
            self,
            "telemetry_provenance",
            _canonical_tuple(self.telemetry_provenance, "CalibrationCase.telemetry_provenance[]"),
        )
        object.__setattr__(
            self,
            "coverage_assumptions",
            _canonical_tuple(self.coverage_assumptions, "CalibrationCase.coverage_assumptions[]"),
        )

        if not isinstance(self.ground_truth, GroundTruth):
            raise CalibrationError(
                f"CalibrationCase.ground_truth must be a GroundTruth, "
                f"got {type(self.ground_truth).__name__}"
            )
        if not isinstance(self.expected_output_shape, ExpectedOutputShape):
            raise CalibrationError(
                "CalibrationCase.expected_output_shape must be an ExpectedOutputShape, "
                f"got {type(self.expected_output_shape).__name__}"
            )
        if not isinstance(self.case_role, CaseRole):
            raise CalibrationError(
                f"CalibrationCase.case_role must be a CaseRole, "
                f"got {type(self.case_role).__name__}"
            )
        _require_nonempty_str(self.corpus_schema_version, "CalibrationCase.corpus_schema_version")

        # Contract-level consistency (ADR-0006 §D7): a *designed negative* must
        # not carry a positive expectation. (ATTRIBUTABLE does NOT force a
        # leading hypothesis: a true actor may still be expected to be
        # insufficiently supported by thin telemetry -- so no such constraint
        # is imposed on ATTRIBUTABLE.)
        if (
            self.ground_truth.label_semantics is LabelSemantics.UNATTRIBUTABLE_BY_DESIGN
            and self.expected_output_shape.outcome is not ExpectedOutcome.INSUFFICIENT_EVIDENCE
        ):
            raise CalibrationError(
                "CalibrationCase: UNATTRIBUTABLE_BY_DESIGN ground truth requires an "
                "expected_output_shape.outcome of INSUFFICIENT_EVIDENCE (a designed negative must "
                "not expect a leading hypothesis)"
            )

        object.__setattr__(
            self,
            "case_id",
            compute_calibration_case_id(
                corpus_schema_version=self.corpus_schema_version,
                source_kind=self.source_kind,
                source_ref=self.source_ref,
                license=self.license,
                attack_kb_version=self.attack_kb_version,
                correlation_group_id=self.correlation_group_id,
                sequence_id=self.sequence_id,
                telemetry_provenance=self.telemetry_provenance,
                coverage_assumptions=self.coverage_assumptions,
                ground_truth=self.ground_truth,
                expected_output_shape=self.expected_output_shape,
            ),
        )
