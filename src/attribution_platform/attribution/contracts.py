"""Attribution domain contracts (gate G3.2, ADR-0005 §D2/§D5/§D9/§D10).

**Contracts only — no attribution is performed here.** This module defines
what a `Candidate`/`Hypothesis`/`EvidenceAssessment`/`AttributionAssessment`/
`NextEvidence`/`AttributionResult`/`CoverageProfile`/`AttributionProvenance`
*are*; it contains no candidate generation (ADR-0005 §D7), no ACH matrix
construction (§D8), no combination-diagnosticity computation (§D3, `g(x)`/
`D(x)`), no likelihood/confidence calculation (§D9/§D10), no abstention
decision (§D13), no calibration (§D17), and no next-evidence counterfactual
algorithm (§D14). Those are later, separately-gated pieces of Phase 3 built
*against* these contracts, never inside them — mirroring exactly how G2.0's
``correlation.contracts`` and G2.4.0's ``correlation.sequence`` preceded
their own respective engines.

Nine contracts (eight ADR-0005 names plus one small forward-compatible
enum), mapped to their exact accepted-ADR section:

- :class:`CoverageState` / :class:`CoverageProfile` — ADR-0005 §D2. The
  four-state coverage model (``OBSERVED_PRESENT`` /
  ``OBSERVED_ABSENT_WITH_ADEQUATE_COVERAGE`` / ``NOT_OBSERVABLE`` /
  ``UNKNOWN``), scoped to one ``(CorrelationGroup, technique)`` pair.
- :class:`AttributionProvenance` — ADR-0005 §D5/§D15. Deliberately parallel
  to :class:`~attribution_platform.correlation.contracts.CorrelationProvenance`
  one layer up: same non-empty-and-canonicalized id-set pattern, same
  optional content-hash field.
- :class:`CandidateType` / :class:`Candidate` — ADR-0005 §D5. A possible
  attribution entity: exactly one of ``actor_ref``/``campaign_ref`` is set
  (an active ATT&CK Group or Campaign, per §D7's candidate universe).
  ``CandidateType`` is a *derived* two-value convenience (not a stored
  field) computed from which ref is set — it names no new stored state.
- :class:`Hypothesis` — ADR-0005 §D5. One competing attribution hypothesis
  for one ``(group, candidate)`` pair. The "Unattributed" null hypothesis is
  represented explicitly and deterministically via the fixed sentinel
  :data:`UNATTRIBUTED_CANDIDATE_ID` used *as* ``candidate_id`` — never a
  missing/``None`` candidate reference (see the module-level note below).
- :class:`EvidenceRole` / :class:`Relevance` / :class:`EvidenceAssessment` —
  ADR-0005 §D5/§D8. The Phase-3 interpretation of one
  ``(BehavioralStep, technique)`` pair against one ``Hypothesis`` — the real
  ACH-matrix cell. ``diagnosticity_ref`` is the accepted bare-``str``
  reference shape (not a ``Diagnosticity`` value object — see the module
  docstring's "Known accepted follow-up" note).
- :class:`SeparationBand` / :class:`Likelihood`, :class:`ConfidenceBand` /
  :class:`ConfidenceReason` / :class:`Confidence` — ADR-0005 §D9/§D10. The
  two *separate*, never-merged assessment axes — Likelihood stays
  categorical/comparative (a WEP band name plus two ``SeparationBand``
  values), Confidence stays a closed band plus categorical reasons. Neither
  is ever a raw number, a percentage, or a combined score.
- :class:`AttributionAssessment` — ADR-0005 §D5. The Likelihood/Confidence
  pair for one ``Hypothesis``, plus the required version stamps.
- :class:`NextEvidence` — ADR-0005 §D5/§D14. A derived recommendation
  *representation* only — no counterfactual algorithm runs here.
- :class:`AttributionResult` — ADR-0005 §D5/§D1. The one required
  persistence unit for exactly one attribution unit (one ``CorrelationGroup``
  → one ``AttributionResult`` — see the module-level note on how this
  1:1 cardinality is enforced at the contract level).

**Two-tier construction — deliberately ONE tier in this gate.** Every G2.x
contracts gate (G2.0, G2.4.0) paired its plain, self-validating constructors
with a "sanctioned builder" that additionally cross-validates against a real,
directly-supplied upstream object (e.g. ``build_behavioral_step`` verifying
``evidence_ids`` against a real ``CorrelationGroup``). This gate
**deliberately omits that second tier**: every cross-object grounding check
a builder could usefully perform here — "this ``actor_ref`` really is an
active ATT&CK Group," "this ``step_id`` really belongs to this
``BehavioralSequence``," "this ``Candidate`` really was placed in the set by
a real technique intersection" — requires either an ATT&CK KB traversal
query (§D6, forbidden this gate: "must not perform ATT&CK traversal
themselves") or literally *is* candidate generation / evidence assessment
construction (§D7/§D8, explicitly out of scope this gate). Building that
verification layer without the traversal/generation logic behind it would
either be a no-op or would smuggle in exactly the algorithm this gate is
scoped to exclude. Each contract below therefore validates only what is
checkable from its own given fields alone (non-empty/canonicalized ids,
enum membership, STIX-id shape, internal self-consistency) — the same
"local, self-contained validation" ``BehavioralStep``'s own plain
constructor already limits itself to. The cross-object grounding tier is
deferred to whichever later gate actually constructs these objects against
real ``CorrelationGroup``/``BehavioralSequence``/``AttackKnowledge`` data.

**Known accepted follow-up, faithfully NOT implemented here.** The Gate 3.1
pre-acceptance audit flagged ``EvidenceAssessment.diagnosticity_ref: str``
as a candidate for a proper ``Diagnosticity`` value object in a future
amendment. ADR-0005's accepted text (as committed) still specifies the bare
``str`` reference shape unchanged — this module implements that accepted
shape faithfully, not the discussed-but-not-adopted refinement. Redesigning
it here would silently rewrite an accepted decision, which this project's
own discipline forbids.

**Explicit, deterministic "Unattributed" — not a magic missing Candidate.**
:data:`UNATTRIBUTED_CANDIDATE_ID` is a fixed, non-KB-derived string constant
(never a random id, never absent/``None``) that stands *as* a
``Hypothesis.candidate_id`` value. ADR-0005 §D5 names it as a sentinel
attached to the ``Candidate`` contract's comment, not as a distinct field on
``Candidate`` itself — and a real ``Candidate`` always has exactly one of
``actor_ref``/``campaign_ref`` set (it names one real, active ATT&CK Group
or Campaign). "Unattributed" names no ATT&CK entity at all, so it is never
represented by constructing a ``Candidate`` instance; it is referenced
purely by this one deterministic id string, exactly as "every candidate set"
(§D4/§D7) always includes it without needing a KB lookup to produce it.
:func:`is_unattributed_hypothesis` makes this check explicit and reusable
rather than repeating the comparison inline at every call site.

**Deeply immutable, deterministic identity.** Every contract is a
``@dataclass(frozen=True)`` whose fields are only scalars, ``tuple``, or
other frozen dataclasses/enums — the same discipline every Phase 0–2
contract already enforces. Every id is composed via the project's existing
SHA-256/``"::"``-join convention (never a naive delimiter join — real
upstream ids already contain ``"::"`` themselves; see
:func:`_sha256_hex`'s docstring), never ``uuid4()``, never wall-clock-
derived. Every semantically-unordered collection (id sets, alias sets) is
canonicalized to a sorted-unique tuple on construction, exactly like
``CorrelationGroup.structural_link_ids``/``BehavioralStep.evidence_ids``.

**No Phase 0–2 mutation, no second Evidence model.** Nothing in this module
imports a *mutable* reference to, or copies the content of, ``Observation``,
``Evidence``, ``DetectionResult``, ``CorrelationGroup``, ``CorrelationLink``,
``BehavioralSequence``, or ``BehavioralStep`` — every reference to one is a
bare ``str`` id (``group_id``, ``sequence_id``, ``step_id``,
``evidence_id``/``observation_id`` inside :class:`AttributionProvenance`),
the identical "store ids, not objects" discipline ``CorrelationGroup``
itself already established for ``structural_link_ids``. This module imports
:class:`~attribution_platform.domain.entities.TimeSpan` only — a plain,
already-shared, identity-free *value type* (not an Evidence/Observation
object), reused unchanged rather than re-invented, exactly as
``domain.evidence.Evidence`` itself already embeds it.

**No Elastic, no network, no database.** This module imports nothing beyond
its own package (``attribution.errors``), ``attribution_platform.domain.entities``
(for ``TimeSpan`` only), and the standard library.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import Enum

from attribution_platform.attribution.errors import AttributionError
from attribution_platform.domain.entities import TimeSpan

#: Version of each new G3.2 contract's own schema, mirroring every prior
#: gate's ``"<slug>/<version>"`` convention exactly.
COVERAGE_PROFILE_SCHEMA_VERSION = "coverage-profile/1"
ATTRIBUTION_PROVENANCE_SCHEMA_VERSION = "attribution-provenance/1"
CANDIDATE_SCHEMA_VERSION = "candidate/1"
HYPOTHESIS_SCHEMA_VERSION = "hypothesis/1"
EVIDENCE_ASSESSMENT_SCHEMA_VERSION = "evidence-assessment/1"
ATTRIBUTION_ASSESSMENT_SCHEMA_VERSION = "attribution-assessment/1"
NEXT_EVIDENCE_SCHEMA_VERSION = "next-evidence/1"
ATTRIBUTION_RESULT_SCHEMA_VERSION = "attribution-result/1"

#: The fixed, non-KB-derived sentinel identifying the null hypothesis
#: (ADR-0005 §D5's ``UNATTRIBUTED_CANDIDATE_ID``). Deliberately NOT
#: SHA-256-shaped (a real :func:`compute_candidate_id` output is always the
#: literal prefix ``"candidate::"`` followed by 64 lowercase hex characters)
#: so it can never collide with a genuine, KB-derived candidate id.
UNATTRIBUTED_CANDIDATE_ID = "candidate::unattributed"


def _require_nonempty_str(value: object, field_name: str) -> str:
    """Attribution-layer non-empty-string check (raises ``AttributionError``)
    — a local copy of the identical check every other layer in this project
    owns independently (``correlation.contracts``/``correlation.sequence``'s
    own private helpers), never imported across a package boundary."""
    if not isinstance(value, str) or not value.strip():
        raise AttributionError(
            f"{field_name} must be a non-empty, non-whitespace string, got {value!r}"
        )
    return value


#: STIX 2.1 ids are ``<type>--<uuid>`` — the identical structural check
#: :class:`attribution_platform.domain.attack.AttackRef` already validates
#: (shape only, never KB resolution — that remains a later gate's job here
#: too, exactly as ``attack_knowledge.resolution.resolve_attack_ref`` is
#: kept separate from ``AttackRef`` itself).
_STIX_ID_SEPARATOR = "--"


def _require_stix_id(value: object, field_name: str, *, expected_prefix: str | None = None) -> str:
    """Validate STIX-id *shape* only (``<type>--<uuid>``), never resolving
    against a loaded ``AttackKnowledge`` — this module has no KB dependency
    at all (see the module docstring). When ``expected_prefix`` is given,
    the id's own type-prefix must match it exactly."""
    text = _require_nonempty_str(value, field_name)
    if _STIX_ID_SEPARATOR not in text:
        raise AttributionError(
            f"{field_name} {text!r} is not a well-formed STIX id "
            f"(expected '<type>{_STIX_ID_SEPARATOR}<uuid>')"
        )
    prefix = text.split(_STIX_ID_SEPARATOR, 1)[0]
    if expected_prefix is not None and prefix != expected_prefix:
        raise AttributionError(
            f"{field_name} {text!r} has STIX type-prefix {prefix!r}, expected {expected_prefix!r}"
        )
    return text


def _sha256_hex(value: str) -> str:
    """SHA-256 hex digest of one caller-supplied, free-text identity
    component — local copy of every prior layer's own helper (see
    ``correlation.contracts._sha256_hex``'s docstring for the exact
    delimiter-collision rationale this exists to avoid; unchanged here)."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _canonical_tuple(values: Iterable[str], field_name: str) -> tuple[str, ...]:
    """Validate every element non-empty, then canonicalize to a
    sorted-unique tuple — the exact ``tuple(sorted(set(...)))`` pattern
    every prior layer's tuple-of-ids field already applies, so equality is
    order-independent and serialization is deterministic."""
    canonical = tuple(sorted(set(values)))
    for element in canonical:
        _require_nonempty_str(element, field_name)
    return canonical


# ===========================================================================
# ADR-0005 §D2 — CoverageProfile
# ===========================================================================


class CoverageState(Enum):
    """The closed, four-value coverage model ADR-0005 §D2 requires —
    deliberately never a continuous/probabilistic coverage percentage.
    Fail-closed default is :attr:`UNKNOWN`, matching every other closed
    enum's own shape discipline in this codebase
    (``LinkClass``/``OrderingBasisKind``/``GapReason``)."""

    OBSERVED_PRESENT = "observed_present"
    OBSERVED_ABSENT_WITH_ADEQUATE_COVERAGE = "observed_absent_with_adequate_coverage"
    NOT_OBSERVABLE = "not_observable"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class AttributionProvenance:
    """Provenance for an attribution object — deliberately parallel to
    :class:`~attribution_platform.correlation.contracts.CorrelationProvenance`,
    one layer up (ADR-0005 §D5/§D15): same non-empty-and-canonicalized
    id-set pattern, same optional content-hash field, same "provenance
    cannot be silently dropped" invariant.

    - ``method`` / ``method_version``: identity of the attribution logic
      that produced this object — the later engine's own identity, supplied
      by the caller, never fabricated here.
    - ``source_group_id`` / ``source_sequence_id``: the one
      ``CorrelationGroup``/``BehavioralSequence`` this object traces back to
      (ADR-0004 D1's 1:1 pairing).
    - ``source_evidence_ids`` / ``source_observation_ids``: the Evidence/
      Observation id(s) backing this object — **required and non-empty**,
      canonicalized to a sorted-unique tuple, exactly like
      ``CorrelationProvenance``/``DerivationProvenance`` one and two layers
      down.
    - ``method_content_hash``: optional — set to the ``calibration_version``
      content hash when applicable (ADR-0005 §D5's own comment), left
      absent (``None``) rather than fabricated otherwise.
    """

    method: str
    method_version: str
    source_group_id: str
    source_sequence_id: str
    source_evidence_ids: tuple[str, ...] = ()
    source_observation_ids: tuple[str, ...] = ()
    method_content_hash: str | None = None
    schema_version: str = field(default=ATTRIBUTION_PROVENANCE_SCHEMA_VERSION)

    def __post_init__(self) -> None:
        _require_nonempty_str(self.method, "AttributionProvenance.method")
        _require_nonempty_str(self.method_version, "AttributionProvenance.method_version")
        _require_nonempty_str(self.source_group_id, "AttributionProvenance.source_group_id")
        _require_nonempty_str(self.source_sequence_id, "AttributionProvenance.source_sequence_id")

        if not self.source_evidence_ids:
            raise AttributionError(
                "AttributionProvenance.source_evidence_ids must be non-empty: an attribution "
                "object must retain provenance to at least one supporting Evidence item"
            )
        object.__setattr__(
            self,
            "source_evidence_ids",
            _canonical_tuple(
                self.source_evidence_ids, "AttributionProvenance.source_evidence_ids[]"
            ),
        )

        if not self.source_observation_ids:
            raise AttributionError(
                "AttributionProvenance.source_observation_ids must be non-empty: an "
                "attribution object must retain provenance to at least one supporting "
                "Observation"
            )
        object.__setattr__(
            self,
            "source_observation_ids",
            _canonical_tuple(
                self.source_observation_ids, "AttributionProvenance.source_observation_ids[]"
            ),
        )

        if self.method_content_hash is not None:
            _require_nonempty_str(
                self.method_content_hash, "AttributionProvenance.method_content_hash"
            )
        _require_nonempty_str(self.schema_version, "AttributionProvenance.schema_version")


@dataclass(frozen=True)
class CoverageProfile:
    """The coverage state for one ``(CorrelationGroup, technique)`` pair
    (ADR-0005 §D2) — an input to the Attribution Engine, never a Phase 2
    output. Distinguishes, deterministically: a technique that *was*
    observed (:attr:`CoverageState.OBSERVED_PRESENT`); one that telemetry
    could have shown but did not
    (:attr:`CoverageState.OBSERVED_ABSENT_WITH_ADEQUATE_COVERAGE` — a
    genuine contradiction); one the required data source was never
    collected for (:attr:`CoverageState.NOT_OBSERVABLE` — a coverage gap,
    not a contradiction); and a genuinely indeterminate case
    (:attr:`CoverageState.UNKNOWN`, fails closed like ``NOT_OBSERVABLE``).

    Field order here deliberately differs from ADR-0005's own prose listing
    (which places ``provenance`` last): Python dataclass field ordering
    requires every non-default field before any defaulted one, so
    ``provenance`` (required, no default) is declared before
    ``data_sources_required``/``data_sources_available``/
    ``observation_interval`` (each optional) — the identical reordering
    :class:`~attribution_platform.correlation.contracts.CorrelationGroup`
    and :class:`~attribution_platform.correlation.sequence.BehavioralSequence`
    already apply to their own required ``provenance`` field.

    This gate does not compute ``state`` — see the module docstring's note
    on why the cross-object grounding/derivation tier is deferred.
    """

    coverage_id: str
    group_id: str
    technique_stix_id: str
    attack_kb_version: str
    state: CoverageState
    provenance: AttributionProvenance
    data_sources_required: tuple[str, ...] = ()
    data_sources_available: tuple[str, ...] = ()
    observation_interval: TimeSpan | None = None
    schema_version: str = field(default=COVERAGE_PROFILE_SCHEMA_VERSION)

    def __post_init__(self) -> None:
        _require_nonempty_str(self.coverage_id, "CoverageProfile.coverage_id")
        _require_nonempty_str(self.group_id, "CoverageProfile.group_id")
        _require_stix_id(
            self.technique_stix_id,
            "CoverageProfile.technique_stix_id",
            expected_prefix="attack-pattern",
        )
        _require_nonempty_str(self.attack_kb_version, "CoverageProfile.attack_kb_version")

        if not isinstance(self.state, CoverageState):
            raise AttributionError(
                f"CoverageProfile.state must be a CoverageState, got {type(self.state).__name__}"
            )
        if not isinstance(self.provenance, AttributionProvenance):
            raise AttributionError(
                f"CoverageProfile.provenance must be an AttributionProvenance, "
                f"got {type(self.provenance).__name__}"
            )

        object.__setattr__(
            self,
            "data_sources_required",
            _canonical_tuple(self.data_sources_required, "CoverageProfile.data_sources_required[]"),
        )
        object.__setattr__(
            self,
            "data_sources_available",
            _canonical_tuple(
                self.data_sources_available, "CoverageProfile.data_sources_available[]"
            ),
        )

        if self.observation_interval is not None and not isinstance(
            self.observation_interval, TimeSpan
        ):
            raise AttributionError(
                "CoverageProfile.observation_interval must be a TimeSpan or None, got "
                f"{type(self.observation_interval).__name__}"
            )

        _require_nonempty_str(self.schema_version, "CoverageProfile.schema_version")


def compute_coverage_profile_id(group_id: str, technique_stix_id: str) -> str:
    """Deterministically compose a ``CoverageProfile.coverage_id`` from its
    owning group and the technique it answers coverage for (ADR-0005 §D2) —
    never a randomly generated id."""
    _require_nonempty_str(group_id, "compute_coverage_profile_id(group_id=...)")
    _require_nonempty_str(technique_stix_id, "compute_coverage_profile_id(technique_stix_id=...)")
    return "::".join(["coverage-profile", _sha256_hex(group_id), _sha256_hex(technique_stix_id)])


# ===========================================================================
# ADR-0005 §D5 — Candidate
# ===========================================================================


class CandidateType(Enum):
    """A *derived* two-value convenience — never a stored field — naming
    which of :attr:`Candidate.actor_ref`/:attr:`Candidate.campaign_ref` is
    set. ADR-0005 §D7's candidate universe is exactly these two ATT&CK
    object kinds; this enum names that existing distinction, it does not
    introduce a new one."""

    GROUP = "group"
    CAMPAIGN = "campaign"


@dataclass(frozen=True)
class Candidate:
    """A possible attribution entity — an active ATT&CK Group or Campaign,
    never a hard-coded actor (ADR-0005 §D5/§D6/§D7). Exactly one of
    ``actor_ref``/``campaign_ref`` is set; "Unattributed" is never
    represented as a ``Candidate`` instance at all — see the module
    docstring's note on :data:`UNATTRIBUTED_CANDIDATE_ID`.

    - ``candidate_id``: deterministic, composed via
      :func:`compute_candidate_id` — **KB-version-scoped, not case-scoped**:
      stable across every ``AttributionResult`` that ever considers this
      candidate, since it names a fact about the pinned KB, not a fact about
      one case.
    - ``generation_basis``: the technique/software STIX ids that placed
      this candidate in the set (§D7) — **required, non-empty**: a
      candidate with no generation basis has no reason to exist in the set,
      the identical reasoning
      :class:`~attribution_platform.correlation.contracts.CorrelationGroup`
      already applies to its own ``structural_link_ids``. This gate does
      not *populate* it correctly (that is §D7's job); it only requires
      that whatever is supplied is non-empty and STIX-id-shaped.
    - ``actor_ref`` / ``campaign_ref``: the canonical STIX id of the Group
      or Campaign this candidate names — exactly one is set.
    - ``alias_stix_ids``: every alias STIX id collapsed into this one
      candidate (§D6) — optional, may be empty; canonicalized sorted-unique.

    Field order here deliberately places ``generation_basis`` before the
    defaulted ``actor_ref``/``campaign_ref``/``alias_stix_ids`` fields
    (Python dataclass ordering requires non-default fields first) — the
    same kind of reordering ADR-0005's own prose-vs-code field order already
    tolerates elsewhere in this codebase (e.g. ``CorrelationGroup``,
    ``BehavioralSequence``).
    """

    candidate_id: str
    attack_kb_version: str
    generation_basis: tuple[str, ...]
    actor_ref: str | None = None
    campaign_ref: str | None = None
    alias_stix_ids: tuple[str, ...] = ()
    schema_version: str = field(default=CANDIDATE_SCHEMA_VERSION)

    def __post_init__(self) -> None:
        _require_nonempty_str(self.candidate_id, "Candidate.candidate_id")
        _require_nonempty_str(self.attack_kb_version, "Candidate.attack_kb_version")

        if not self.generation_basis:
            raise AttributionError(
                "Candidate.generation_basis must be non-empty: a candidate with no "
                "technique/software basis has no reason to exist in the candidate set"
            )
        object.__setattr__(
            self,
            "generation_basis",
            _canonical_tuple(self.generation_basis, "Candidate.generation_basis[]"),
        )

        if (self.actor_ref is None) == (self.campaign_ref is None):
            raise AttributionError(
                "Candidate: exactly one of actor_ref/campaign_ref must be set "
                f"(got actor_ref={self.actor_ref!r}, campaign_ref={self.campaign_ref!r})"
            )
        if self.actor_ref is not None:
            _require_stix_id(self.actor_ref, "Candidate.actor_ref", expected_prefix="intrusion-set")
        if self.campaign_ref is not None:
            _require_stix_id(
                self.campaign_ref, "Candidate.campaign_ref", expected_prefix="campaign"
            )

        object.__setattr__(
            self,
            "alias_stix_ids",
            _canonical_tuple(self.alias_stix_ids, "Candidate.alias_stix_ids[]"),
        )
        _require_nonempty_str(self.schema_version, "Candidate.schema_version")

    @property
    def candidate_type(self) -> CandidateType:
        """Derived from which of ``actor_ref``/``campaign_ref`` is set —
        never independently stored (see :class:`CandidateType`)."""
        return CandidateType.GROUP if self.actor_ref is not None else CandidateType.CAMPAIGN


def compute_candidate_id(actor_or_campaign_stix_id: str) -> str:
    """Deterministically compose a ``Candidate.candidate_id`` from the
    canonical Group/Campaign STIX id it names (ADR-0005 §D5) — never a
    randomly generated id. Stable across every case that considers this
    candidate, since it names a KB fact, not a case fact."""
    _require_nonempty_str(
        actor_or_campaign_stix_id, "compute_candidate_id(actor_or_campaign_stix_id=...)"
    )
    return "::".join(["candidate", _sha256_hex(actor_or_campaign_stix_id)])


# ===========================================================================
# ADR-0005 §D5 — Hypothesis
# ===========================================================================


@dataclass(frozen=True)
class Hypothesis:
    """One competing attribution hypothesis for one ``(group, candidate)``
    pair (ADR-0005 §D5). Preserves the distinction the Gate 3.2 task
    requires: ``candidate_id`` is the candidate *identity* (a bare id, never
    embedding the ``Candidate`` object itself — the same "store ids, not
    objects" discipline every upstream contract already uses);
    ``evidence_assessment_ids``/``coverage_notes`` are this hypothesis's own
    *state* (which assessments/coverage facts it currently rests on); no
    attribution *decision* (leading candidate, likelihood, confidence) is
    made or stored here — that is :class:`AttributionAssessment`'s and
    :class:`AttributionResult`'s job.

    ``candidate_id`` may equal :data:`UNATTRIBUTED_CANDIDATE_ID` — the
    explicit, deterministic representation of the null hypothesis (see the
    module docstring). It is never ``None``/omitted: every ``Hypothesis``
    names a candidate identity, real or the sentinel, unconditionally.
    """

    hypothesis_id: str
    group_id: str
    candidate_id: str
    evidence_assessment_ids: tuple[str, ...] = ()
    coverage_notes: tuple[str, ...] = ()
    alternative_explanations: tuple[str, ...] = ()
    schema_version: str = field(default=HYPOTHESIS_SCHEMA_VERSION)

    def __post_init__(self) -> None:
        _require_nonempty_str(self.hypothesis_id, "Hypothesis.hypothesis_id")
        _require_nonempty_str(self.group_id, "Hypothesis.group_id")
        _require_nonempty_str(self.candidate_id, "Hypothesis.candidate_id")

        object.__setattr__(
            self,
            "evidence_assessment_ids",
            _canonical_tuple(self.evidence_assessment_ids, "Hypothesis.evidence_assessment_ids[]"),
        )
        object.__setattr__(
            self,
            "coverage_notes",
            _canonical_tuple(self.coverage_notes, "Hypothesis.coverage_notes[]"),
        )
        object.__setattr__(
            self,
            "alternative_explanations",
            _canonical_tuple(
                self.alternative_explanations, "Hypothesis.alternative_explanations[]"
            ),
        )
        _require_nonempty_str(self.schema_version, "Hypothesis.schema_version")

    @property
    def is_unattributed(self) -> bool:
        """``True`` iff this hypothesis names the explicit null-hypothesis
        sentinel — see :func:`is_unattributed_hypothesis`."""
        return self.candidate_id == UNATTRIBUTED_CANDIDATE_ID


def is_unattributed_hypothesis(hypothesis: Hypothesis) -> bool:
    """Explicit, reusable check for the null hypothesis — never re-derive
    this comparison inline at a call site (ADR-0005 §D4/§D7; Gate 3.2's own
    "Unattributed must be represented explicitly and deterministically")."""
    if not isinstance(hypothesis, Hypothesis):
        raise AttributionError(
            f"is_unattributed_hypothesis: expected a Hypothesis, got {type(hypothesis).__name__}"
        )
    return hypothesis.is_unattributed


def compute_hypothesis_id(group_id: str, candidate_id: str) -> str:
    """Deterministically compose a ``Hypothesis.hypothesis_id`` from its
    ``(group, candidate)`` pair (ADR-0005 §D5) — never a randomly generated
    id. ``candidate_id`` may be :data:`UNATTRIBUTED_CANDIDATE_ID`."""
    _require_nonempty_str(group_id, "compute_hypothesis_id(group_id=...)")
    _require_nonempty_str(candidate_id, "compute_hypothesis_id(candidate_id=...)")
    return "::".join(["hypothesis", _sha256_hex(group_id), _sha256_hex(candidate_id)])


# ===========================================================================
# ADR-0005 §D5/§D8 — EvidenceAssessment
# ===========================================================================


class EvidenceRole(Enum):
    """The closed, two-value evidentiary role ADR-0005 §D5 requires for one
    ACH-matrix cell."""

    SUPPORTING = "supporting"
    CONTRADICTING = "contradicting"


class Relevance(Enum):
    """The closed, three-value relevance category ADR-0005 §D5 requires,
    derived from the pinned KB's own ``uses`` data (not computed in this
    gate — see the module docstring)."""

    CONSISTENT = "consistent"
    INCONSISTENT = "inconsistent"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class EvidenceAssessment:
    """The Phase-3 interpretation of one ``(BehavioralStep, technique)``
    pair against one ``Hypothesis`` — the real ACH-matrix cell (ADR-0005
    §D5/§D8). References upstream evidence/behavior by id only
    (``step_id``) — never a copy of any ``Evidence``/``BehavioralStep``
    field content.

    ``diagnosticity_ref`` is the accepted bare-``str`` reference to the
    (not-yet-computed) ``D(x)``/``D(C)`` value — "never a bare float stored
    with no explanation attached" (ADR-0005 §D5's own comment). This gate
    computes nothing; it only requires the reference be a genuine non-empty
    string, never a numeric literal masquerading as one (see the guard test
    in ``tests/test_attribution_contracts.py``).
    """

    assessment_id: str
    hypothesis_id: str
    step_id: str
    technique_stix_id: str
    role: EvidenceRole
    relevance: Relevance
    diagnosticity_ref: str
    coverage_id: str | None = None
    schema_version: str = field(default=EVIDENCE_ASSESSMENT_SCHEMA_VERSION)

    def __post_init__(self) -> None:
        _require_nonempty_str(self.assessment_id, "EvidenceAssessment.assessment_id")
        _require_nonempty_str(self.hypothesis_id, "EvidenceAssessment.hypothesis_id")
        _require_nonempty_str(self.step_id, "EvidenceAssessment.step_id")
        _require_stix_id(
            self.technique_stix_id,
            "EvidenceAssessment.technique_stix_id",
            expected_prefix="attack-pattern",
        )

        if not isinstance(self.role, EvidenceRole):
            raise AttributionError(
                f"EvidenceAssessment.role must be an EvidenceRole, got {type(self.role).__name__}"
            )
        if not isinstance(self.relevance, Relevance):
            raise AttributionError(
                f"EvidenceAssessment.relevance must be a Relevance, "
                f"got {type(self.relevance).__name__}"
            )
        if isinstance(self.diagnosticity_ref, bool) or not isinstance(self.diagnosticity_ref, str):
            raise AttributionError(
                "EvidenceAssessment.diagnosticity_ref must be a str reference, never a bare "
                f"numeric score, got {type(self.diagnosticity_ref).__name__}"
            )
        _require_nonempty_str(self.diagnosticity_ref, "EvidenceAssessment.diagnosticity_ref")

        if self.coverage_id is not None:
            _require_nonempty_str(self.coverage_id, "EvidenceAssessment.coverage_id")
        _require_nonempty_str(self.schema_version, "EvidenceAssessment.schema_version")


def compute_evidence_assessment_id(hypothesis_id: str, step_id: str, technique_stix_id: str) -> str:
    """Deterministically compose an ``EvidenceAssessment.assessment_id``
    from the ACH-matrix cell it represents (ADR-0005 §D5) — never a
    randomly generated id."""
    _require_nonempty_str(hypothesis_id, "compute_evidence_assessment_id(hypothesis_id=...)")
    _require_nonempty_str(step_id, "compute_evidence_assessment_id(step_id=...)")
    _require_nonempty_str(
        technique_stix_id, "compute_evidence_assessment_id(technique_stix_id=...)"
    )
    return "::".join(
        [
            "evidence-assessment",
            _sha256_hex(hypothesis_id),
            _sha256_hex(step_id),
            _sha256_hex(technique_stix_id),
        ]
    )


# ===========================================================================
# ADR-0005 §D9/§D10 — Likelihood, Confidence (kept strictly separate)
# ===========================================================================


class SeparationBand(Enum):
    """The categorical separation band ADR-0005 §D9 names by example
    (``CLEAR | MARGINAL | OVERLAPPING``) — never a raw number rendered to
    the analyst."""

    CLEAR = "clear"
    MARGINAL = "marginal"
    OVERLAPPING = "overlapping"


@dataclass(frozen=True)
class Likelihood:
    """The comparative, never-a-raw-probability Likelihood axis (ADR-0005
    §D9). ``wep_band`` stays a plain ``str`` (not a closed enum) because
    ADR-0005 is explicit that the exact WEP band set/thresholds are a
    ``calibration_version`` parameter, never chosen in this ADR or this
    gate — enumerating a fixed set here would silently invent a decision
    §D17 reserves for calibration."""

    wep_band: str
    separation_from_null: SeparationBand
    separation_from_next: SeparationBand

    def __post_init__(self) -> None:
        _require_nonempty_str(self.wep_band, "Likelihood.wep_band")
        if not isinstance(self.separation_from_null, SeparationBand):
            raise AttributionError(
                "Likelihood.separation_from_null must be a SeparationBand, "
                f"got {type(self.separation_from_null).__name__}"
            )
        if not isinstance(self.separation_from_next, SeparationBand):
            raise AttributionError(
                "Likelihood.separation_from_next must be a SeparationBand, "
                f"got {type(self.separation_from_next).__name__}"
            )


class ConfidenceBand(Enum):
    """The closed, three-value Confidence band ADR-0005 §D10 requires."""

    HIGH = "high"
    MODERATE = "moderate"
    LOW = "low"


class ConfidenceReason(Enum):
    """The closed, six-value categorical Confidence factor set ADR-0005
    §D10 requires — each a named reason, never a numeric weight."""

    COVERAGE_GAP = "coverage_gap"
    RELIABILITY = "reliability"
    CORROBORATION = "corroboration"
    CONSISTENCY = "consistency"
    CONTRADICTION_LOAD = "contradiction_load"
    OUTSIDE_CALIBRATED_REGIME = "outside_calibrated_regime"


@dataclass(frozen=True)
class Confidence:
    """The categorical, never-a-percentage Confidence axis (ADR-0005 §D10)
    — kept strictly separate from :class:`Likelihood` (Gate 3.2's own
    "MUST NOT be merged" requirement); nothing in this module ever combines
    the two into a single score."""

    band: ConfidenceBand
    reasons: tuple[ConfidenceReason, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.band, ConfidenceBand):
            raise AttributionError(
                f"Confidence.band must be a ConfidenceBand, got {type(self.band).__name__}"
            )
        for reason in self.reasons:
            if not isinstance(reason, ConfidenceReason):
                raise AttributionError(
                    f"Confidence.reasons must contain only ConfidenceReason values, "
                    f"got {type(reason).__name__}"
                )
        object.__setattr__(self, "reasons", tuple(sorted(set(self.reasons), key=lambda r: r.value)))


# ===========================================================================
# ADR-0005 §D5 — AttributionAssessment
# ===========================================================================


@dataclass(frozen=True)
class AttributionAssessment:
    """The Likelihood/Confidence assessment of one ``Hypothesis`` (ADR-0005
    §D5). Preserves the accepted Likelihood/Confidence separation (Gate 3.2
    §7) — both are present as distinct, typed, categorical fields; nothing
    here is a percentage, a probability, or a combined score.

    Field order here places ``next_evidence_id`` after every required
    version stamp (Python dataclass ordering requires non-default fields
    first) rather than ADR-0005's own prose order.
    """

    assessment_id: str
    hypothesis_id: str
    likelihood: Likelihood
    confidence: Confidence
    uncertainty: str
    calibration_version: str
    attack_kb_version: str
    methodology_version: str
    next_evidence_id: str | None = None
    schema_version: str = field(default=ATTRIBUTION_ASSESSMENT_SCHEMA_VERSION)

    def __post_init__(self) -> None:
        _require_nonempty_str(self.assessment_id, "AttributionAssessment.assessment_id")
        _require_nonempty_str(self.hypothesis_id, "AttributionAssessment.hypothesis_id")

        if not isinstance(self.likelihood, Likelihood):
            raise AttributionError(
                f"AttributionAssessment.likelihood must be a Likelihood, "
                f"got {type(self.likelihood).__name__}"
            )
        if not isinstance(self.confidence, Confidence):
            raise AttributionError(
                f"AttributionAssessment.confidence must be a Confidence, "
                f"got {type(self.confidence).__name__}"
            )
        _require_nonempty_str(self.uncertainty, "AttributionAssessment.uncertainty")
        _require_nonempty_str(self.calibration_version, "AttributionAssessment.calibration_version")
        _require_nonempty_str(self.attack_kb_version, "AttributionAssessment.attack_kb_version")
        _require_nonempty_str(self.methodology_version, "AttributionAssessment.methodology_version")
        if self.next_evidence_id is not None:
            _require_nonempty_str(self.next_evidence_id, "AttributionAssessment.next_evidence_id")
        _require_nonempty_str(self.schema_version, "AttributionAssessment.schema_version")


def compute_attribution_assessment_id(hypothesis_id: str, calibration_version: str) -> str:
    """Deterministically compose an
    ``AttributionAssessment.assessment_id`` (ADR-0005 §D5) — never a
    randomly generated id."""
    _require_nonempty_str(hypothesis_id, "compute_attribution_assessment_id(hypothesis_id=...)")
    _require_nonempty_str(
        calibration_version, "compute_attribution_assessment_id(calibration_version=...)"
    )
    return "::".join(
        ["attribution-assessment", _sha256_hex(hypothesis_id), _sha256_hex(calibration_version)]
    )


# ===========================================================================
# ADR-0005 §D5/§D14 — NextEvidence
# ===========================================================================


@dataclass(frozen=True)
class NextEvidence:
    """A derived recommendation *representation* only (ADR-0005 §D5/§D14) —
    no counterfactual algorithm runs in this gate; this contract merely
    holds the shape a later gate's computation will populate.
    ``affected_hypothesis_ids`` is required non-empty: a next-evidence item
    naming no hypothesis it would help discriminate has no reason to exist,
    the same reasoning every other "no reason to exist" invariant in this
    codebase already applies.
    """

    next_evidence_id: str
    group_id: str
    target_technique_stix_id: str
    rationale: str
    affected_hypothesis_ids: tuple[str, ...]
    schema_version: str = field(default=NEXT_EVIDENCE_SCHEMA_VERSION)

    def __post_init__(self) -> None:
        _require_nonempty_str(self.next_evidence_id, "NextEvidence.next_evidence_id")
        _require_nonempty_str(self.group_id, "NextEvidence.group_id")
        _require_stix_id(
            self.target_technique_stix_id,
            "NextEvidence.target_technique_stix_id",
            expected_prefix="attack-pattern",
        )
        _require_nonempty_str(self.rationale, "NextEvidence.rationale")

        if not self.affected_hypothesis_ids:
            raise AttributionError(
                "NextEvidence.affected_hypothesis_ids must be non-empty: a next-evidence item "
                "that would discriminate no hypothesis has no reason to exist"
            )
        object.__setattr__(
            self,
            "affected_hypothesis_ids",
            _canonical_tuple(
                self.affected_hypothesis_ids, "NextEvidence.affected_hypothesis_ids[]"
            ),
        )
        _require_nonempty_str(self.schema_version, "NextEvidence.schema_version")


def compute_next_evidence_id(
    group_id: str, technique_stix_id: str, calibration_version: str
) -> str:
    """Deterministically compose a ``NextEvidence.next_evidence_id``
    (ADR-0005 §D5) — never a randomly generated id."""
    _require_nonempty_str(group_id, "compute_next_evidence_id(group_id=...)")
    _require_nonempty_str(technique_stix_id, "compute_next_evidence_id(technique_stix_id=...)")
    _require_nonempty_str(calibration_version, "compute_next_evidence_id(calibration_version=...)")
    return "::".join(
        [
            "next-evidence",
            _sha256_hex(group_id),
            _sha256_hex(technique_stix_id),
            _sha256_hex(calibration_version),
        ]
    )


# ===========================================================================
# ADR-0005 §D1/§D5 — AttributionResult
# ===========================================================================


@dataclass(frozen=True)
class AttributionResult:
    """The final Phase-3 output for exactly ONE attribution unit (ADR-0005
    §D1/§D5) — one ``CorrelationGroup`` → one ``AttributionResult``, never a
    cross-group or campaign-wide object (§D1's explicit prohibition on
    merging ``CorrelationGroup``\\ s).

    **How the 1:1 cardinality is enforced at the contract level.** This
    gate cannot check "does another ``AttributionResult`` already exist for
    this group" — that is a persistence-layer/runtime concern, out of scope
    here (Gate 3.2 §15 forbids databases). What this contract *can* and
    does guarantee: ``result_id`` is a pure, deterministic function of
    ``(group_id, calibration_version, attack_kb_version)`` via
    :func:`compute_attribution_result_id` — recomputing attribution for the
    *same* group under the *same* methodology snapshot always yields the
    identical ``result_id``, never a second, different object for one
    group. This is the identical mechanism
    ``compute_group_id``/``compute_sequence_id`` already use to make their
    own cardinality guarantees structural rather than runtime-checked.

    It can represent "insufficient evidence for attribution" without
    forcing a candidate winner: ``leading_hypothesis_id`` may equal (and,
    per ADR-0005 §D13, in the abstention case *does* equal) the
    Unattributed candidate's own ``Hypothesis.hypothesis_id`` — this
    contract enforces only that whichever hypothesis leads is genuinely a
    member of ``candidate_hypothesis_ids``, never that it be a real,
    non-Unattributed candidate.

    Self-contained invariants enforced here (no cross-object grounding —
    see the module docstring):

    - ``candidate_hypothesis_ids`` is required non-empty (every result
      names at least the Unattributed hypothesis).
    - ``leading_hypothesis_id`` must be a member of
      ``candidate_hypothesis_ids``.
    - ``supporting_evidence_ids``/``contradicting_evidence_ids`` are
      disjoint (one ``EvidenceAssessment`` cannot be both roles for the
      same result), mirroring
      ``CorrelationGroup.structural_link_ids``/``contextual_link_ids``.
    - ``discriminating_evidence_ids`` is a subset of
      ``supporting_evidence_ids | contradicting_evidence_ids`` (ADR-0005
      §D5's own "a VIEW over the links, not a separate assertion").

    Field order here places every required scalar/``provenance`` field
    before the defaulted tuple/optional fields (Python dataclass ordering),
    not ADR-0005's own prose order.
    """

    result_id: str
    group_id: str
    sequence_id: str
    leading_hypothesis_id: str
    uncertainty: str
    ranking_explanation: str
    provenance: AttributionProvenance
    attack_kb_version: str
    methodology_version: str
    calibration_version: str
    dataset_ref: str
    engine_version: str
    determinism_hash: str
    candidate_hypothesis_ids: tuple[str, ...] = ()
    supporting_evidence_ids: tuple[str, ...] = ()
    contradicting_evidence_ids: tuple[str, ...] = ()
    discriminating_evidence_ids: tuple[str, ...] = ()
    attack_techniques_involved: tuple[str, ...] = ()
    ti_kb_version: str | None = None
    schema_version: str = field(default=ATTRIBUTION_RESULT_SCHEMA_VERSION)

    def __post_init__(self) -> None:
        _require_nonempty_str(self.result_id, "AttributionResult.result_id")
        _require_nonempty_str(self.group_id, "AttributionResult.group_id")
        _require_nonempty_str(self.sequence_id, "AttributionResult.sequence_id")
        _require_nonempty_str(self.leading_hypothesis_id, "AttributionResult.leading_hypothesis_id")
        _require_nonempty_str(self.uncertainty, "AttributionResult.uncertainty")
        _require_nonempty_str(self.ranking_explanation, "AttributionResult.ranking_explanation")

        if not isinstance(self.provenance, AttributionProvenance):
            raise AttributionError(
                f"AttributionResult.provenance must be an AttributionProvenance, "
                f"got {type(self.provenance).__name__}"
            )

        _require_nonempty_str(self.attack_kb_version, "AttributionResult.attack_kb_version")
        _require_nonempty_str(self.methodology_version, "AttributionResult.methodology_version")
        _require_nonempty_str(self.calibration_version, "AttributionResult.calibration_version")
        _require_nonempty_str(self.dataset_ref, "AttributionResult.dataset_ref")
        _require_nonempty_str(self.engine_version, "AttributionResult.engine_version")
        _require_nonempty_str(self.determinism_hash, "AttributionResult.determinism_hash")

        if not self.candidate_hypothesis_ids:
            raise AttributionError(
                "AttributionResult.candidate_hypothesis_ids must be non-empty: every result "
                "names at least the Unattributed hypothesis"
            )
        canonical_candidates = _canonical_tuple(
            self.candidate_hypothesis_ids, "AttributionResult.candidate_hypothesis_ids[]"
        )
        object.__setattr__(self, "candidate_hypothesis_ids", canonical_candidates)

        if self.leading_hypothesis_id not in canonical_candidates:
            raise AttributionError(
                f"AttributionResult.leading_hypothesis_id {self.leading_hypothesis_id!r} is not "
                "a member of candidate_hypothesis_ids — a leading hypothesis must be part of "
                "this result's own candidate set"
            )

        canonical_supporting = _canonical_tuple(
            self.supporting_evidence_ids, "AttributionResult.supporting_evidence_ids[]"
        )
        canonical_contradicting = _canonical_tuple(
            self.contradicting_evidence_ids, "AttributionResult.contradicting_evidence_ids[]"
        )
        overlap = set(canonical_supporting) & set(canonical_contradicting)
        if overlap:
            raise AttributionError(
                f"AttributionResult: evidence assessment id(s) {sorted(overlap)!r} appear in "
                "both supporting_evidence_ids and contradicting_evidence_ids — a single "
                "assessment cannot be both roles for one result"
            )
        object.__setattr__(self, "supporting_evidence_ids", canonical_supporting)
        object.__setattr__(self, "contradicting_evidence_ids", canonical_contradicting)

        canonical_discriminating = _canonical_tuple(
            self.discriminating_evidence_ids, "AttributionResult.discriminating_evidence_ids[]"
        )
        allowed = set(canonical_supporting) | set(canonical_contradicting)
        stray = set(canonical_discriminating) - allowed
        if stray:
            raise AttributionError(
                f"AttributionResult: discriminating_evidence_ids {sorted(stray)!r} are not in "
                "supporting_evidence_ids or contradicting_evidence_ids — discriminating "
                "evidence must be a view over this result's own evidence, not a separate "
                "assertion (ADR-0005 §D5)"
            )
        object.__setattr__(self, "discriminating_evidence_ids", canonical_discriminating)

        object.__setattr__(
            self,
            "attack_techniques_involved",
            tuple(
                sorted(
                    _require_stix_id(
                        t,
                        "AttributionResult.attack_techniques_involved[]",
                        expected_prefix="attack-pattern",
                    )
                    for t in set(self.attack_techniques_involved)
                )
            ),
        )

        if self.ti_kb_version is not None:
            _require_nonempty_str(self.ti_kb_version, "AttributionResult.ti_kb_version")

        _require_nonempty_str(self.schema_version, "AttributionResult.schema_version")


def compute_attribution_result_id(
    group_id: str, calibration_version: str, attack_kb_version: str
) -> str:
    """Deterministically compose an ``AttributionResult.result_id`` from
    the attribution unit and the exact methodology snapshot it was computed
    under (ADR-0005 §D5) — never a randomly generated id. Pure function of
    its three inputs: this is what makes "one ``CorrelationGroup`` = one
    ``AttributionResult``" a structural guarantee rather than a runtime
    check (see :class:`AttributionResult`'s own docstring)."""
    _require_nonempty_str(group_id, "compute_attribution_result_id(group_id=...)")
    _require_nonempty_str(
        calibration_version, "compute_attribution_result_id(calibration_version=...)"
    )
    _require_nonempty_str(attack_kb_version, "compute_attribution_result_id(attack_kb_version=...)")
    return "::".join(
        [
            "attribution-result",
            _sha256_hex(group_id),
            _sha256_hex(calibration_version),
            _sha256_hex(attack_kb_version),
        ]
    )
