"""ACH evidence-assessment / matrix construction (gate G3.4, ADR-0005 §D4/§D8).

**Structured evidence × hypothesis assessment only — no attribution decision
is made here.** This module answers exactly one question per cell: *"how
does this one observed (BehavioralStep, technique) pair relate to this one
competing hypothesis?"* — never *"which hypothesis is correct."* It contains
no combination-diagnosticity computation (§D3, no `g(x)`/`D(x)`/`D(C)`), no
``support(h)`` statistic, no likelihood/confidence calculation (§D9/§D10),
no abstention decision (§D13), and no calibration (§D17). Those are later,
separately-gated pieces of Phase 3 built *on top of* this module's output,
never inside it.

**Input boundary.** Consumes exactly the three things already available at
this point in the pipeline — the real ``CorrelationGroup``, its one
``BehavioralSequence`` (ADR-0004 D1), and the **already-generated** Gate 3.3
:class:`~attribution_platform.attribution.candidate_generation.CandidateGenerationResult`
— plus the pinned ``AttackKnowledge``. It never regenerates, adds to, or
drops a candidate/hypothesis: the input hypothesis set (real candidates +
the mandatory Unattributed one) passes through to :class:`ACHMatrix.hypotheses`
completely unchanged, in the identical order Gate 3.3 already established.

**Row/column model (ADR-0005 §D8).** Conceptually: rows are one real
``(BehavioralStep, technique)`` pair; columns are every generated
``Candidate`` (never Unattributed — see below); cells are
:class:`~attribution_platform.attribution.contracts.EvidenceAssessment`
objects. §D8 itself is explicit that this is a *derived, computation-time*
structure, never independently persisted — :class:`ACHMatrix` is a plain
frozen container, the identical "derived result, not a competing model"
shape :class:`~attribution_platform.attribution.candidate_generation.CandidateGenerationResult`
and :class:`~attribution_platform.correlation.structural.StructuralCorrelationResult`
already establish.

**The matrix this module builds is deliberately SPARSE, not dense — and
this is the key design finding this gate makes, stated explicitly rather
than silently decided.** A naive dense reading of "rows × columns" would
materialize one ``EvidenceAssessment`` for *every* (step, technique,
candidate) combination, including every combination where the candidate's
own ATT&CK profile simply does not mention the technique. That naive
reading is wrong for two independent, provable reasons:

1. **``Relevance.INCONSISTENT`` is not reachable from this gate's own data.**
   ADR-0005 §D11's table is explicit that a genuine contradiction
   (``ContradictingEvidence``, lowering *likelihood*) requires
   ``CoverageState.OBSERVED_ABSENT_WITH_ADEQUATE_COVERAGE`` — i.e. it
   requires ``CoverageProfile``, which this gate is explicitly forbidden
   from computing ("Do NOT decide whether a missing technique is a
   contradiction. That is later attribution logic."). Nothing in the pinned
   KB's own ``uses`` relationship data can establish "documented as NOT
   using X" (STIX has no such relationship type — verified against the
   real v19.0 bundle: only ``uses``/``mitigates``/``detects``/
   ``subtechnique-of``/``revoked-by``/``attributed-to`` exist). A candidate
   not using a technique is therefore always ``UNKNOWN`` relevance, never
   ``INCONSISTENT`` — exactly the Gate 3.4 task's own explicit instruction:
   *"Do NOT equate 'not documented' with 'contradicted.'"* This gate
   therefore never constructs an ``INCONSISTENT``/``CONTRADICTING`` cell —
   proven by a dedicated structural test, not merely untested.
2. **``EvidenceRole`` has no third, "neutral" value** (ADR-0005 §D5: a
   closed *two*-value enum, ``SUPPORTING | CONTRADICTING``). A materialized
   cell for an ``UNKNOWN``-relevance combination would have no legal role to
   carry — the Gate 3.4 task is explicit that "UNKNOWN relevance must not
   silently become supporting or contradicting." The only representation
   consistent with both the closed-role shape *and* that instruction is to
   never materialize the cell at all: absence of a cell **is** the ``UNKNOWN``
   state, exactly as ``AttributionResult.supporting_evidence_ids``/
   ``contradicting_evidence_ids`` (§D5) already have no third "neutral" list
   for an ``EvidenceAssessment`` to belong to.

This module therefore materializes exactly one ``EvidenceAssessment`` per
``(step, technique, candidate)`` triple where the candidate's own active
``uses`` profile genuinely contains the technique — always
``role=SUPPORTING``, ``relevance=CONSISTENT``, ``coverage_id=None`` (ADR-0005
§D11's own ``OBSERVED_PRESENT`` row: *"no CoverageProfile reference needed
beyond confirming presence"*). Every other combination is a legitimate,
correctly-unmaterialized ``UNKNOWN`` — recoverable at any time by a later
gate as "no assessment exists for this (step, technique, candidate)."
**Unattributed never receives a materialized cell**: it names no ATT&CK
entity, so every technique is trivially ``UNKNOWN`` relevance to it; it
still appears, unchanged, in :class:`ACHMatrix.hypotheses`.

**Software evidence.** ``EvidenceAssessment.technique_stix_id`` is validated
by the frozen Gate 3.2 contract as an ``attack-pattern``-prefixed STIX id
only (``EvidenceAssessment.__post_init__``) — unlike
``BehavioralStep.technique_stix_ids``/``Candidate.generation_basis``, which
are technique/software-agnostic by their own accepted shape. This is an
already-accepted Gate 3.2 boundary, not a new decision made here: a
software (``malware``/``tool``) observed feature cannot be represented by
this contract's ``technique_stix_id`` field at all. This module therefore
skips (never errors on) a software-typed observed feature when building
ACH cells — "keep the software path structurally supported [no crash] but
do not manufacture software evidence [no cell the frozen contract can't
actually hold]," per the Gate 3.4 task's own instruction. This has no
practical effect today: Phase 1's detection-rule schema does not yet
produce software-typed ``Evidence.attack_ref`` values at all (ADR-0005's
own Open Question #1, unchanged) — Gate 3.3's own software-matched
candidates still fully appear as columns; they simply accumulate no
technique-side ACH cells from *this* module until that upstream reachability
question is resolved.

**Diagnosticity reference.** :func:`compute_diagnosticity_ref` composes the
same kind of deterministic, SHA-256/``"::"``-joined *reference string*
every other id in this codebase uses — never a numeric value. It identifies
*which* feature a later scoring gate must compute ``g(x)``/``D(x)`` for; it
computes nothing itself.

**Determinism.** A pure function of its four inputs. Every collection is
canonicalized (sorted by id); the hypothesis ordering Gate 3.3 already
established is passed through unchanged, never re-sorted or re-derived.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from attribution_platform.attack_knowledge.loader import AttackKnowledge
from attribution_platform.attack_knowledge.traversal import (
    UnknownAttackEntityError,
    campaigns_using_technique,
    groups_using_technique,
    resolve_entity,
)
from attribution_platform.attribution.candidate_generation import CandidateGenerationResult
from attribution_platform.attribution.contracts import (
    EvidenceAssessment,
    EvidenceRole,
    Hypothesis,
    Relevance,
    compute_evidence_assessment_id,
)
from attribution_platform.attribution.errors import AttributionError
from attribution_platform.correlation.contracts import CorrelationGroup
from attribution_platform.correlation.sequence import BehavioralSequence

#: Method identity for this engine, mirroring every prior gate's own
#: constant-pair convention — not yet consumed by any provenance object
#: this gate constructs (kept for the later gate that assembles
#: ``AttributionProvenance.method``).
ACH_MATRIX_METHOD = "ach-matrix"
ACH_MATRIX_METHOD_VERSION = "1.0"

#: The one STIX type ``EvidenceAssessment.technique_stix_id`` may legally
#: hold (Gate 3.2's own accepted validation) — sub-techniques share this
#: identical STIX type, no separate handling needed.
_TECHNIQUE_TYPE = "attack-pattern"


def _require_nonempty_str(value: object, field_name: str) -> str:
    """Local non-empty-string check (raises ``AttributionError``) — a local
    copy of the identical check every other layer in this project owns
    independently, never imported across a module boundary."""
    if not isinstance(value, str) or not value.strip():
        raise AttributionError(
            f"{field_name} must be a non-empty, non-whitespace string, got {value!r}"
        )
    return value


def _sha256_hex(value: str) -> str:
    """SHA-256 hex digest of one caller-supplied, free-text identity
    component — local copy of every prior layer's own helper."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def compute_diagnosticity_ref(feature_stix_id: str, attack_kb_version: str) -> str:
    """Deterministically compose the ``diagnosticity_ref`` string for one
    observed ATT&CK feature under one pinned KB version (ADR-0005 §D5's
    "a reference to the `D(x)`/`D(C)` computation... never a bare float").

    This is an **opaque reference**, never a computed value: it names
    *which* feature a later scoring gate must calculate `g(x)`/`D(x)` for —
    this function computes nothing about that feature's actual prevalence.
    """
    _require_nonempty_str(feature_stix_id, "compute_diagnosticity_ref(feature_stix_id=...)")
    _require_nonempty_str(attack_kb_version, "compute_diagnosticity_ref(attack_kb_version=...)")
    return "::".join(
        ["diagnosticity-ref", _sha256_hex(feature_stix_id), _sha256_hex(attack_kb_version)]
    )


@dataclass(frozen=True)
class ACHMatrix:
    """What :func:`build_ach_matrix` produced for one attribution unit
    (ADR-0005 §D8) — a derived, computation-time structure, never
    independently persisted (§D8's own text). ``hypotheses`` is the
    *unmodified* Gate 3.3 hypothesis set, in its already-established order;
    ``assessments`` is the sparse set of materialized ACH cells (see the
    module docstring for why the matrix is sparse), sorted by
    ``assessment_id``.
    """

    group_id: str
    attack_kb_version: str
    hypotheses: tuple[Hypothesis, ...] = ()
    assessments: tuple[EvidenceAssessment, ...] = ()


def build_ach_matrix(
    group: CorrelationGroup,
    sequence: BehavioralSequence,
    candidate_result: CandidateGenerationResult,
    knowledge: AttackKnowledge,
) -> ACHMatrix:
    """Construct the deterministic ACH evidence-assessment matrix for one
    attribution unit (ADR-0005 §D4/§D8) — structured assessment only, no
    scoring, no attribution decision.

    Fails closed on a structural mismatch between ``sequence``/
    ``candidate_result`` and ``group`` — never silently operates on inputs
    that do not actually belong to this attribution unit or this pinned KB.
    """
    if not isinstance(group, CorrelationGroup):
        raise AttributionError(
            f"build_ach_matrix: group must be a CorrelationGroup, got {type(group).__name__}"
        )
    if not isinstance(sequence, BehavioralSequence):
        raise AttributionError(
            f"build_ach_matrix: sequence must be a BehavioralSequence, "
            f"got {type(sequence).__name__}"
        )
    if not isinstance(candidate_result, CandidateGenerationResult):
        raise AttributionError(
            "build_ach_matrix: candidate_result must be a CandidateGenerationResult, "
            f"got {type(candidate_result).__name__}"
        )
    if not isinstance(knowledge, AttackKnowledge):
        raise AttributionError(
            f"build_ach_matrix: knowledge must be an AttackKnowledge, "
            f"got {type(knowledge).__name__}"
        )
    if sequence.group_id != group.group_id:
        raise AttributionError(
            f"build_ach_matrix: sequence.group_id {sequence.group_id!r} does not match "
            f"group.group_id {group.group_id!r} — ADR-0004 D1's one-group-one-sequence pairing"
        )
    if candidate_result.group_id != group.group_id:
        raise AttributionError(
            f"build_ach_matrix: candidate_result.group_id {candidate_result.group_id!r} does "
            f"not match group.group_id {group.group_id!r}"
        )
    if candidate_result.attack_kb_version != knowledge.attack_kb_version:
        raise AttributionError(
            "build_ach_matrix: candidate_result.attack_kb_version "
            f"{candidate_result.attack_kb_version!r} does not match the loaded "
            f"knowledge.attack_kb_version {knowledge.attack_kb_version!r} — a candidate set "
            "generated under one KB version cannot be assessed against another"
        )

    hypothesis_by_candidate_id = {h.candidate_id: h for h in candidate_result.hypotheses}

    assessments: dict[str, EvidenceAssessment] = {}
    for step in sequence.steps:
        for feature_id in step.technique_stix_ids:
            try:
                feature_obj = resolve_entity(knowledge, feature_id)
            except UnknownAttackEntityError:
                # Fail closed for this one feature only, mirroring Gate 3.3's
                # own per-feature discipline -- never fabricate a cell for an
                # id this KB version does not recognize.
                continue
            if feature_obj.get("type") != _TECHNIQUE_TYPE:
                # Software (or any other) feature type -- not representable
                # by EvidenceAssessment.technique_stix_id's own accepted
                # shape (see module docstring). Structurally skipped, never
                # an error.
                continue

            consistent_stix_ids = frozenset(groups_using_technique(knowledge, feature_id)) | (
                frozenset(campaigns_using_technique(knowledge, feature_id))
            )

            for candidate in candidate_result.candidates:
                candidate_stix_id = (
                    candidate.actor_ref
                    if candidate.actor_ref is not None
                    else candidate.campaign_ref
                )
                if candidate_stix_id not in consistent_stix_ids:
                    # UNKNOWN relevance -- deliberately not materialized as
                    # a cell (see module docstring: no legal role to carry,
                    # and "not documented" must never become "contradicted").
                    continue

                hypothesis = hypothesis_by_candidate_id.get(candidate.candidate_id)
                if hypothesis is None:
                    raise AttributionError(
                        f"build_ach_matrix: candidate {candidate.candidate_id!r} has no "
                        "matching Hypothesis in candidate_result — a malformed "
                        "CandidateGenerationResult"
                    )

                assessment_id = compute_evidence_assessment_id(
                    hypothesis.hypothesis_id, step.step_id, feature_id
                )
                if assessment_id in assessments:
                    continue
                assessments[assessment_id] = EvidenceAssessment(
                    assessment_id=assessment_id,
                    hypothesis_id=hypothesis.hypothesis_id,
                    step_id=step.step_id,
                    technique_stix_id=feature_id,
                    role=EvidenceRole.SUPPORTING,
                    relevance=Relevance.CONSISTENT,
                    diagnosticity_ref=compute_diagnosticity_ref(
                        feature_id, knowledge.attack_kb_version
                    ),
                    coverage_id=None,
                )

    return ACHMatrix(
        group_id=group.group_id,
        attack_kb_version=knowledge.attack_kb_version,
        hypotheses=candidate_result.hypotheses,
        assessments=tuple(sorted(assessments.values(), key=lambda a: a.assessment_id)),
    )
