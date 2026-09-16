"""Dynamic candidate generation (gate G3.3, ADR-0005 §D7).

**Candidate SET construction only — no attribution decision is made here.**
This module answers exactly one question: *"which entities should enter the
competition for this attribution unit?"* — never *"which one is correct."*
It contains no combination-diagnosticity computation (§D3, no `g(x)`/`D(x)`),
no ACH matrix (§D8), no likelihood/confidence calculation (§D9/§D10), no
abstention decision (§D13), and no calibration (§D17). Those are later,
separately-gated pieces of Phase 3 built *on top of* this module's output,
never inside it.

**Attribution unit boundary (ADR-0005 §D1).** Operates on exactly ONE
``CorrelationGroup`` and its one ``BehavioralSequence`` at a time — never a
set of groups, never a cross-group/campaign-wide candidate universe. Nothing
here merges ``CorrelationGroup``\\ s, reorders a ``BehavioralSequence``, or
mutates any Phase 0–2 object; every upstream object is read-only input.

**Input boundary — deliberately narrower than the gate's own conceptual
sketch.** ADR-0005 §D7 step 1 is explicit: *"Collect the attribution unit's
observed technique/software ids: the union of `technique_stix_ids` across
every `BehavioralStep` in the `CorrelationGroup`'s `BehavioralSequence`."*
That field is already the mechanically-complete, de-duplicated observed-
feature set G2.4.1 derived from the real ``Evidence.attack_ref`` values
(:mod:`attribution_platform.correlation.sequence_engine`) — including
whatever object type each ``Evidence.attack_ref`` actually names, technique
*or* software, never restricted to ``attack-pattern`` by that field's own
derivation. Re-reading raw ``Evidence``/``Observation`` objects here would
duplicate work G2.4.1 already did and reopen a boundary ADR-0005's own
Context section describes as closed ("Phase 2 delivers exactly two things to
Phase 3: `CorrelationGroup` and `BehavioralSequence`"). :func:`generate_candidates`
therefore takes ``(CorrelationGroup, BehavioralSequence, AttackKnowledge)`` —
not a fourth ``evidence`` parameter — as the more faithful, already-
established reading of the accepted ADR text.

**Algorithm (ADR-0005 §D7, steps 1–4; step 5 is the caller's later job):**

1. Collect the observed feature set: the union of every step's
   ``technique_stix_ids`` (technique *and* software ids alike — see above).
2. For each observed feature, resolve it against the pinned KB
   (:func:`~attribution_platform.attack_knowledge.traversal.resolve_entity`)
   and, by its real STIX type, look up every **active** Group/Campaign whose
   ``uses`` profile contains it
   (:func:`~attribution_platform.attack_knowledge.traversal.groups_using_technique`/
   :func:`campaigns_using_technique` for ``attack-pattern`` features,
   :func:`groups_using_software`/:func:`campaigns_using_software` for
   ``malware``/``tool`` features) — a **union**, never an intersection: a
   candidate is included for matching *any* observed feature, never required
   to match *all* of them (§8 — this is recall-oriented set construction,
   not scoring).
3. Collapse every canonical STIX id discovered through more than one
   observed feature into exactly one :class:`~attribution_platform.attribution.contracts.Candidate`,
   with ``generation_basis`` set to the deterministic, canonicalized union of
   every observed feature that matched it (provenance/explainability
   metadata only — never a score, never a weight).
4. Always add the explicit, deterministic "Unattributed" hypothesis
   (:data:`~attribution_platform.attribution.contracts.UNATTRIBUTED_CANDIDATE_ID`)
   — unconditionally, regardless of how many or how few real candidates were
   found.

**Fail-closed per feature, not per attribution unit (§9.D).** An observed
feature id that does not resolve against the loaded KB (a stale/unknown
STIX id) is skipped — it contributes no candidates — while every other,
resolvable feature is still processed normally. This is the identical
"exclude the unresolvable, count the gap, never fabricate" discipline
ADR-0005 §D19 already requires of the (not-yet-implemented) diagnosticity
layer, applied here to candidate inclusion instead. A feature that resolves
to a STIX type other than a technique/sub-technique/malware/tool (e.g. a
``course-of-action``/mitigation reference some future evidence type might
carry) is likewise skipped — it is not a technique/software feature ADR-0005
§D3 defines candidate generation over at all.

**No alias-ambiguity exposure by construction, not by special-casing.**
Every identity this module ever handles is already a canonical STIX id: the
observed features come from ``Evidence.attack_ref.stix_id`` (validated
STIX-id-shaped at ``AttackRef`` construction), and every Group/Campaign id
comes back from the traversal layer's own canonical-id-returning reverse
queries. This module never calls
:func:`~attribution_platform.attack_knowledge.traversal.resolve_alias` (the
one function that *can* raise ``AmbiguousAliasError``) — there is structurally
no alias *name* string anywhere in this module's own data flow for it to
resolve, so "ambiguous alias" (§9.M) can never arise here, not merely
handled if it did. :data:`~attribution_platform.attribution.contracts.Candidate.alias_stix_ids`
is deliberately left empty (``()``) on every generated candidate: ADR-0005's
own text for that field ("every alias STIX id collapsed... via §D6") and
Gate 3.1's actual ``aliases_for()`` shape (alias *name* strings, not STIX
ids) do not yet agree on what that field should contain — populating it here
would silently resolve an already-flagged open question rather than
constructing the candidate set this gate is scoped to.

**Determinism.** A pure function of its three inputs: identical
``(CorrelationGroup, BehavioralSequence, AttackKnowledge)`` always produces
an identical result, including across two independently-loaded
``AttackKnowledge`` instances of the same pinned artifact. Every returned
collection is canonicalized (sorted by id) — never raw set/dict iteration
order — the same discipline every prior gate's own output already applies.
"""

from __future__ import annotations

from dataclasses import dataclass

from attribution_platform.attack_knowledge.loader import AttackKnowledge
from attribution_platform.attack_knowledge.traversal import (
    UnknownAttackEntityError,
    campaigns_using_software,
    campaigns_using_technique,
    groups_using_software,
    groups_using_technique,
    resolve_entity,
)
from attribution_platform.attribution.contracts import (
    UNATTRIBUTED_CANDIDATE_ID,
    Candidate,
    Hypothesis,
    compute_candidate_id,
    compute_hypothesis_id,
)
from attribution_platform.attribution.errors import AttributionError
from attribution_platform.correlation.contracts import CorrelationGroup
from attribution_platform.correlation.sequence import BehavioralSequence

#: Method identity for this engine, mirroring every prior gate's own
#: ``<slug>``/``<version>`` constant pair convention
#: (``STRUCTURAL_CORRELATION_METHOD``, ``SEQUENCE_ENGINE_METHOD``, ...) —
#: not yet consumed by any provenance object this gate constructs (Gate 3.2's
#: ``Candidate``/``Hypothesis`` carry no provenance field of their own), kept
#: here for the later gate that assembles ``AttributionProvenance.method``.
CANDIDATE_GENERATION_METHOD = "candidate-generation"
CANDIDATE_GENERATION_METHOD_VERSION = "1.0"

#: STIX object types this module treats as a "technique" feature (ADR-0005
#: §D3's atomic feature: "one technique or software id"). Sub-techniques
#: share the identical ``attack-pattern`` STIX type as base techniques —
#: no separate handling is needed or added.
_TECHNIQUE_TYPE = "attack-pattern"
#: STIX object types this module treats as a "software" feature.
_SOFTWARE_TYPES = frozenset({"malware", "tool"})


@dataclass(frozen=True)
class CandidateGenerationResult:
    """What :func:`generate_candidates` produced for one attribution unit:
    the real, KB-backed candidates it found, and the full hypothesis set
    (every real candidate's ``Hypothesis`` plus the mandatory Unattributed
    one) later ACH will consume. Both are sorted by their own id for
    deterministic, stable output ordering — mirroring
    :class:`~attribution_platform.correlation.structural.StructuralCorrelationResult`'s
    own shape exactly (a passive container; the ordering/dedup/inclusion
    guarantees live in :func:`generate_candidates`, not here).
    """

    group_id: str
    attack_kb_version: str
    candidates: tuple[Candidate, ...] = ()
    hypotheses: tuple[Hypothesis, ...] = ()


def _observed_features(sequence: BehavioralSequence) -> tuple[str, ...]:
    """The union of every step's ``technique_stix_ids`` (ADR-0005 §D7 step
    1) — technique and software ids alike, whatever ``BehavioralStep``
    itself already carries. Canonicalized (sorted-unique) for deterministic
    downstream iteration order."""
    features: set[str] = set()
    for step in sequence.steps:
        features.update(step.technique_stix_ids)
    return tuple(sorted(features))


def generate_candidates(
    group: CorrelationGroup,
    sequence: BehavioralSequence,
    knowledge: AttackKnowledge,
) -> CandidateGenerationResult:
    """Construct the deterministic candidate/hypothesis set for one
    attribution unit (ADR-0005 §D7) — candidate SET construction only, no
    scoring, no attribution decision.

    Fails closed on a structural mismatch between ``sequence`` and
    ``group`` (ADR-0004 D1's 1:1 pairing) — never silently operates on a
    sequence that does not actually belong to this group.
    """
    if not isinstance(group, CorrelationGroup):
        raise AttributionError(
            f"generate_candidates: group must be a CorrelationGroup, got {type(group).__name__}"
        )
    if not isinstance(sequence, BehavioralSequence):
        raise AttributionError(
            "generate_candidates: sequence must be a BehavioralSequence, "
            f"got {type(sequence).__name__}"
        )
    if not isinstance(knowledge, AttackKnowledge):
        raise AttributionError(
            "generate_candidates: knowledge must be an AttackKnowledge, "
            f"got {type(knowledge).__name__}"
        )
    if sequence.group_id != group.group_id:
        raise AttributionError(
            f"generate_candidates: sequence.group_id {sequence.group_id!r} does not match "
            f"group.group_id {group.group_id!r} — ADR-0004 D1's one-group-one-sequence pairing"
        )

    # basis[stix_id] = the set of observed feature ids that matched this
    # canonical Group/Campaign STIX id -- accumulated across every observed
    # feature so a candidate discovered through multiple features (§9.J)
    # collapses into exactly one entry with a combined generation_basis.
    group_basis: dict[str, set[str]] = {}
    campaign_basis: dict[str, set[str]] = {}

    for feature_id in _observed_features(sequence):
        try:
            feature_obj = resolve_entity(knowledge, feature_id)
        except UnknownAttackEntityError:
            # §9.D: fail closed for this one feature only -- never fabricate
            # a candidate for an id this KB version does not recognize, and
            # never let one bad id abort the whole attribution unit.
            continue

        feature_type = feature_obj.get("type")
        if feature_type == _TECHNIQUE_TYPE:
            matching_groups = groups_using_technique(knowledge, feature_id)
            matching_campaigns = campaigns_using_technique(knowledge, feature_id)
        elif feature_type in _SOFTWARE_TYPES:
            # §9.N: software evidence is used exactly when it is genuinely
            # present in technique_stix_ids (i.e. some Evidence.attack_ref
            # really named a malware/tool object) -- never fabricated here.
            matching_groups = groups_using_software(knowledge, feature_id)
            matching_campaigns = campaigns_using_software(knowledge, feature_id)
        else:
            # Not a technique/software feature (ADR-0005 §D3's atomic
            # feature domain) -- out of scope for candidate generation,
            # never an error.
            continue

        for group_stix_id in matching_groups:
            group_basis.setdefault(group_stix_id, set()).add(feature_id)
        for campaign_stix_id in matching_campaigns:
            campaign_basis.setdefault(campaign_stix_id, set()).add(feature_id)

    candidates = [
        Candidate(
            candidate_id=compute_candidate_id(group_stix_id),
            attack_kb_version=knowledge.attack_kb_version,
            generation_basis=tuple(sorted(features)),
            actor_ref=group_stix_id,
        )
        for group_stix_id, features in group_basis.items()
    ] + [
        Candidate(
            candidate_id=compute_candidate_id(campaign_stix_id),
            attack_kb_version=knowledge.attack_kb_version,
            generation_basis=tuple(sorted(features)),
            campaign_ref=campaign_stix_id,
        )
        for campaign_stix_id, features in campaign_basis.items()
    ]
    candidates_sorted = tuple(sorted(candidates, key=lambda c: c.candidate_id))

    hypotheses = [
        Hypothesis(
            hypothesis_id=compute_hypothesis_id(group.group_id, candidate.candidate_id),
            group_id=group.group_id,
            candidate_id=candidate.candidate_id,
        )
        for candidate in candidates_sorted
    ]
    hypotheses.append(
        Hypothesis(
            hypothesis_id=compute_hypothesis_id(group.group_id, UNATTRIBUTED_CANDIDATE_ID),
            group_id=group.group_id,
            candidate_id=UNATTRIBUTED_CANDIDATE_ID,
        )
    )
    hypotheses_sorted = tuple(sorted(hypotheses, key=lambda h: h.hypothesis_id))

    return CandidateGenerationResult(
        group_id=group.group_id,
        attack_kb_version=knowledge.attack_kb_version,
        candidates=candidates_sorted,
        hypotheses=hypotheses_sorted,
    )
