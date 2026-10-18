"""Thin fan-out: DetectionResult -> Evidence (gate G1.0).

**This module contains no derivation logic of its own.** It calls
:func:`attribution_platform.extraction.evidence_derivation.derive_evidence`
(gate G0.6 — additively extended, not redesigned, with one new optional
``method_content_hash`` keyword; every existing caller and behavior is
unaffected) once per :class:`~attribution_platform.detection.contracts.TechniqueMapping`
on a :class:`~attribution_platform.detection.contracts.DetectionResult` (or
once, with no ATT&CK reference, if the detection has none) — closing the
loop the Phase 1 design proposal described: a detection's ``rule_ref`` and
``technique_mappings`` become exactly the ``rule_ref``/``attack_ref``
arguments G0.6 already accepts, and ``detection.rule_pack_content_hash``
becomes ``method_content_hash`` (see
:mod:`attribution_platform.detection.rules`). Every fail-closed check
(non-empty Observations, ATT&CK reference validation against the pinned KB,
no wall-clock/no generated ids) is still enforced by G0.6's own code, not
duplicated here.

``evidence_id`` is composed deterministically from ``detection_id`` plus
either the mapped technique's ``stix_id`` or the literal ``"unmapped"`` — so
re-deriving from the same ``DetectionResult`` is byte-for-byte reproducible
and never collides across techniques for one detection (duplicate
``attack_ref.stix_id`` values within one rule are rejected at
``DetectionRule`` construction — see
:class:`attribution_platform.detection.rules.DetectionRule` — so this
module never has to guard against it here).
"""

from __future__ import annotations

from attribution_platform.attack_knowledge.loader import AttackKnowledge
from attribution_platform.detection.contracts import DetectionResult, MatchedField
from attribution_platform.detection.errors import DetectionError
from attribution_platform.domain import Evidence, EvidenceQuality, Observation
from attribution_platform.extraction import derive_evidence


def _describe_matched_field(mf: MatchedField) -> str:
    """One matched predicate in words. The ADR-0007 D4 markers ("not",
    "(case-insensitive)", "(field absent)") appear only when set, so claims
    from conditions that do not use them are byte-identical to before."""
    operator = f"not {mf.operator}" if mf.negated else mf.operator
    text = (
        f"{mf.field_path} {operator} {mf.expected!r}"
        if mf.expected is not None
        else f"{mf.field_path} {operator}"
    )
    if mf.case_insensitive:
        text += " (case-insensitive)"
    if not mf.field_present:
        text += " (field absent)"
    return text


def _compose_claim(detection: DetectionResult) -> str:
    """A deterministic, human-readable summary of *why* the rule fired,
    built only from the DetectionResult's own fields — never fabricated."""
    field_summary = "; ".join(
        _describe_matched_field(mf) for mf in detection.match_basis.matched_fields
    )
    claim = (
        f"rule {detection.rule_ref.rule_id} v{detection.rule_ref.rule_version} "
        f"({detection.detection_source}) matched: {field_summary}"
    )
    if detection.aggregate_note is not None:
        claim += f" [{detection.aggregate_note}]"
    return claim


_TECHNIQUE_TYPE = "attack-pattern"


def ambiguous_technique_ids(
    detection: DetectionResult, reviewed: frozenset[str] | None = None
) -> frozenset[str]:
    """The STIX ids of the technique mappings this firing **declares but does
    not establish** (ADR-0025).

    A rule's ATT&CK tags describe the rule, not the match. One firing
    establishes all of them only when they cannot be alternatives:

    - a technique and its own sub-technique are one claim (the sub-technique
      implies its parent);
    - several sub-techniques of one parent are alternatives: the parent, if
      declared, is established, each sub-technique is not;
    - techniques of different parents are alternatives: none is established by
      the match alone.

    ``reviewed`` is the set of ATT&CK ids a recorded review of this rule found
    its logic to establish whenever it fires (``None``: not reviewed). A review
    is authoritative: exactly the techniques it names are established - an
    empty review says a match establishes none - and it can only name
    techniques the rule declares. Mappings to software or Groups are not techniques and are never
    returned. A mapping without an ATT&CK id is its own parent."""
    techniques = [
        m.attack_ref
        for m in detection.technique_mappings
        if m.attack_ref.object_type == _TECHNIQUE_TYPE
    ]
    parent_of = {ref.stix_id: (ref.external_id or ref.stix_id).split(".")[0] for ref in techniques}
    if len(set(parent_of.values())) > 1:
        ambiguous = set(parent_of)
    else:
        subs = [ref.stix_id for ref in techniques if "." in (ref.external_id or "")]
        ambiguous = set(subs) if len(subs) > 1 else set()
    if reviewed is not None:
        # A reviewed rule establishes exactly what its review names - which may be
        # nothing, when its logic cannot tell its technique from ordinary activity.
        ambiguous = {ref.stix_id for ref in techniques if ref.external_id not in reviewed}
    return frozenset(ambiguous)


def derive_evidence_from_detection(
    detection: DetectionResult,
    observation: Observation,
    *,
    knowledge: AttackKnowledge,
    reviewed: frozenset[str] | None = None,
    counts_when_linked: bool = False,
) -> tuple[Evidence, ...]:
    """Derive one Evidence per technique mapping on ``detection`` (or one,
    unmapped, if it has none), grounded in ``observation``.

    Phase 1 is single-Observation scope (see
    :mod:`attribution_platform.detection.rules`): ``observation`` must be
    the exact Observation named in
    ``detection.supporting_observation_ids`` — this is checked, not assumed.

    Every returned Evidence's ``attack_ref`` (when present) has already been
    validated against ``knowledge`` twice: once when the owning rule pack was
    loaded (:func:`attribution_platform.detection.rules.load_rule_pack`) and
    again here, inside :func:`~attribution_platform.extraction.derive_evidence`
    itself — defence-in-depth, not redundant trust.
    """
    if not isinstance(detection, DetectionResult):
        raise DetectionError(
            f"derive_evidence_from_detection requires a DetectionResult, "
            f"got {type(detection).__name__}"
        )
    if not isinstance(observation, Observation):
        raise DetectionError(
            f"derive_evidence_from_detection requires a domain Observation, "
            f"got {type(observation).__name__}"
        )
    if observation.observation_id not in detection.supporting_observation_ids:
        raise DetectionError(
            f"observation {observation.observation_id!r} is not among detection "
            f"{detection.detection_id!r}'s supporting_observation_ids "
            f"{detection.supporting_observation_ids!r}"
        )

    claim = _compose_claim(detection)

    if not detection.technique_mappings:
        evidence = derive_evidence(
            evidence_id=f"{detection.detection_id}::unmapped",
            evidence_type=detection.evidence_type,
            claim=claim,
            observations=(observation,),
            rule_ref=detection.rule_ref,
            attack_ref=None,
            knowledge=knowledge,
            time_span=detection.time_span,
            method_content_hash=detection.rule_pack_content_hash,
            quality=detection.evidence_quality,
        )
        return (evidence,)

    evidences = []
    alternatives = ambiguous_technique_ids(detection, reviewed)
    for mapping in detection.technique_mappings:
        technique_label = mapping.attack_ref.external_id or mapping.attack_ref.stix_id
        mapped_claim = f"{claim} (maps to {technique_label}: {mapping.mapping_basis})"
        if mapping.attack_ref.stix_id in alternatives:
            # ADR-0025: stated, shown, and kept out of the group comparison.
            mapped_claim += (
                f" [one of {len(alternatives)} techniques this rule declares; the match does "
                "not say which, so it is not counted when comparing with group profiles]"
            )
        evidence = derive_evidence(
            evidence_id=f"{detection.detection_id}::{mapping.attack_ref.stix_id}",
            evidence_type=detection.evidence_type,
            claim=mapped_claim,
            observations=(observation,),
            rule_ref=detection.rule_ref,
            attack_ref=mapping.attack_ref,
            knowledge=knowledge,
            time_span=detection.time_span,
            method_content_hash=detection.rule_pack_content_hash,
            quality=detection.evidence_quality,
            technique_ambiguous=mapping.attack_ref.stix_id in alternatives,
            # a reviewed low-level rule: its technique counts inside a cluster
            counted_when_linked=counts_when_linked
            and detection.evidence_quality is EvidenceQuality.LOW
            and mapping.attack_ref.stix_id not in alternatives,
        )
        evidences.append(evidence)
    return tuple(evidences)
