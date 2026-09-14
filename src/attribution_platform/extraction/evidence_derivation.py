"""Observation -> Evidence derivation, with optional ATT&CK linkage (gate G0.6).

The minimal deterministic step that turns supporting
:class:`~attribution_platform.domain.Observation` objects plus their
detection/rule context (the G0.5 :class:`~attribution_platform.extraction.detection_match.RuleRef`)
into a derived :class:`~attribution_platform.domain.Evidence` claim, optionally
linked to a validated ATT&CK technique/sub-technique reference.

Scope reconciliation (recorded per CLAUDE.md principle 12): the G0.0 module
map created no separate ``evidence/`` package. Evidence *contracts* live in
``domain`` (G0.3); the *derivation logic* is the interpretation step of the
extraction/ingestion layer, so it lands in ``extraction`` alongside the
Observation extractor. Doc 06's standalone ``TechniqueAssertion`` object is
NOT built here: this gate expresses "this Evidence references ATT&CK
technique T" via the existing G0.3 ``AttackRef`` on ``Evidence`` (validated
against the pinned KB), which is the minimal form. A richer assertion object,
if ever needed, is a later concern.

Guarantees:

- **Deterministic:** a pure function of its inputs; no wall-clock time and no
  generated ids (``evidence_id`` and any ``derived_at`` are supplied).
- **Provenance-preserving:** the derived Evidence retains the supporting
  Observation ids and the rule context (``rule_id``/``rule_version`` become
  ``DerivationProvenance.method``/``method_version``). An optional
  ``method_content_hash`` (gate G1.0 addition — additive, defaults to
  ``None``) is carried onto ``DerivationProvenance.method_content_hash``
  unchanged, for callers (e.g. the detection rule engine) that can supply a
  content hash of the exact method definition used.
- **ATT&CK linkage is validated, not copied:** if an ``AttackRef`` is given, it
  is checked against the loaded pinned KB via
  :func:`attribution_platform.attack_knowledge.resolution.resolve_attack_ref`
  (exists + type matches + KB version matches); the Evidence keeps only the
  pointer, never a copied STIX object.
- **Fail-closed with typed errors:** :class:`EvidenceDerivationError` for
  derivation-level problems (no observations, an ``AttackRef`` supplied
  without a KB to validate it against) and for wrapped domain-contract
  violations; :class:`~attribution_platform.attack_knowledge.resolution.AttackReferenceError`
  propagates for an ATT&CK reference that does not resolve.

Deliberately NOT here (later gates / forbidden this gate): ATT&CK alias
resolution, relationship traversal, candidate generation, correlation, attack
chains, scoring, likelihood, attribution confidence, attribution; Elastic; API.
Source-agnostic throughout.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime

from attribution_platform.attack_knowledge.loader import AttackKnowledge
from attribution_platform.attack_knowledge.resolution import resolve_attack_ref
from attribution_platform.domain import (
    AttackRef,
    DerivationProvenance,
    DomainContractError,
    Evidence,
    EvidenceQuality,
    EvidenceType,
    HostRef,
    Observation,
    TimeSpan,
    UserRef,
)
from attribution_platform.extraction.detection_match import RuleRef


class EvidenceDerivationError(ValueError):
    """Raised when Evidence cannot be derived from the supplied inputs (fail-closed)."""


def derive_evidence(
    *,
    evidence_id: str,
    evidence_type: EvidenceType,
    claim: str,
    observations: Sequence[Observation],
    rule_ref: RuleRef,
    attack_ref: AttackRef | None = None,
    knowledge: AttackKnowledge | None = None,
    quality: EvidenceQuality | None = None,
    time_span: TimeSpan | None = None,
    host: HostRef | None = None,
    user: UserRef | None = None,
    derived_at: datetime | None = None,
    method_content_hash: str | None = None,
) -> Evidence:
    """Derive one ``Evidence`` from supporting Observations and rule context.

    - ``observations``: the supporting Observations (**non-empty**); their
      ``observation_id``s become the Evidence's provenance.
    - ``rule_ref``: the detection/rule context from G0.5; its id/version
      become ``DerivationProvenance.method``/``method_version``.
    - ``attack_ref`` (optional): if given, ``knowledge`` is required and the
      reference is validated against it (raising ``AttackReferenceError`` if it
      does not resolve); the validated reference is attached to the Evidence.
    - ``method_content_hash`` (optional, additive — gate G1.0): a content
      hash of the exact method/rule definition used (e.g. a detection
      rule-pack's SHA-256), carried onto
      ``DerivationProvenance.method_content_hash`` unchanged. Distinguishes
      two derivations that share the same ``rule_ref`` identity/version but
      came from genuinely different rule content; left absent when the
      caller has no such hash to record.

    All ids/timestamps are supplied by the caller; nothing is generated here.
    """
    if not observations:
        raise EvidenceDerivationError(
            "derive_evidence requires at least one supporting Observation "
            "(Evidence must retain provenance to the telemetry it was derived from)"
        )
    for i, obs in enumerate(observations):
        if not isinstance(obs, Observation):
            raise EvidenceDerivationError(
                f"observations[{i}] must be a domain Observation, got {type(obs).__name__}"
            )

    if not isinstance(rule_ref, RuleRef):
        raise EvidenceDerivationError(f"rule_ref must be a RuleRef, got {type(rule_ref).__name__}")

    if attack_ref is not None:
        if knowledge is None:
            raise EvidenceDerivationError(
                "an attack_ref was supplied but no loaded ATT&CK knowledge was provided to "
                "validate it against; refusing to attach an unvalidated ATT&CK reference"
            )
        # Fail-closed: raises AttackReferenceError if the ref does not resolve
        # (nonexistent id, wrong object_type, or KB-version mismatch).
        resolve_attack_ref(knowledge, attack_ref)

    source_observation_ids = tuple(obs.observation_id for obs in observations)

    try:
        provenance = DerivationProvenance(
            method=rule_ref.rule_id,
            method_version=rule_ref.rule_version,
            source_observation_ids=source_observation_ids,
            derived_at=derived_at,
            method_content_hash=method_content_hash,
        )
        return Evidence(
            evidence_id=evidence_id,
            evidence_type=evidence_type,
            claim=claim,
            provenance=provenance,
            attack_ref=attack_ref,
            quality=quality,
            time_span=time_span,
            host=host,
            user=user,
        )
    except DomainContractError as exc:
        raise EvidenceDerivationError(
            f"could not derive a valid Evidence (evidence_id={evidence_id!r}): {exc}"
        ) from exc
