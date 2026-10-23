"""Detection-result contracts (gate G1.0): the output of evaluating a
:class:`~attribution_platform.detection.rules.DetectionRule` against an
:class:`~attribution_platform.domain.Observation`.

These are new, additive contracts — they do **not** replace or modify
:class:`~attribution_platform.domain.Observation`/:class:`~attribution_platform.domain.Evidence`
(gate G0.3) or :class:`~attribution_platform.extraction.detection_match.RuleRef`
(gate G0.5); ``DetectionResult`` *reuses* ``RuleRef`` unchanged as the
identity of the rule/method that fired, exactly as G0.5 defined it.

Four contracts, mirroring the accepted Phase 1 design proposal:

- :class:`MatchedField` / :class:`MatchBasis` — the *why*: which Observation
  fields caused a rule to fire, and against what. Operationalizes doc 06's
  "matched_fields" requirement and its U3 rule ("no silent inference" — the
  basis is a recorded fact, not an inferred judgment).
- :class:`TechniqueMapping` — a single validated rule-to-technique link: a
  G0.3 :class:`~attribution_platform.domain.AttackRef` (a pure pointer, never
  a copy of KB content) plus *why* the rule maps to that technique
  (``mapping_basis``) and *who* asserts the mapping (``mapping_source``).
  **Distinct from the rule's own identity** (``DetectionResult.rule_ref``) —
  this is what keeps "which rule/method fired" and "which ATT&CK technique it
  maps to" two separate, independently-inspectable facts, per this gate's
  explicit requirement.
- :class:`DetectionResult` — one rule firing against one supporting
  Observation (Phase 1 is strictly single-Observation scope; multi-event
  correlation is Phase 2, out of scope here). Carries zero-or-more
  ``technique_mappings`` (a detection may fire with no confident technique
  link at all — doc 06 allows evidentiary/contextual Evidence with no
  ``attack_ref``) and an ``evidence_type`` inherited from the firing rule.
  Also carries ``rule_pack_content_hash`` (the owning rule pack's SHA-256,
  when the rule was loaded from one) — a later provenance-audit finding: a
  detection's ``rule_ref`` alone cannot distinguish two rule packs that
  share a ``(rule_id, rule_version)`` pair but differ in actual content;
  the content hash closes that gap and is threaded through to
  ``Evidence.provenance.method_content_hash`` unchanged (see
  :mod:`attribution_platform.detection.evidence`).

Deeply immutable and value-equal by construction, exactly like the G0.3
contracts: ``@dataclass(frozen=True)`` with only scalars, ``tuple``, and
other frozen dataclasses. Deterministic by construction: nothing here reads
the clock or generates a random id — ``detection_id`` is composed by the
engine from stable inputs (rule identity + observation id), never fabricated.

Reuses :func:`attribution_platform.domain.to_serializable`/``to_canonical_json``
unmodified for deterministic serialization — those functions walk any frozen
dataclass tree structurally, so no second serializer is needed here.

Nothing in this module claims or implies adversary identity: there is no
actor/group/campaign field anywhere on these contracts, and a
``TechniqueMapping`` asserts only that a technique is *consistent with* the
observed behavior, never that it proves who performed it.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from attribution_platform.detection.errors import DetectionError
from attribution_platform.domain import AttackRef, EvidenceQuality, EvidenceType, TimeSpan
from attribution_platform.extraction.detection_match import RuleRef

#: Version of THIS DetectionResult contract (our schema).
DETECTION_RESULT_SCHEMA_VERSION = "detection-result/1"

#: The closed set of predicate operators a MatchedField may record — kept in
#: sync with, but not imported from, rules.py (contracts must not depend on
#: the rule-evaluation module; rules.py imports this constant instead).
#: ``startswith``/``endswith``/``has_element`` added by ADR-0007 D4; ``wildcard`` and
#: the ``element_*`` array operators by ADR-0015 (Elastic rule translation).
MATCH_OPERATORS = (
    "equals",
    "contains",
    "in",
    "exists",
    "startswith",
    "endswith",
    "has_element",
    "wildcard",
    "element_in",
    "element_contains",
    "element_startswith",
    "element_endswith",
    "element_wildcard",
    # integer ordering (ADR-0015 Amendment E): on integer-valued fields only
    "gt",
    "gte",
    "lt",
    "lte",
)


def _require_nonempty_str(value: object, field_name: str) -> str:
    """Detection-layer non-empty-string check (raises ``DetectionError``)."""
    if not isinstance(value, str) or not value.strip():
        raise DetectionError(
            f"{field_name} must be a non-empty, non-whitespace string, got {value!r}"
        )
    return value


@dataclass(frozen=True)
class MatchedField:
    """One Observation field that contributed to a rule firing.

    - ``field_path``: the dotted path into the Observation's entity groups
      that was tested, e.g. ``"process.command_line"`` (mirrors doc 06's
      ``Observation.matched_fields`` — field *names*, not a copy of the
      Observation).
    - ``operator``: which predicate matched (one of :data:`MATCH_OPERATORS`).
    - ``observed``: the field's actual value at match time, as a string —
      recorded directly (not re-derived by dereferencing the Observation
      later) so the *why* is self-contained and auditable even if the
      Observation is inspected separately.
    - ``expected``: the rule's own reference value, where the operator has
      one (``None`` for ``exists``, which has no comparison value).
    - ``negated`` / ``case_insensitive``: the condition's ADR-0007 D4 flags,
      recorded so the *why* states exactly which predicate matched (e.g.
      "``process.executable`` not endswith ``explorer.exe``").
    - ``field_present``: ``False`` only for a negated condition that matched
      because the field was absent (Sigma semantics, ADR-0007 D4); then
      ``observed`` is ``""``. A non-negated match always has the field.
    """

    field_path: str
    operator: str
    observed: str
    expected: str | None = None
    negated: bool = False
    case_insensitive: bool = False
    field_present: bool = True

    def __post_init__(self) -> None:
        _require_nonempty_str(self.field_path, "MatchedField.field_path")
        _require_nonempty_str(self.operator, "MatchedField.operator")
        if self.operator not in MATCH_OPERATORS:
            raise DetectionError(
                f"MatchedField.operator {self.operator!r} is not one of {MATCH_OPERATORS}"
            )
        if not isinstance(self.observed, str):
            raise DetectionError(
                f"MatchedField.observed must be a str, got {type(self.observed).__name__}"
            )
        if self.expected is not None:
            _require_nonempty_str(self.expected, "MatchedField.expected")
        for flag_name in ("negated", "case_insensitive", "field_present"):
            if not isinstance(getattr(self, flag_name), bool):
                raise DetectionError(f"MatchedField.{flag_name} must be a bool")
        if not self.field_present:
            if not self.negated:
                raise DetectionError(
                    "MatchedField.field_present=False is only valid for a negated condition"
                )
            if self.observed != "":
                raise DetectionError("MatchedField.observed must be '' when field_present is False")


@dataclass(frozen=True)
class MatchBasis:
    """The complete set of matched fields that caused one rule to fire.

    ``matched_fields`` must be non-empty — a "match" that names no evidence
    for itself is meaningless (mirrors
    :class:`~attribution_platform.extraction.detection_match.DetectionMatchRecord`'s
    non-empty ``matched_events`` requirement).
    """

    matched_fields: tuple[MatchedField, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.matched_fields, tuple) or not self.matched_fields:
            raise DetectionError("MatchBasis.matched_fields must be a non-empty tuple")
        for i, mf in enumerate(self.matched_fields):
            if not isinstance(mf, MatchedField):
                raise DetectionError(
                    f"MatchBasis.matched_fields[{i}] must be a MatchedField, "
                    f"got {type(mf).__name__}"
                )


@dataclass(frozen=True)
class TechniqueMapping:
    """A single, validated rule-to-ATT&CK-technique link.

    - ``attack_ref``: a pure pointer (G0.3 ``AttackRef``) — never a copy of
      KB content. Validated against the pinned KB via the existing
      :func:`attribution_platform.attack_knowledge.resolution.resolve_attack_ref`
      at rule-pack load time (see ``rules.load_rule_pack``) and again,
      independently, wherever :func:`~attribution_platform.extraction.derive_evidence`
      is called with it — defence-in-depth, not redundant trust.
    - ``mapping_basis``: human-readable explanation of *why* the rule maps to
      this technique (rule-author-supplied, never inferred here).
    - ``mapping_source``: who asserts the mapping (e.g. ``"platform-rules"``
      for our own rule packs, ``"elastic"`` for an alert's own
      ``threat.technique``) — a label, not a trust ranking.

    This mapping is a claim that the observed behavior is **consistent
    with** the referenced technique — never proof of a technique, and never
    an assertion about who performed it.
    """

    attack_ref: AttackRef
    mapping_basis: str
    mapping_source: str = "platform-rules"

    def __post_init__(self) -> None:
        if not isinstance(self.attack_ref, AttackRef):
            raise DetectionError(
                f"TechniqueMapping.attack_ref must be a domain AttackRef, "
                f"got {type(self.attack_ref).__name__}"
            )
        _require_nonempty_str(self.mapping_basis, "TechniqueMapping.mapping_basis")
        _require_nonempty_str(self.mapping_source, "TechniqueMapping.mapping_source")


@dataclass(frozen=True)
class DetectionResult:
    """One detection rule firing against one supporting Observation.

    Required:
    - ``detection_id``: stable, opaque identifier. **Composed deterministically
      by the rule** from its own identity (``rule_ref``), the Observation's
      id, and — when the rule was loaded from a rule pack —
      ``rule_pack_content_hash`` (never randomly generated, never
      wall-clock-derived — G0.3 §5's no-fabrication invariant, carried into
      this layer). Including the content hash means two rules sharing a
      ``(rule_id, rule_version)`` identity but differing in actual rule-pack
      content produce *different* ids for the same Observation — see
      :meth:`attribution_platform.detection.rules.DetectionRule.evaluate`.
    - ``rule_ref``: the G0.5 :class:`RuleRef` of the rule/method that fired —
      identity + version, reused unchanged. This is *distinct* from any
      ``technique_mappings`` below (the rule/method vs. the technique it maps
      to are never conflated).
    - ``detection_source``: opaque producer label (e.g. ``"platform-rules"``,
      ``"elastic"``, ``"synthetic"``) — a peer label, never privileged, exactly
      like :class:`~attribution_platform.sources.adapter.SourceAdapter.source_type`.
    - ``supporting_observation_ids``: **non-empty**, the Observation id(s)
      this detection is grounded in (Phase 1: always exactly one — single-
      Observation scope; the tuple shape is kept for forward compatibility
      with Phase 2 correlation, which is not implemented here).
    - ``match_basis``: the *why* (see :class:`MatchBasis`).

    Optional:
    - ``technique_mappings``: zero or more validated :class:`TechniqueMapping`
      (a detection may legitimately have none — doc 06 allows evidentiary/
      contextual Evidence with no ``attack_ref``). Every ``attack_ref.stix_id``
      across this tuple must be distinct — enforced structurally here (a
      G1.1 provenance-review finding), not only by
      :class:`~attribution_platform.detection.rules.DetectionRule`, so that
      *any* producer of a ``DetectionResult`` — including gate G1.1's
      Elastic-alert adapter, which constructs one directly rather than via
      ``DetectionRule`` — is guaranteed the same collision-free
      ``evidence_id`` derivation invariant
      (:func:`attribution_platform.detection.evidence.derive_evidence_from_detection`
      composes ``evidence_id`` from ``detection_id`` + ``attack_ref.stix_id``,
      so a duplicate would otherwise produce two ``Evidence`` objects sharing
      one id).
    - ``evidence_type``: the :class:`~attribution_platform.domain.EvidenceType`
      the firing rule declares for any Evidence derived from this detection
      (defaults to ``BEHAVIORAL`` — Phase 1 rules are behavioral pattern
      matches over Observation fields).
    - ``time_span``: the detection's temporal scope, derived from the
      supporting Observation's own timestamp (never wall-clock).
    - ``rule_pack_content_hash``: the SHA-256 content hash (see
      :class:`~attribution_platform.detection.rules.RulePack`) of the exact
      rule-pack file the firing rule was loaded from, when known. Records
      *which exact rule content* produced this detection — distinct from
      ``rule_ref`` (a human-assigned identity+version): nothing technical
      guarantees ``rule_ref.rule_version`` changes when a rule pack's actual
      content does, so this closes that reproducibility gap. ``None`` when a
      rule was constructed directly rather than via
      :func:`~attribution_platform.detection.rules.load_rule_pack` (never
      fabricated).

    ``schema_version`` defaults to the current contract version.
    """

    detection_id: str
    rule_ref: RuleRef
    detection_source: str
    supporting_observation_ids: tuple[str, ...]
    match_basis: MatchBasis
    technique_mappings: tuple[TechniqueMapping, ...] = ()
    evidence_type: EvidenceType = EvidenceType.BEHAVIORAL
    time_span: TimeSpan | None = None
    rule_pack_content_hash: str | None = None
    #: ADR-0007 Amendment A: the firing rule's Evidence quality (``LOW`` for the
    #: enrich tier), passed to every Evidence derived from this detection.
    evidence_quality: EvidenceQuality | None = None
    #: A statement appended to the Evidence claim. ADR-0015 Amendment C: for a
    #: multi-event rule, what was counted to reach the detection
    #: (``supporting_observation_ids`` then names every counted event). ADR-0023:
    #: for a Wazuh alert, the declared ATT&CK ids that could not be mapped.
    aggregate_note: str | None = None
    schema_version: str = field(default=DETECTION_RESULT_SCHEMA_VERSION)

    def __post_init__(self) -> None:
        _require_nonempty_str(self.detection_id, "DetectionResult.detection_id")
        if not isinstance(self.rule_ref, RuleRef):
            raise DetectionError(
                f"DetectionResult.rule_ref must be a RuleRef, got {type(self.rule_ref).__name__}"
            )
        _require_nonempty_str(self.detection_source, "DetectionResult.detection_source")

        if (
            not isinstance(self.supporting_observation_ids, tuple)
            or not self.supporting_observation_ids
        ):
            raise DetectionError(
                "DetectionResult.supporting_observation_ids must be a non-empty tuple "
                "(a detection must retain provenance to at least one supporting Observation)"
            )
        for oid in self.supporting_observation_ids:
            _require_nonempty_str(oid, "DetectionResult.supporting_observation_ids[]")

        if not isinstance(self.match_basis, MatchBasis):
            raise DetectionError(
                f"DetectionResult.match_basis must be a MatchBasis, "
                f"got {type(self.match_basis).__name__}"
            )

        if not isinstance(self.technique_mappings, tuple):
            raise DetectionError("DetectionResult.technique_mappings must be a tuple")
        seen_stix_ids: set[str] = set()
        for i, tm in enumerate(self.technique_mappings):
            if not isinstance(tm, TechniqueMapping):
                raise DetectionError(
                    f"DetectionResult.technique_mappings[{i}] must be a TechniqueMapping, "
                    f"got {type(tm).__name__}"
                )
            if tm.attack_ref.stix_id in seen_stix_ids:
                raise DetectionError(
                    f"DetectionResult.technique_mappings contains duplicate "
                    f"attack_ref.stix_id {tm.attack_ref.stix_id!r} "
                    f"(technique_mappings[{i}]) — a detection must map each technique at most once"
                )
            seen_stix_ids.add(tm.attack_ref.stix_id)

        if not isinstance(self.evidence_type, EvidenceType):
            raise DetectionError(
                f"DetectionResult.evidence_type must be an EvidenceType, "
                f"got {type(self.evidence_type).__name__}"
            )
        if self.time_span is not None and not isinstance(self.time_span, TimeSpan):
            raise DetectionError(
                f"DetectionResult.time_span must be a TimeSpan or None, "
                f"got {type(self.time_span).__name__}"
            )
        if self.rule_pack_content_hash is not None:
            _require_nonempty_str(
                self.rule_pack_content_hash, "DetectionResult.rule_pack_content_hash"
            )
        if self.aggregate_note is not None:
            _require_nonempty_str(self.aggregate_note, "DetectionResult.aggregate_note")
        _require_nonempty_str(self.schema_version, "DetectionResult.schema_version")
