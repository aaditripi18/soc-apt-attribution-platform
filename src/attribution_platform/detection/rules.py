"""Deterministic, single-Observation detection rules + engine (gate G1.0).

A :class:`DetectionRule` is **data + a small, closed predicate language**,
never arbitrary code — "prefer deterministic, explainable detection results
over opaque ML" and "no ML" are structural properties of this module, not
just a design intent. Rules are authored as JSON (a *rule pack*, loaded by
:func:`load_rule_pack`) and evaluated by the pure :class:`DetectionEngine`.

**Predicate language (deliberately minimal — extend later, never
speculatively, exactly the discipline G0.4's ``SyntheticRecord`` and G0.11's
Sysmon adapter already established):** four operators —
``equals`` / ``contains`` / ``in`` / ``exists`` — over a dotted
``field_path`` into an Observation's ECS-aligned entity groups
(``event`` / ``host`` / ``user`` / ``process`` / ``network`` / ``file``).
All comparisons are case-sensitive string comparisons (even for a numeric
Observation field, both sides are compared as ``str``) — the simplest,
least-ambiguous semantics for a v1 engine. A rule's conditions are combined
with AND (all must match); there is no OR/NOT — a behavior needing that is
better expressed as two separate rules mapping to the same technique.
**Array-typed ECS fields are out of scope** (``event.category``,
``event.type``, ``host.ip``): a ``field_path`` that resolves to a tuple
fails closed with :class:`~attribution_platform.detection.errors.DetectionError`
rather than silently comparing against Python's tuple ``repr()`` — an
element-membership predicate mode is a deliberate future extension, not
implemented here.

**Strictly single-Observation (Phase 1 boundary, not a temporary
limitation):** :meth:`DetectionEngine.evaluate` takes a sequence of
Observations and evaluates each rule against each Observation
*independently* — a condition can never reference two different
Observations, and there is no notion of a time window or sequence here.
Multi-event/sequence logic is explicitly Phase 2 correlation and does not
belong in this module; see docs/architecture/13's dependency graph note that
correlation is a later gate.

**Rule content is data, not code, and is reproducible:** a rule pack is one
JSON file, content-hashed exactly like G0.1's ATT&CK artifact and G0.9's
replay fixtures (SHA-256 over the raw file bytes) — the same
inputs+rule-pack+KB version always produce the same
:class:`~attribution_platform.detection.contracts.DetectionResult` set. That
hash is **not** discarded after loading: :func:`load_rule_pack` stamps it
onto every :class:`DetectionRule` it builds, ``DetectionRule.evaluate``
carries it onto every ``DetectionResult.rule_pack_content_hash``, and
:func:`attribution_platform.detection.evidence.derive_evidence_from_detection`
carries it onto ``Evidence.provenance.method_content_hash`` — a
provenance-audit finding this module now closes. ``rule_ref``
(``rule_id``/``rule_version``) is a human-assigned identity; the content
hash is what actually proves two detections came from identical rule logic,
not just the same declared version.

**ATT&CK mapping validation happens at rule-pack load time, not lazily at
detection time:** :func:`load_rule_pack` *requires* a loaded
:class:`~attribution_platform.attack_knowledge.loader.AttackKnowledge` and
validates every declared ``technique_mappings[].attack_ref`` against it via
the existing, unmodified
:func:`attribution_platform.attack_knowledge.resolution.resolve_attack_ref`
— a rule pack that references a technique absent from the pinned v19.0 KB
(or the wrong STIX object type, or the wrong KB version) is rejected before
it is ever used to evaluate telemetry, not silently accepted and discovered
mid-run. No ATT&CK technique/tactic id is hard-coded in this module's
source — every reference comes from the loaded rule-pack *data*.

Deliberately NOT here (forbidden this gate): attribution, scoring, candidate
generation, correlation, attack-chain reconstruction, ML of any kind, a
Sysmon/Elastic-specific field name anywhere (rules reference only the G0.3
ECS-aligned entity groups — the same fields any source populates).
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from attribution_platform.attack_knowledge.loader import AttackKnowledge
from attribution_platform.attack_knowledge.resolution import (
    AttackReferenceError,
    resolve_attack_ref,
)
from attribution_platform.detection.contracts import (
    MATCH_OPERATORS,
    DetectionResult,
    MatchBasis,
    MatchedField,
    TechniqueMapping,
)
from attribution_platform.detection.errors import DetectionError
from attribution_platform.domain import (
    AttackRef,
    DomainContractError,
    EvidenceType,
    Observation,
    TimeSpan,
)
from attribution_platform.extraction.detection_match import RuleRef

#: The only top-level Observation attributes a rule's field_path may
#: address. Deeper segments are resolved dynamically (a legitimately-absent
#: nested entity group, e.g. an Observation with no ``process``, resolves to
#: ``None`` rather than erroring) — only the top-level name is validated
#: against a fixed, closed set, catching the most likely rule-authoring
#: mistake (a wrong entity-group name entirely) without requiring full
#: dataclass-field introspection for every nested type.
_ALLOWED_TOP_LEVEL_FIELDS = frozenset({"event", "host", "user", "process", "network", "file"})

_OPERATORS_REQUIRING_VALUE = frozenset({"equals", "contains", "in"})


def _resolve_field(observation: Observation, field_path: str) -> Any:
    """Resolve a dotted field_path against an Observation's entity groups.

    Returns ``None`` if any hop along the path is absent (a legitimately
    unpopulated optional entity group/field) — only an unrecognized
    *top-level* segment is a hard error (see module docstring).
    """
    segments = field_path.split(".")
    top = segments[0]
    if top not in _ALLOWED_TOP_LEVEL_FIELDS:
        raise DetectionError(
            f"unknown field_path top-level segment {top!r} in {field_path!r}; "
            f"must be one of {sorted(_ALLOWED_TOP_LEVEL_FIELDS)}"
        )
    current: Any = observation
    for segment in segments:
        if current is None:
            return None
        current = getattr(current, segment, None)
    return current


@dataclass(frozen=True)
class FieldCondition:
    """One predicate over a single Observation field.

    - ``field_path``: dotted path, e.g. ``"process.command_line"``.
    - ``operator``: one of :data:`~attribution_platform.detection.contracts.MATCH_OPERATORS`.
    - ``value``: the rule's reference value. Required (a non-empty ``str``
      for ``equals``/``contains``, a non-empty ``tuple[str, ...]`` for
      ``in``) for every operator except ``exists``, which must leave it
      ``None`` (there is nothing to compare against).
    """

    field_path: str
    operator: str
    value: str | tuple[str, ...] | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.field_path, str) or not self.field_path.strip():
            raise DetectionError("FieldCondition.field_path must be a non-empty string")
        if self.operator not in MATCH_OPERATORS:
            raise DetectionError(
                f"FieldCondition.operator {self.operator!r} is not one of {MATCH_OPERATORS}"
            )
        if self.operator == "exists":
            if self.value is not None:
                raise DetectionError("FieldCondition.value must be None for operator 'exists'")
        elif self.operator == "in":
            if not isinstance(self.value, tuple) or not self.value:
                raise DetectionError(
                    "FieldCondition.value must be a non-empty tuple[str, ...] for operator 'in'"
                )
            for v in self.value:
                if not isinstance(v, str) or not v.strip():
                    raise DetectionError("FieldCondition.value entries must be non-empty strings")
        else:  # equals / contains
            if not isinstance(self.value, str) or not self.value.strip():
                raise DetectionError(
                    f"FieldCondition.value must be a non-empty string for operator "
                    f"{self.operator!r}"
                )

    def evaluate(self, observation: Observation) -> MatchedField | None:
        """Return the ``MatchedField`` if this condition matches, else ``None``."""
        resolved = _resolve_field(observation, self.field_path)

        if isinstance(resolved, tuple):
            # Array-typed ECS fields (event.category/type, host.ip, ...) have
            # no defined semantics in this v1 predicate language — stringifying
            # the tuple would make 'contains' silently match on Python's repr
            # punctuation rather than element membership. Fail closed rather
            # than risk a subtly-wrong match; extend deliberately (an
            # element-membership mode) if a rule genuinely needs this later.
            raise DetectionError(
                f"FieldCondition.field_path {self.field_path!r} resolves to an array-typed "
                f"field ({resolved!r}); this predicate language does not support array fields yet"
            )

        if self.operator == "exists":
            if resolved is None:
                return None
            return MatchedField(
                field_path=self.field_path, operator="exists", observed=str(resolved)
            )

        if resolved is None:
            return None  # every remaining operator requires a value to compare
        observed_str = str(resolved)

        if self.operator == "equals":
            expected_str = cast(str, self.value)  # __post_init__ guarantees str for this operator
            if observed_str != expected_str:
                return None
            return MatchedField(
                field_path=self.field_path,
                operator="equals",
                observed=observed_str,
                expected=expected_str,
            )

        if self.operator == "contains":
            expected_str = cast(str, self.value)  # __post_init__ guarantees str for this operator
            if expected_str not in observed_str:
                return None
            return MatchedField(
                field_path=self.field_path,
                operator="contains",
                observed=observed_str,
                expected=expected_str,
            )

        if self.operator == "in":
            # __post_init__ guarantees tuple[str, ...] for this operator
            expected_values = cast("tuple[str, ...]", self.value)
            if observed_str not in expected_values:
                return None
            return MatchedField(
                field_path=self.field_path,
                operator="in",
                observed=observed_str,
                expected=",".join(expected_values),
            )

        raise DetectionError(
            f"unreachable: unhandled operator {self.operator!r}"
        )  # pragma: no cover


@dataclass(frozen=True)
class DetectionRule:
    """A single deterministic, single-Observation detection rule.

    - ``rule_ref``: identity + version (the G0.5 :class:`RuleRef`, reused).
    - ``conditions``: non-empty; **all** must match (AND) for the rule to fire.
    - ``technique_mappings``: zero or more (validated at load time — see
      :func:`load_rule_pack`). Every ``attack_ref.stix_id`` across this
      tuple must be distinct — a rule mapping the same technique twice
      would make :func:`attribution_platform.detection.evidence.derive_evidence_from_detection`
      compose two identical ``evidence_id`` values (a provenance-audit
      finding), so this is rejected at construction, fail-closed.
    - ``evidence_type``: the ``EvidenceType`` any Evidence derived from this
      rule's firings should carry (defaults to ``BEHAVIORAL``).
    - ``rule_source``: becomes ``DetectionResult.detection_source`` when this
      rule fires (e.g. ``"platform-rules"``).
    - ``content_hash``: the owning rule pack's SHA-256 (see
      :func:`load_rule_pack`), stamped onto every ``DetectionResult`` this
      rule produces. ``None`` when the rule was constructed directly rather
      than loaded from a rule pack.
    """

    rule_ref: RuleRef
    conditions: tuple[FieldCondition, ...]
    technique_mappings: tuple[TechniqueMapping, ...] = ()
    evidence_type: EvidenceType = EvidenceType.BEHAVIORAL
    rule_source: str = "platform-rules"
    content_hash: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.rule_ref, RuleRef):
            raise DetectionError(
                f"DetectionRule.rule_ref must be a RuleRef, got {type(self.rule_ref).__name__}"
            )
        if not isinstance(self.conditions, tuple) or not self.conditions:
            raise DetectionError("DetectionRule.conditions must be a non-empty tuple")
        for i, c in enumerate(self.conditions):
            if not isinstance(c, FieldCondition):
                raise DetectionError(
                    f"DetectionRule.conditions[{i}] must be a FieldCondition, "
                    f"got {type(c).__name__}"
                )
        seen_stix_ids: set[str] = set()
        for i, tm in enumerate(self.technique_mappings):
            if not isinstance(tm, TechniqueMapping):
                raise DetectionError(
                    f"DetectionRule.technique_mappings[{i}] must be a TechniqueMapping, "
                    f"got {type(tm).__name__}"
                )
            if tm.attack_ref.stix_id in seen_stix_ids:
                raise DetectionError(
                    f"DetectionRule.technique_mappings contains duplicate "
                    f"attack_ref.stix_id {tm.attack_ref.stix_id!r} "
                    f"(technique_mappings[{i}]) — a rule must map each technique at most once"
                )
            seen_stix_ids.add(tm.attack_ref.stix_id)
        if not isinstance(self.evidence_type, EvidenceType):
            raise DetectionError(
                f"DetectionRule.evidence_type must be an EvidenceType, "
                f"got {type(self.evidence_type).__name__}"
            )
        if not isinstance(self.rule_source, str) or not self.rule_source.strip():
            raise DetectionError("DetectionRule.rule_source must be a non-empty string")
        if self.content_hash is not None and (
            not isinstance(self.content_hash, str) or not self.content_hash.strip()
        ):
            raise DetectionError("DetectionRule.content_hash must be a non-empty string if present")

    def evaluate(self, observation: Observation) -> DetectionResult | None:
        """Return the ``DetectionResult`` if every condition matches this
        Observation, else ``None``. Pure; no id generation happens here in
        the sense of randomness or wall-clock — ``detection_id`` is composed
        deterministically from ``rule_ref`` + ``observation.observation_id``,
        and (when known) the owning rule pack's own ``content_hash``.

        Including ``content_hash`` when present means two rules that share a
        ``(rule_id, rule_version)`` identity but come from genuinely
        different rule-pack content produce *different* ids for the same
        Observation — closing a provenance-audit finding: the id itself
        previously could not distinguish drifted rule content sharing a
        stale declared version, only ``DetectionResult.rule_pack_content_hash``/
        ``Evidence.provenance.method_content_hash`` could. A rule with no
        ``content_hash`` (constructed directly, not via a rule pack) keeps
        the exact id format used before this change — fully backward
        compatible.
        """
        if not isinstance(observation, Observation):
            raise DetectionError(
                f"DetectionRule.evaluate requires a domain Observation, "
                f"got {type(observation).__name__}"
            )
        matched: list[MatchedField] = []
        for condition in self.conditions:
            result = condition.evaluate(observation)
            if result is None:
                return None  # AND semantics: any non-match rejects the whole rule
            matched.append(result)

        if self.content_hash is not None:
            detection_id = (
                f"{self.rule_ref.rule_id}::{self.rule_ref.rule_version}::"
                f"{self.content_hash}::{observation.observation_id}"
            )
        else:
            detection_id = (
                f"{self.rule_ref.rule_id}::{self.rule_ref.rule_version}::"
                f"{observation.observation_id}"
            )
        time_span = TimeSpan(start=observation.timestamp, end=observation.timestamp)
        return DetectionResult(
            detection_id=detection_id,
            rule_ref=self.rule_ref,
            detection_source=self.rule_source,
            supporting_observation_ids=(observation.observation_id,),
            match_basis=MatchBasis(matched_fields=tuple(matched)),
            technique_mappings=self.technique_mappings,
            evidence_type=self.evidence_type,
            time_span=time_span,
            rule_pack_content_hash=self.content_hash,
        )


@dataclass(frozen=True)
class RulePack:
    """A loaded, content-hashed set of detection rules."""

    pack_id: str
    content_hash: str
    rules: tuple[DetectionRule, ...]


@dataclass(frozen=True)
class DetectionEngine:
    """A pure, deterministic rule evaluator.

    ``evaluate(observations)`` applies every rule to every Observation
    independently (single-Observation scope — see module docstring) and
    returns every firing, in a fixed, reproducible order: Observations in
    the order given, rules in rule-pack order. No I/O, no ATT&CK KB access,
    no randomness, no wall-clock — a pure function of ``self.rules`` and the
    ``observations`` argument.
    """

    rules: tuple[DetectionRule, ...]

    def evaluate(self, observations: Sequence[Observation]) -> tuple[DetectionResult, ...]:
        results: list[DetectionResult] = []
        for observation in observations:
            if not isinstance(observation, Observation):
                raise DetectionError(
                    f"DetectionEngine.evaluate requires domain Observations, "
                    f"got {type(observation).__name__}"
                )
            for rule in self.rules:
                result = rule.evaluate(observation)
                if result is not None:
                    results.append(result)
        return tuple(results)


# ===========================================================================
# Rule-pack loading (JSON, content-hashed, ATT&CK-validated at load time)
# ===========================================================================


def _require_str(d: dict[str, Any], key: str, *, where: str) -> str:
    value = d.get(key)
    if not isinstance(value, str) or not value.strip():
        raise DetectionError(f"{where}: {key!r} must be a non-empty string")
    return value


def _condition_from_dict(d: Any, *, where: str) -> FieldCondition:
    if not isinstance(d, dict):
        raise DetectionError(f"{where}: condition must be a JSON object")
    field_path = _require_str(d, "field_path", where=where)
    operator = _require_str(d, "operator", where=where)
    raw_value = d.get("value")
    value: str | tuple[str, ...] | None
    if operator == "in":
        if not isinstance(raw_value, list):
            raise DetectionError(f"{where}: 'value' must be a list for operator 'in'")
        value = tuple(raw_value)
    else:
        value = raw_value
    try:
        return FieldCondition(field_path=field_path, operator=operator, value=value)
    except DetectionError as exc:
        raise DetectionError(f"{where}: {exc}") from exc


def _technique_mapping_from_dict(
    d: Any, *, where: str, knowledge: AttackKnowledge
) -> TechniqueMapping:
    if not isinstance(d, dict):
        raise DetectionError(f"{where}: technique_mapping must be a JSON object")
    stix_id = _require_str(d, "stix_id", where=where)
    object_type = _require_str(d, "object_type", where=where)
    attack_kb_version = _require_str(d, "attack_kb_version", where=where)
    mapping_basis = _require_str(d, "mapping_basis", where=where)
    external_id = d.get("external_id")
    mapping_source = d.get("mapping_source", "platform-rules")

    try:
        attack_ref = AttackRef(
            stix_id=stix_id,
            object_type=object_type,
            attack_kb_version=attack_kb_version,
            external_id=external_id,
        )
    except DomainContractError as exc:
        raise DetectionError(f"{where}: invalid attack reference: {exc}") from exc

    # Fail closed at LOAD time: reject a rule pack that maps to a technique
    # absent from (or the wrong type/version in) the pinned KB, before it is
    # ever used to evaluate telemetry.
    try:
        resolve_attack_ref(knowledge, attack_ref)
    except AttackReferenceError as exc:
        raise DetectionError(f"{where}: technique mapping does not resolve: {exc}") from exc

    try:
        return TechniqueMapping(
            attack_ref=attack_ref, mapping_basis=mapping_basis, mapping_source=mapping_source
        )
    except DetectionError as exc:
        raise DetectionError(f"{where}: {exc}") from exc


def _rule_from_dict(
    d: Any, *, index: int, source: str, knowledge: AttackKnowledge, content_hash: str
) -> DetectionRule:
    where = f"{source}: rules[{index}]"
    if not isinstance(d, dict):
        raise DetectionError(f"{where} must be a JSON object")

    rule_id = _require_str(d, "rule_id", where=where)
    rule_version = _require_str(d, "rule_version", where=where)
    try:
        rule_ref = RuleRef(rule_id=rule_id, rule_version=rule_version)
    except ValueError as exc:  # ExtractionError, also a ValueError
        raise DetectionError(f"{where}: invalid rule_ref: {exc}") from exc

    raw_conditions = d.get("conditions")
    if not isinstance(raw_conditions, list) or not raw_conditions:
        raise DetectionError(f"{where}: 'conditions' must be a non-empty list")
    conditions = tuple(
        _condition_from_dict(c, where=f"{where}.conditions[{i}]")
        for i, c in enumerate(raw_conditions)
    )

    raw_mappings = d.get("technique_mappings", [])
    if not isinstance(raw_mappings, list):
        raise DetectionError(f"{where}: 'technique_mappings' must be a list if present")
    technique_mappings = tuple(
        _technique_mapping_from_dict(
            m, where=f"{where}.technique_mappings[{i}]", knowledge=knowledge
        )
        for i, m in enumerate(raw_mappings)
    )

    evidence_type_raw = d.get("evidence_type", "behavioral")
    try:
        evidence_type = EvidenceType(evidence_type_raw)
    except ValueError as exc:
        raise DetectionError(
            f"{where}: invalid evidence_type {evidence_type_raw!r}: {exc}"
        ) from exc

    rule_source = d.get("rule_source", "platform-rules")
    if not isinstance(rule_source, str) or not rule_source.strip():
        raise DetectionError(f"{where}: 'rule_source' must be a non-empty string if present")

    return DetectionRule(
        rule_ref=rule_ref,
        conditions=conditions,
        technique_mappings=technique_mappings,
        evidence_type=evidence_type,
        rule_source=rule_source,
        content_hash=content_hash,
    )


def load_rule_pack(path: Path, *, knowledge: AttackKnowledge) -> RulePack:
    """Load and validate one rule-pack JSON file from disk.

    ``knowledge`` is **required** (not optional): every declared technique
    mapping in the pack is validated against it before this function
    returns — a rule pack cannot be loaded at all if it maps to a technique
    the pinned KB does not contain (see module docstring).

    Fail-closed: any structural problem (invalid JSON, a missing/wrong-typed
    field, an unknown predicate operator, a duplicate rule id+version, a rule
    mapping the same ATT&CK technique twice, an unresolvable technique
    mapping) raises :class:`DetectionError` naming exactly what and where.
    """
    try:
        raw_bytes = path.read_bytes()
    except OSError as exc:
        raise DetectionError(f"could not read rule pack file {path}: {exc}") from exc

    content_hash = hashlib.sha256(raw_bytes).hexdigest()

    try:
        data = json.loads(raw_bytes.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise DetectionError(f"{path}: not valid JSON: {exc}") from exc

    if not isinstance(data, dict):
        raise DetectionError(f"{path}: rule pack root must be a JSON object")

    pack_id = _require_str(data, "pack_id", where=str(path))

    raw_rules = data.get("rules")
    if not isinstance(raw_rules, list) or not raw_rules:
        raise DetectionError(f"{path}: 'rules' must be a non-empty list")

    rules = tuple(
        _rule_from_dict(
            r, index=i, source=str(path), knowledge=knowledge, content_hash=content_hash
        )
        for i, r in enumerate(raw_rules)
    )

    seen: set[tuple[str, str]] = set()
    for rule in rules:
        key = (rule.rule_ref.rule_id, rule.rule_ref.rule_version)
        if key in seen:
            raise DetectionError(f"{path}: duplicate rule (rule_id, rule_version): {key}")
        seen.add(key)

    return RulePack(pack_id=pack_id, content_hash=content_hash, rules=rules)
