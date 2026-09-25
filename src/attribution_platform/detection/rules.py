"""Deterministic, single-Observation detection rules + engine (gate G1.0).

A :class:`DetectionRule` is **data + a small, closed predicate language**,
never arbitrary code — "prefer deterministic, explainable detection results
over opaque ML" and "no ML" are structural properties of this module, not
just a design intent. Rules are authored as JSON (a *rule pack*, loaded by
:func:`load_rule_pack`) and evaluated by the pure :class:`DetectionEngine`.

**Predicate language (deliberately minimal — extend later, never
speculatively, exactly the discipline G0.4's ``SyntheticRecord`` and G0.11's
Sysmon adapter already established):** originally four operators —
``equals`` / ``contains`` / ``in`` / ``exists`` — extended by ADR-0007 D4
(for faithful Sigma translation) with ``startswith`` / ``endswith`` /
``has_element`` and two per-condition flags, ``case_insensitive`` and
``negate`` (see :class:`FieldCondition`; both default off, so the text below
describes every condition that does not set them) — over a dotted
``field_path`` into an Observation's ECS-aligned entity groups
(``event`` / ``host`` / ``user`` / ``process`` / ``network`` / ``file``).
All comparisons are case-sensitive string comparisons (even for a numeric
Observation field, both sides are compared as ``str``) — the simplest,
least-ambiguous semantics for a v1 engine. A rule's conditions are combined
with AND (all must match); there is no OR/NOT — a behavior needing that is
better expressed as two separate rules mapping to the same technique.
**Array-typed ECS fields** (``event.category``, ``event.type``,
``host.ip``) are addressable only by the ``has_element`` membership
operator (ADR-0007 D4); any other operator on a tuple-valued field fails
closed with :class:`~attribution_platform.detection.errors.DetectionError`
rather than silently comparing against Python's tuple ``repr()``.

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
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
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
_ALLOWED_TOP_LEVEL_FIELDS = frozenset(
    {
        "event",
        "host",
        "user",
        "process",
        "network",
        "file",
        "dll",
        "registry",
        "target_process",
        "process_access",
        "remote_thread",
        "dns",
        "file_stream",
        "pipe",
        "wmi",
        "powershell",
        "target_user",
        "logon",
        "object_access",
        "share",
    }
)

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
      for ``equals``/``contains``/``startswith``/``endswith``/``has_element``,
      a non-empty ``tuple[str, ...]`` for ``in``) for every operator except
      ``exists``, which must leave it ``None`` (there is nothing to compare
      against).
    - ``case_insensitive`` (ADR-0007 D4): compare ``casefold()``-ed strings.
      Invalid with ``exists`` (nothing is compared).
    - ``negate`` (ADR-0007 D4): the condition matches iff the positive
      predicate does **not**. A negated condition on an **absent** field
      matches (Sigma semantics: the positive match is false).

    ``has_element`` is the only operator valid on array-typed fields
    (``event.category``/``event.type``, ``host.ip``): true iff one element
    equals ``value``. It fails closed on a scalar field, and every other
    operator still fails closed on an array field.
    """

    field_path: str
    operator: str
    value: str | tuple[str, ...] | None = None
    case_insensitive: bool = False
    negate: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.field_path, str) or not self.field_path.strip():
            raise DetectionError("FieldCondition.field_path must be a non-empty string")
        if self.operator not in MATCH_OPERATORS:
            raise DetectionError(
                f"FieldCondition.operator {self.operator!r} is not one of {MATCH_OPERATORS}"
            )
        for flag_name in ("case_insensitive", "negate"):
            if not isinstance(getattr(self, flag_name), bool):
                raise DetectionError(f"FieldCondition.{flag_name} must be a bool")
        if self.operator == "exists":
            if self.value is not None:
                raise DetectionError("FieldCondition.value must be None for operator 'exists'")
            if self.case_insensitive:
                raise DetectionError(
                    "FieldCondition.case_insensitive is meaningless for operator 'exists'"
                )
        elif self.operator == "in":
            if not isinstance(self.value, tuple) or not self.value:
                raise DetectionError(
                    "FieldCondition.value must be a non-empty tuple[str, ...] for operator 'in'"
                )
            for v in self.value:
                if not isinstance(v, str) or not v.strip():
                    raise DetectionError("FieldCondition.value entries must be non-empty strings")
        else:  # equals / contains / startswith / endswith / has_element
            if not isinstance(self.value, str) or not self.value.strip():
                raise DetectionError(
                    f"FieldCondition.value must be a non-empty string for operator "
                    f"{self.operator!r}"
                )

    def _fold(self, text: str) -> str:
        return text.casefold() if self.case_insensitive else text

    def _positive_match(self, resolved: Any) -> bool:
        """The un-negated predicate. ``resolved`` is ``None`` (absent), a
        tuple (array field -- ``has_element`` only), or a scalar."""
        if self.operator == "exists":
            return resolved is not None
        if resolved is None:
            return False  # every remaining operator requires a value to compare
        if self.operator == "has_element":
            wanted = self._fold(cast(str, self.value))
            return any(self._fold(str(element)) == wanted for element in resolved)
        observed = self._fold(str(resolved))
        if self.operator == "in":
            # __post_init__ guarantees tuple[str, ...] for this operator
            return observed in {self._fold(v) for v in cast("tuple[str, ...]", self.value)}
        expected = self._fold(cast(str, self.value))
        if self.operator == "equals":
            return observed == expected
        if self.operator == "contains":
            return expected in observed
        if self.operator == "startswith":
            return observed.startswith(expected)
        if self.operator == "endswith":
            return observed.endswith(expected)
        raise DetectionError(
            f"unreachable: unhandled operator {self.operator!r}"
        )  # pragma: no cover

    def _resolve_checked(self, observation: Observation) -> Any:
        """Resolve the field and apply the array/scalar fail-closed checks."""
        resolved = _resolve_field(observation, self.field_path)
        if self.operator == "has_element":
            if resolved is not None and not isinstance(resolved, tuple):
                raise DetectionError(
                    f"FieldCondition.field_path {self.field_path!r} resolves to a scalar "
                    f"({resolved!r}); operator 'has_element' requires an array-typed field"
                )
        elif isinstance(resolved, tuple):
            # Array-typed ECS fields have no defined semantics for scalar
            # operators -- stringifying the tuple would make 'contains' match
            # on Python's repr punctuation rather than element membership.
            # Fail closed; 'has_element' is the element-membership operator.
            raise DetectionError(
                f"FieldCondition.field_path {self.field_path!r} resolves to an array-typed "
                f"field ({resolved!r}); only operator 'has_element' supports array fields"
            )
        return resolved

    def matches(self, observation: Observation) -> bool:
        """Whether this condition matches -- the same decision (and the same
        fail-closed errors) as :meth:`evaluate`, without building the
        explanation. Used by :meth:`DetectionRule.evaluate` so explanations are
        only built for rules that actually fire."""
        return self._positive_match(self._resolve_checked(observation)) != self.negate

    def evaluate(self, observation: Observation) -> MatchedField | None:
        """Return the ``MatchedField`` if this condition matches, else ``None``."""
        resolved = self._resolve_checked(observation)
        if self._positive_match(resolved) == self.negate:
            return None

        if resolved is None:
            observed = ""
        elif isinstance(resolved, tuple):
            observed = ",".join(str(element) for element in resolved)
        else:
            observed = str(resolved)
        if self.operator == "exists":
            expected: str | None = None
        elif self.operator == "in":
            expected = ",".join(cast("tuple[str, ...]", self.value))
        else:
            expected = cast(str, self.value)
        return MatchedField(
            field_path=self.field_path,
            operator=self.operator,
            observed=observed,
            expected=expected,
            negated=self.negate,
            case_insensitive=self.case_insensitive,
            field_present=resolved is not None,
        )


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
      finding), so this is rejected at construction, fail-closed. As of the
      G1.1 provenance review this same uniqueness invariant is *also*
      enforced structurally by
      :class:`~attribution_platform.detection.contracts.DetectionResult`
      itself (covering every producer, not just this class) — the check
      here is kept anyway so a rule pack with a duplicate mapping is
      rejected at rule-pack **load** time, before it is ever evaluated
      against telemetry, rather than only the first time it happens to fire.
    - ``evidence_type``: the ``EvidenceType`` any Evidence derived from this
      rule's firings should carry (defaults to ``BEHAVIORAL``).
    - ``rule_source``: becomes ``DetectionResult.detection_source`` when this
      rule fires (e.g. ``"platform-rules"``).
    - ``content_hash``: the owning rule pack's SHA-256 (see
      :func:`load_rule_pack`), stamped onto every ``DetectionResult`` this
      rule produces. ``None`` when the rule was constructed directly rather
      than loaded from a rule pack.
    - ``rule_family``: optional identity shared by rules that are branches of
      one source detection (e.g. the DNF conjuncts of one Sigma rule, ADR-0007
      D6). :class:`DetectionEngine` emits at most one detection per family per
      Observation -- the first firing branch in rule order -- so one source rule
      matching once never becomes several Evidence items. ``None`` (the
      default, and every hand-authored platform rule) means the rule stands
      alone.
    """

    rule_ref: RuleRef
    conditions: tuple[FieldCondition, ...]
    technique_mappings: tuple[TechniqueMapping, ...] = ()
    evidence_type: EvidenceType = EvidenceType.BEHAVIORAL
    rule_source: str = "platform-rules"
    content_hash: str | None = None
    rule_family: str | None = None

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
        if self.rule_family is not None and (
            not isinstance(self.rule_family, str) or not self.rule_family.strip()
        ):
            raise DetectionError("DetectionRule.rule_family must be a non-empty string if present")

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
        for condition in self.conditions:
            if not condition.matches(observation):
                return None  # AND semantics: any non-match rejects the whole rule
        # The rule fired: now build the explanation (pure, so re-evaluating
        # each condition yields exactly the MatchedField it would have).
        matched = [
            cast(MatchedField, condition.evaluate(observation)) for condition in self.conditions
        ]

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


#: The array field whose ``has_element`` scope condition the engine indexes on.
_SCOPE_FIELD = "event.category"
#: The scalar field whose ``equals`` scope condition the engine also indexes on
#: (Windows event-log channels, ADR-0008).
_DATASET_FIELD = "event.dataset"


def _dataset_key(rule: DetectionRule) -> tuple[str, bool] | None:
    """``(value, case_insensitive)`` when the rule's **first** condition is a
    non-negated ``equals`` on ``event.dataset``, else ``None``. Skipping such a
    rule for an Observation with a different dataset is exact for the same
    reason as :func:`_scope_key`."""
    first = rule.conditions[0]
    if first.operator == "equals" and first.field_path == _DATASET_FIELD and not first.negate:
        return cast(str, first.value), first.case_insensitive
    return None


def _scope_key(rule: DetectionRule) -> tuple[str, bool] | None:
    """``(value, case_insensitive)`` when the rule's **first** condition is a
    non-negated ``has_element`` on ``event.category``, else ``None``.

    Only the first condition is used so that skipping a rule is exactly
    equivalent to evaluating it: conditions run in order and stop at the first
    non-match, so a rule whose first condition fails can neither fire nor
    reach (and raise on) any later condition.
    """
    first = rule.conditions[0]
    if first.operator == "has_element" and first.field_path == _SCOPE_FIELD and not first.negate:
        return cast(str, first.value), first.case_insensitive
    return None


#: The array field of the optional second-level scope condition.
_TYPE_SCOPE_FIELD = "event.type"


def _type_requirement(rule: DetectionRule) -> tuple[str, bool] | None:
    """For a category-scoped rule, ``(value, case_insensitive)`` when its
    **second** condition is a non-negated ``has_element`` on ``event.type``.

    Skipping on it is exact for the same reason as :func:`_scope_key`: the rule
    already passes its first condition (it is in the observation's category
    bucket), and ``has_element`` over a tuple/absent field never raises — so a
    failing second condition is a clean non-match either way."""
    if len(rule.conditions) < 2 or _scope_key(rule) is None:
        return None
    second = rule.conditions[1]
    if (
        second.operator == "has_element"
        and second.field_path == _TYPE_SCOPE_FIELD
        and not second.negate
    ):
        return cast(str, second.value), second.case_insensitive
    return None


@dataclass(frozen=True)
class _RuleIndex:
    unscoped: tuple[int, ...]
    exact: MappingProxyType[str, tuple[int, ...]]
    folded: MappingProxyType[str, tuple[int, ...]]
    type_requirements: tuple[tuple[str, bool] | None, ...]
    dataset_exact: MappingProxyType[str, tuple[int, ...]]
    dataset_folded: MappingProxyType[str, tuple[int, ...]]


def _build_index(rules: tuple[DetectionRule, ...]) -> _RuleIndex:
    unscoped: list[int] = []
    exact: dict[str, list[int]] = {}
    folded: dict[str, list[int]] = {}
    dataset_exact: dict[str, list[int]] = {}
    dataset_folded: dict[str, list[int]] = {}
    for position, rule in enumerate(rules):
        key = _scope_key(rule)
        dataset = _dataset_key(rule) if key is None else None
        if dataset is not None:
            if dataset[1]:
                dataset_folded.setdefault(dataset[0].casefold(), []).append(position)
            else:
                dataset_exact.setdefault(dataset[0], []).append(position)
        elif key is None:
            unscoped.append(position)
        elif key[1]:
            folded.setdefault(key[0].casefold(), []).append(position)
        else:
            exact.setdefault(key[0], []).append(position)
    return _RuleIndex(
        unscoped=tuple(unscoped),
        exact=MappingProxyType({k: tuple(v) for k, v in exact.items()}),
        folded=MappingProxyType({k: tuple(v) for k, v in folded.items()}),
        type_requirements=tuple(_type_requirement(rule) for rule in rules),
        dataset_exact=MappingProxyType({k: tuple(v) for k, v in dataset_exact.items()}),
        dataset_folded=MappingProxyType({k: tuple(v) for k, v in dataset_folded.items()}),
    )


@dataclass(frozen=True)
class DetectionEngine:
    """A pure, deterministic rule evaluator.

    ``evaluate(observations)`` applies every rule to every Observation
    independently (single-Observation scope -- see module docstring) and
    returns every firing, in a fixed, reproducible order: Observations in
    the order given, rules in rule-pack order. No I/O, no ATT&CK KB access,
    no randomness, no wall-clock -- a pure function of ``self.rules`` and the
    ``observations`` argument.

    **Scope index (performance only, ADR-0007 follow-up).** Rules whose first
    condition is ``event.category has_element X`` are only tried against
    Observations whose ``event.category`` contains ``X``, and rules whose
    first condition is ``event.dataset equals X`` only against Observations of
    dataset ``X``; see :func:`_scope_key` for why this is exactly equivalent to
    trying them all.

    **Rule families.** Among rules sharing a non-``None``
    :attr:`DetectionRule.rule_family`, at most one detection is emitted per
    Observation: the first firing rule in rule order (later siblings are not
    evaluated for that Observation).
    """

    rules: tuple[DetectionRule, ...]
    _index: _RuleIndex = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "_index", _build_index(self.rules))

    def _candidates(self, observation: Observation) -> Sequence[int]:
        categories = observation.event.category if observation.event is not None else ()
        if not isinstance(categories, tuple):
            return range(len(self.rules))  # unexpected shape: evaluate everything
        index = self._index
        scoped: set[int] = set()
        for element in categories:
            text = str(element)
            scoped.update(index.exact.get(text, ()))
            scoped.update(index.folded.get(text.casefold(), ()))
        types = observation.event.type if observation.event is not None else ()
        if isinstance(types, tuple):
            exact_types = {str(t) for t in types}
            folded_types = {t.casefold() for t in exact_types}

            def type_ok(requirement: tuple[str, bool] | None) -> bool:
                if requirement is None:
                    return True
                value, case_insensitive = requirement
                if case_insensitive:
                    return value.casefold() in folded_types
                return value in exact_types

            scoped = {p for p in scoped if type_ok(index.type_requirements[p])}
        dataset = observation.event.dataset if observation.event is not None else None
        if isinstance(dataset, str):
            scoped.update(index.dataset_exact.get(dataset, ()))
            scoped.update(index.dataset_folded.get(dataset.casefold(), ()))
        elif dataset is not None:
            return range(len(self.rules))  # unexpected shape: evaluate everything
        return sorted(scoped.union(index.unscoped))

    def evaluate(self, observations: Sequence[Observation]) -> tuple[DetectionResult, ...]:
        results: list[DetectionResult] = []
        for observation in observations:
            if not isinstance(observation, Observation):
                raise DetectionError(
                    f"DetectionEngine.evaluate requires domain Observations, "
                    f"got {type(observation).__name__}"
                )
            fired_families: set[str] = set()
            for position in self._candidates(observation):
                rule = self.rules[position]
                if rule.rule_family is not None and rule.rule_family in fired_families:
                    continue
                result = rule.evaluate(observation)
                if result is not None:
                    results.append(result)
                    if rule.rule_family is not None:
                        fired_families.add(rule.rule_family)
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
    # ADR-0007 D4 flags: optional JSON booleans; absent means the original
    # (case-sensitive, non-negated) semantics, so existing packs are unchanged.
    flags: dict[str, bool] = {}
    for flag_name in ("case_insensitive", "negate"):
        raw_flag = d.get(flag_name, False)
        if not isinstance(raw_flag, bool):
            raise DetectionError(f"{where}: {flag_name!r} must be a JSON boolean if present")
        flags[flag_name] = raw_flag
    try:
        return FieldCondition(field_path=field_path, operator=operator, value=value, **flags)
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

    rule_family = d.get("rule_family")
    if rule_family is not None and (not isinstance(rule_family, str) or not rule_family.strip()):
        raise DetectionError(f"{where}: 'rule_family' must be a non-empty string if present")

    return DetectionRule(
        rule_ref=rule_ref,
        conditions=conditions,
        technique_mappings=technique_mappings,
        evidence_type=evidence_type,
        rule_source=rule_source,
        content_hash=content_hash,
        rule_family=rule_family,
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
