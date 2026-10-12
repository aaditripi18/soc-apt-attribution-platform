"""Build-time Elastic prebuilt-rule → rule-pack importer (ADR-0015).

Reads Elastic's detection rules (TOML, ``elastic/detection-rules`` at a pinned
commit, each file verified against the acquisition manifest), parses their
queries (:mod:`.elastic_query`) and translates them into the same JSON rule-pack
format the Sigma importer produces. Runtime detection never imports this module.

**Translate exactly, or not at all** (D1). A rule is considered only if it is a
single-event rule (EQL without ``sequence`` / ``sample``, or a KQL ``query``
rule) whose index patterns include a data stream this platform has telemetry for
(D3; :mod:`.elastic_field_map`). For each supported event profile the query is
partially evaluated — conditions on the profile's constant ECS fields are
decided — and the rest is rewritten to disjunctive normal form; each conjunct
becomes one AND-only rule, kept only if **every** literal translates exactly
(field available through a verified derived view, operator and value meaningful
for the field's ECS type). Dropping a conjunct only removes one OR branch, so an
imported rule is never broader than its author wrote.

**ATT&CK mapping.** The rule's ``[[rule.threat]]`` entries (framework
``MITRE ATT&CK``) name techniques and sub-techniques; each is resolved against
the pinned KB by external id (following ``revoked-by``), exactly as the Sigma
importer resolves tags. Tactic-only entries carry no mapping.

**Tiers.** ``severity`` medium / high / critical rules are the core tier;
``low`` severity and building-block rules (Elastic's own "not an alert by
itself" content) are the enrich tier — Evidence quality ``low``, never forming a
unit on their own (ADR-0003 Amendment H), as for the Sigma enrich tier.
"""

from __future__ import annotations

import hashlib
import json
import re
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass, field
from importlib.metadata import version as installed_version
from pathlib import Path
from typing import Any

from attribution_platform.attack_knowledge.loader import AttackKnowledge
from attribution_platform.detection.derived_views import ViewSet
from attribution_platform.detection.rules import _wildcard_regex
from attribution_platform.detection_content.elastic_field_map import (
    ECS_VERSION,
    ELASTIC_FIELD_MAP_VERSION,
    INTEGRATIONS_COMMIT,
    STREAMS,
    DataStream,
    EventProfile,
)
from attribution_platform.detection_content.elastic_query import (
    And,
    ElasticQueryError,
    Node,
    Not,
    Or,
    ParsedQuery,
    Pred,
    Unsupported,
    is_single_event_eql,
    parse_eql,
    parse_kql,
)
from attribution_platform.detection_content.sigma_import import (
    DEFAULT_DNF_BOUND,
    Gap,
    GapKind,
    Literal,
    RejectionReason,
    RuleStatus,
    _AttackIndex,
)

IMPORTER_METHOD = "elastic-importer"
# 1.1: several data streams; 1.2: analysed text fields; 1.3: threshold and new-terms rules
IMPORTER_VERSION = "1.3"

CORE_SEVERITIES = frozenset({"medium", "high", "critical"})
ENRICH_SEVERITIES = frozenset({"low"})

_ARRAY_OPERATORS = {
    "equals": "has_element",
    "in": "element_in",
    "contains": "element_contains",
    "startswith": "element_startswith",
    "endswith": "element_endswith",
    "wildcard": "element_wildcard",
    "exists": "exists",
}

Item = Literal | Gap
Conjunct = tuple[Item, ...]


class ElasticImportError(ValueError):
    """Fail-closed error for importer inputs (not per-rule outcomes)."""


class _DNFBoundExceeded(Exception):
    pass


@dataclass
class ElasticRuleOutcome:
    """Per-Elastic-rule import record (one row of the import report)."""

    rule_id: str
    name: str
    path: str
    rule_type: str
    status: RuleStatus
    content_tier: str = "core"
    profiles: tuple[str, ...] = ()
    conjuncts_total: int = 0
    conjuncts_imported: int = 0
    reasons: dict[str, int] = field(default_factory=dict)
    rejection: RejectionReason | None = None
    technique_ids: tuple[str, ...] = ()
    dropped_ids: tuple[str, ...] = ()
    #: ``threshold`` / ``new_terms`` for a multi-event rule (Amendment C)
    multi_event: str | None = None

    def to_json(self, commit: str) -> dict[str, Any]:
        enrich = {"content_tier": "enrich"} if self.content_tier == "enrich" else {}
        return {
            **enrich,
            "rule_id": self.rule_id,
            "name": self.name,
            "path": self.path,
            # Elastic License 2.0: a link to the exact rule, pinned to the commit.
            "rule_url": f"https://github.com/elastic/detection-rules/blob/{commit}/{self.path}",
            "rule_type": self.rule_type,
            "status": self.status.value,
            "rejection": self.rejection.value if self.rejection else None,
            "profiles": list(self.profiles),
            # The Sigma-style logsource of every event profile a branch came from
            # (read by the detectability loader beside the Sigma report's).
            "logsources": sorted(
                {
                    p.logsource
                    for stream in STREAMS
                    for p in stream.profiles
                    if p.profile_id in self.profiles
                }
            )
            if self.conjuncts_imported
            else [],
            "conjuncts_total": self.conjuncts_total,
            "conjuncts_imported": self.conjuncts_imported,
            "gap_reasons": dict(sorted(self.reasons.items())),
            "attack_ids": list(self.technique_ids),
            "dropped_attack_ids": list(self.dropped_ids),
            **({"multi_event": self.multi_event} if self.multi_event else {}),
        }


@dataclass(frozen=True)
class ElasticImportResult:
    pack: dict[str, Any]
    report: dict[str, Any]


# ===========================================================================
# Partial evaluation against an event profile
# ===========================================================================


def _constant_holds(pred: Pred, values: tuple[str, ...] | None) -> bool:
    """Elasticsearch semantics of ``pred`` on a constant field (any element)."""
    if values is None:
        return False  # the field is absent: no positive predicate matches
    if pred.operator == "exists":
        return True

    def fold(text: str) -> str:
        return text.casefold() if pred.case_insensitive else text

    wanted = pred.value if isinstance(pred.value, tuple) else (str(pred.value),)
    for observed in values:
        o = fold(observed)
        for w in wanted:
            if pred.operator == "wildcard":
                if _wildcard_regex(w, pred.case_insensitive).fullmatch(o) is not None:
                    return True
                continue
            e = fold(w)
            if (
                (pred.operator in ("equals", "in") and o == e)
                or (pred.operator == "startswith" and o.startswith(e))
                or (pred.operator == "endswith" and o.endswith(e))
                or (pred.operator == "contains" and e in o)
            ):
                return True
    return False


def _specialise(node: Node, profile: EventProfile, stream: DataStream) -> Node | bool:
    """Decide every condition on a constant field; ``True`` / ``False`` when the
    whole node is decided."""
    if isinstance(node, Pred):
        if node.field in profile.constants:
            return _constant_holds(node, profile.constants[node.field])
        if node.field in profile.always_contains:
            # Only "has one of the always-present elements" is decidable here.
            if node.operator in ("equals", "in") and _constant_holds(
                node, profile.always_contains[node.field]
            ):
                return True
            return Unsupported(f"undetermined:{node.field}")
        if stream.absent(node.field):
            return False  # never in this stream's documents: no positive predicate holds
        return node
    if isinstance(node, Unsupported):
        return node
    if isinstance(node, Not):
        inner = _specialise(node.arg, profile, stream)
        return (not inner) if isinstance(inner, bool) else Not(inner)
    is_and = isinstance(node, And)
    kept: list[Node] = []
    for arg in node.args:
        value = _specialise(arg, profile, stream)
        if isinstance(value, bool):
            if value != is_and:  # False in an AND, True in an OR: decided
                return value
            continue
        kept.append(value)
    if not kept:
        return is_and
    if len(kept) == 1:
        return kept[0]
    return And(tuple(kept)) if is_and else Or(tuple(kept))


# ===========================================================================
# Literal translation and DNF
# ===========================================================================


def _literal(pred: Pred, negate: bool, views: ViewSet) -> Item:
    ecs_type = views.type_of(pred.field)
    if ecs_type is None:
        return Gap(GapKind.TELEMETRY, f"field:{pred.field}")
    operator, value, case_insensitive = pred.operator, pred.value, pred.case_insensitive
    if ecs_type == "text":
        # An analysed field (ADR-0015 Amendment B): a quoted value is a phrase of
        # the field's tokens. Any other use is not reproduced.
        if operator not in ("equals", "in") or pred.boolean:
            return Gap(GapKind.TRANSLATION, f"text_field:{pred.field}:{operator}")
        forms = []
        for phrase in value if isinstance(value, tuple) else (str(value),):
            form = views.analyzers[pred.field](phrase)
            if form is None:
                # no token: in Elasticsearch such a phrase matches no document, so
                # among alternatives it adds nothing
                continue
            if not pred.quoted and form.count(" ") > 2:
                # an unquoted value of several tokens is not a phrase (any token matches)
                return Gap(GapKind.TRANSLATION, f"text_field:{pred.field}:unquoted_multi_token")
            forms.append(form)
        if not forms:
            return Gap(GapKind.TRANSLATION, f"text_field:{pred.field}:value_without_tokens")
        unique = tuple(dict.fromkeys(forms))
        return Literal(
            views.path(pred.field),
            "contains",
            unique[0] if len(unique) == 1 else unique,  # type: ignore[arg-type]
            False,
            negate,
        )
    if ecs_type == "boolean":
        # A boolean field holds only true / false (the view renders them so).
        values = value if isinstance(value, tuple) else (value,)
        if operator not in ("equals", "in", "exists") or not all(
            v in ("true", "false") for v in values if v is not None
        ):
            return Gap(GapKind.TRANSLATION, f"value_semantics:{pred.field}:{operator}")
        case_insensitive = False
    elif pred.boolean:
        return Gap(GapKind.TRANSLATION, f"boolean_value:{pred.field}")
    if ecs_type == "long":
        values = value if isinstance(value, tuple) else (value,)
        if operator not in ("equals", "in", "exists") or not all(
            isinstance(v, str) and v.lstrip("-").isdigit() for v in values if v is not None
        ):
            return Gap(GapKind.TRANSLATION, f"value_semantics:{pred.field}:{operator}")
        if operator != "exists":
            value = (
                tuple(str(int(v)) for v in value)
                if isinstance(value, tuple)
                else str(int(str(value)))
            )
        case_insensitive = False
    if views.is_array(pred.field):
        operator = _ARRAY_OPERATORS[operator]
    if isinstance(value, tuple) and operator in ("equals", "has_element"):
        return Gap(GapKind.TRANSLATION, "internal:multi_value_equality")  # pragma: no cover
    if operator == "exists":
        case_insensitive = False
    if isinstance(value, str) and not value.strip():
        return Gap(GapKind.TRANSLATION, "blank_value")
    if isinstance(value, tuple) and any(not v.strip() for v in value):
        return Gap(GapKind.TRANSLATION, "blank_value")
    return Literal(
        views.path(pred.field),
        operator,
        value,  # type: ignore[arg-type]  # tuple values are JSON lists
        case_insensitive,
        negate,
    )


def _merge_phrases(node: Or, views: ViewSet) -> Node:
    """Alternative quoted phrases on one analysed field as a single any-of
    predicate (what ``field : ("a" or "b")`` is), so a long list of phrases is one
    condition rather than one branch each."""
    phrases: dict[str, list[str]] = {}
    rest: list[Node] = []
    for child in node.args:
        if (
            isinstance(child, Pred)
            and child.quoted
            and child.operator == "equals"
            and isinstance(child.value, str)
            and views.type_of(child.field) == "text"
        ):
            phrases.setdefault(child.field, []).append(child.value)
        else:
            rest.append(child)
    merged: list[Node] = [
        Pred(field, "equals", values[0], False, quoted=True)
        if len(values) == 1
        else Pred(field, "in", tuple(dict.fromkeys(values)), False, quoted=True)
        for field, values in phrases.items()
    ]
    args = (*merged, *rest)
    return args[0] if len(args) == 1 else Or(args)


def _dnf(node: Node, negated: bool, bound: int, views: ViewSet) -> list[Conjunct]:
    if isinstance(node, Not):
        return _dnf(node.arg, not negated, bound, views)
    if isinstance(node, Or):
        node = _merge_phrases(node, views)
        if not isinstance(node, And | Or):
            return _dnf(node, negated, bound, views)
    if isinstance(node, And | Or):
        conjunctive = isinstance(node, And) != negated
        children = [_dnf(child, negated, bound, views) for child in node.args]
        if not conjunctive:
            result = [c for child in children for c in child]
            if len(result) > bound:
                raise _DNFBoundExceeded
            return result
        acc: list[Conjunct] = [()]
        for child in children:
            if len(acc) * len(child) > bound:
                raise _DNFBoundExceeded
            acc = [a + b for a in acc for b in child]
        return acc
    if isinstance(node, Unsupported):
        return [(Gap(GapKind.TRANSLATION, node.detail),)]
    return [(_literal(node, negated, views),)]


def _dedupe(conjunct: Conjunct) -> Conjunct:
    seen: list[Item] = []
    for item in conjunct:
        if item not in seen:
            seen.append(item)
    return tuple(seen)


# ===========================================================================
# Per-rule import
# ===========================================================================

# ===========================================================================
# Multi-event rules (Amendment C)
# ===========================================================================

_UNIT_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400}
_DURATION = re.compile(r"\A(?:now-)?(\d+)([smhd])\Z")
#: Kibana's defaults for a rule that states neither.
_DEFAULT_FROM, _DEFAULT_INTERVAL = "now-6m", "5m"


def _seconds(text: str) -> int | None:
    found = _DURATION.match(text.strip())
    return int(found.group(1)) * _UNIT_SECONDS[found.group(2)] if found else None


def _aggregation_field(
    name: str, profile: EventProfile, stream: DataStream
) -> dict[str, str] | Gap | None:
    """How a grouping field is read on ``profile``'s events; ``None`` when those
    events never carry it (they are then never counted, as in Elasticsearch)."""
    if name in profile.constants:
        values = profile.constants[name]
        if values is None:
            return None
        if len(values) != 1:
            return Gap(GapKind.TRANSLATION, f"aggregation_field:{name}:multi_valued_constant")
        return {"name": name, "constant": values[0]}
    if name in profile.always_contains:
        return Gap(GapKind.TRANSLATION, f"aggregation_field:{name}:undetermined")
    if stream.absent(name):
        return None
    ecs_type = stream.views.type_of(name)
    if ecs_type is None:
        return Gap(GapKind.TELEMETRY, f"field:{name}")
    if ecs_type == "text":
        return Gap(GapKind.TRANSLATION, f"aggregation_field:{name}:text")
    return {"name": name, "field_path": stream.views.path(name)}


def _aggregation(
    rule: Mapping[str, Any], profile: EventProfile, stream: DataStream
) -> dict[str, Any] | Gap | None:
    """The rule-pack ``aggregation`` of a threshold / new-terms rule on one event
    profile, a :class:`Gap` when it cannot be reproduced exactly, or ``None``
    when the profile's events can never be counted."""

    def fields(names: list[str]) -> list[dict[str, str]] | Gap | None:
        out = []
        for name in names:
            resolved = _aggregation_field(name, profile, stream)
            if resolved is None or isinstance(resolved, Gap):
                return resolved
            out.append(resolved)
        return out

    if rule.get("type") == "new_terms":
        spec = rule.get("new_terms") or {}
        windows = spec.get("history_window_start") or [{}]
        history = _seconds(str(windows[0].get("value", "")))
        names = [str(n) for n in spec.get("value") or []]
        if history is None or not names:
            return Gap(GapKind.TRANSLATION, "new_terms:unreadable_specification")
        resolved = fields(names)
        if resolved is None or isinstance(resolved, Gap):
            return resolved
        return {"kind": "new_terms", "fields": resolved, "history_seconds": history}

    spec = rule.get("threshold") or {}
    raw_names = spec.get("field") or []
    names = [raw_names] if isinstance(raw_names, str) else [str(n) for n in raw_names]
    look_back = _seconds(str(rule.get("from") or _DEFAULT_FROM))
    interval = _seconds(str(rule.get("interval") or _DEFAULT_INTERVAL))
    value = spec.get("value")
    if look_back is None or interval is None or not isinstance(value, int) or value < 1:
        return Gap(GapKind.TRANSLATION, "threshold:unreadable_specification")
    if look_back <= interval:
        # no distance between events is inside one look-back window on every schedule
        return Gap(GapKind.TRANSLATION, "threshold:no_guaranteed_window")
    resolved = fields(names)
    if resolved is None or isinstance(resolved, Gap):
        return resolved
    cardinality = []
    for entry in spec.get("cardinality") or []:
        counted = _aggregation_field(str(entry.get("field")), profile, stream)
        if counted is None or isinstance(counted, Gap):
            return counted
        needed = entry.get("value")
        if not isinstance(needed, int) or needed < 1:
            return Gap(GapKind.TRANSLATION, "threshold:unreadable_specification")
        cardinality.append({"field": counted, "count": needed})
    return {
        "kind": "threshold",
        "fields": resolved,
        "count": value,
        "span_seconds": look_back - interval,
        "cardinality": cardinality,
    }


def _threat_ids(rule: Mapping[str, Any]) -> list[str]:
    ids: list[str] = []
    for threat in rule.get("threat", []) or []:
        if threat.get("framework") != "MITRE ATT&CK":
            continue
        for technique in threat.get("technique", []) or []:
            ids.append(str(technique["id"]))
            for sub in technique.get("subtechnique", []) or []:
                ids.append(str(sub["id"]))
    return sorted(dict.fromkeys(ids))


def _parse(rule: Mapping[str, Any]) -> ParsedQuery:
    query = str(rule.get("query", ""))
    if rule.get("type") == "eql":
        return parse_eql(query)
    return parse_kql(query)


def _scope_query(parsed: ParsedQuery) -> Node:
    if parsed.category is None:
        return parsed.expr
    return And((Pred("event.category", "equals", parsed.category, False), parsed.expr))


def _import_rule(
    document: Mapping[str, Any],
    path: str,
    *,
    index: _AttackIndex,
    attack_kb_version: str,
    commit: str,
    bound: int,
) -> tuple[ElasticRuleOutcome, list[dict[str, Any]]]:
    rule = document.get("rule", {})
    metadata = document.get("metadata", {})
    rule_type = str(rule.get("type", ""))
    language = str(rule.get("language", ""))
    outcome = ElasticRuleOutcome(
        rule_id=str(rule.get("rule_id", f"unparsed:{path}")),
        name=str(rule.get("name", "")),
        path=path,
        rule_type=f"{rule_type}/{language}" if language else rule_type,
        status=RuleStatus.REJECTED,
    )
    severity = str(rule.get("severity", ""))
    building_block = rule.get("building_block_type") is not None
    outcome.content_tier = "enrich" if building_block or severity in ENRICH_SEVERITIES else "core"

    def reject(reason: RejectionReason, key: str) -> tuple[ElasticRuleOutcome, list[Any]]:
        outcome.rejection = reason
        outcome.reasons = {key: 1}
        return outcome, []

    if metadata.get("maturity") != "production":
        return reject(RejectionReason.EXCLUDED_BY_POLICY, f"maturity:{metadata.get('maturity')}")
    if severity not in CORE_SEVERITIES | ENRICH_SEVERITIES:
        return reject(RejectionReason.EXCLUDED_BY_POLICY, f"severity:{severity or 'none'}")

    mapped: dict[str, Any] = {}
    dropped: list[str] = []
    for external_id in _threat_ids(rule):
        resolved = index.resolve(external_id, external_id)
        if resolved is None or resolved.object_type != "attack-pattern":
            dropped.append(external_id)
            continue
        mapped.setdefault(resolved.stix_id, resolved)
    mappings = [mapped[k] for k in sorted(mapped)]
    outcome.technique_ids = tuple(m.external_id for m in mappings)
    outcome.dropped_ids = tuple(dropped)
    if not mappings:
        return reject(RejectionReason.NO_ATTACK_MAPPING, "no_attack_mapping")

    # Amendment C: a threshold or new-terms rule is a KQL query plus a statement of
    # which sets of matching events detect.
    multi_event = rule_type in ("threshold", "new_terms") and language == "kuery"
    outcome.multi_event = rule_type if multi_event else None
    single_event = (rule_type == "eql" and is_single_event_eql(str(rule.get("query", "")))) or (
        rule_type == "query" and language == "kuery"
    )
    if not single_event and not multi_event:
        kind = "eql_sequence" if rule_type == "eql" else f"{rule_type}/{language or '-'}"
        return reject(RejectionReason.TRANSLATION_GAP, f"rule_type:{kind}")
    index_patterns = tuple(str(i) for i in rule.get("index", []) or [])
    streams = [stream for stream in STREAMS if stream.applies_to(index_patterns)]
    if not streams:
        return reject(RejectionReason.TELEMETRY_GAP, "index:no_supported_data_stream")
    try:
        query = _scope_query(_parse(rule))
    except ElasticQueryError as exc:
        return reject(RejectionReason.TRANSLATION_GAP, f"parse_error:{str(exc)[:40]}")

    technique_mappings = [
        {
            "stix_id": m.stix_id,
            "object_type": m.object_type,
            "attack_kb_version": attack_kb_version,
            "external_id": m.external_id,
            "mapping_basis": (
                f"Elastic rule {outcome.rule_id} '{outcome.name}' "
                f"(author: {', '.join(rule.get('author', []) or ['unknown'])}) "
                f"threat mapping {m.tag}"
                + (
                    f"; {m.revoked_from} is revoked, followed ATT&CK revoked-by to "
                    f"{m.external_id}"
                    if m.revoked_from
                    else ""
                )
            ),
            "mapping_source": "elastic",
        }
        for m in mappings
    ]
    rules: list[dict[str, Any]] = []
    profiles: list[str] = []
    total = 0
    for stream, profile in ((s, p) for s in streams for p in s.profiles):
        specialised = _specialise(query, profile, stream)
        if specialised is False:
            continue
        try:
            conjuncts = (
                [()] if specialised is True else _dnf(specialised, False, bound, stream.views)
            )
        except _DNFBoundExceeded:
            key = f"dnf_bound_exceeded:{profile.profile_id}:>{bound}"
            outcome.reasons[key] = outcome.reasons.get(key, 0) + 1
            total += 1
            continue
        aggregation: dict[str, Any] | None = None
        if multi_event:
            built = _aggregation(rule, profile, stream)
            if built is None:
                continue  # these events never carry a grouping field: never counted
            if isinstance(built, Gap):
                key = f"{built.kind.value}:{built.detail}"
                outcome.reasons[key] = outcome.reasons.get(key, 0) + 1
                total += 1
                continue
            aggregation = built
        profiles.append(profile.profile_id)
        selector = [Literal(p, o, v, False, n) for p, o, v, n in profile.selector]  # type: ignore[arg-type]
        for raw in conjuncts:
            total += 1
            conjunct = _dedupe(raw)
            gaps = [item for item in conjunct if isinstance(item, Gap)]
            if gaps:
                for gap in gaps:
                    key = f"{gap.kind.value}:{gap.detail}"
                    outcome.reasons[key] = outcome.reasons.get(key, 0) + 1
                continue
            literals = [item for item in conjunct if isinstance(item, Literal)]
            rules.append(
                {
                    "rule_id": (f"elastic:{outcome.rule_id}:{profile.profile_id}:{len(rules):03d}"),
                    "rule_version": f"{rule.get('version', 0)}@{commit[:12]}",
                    "conditions": [_condition_json(lit) for lit in [*selector, *literals]],
                    "technique_mappings": technique_mappings,
                    "evidence_type": "behavioral",
                    "rule_source": f"elastic:{outcome.rule_id}",
                    # Branches of one Elastic rule are one detection (engine dedups).
                    "rule_family": f"elastic:{outcome.rule_id}",
                    **({"evidence_quality": "low"} if outcome.content_tier == "enrich" else {}),
                    **({"aggregation": aggregation} if aggregation is not None else {}),
                }
            )
    if rule_type == "new_terms" and outcome.reasons:
        # A branch that is not reproduced is history that is not seen: a value could
        # then be called new when it is not. All of the query, or none of the rule.
        outcome.reasons["new_terms:incomplete_query"] = 1
        rules = []
    outcome.profiles = tuple(profiles) if rules else ()
    outcome.conjuncts_total = total
    outcome.conjuncts_imported = len(rules)
    if not rules:
        if total == 0:
            # Every branch is decided false for every supported event kind: the rule
            # targets events or field values these streams' documents never have.
            return reject(RejectionReason.TELEMETRY_GAP, "event:no_supported_event_satisfies_scope")
        outcome.rejection = (
            RejectionReason.TELEMETRY_GAP
            if all(k.startswith(GapKind.TELEMETRY.value) for k in outcome.reasons)
            else RejectionReason.TRANSLATION_GAP
        )
        return outcome, []
    outcome.status = RuleStatus.IMPORTED if len(rules) == total else RuleStatus.PARTIAL
    return outcome, rules


def _condition_json(lit: Literal) -> dict[str, Any]:
    out = lit.to_json()
    if isinstance(lit.value, tuple):
        out["value"] = list(lit.value)
    return out


# ===========================================================================
# Pack import
# ===========================================================================


def import_elastic_rules(
    cache_dir: Path,
    manifest_path: Path,
    *,
    knowledge: AttackKnowledge,
    dnf_bound: int = DEFAULT_DNF_BOUND,
) -> ElasticImportResult:
    """Import every rule file listed in the acquisition manifest (each verified
    by SHA-256 against it). Returns the rule pack and the import report. Pure
    function of its inputs; nothing is written here."""
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    commit = str(manifest["source_commit"])
    index = _AttackIndex(knowledge)
    outcomes: list[ElasticRuleOutcome] = []
    rules: list[dict[str, Any]] = []
    rule_files = sorted(
        (
            f
            for f in manifest["files"]
            if str(f["path"]).endswith(".toml")
            and str(f["path"]).startswith(("rules/", "rules_building_block/"))
        ),
        key=lambda f: str(f["path"]),
    )
    for entry in rule_files:
        path = str(entry["path"])
        raw = (cache_dir / path).read_bytes()
        if hashlib.sha256(raw).hexdigest() != entry["sha256"]:
            raise ElasticImportError(f"{path}: SHA-256 does not match the manifest")
        document = tomllib.loads(raw.decode("utf-8"))
        outcome, rule_dicts = _import_rule(
            document,
            path,
            index=index,
            attack_kb_version=knowledge.attack_kb_version,
            commit=commit,
            bound=dnf_bound,
        )
        outcomes.append(outcome)
        rules.extend(rule_dicts)
    seen: set[str] = set()
    for outcome in outcomes:
        if outcome.rule_id in seen:
            raise ElasticImportError(f"rule id {outcome.rule_id} appears twice")
        seen.add(outcome.rule_id)
    outcomes.sort(key=lambda o: (o.rule_id, o.path))
    rules.sort(key=lambda r: str(r["rule_id"]))
    provenance = {
        "importer": f"{IMPORTER_METHOD}/{IMPORTER_VERSION}",
        "source": manifest["source"],
        "source_commit": commit,
        "manifest_sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
        "lark_version": installed_version("lark"),
        "field_map_version": ELASTIC_FIELD_MAP_VERSION,
        "integrations_commit": INTEGRATIONS_COMMIT,
        "ecs_version": ECS_VERSION,
        "data_streams": [stream.data_stream for stream in STREAMS],
        "attack_kb_version": knowledge.attack_kb_version,
        "dnf_bound": dnf_bound,
        "license": "Elastic License 2.0 — see data/detection/elastic/NOTICE.md",
    }
    pack = {
        "pack_id": f"elastic-{commit[:12]}",
        "description": (
            "Generated by the ADR-0015 Elastic importer from the pinned elastic/detection-rules "
            "commit. Do not edit by hand; regenerate with scripts/import_elastic_rules.py."
        ),
        "provenance": provenance,
        "rules": rules,
    }
    status_counts: dict[str, int] = {}
    rejection_counts: dict[str, int] = {}
    reason_counts: dict[str, int] = {}
    for o in outcomes:
        status_counts[o.status.value] = status_counts.get(o.status.value, 0) + 1
        if o.rejection:
            rejection_counts[o.rejection.value] = rejection_counts.get(o.rejection.value, 0) + 1
        for key, n in o.reasons.items():
            reason_counts[key] = reason_counts.get(key, 0) + n
    covered = sorted(
        {t for o in outcomes if o.status is not RuleStatus.REJECTED for t in o.technique_ids}
    )
    report = {
        "provenance": provenance,
        "summary": {
            "elastic_rules_total": len(outcomes),
            "by_status": dict(sorted(status_counts.items())),
            "rejected_by_reason": dict(sorted(rejection_counts.items())),
            "generated_rules": len(rules),
            "attack_ids_with_imported_rule": len(covered),
        },
        "gap_reasons": dict(sorted(reason_counts.items(), key=lambda kv: (-kv[1], kv[0]))),
        "attack_ids_with_imported_rule": covered,
        "rules": [o.to_json(commit) for o in outcomes],
    }
    return ElasticImportResult(pack=pack, report=report)


__all__ = [
    "IMPORTER_METHOD",
    "IMPORTER_VERSION",
    "CORE_SEVERITIES",
    "ENRICH_SEVERITIES",
    "ElasticImportError",
    "ElasticRuleOutcome",
    "ElasticImportResult",
    "import_elastic_rules",
]
