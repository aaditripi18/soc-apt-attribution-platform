"""Build-time SigmaHQ → rule-pack importer (ADR-0007 D2/D3/D5/D6/D7).

Reads the pinned Sigma release archive, parses each rule with pySigma (its rule
model and parsed condition tree only — no backend, no query conversion), and
translates it into our JSON rule-pack format. Runtime detection never imports
this module or pySigma; it only loads the generated pack.

**Translation (faithful or not at all).** A Sigma condition is rewritten to
negation normal form, then disjunctive normal form; each conjunct becomes one
of our AND-only rules sharing the Sigma rule id. A conjunct is kept only if
**every** literal in it translates exactly; otherwise the whole conjunct is
dropped and the reason recorded. Dropping a whole conjunct only removes one OR
branch, so a partially imported rule is never broader than its author wrote
(a negated filter is never dropped on its own). Case-insensitivity follows
Sigma: plain strings match case-insensitively, ``|cased`` strings do not.

**ATT&CK mapping (anti-circular).** ``attack.tNNNN[.NNN]`` and
``attack.sNNNN`` tags are resolved against the pinned KB by ATT&CK external id;
a revoked object is followed through the KB's own ``revoked-by`` relationship;
deprecated/unresolvable ids are dropped and reported. **Group tags
(``attack.gNNNN``) are never mapped** — a rule author's actor label is not an
observation. Tactic and other tags are ignored.

**Outcome categories** (ADR-0007 D9): ``telemetry_gap`` (logsource/field no
adapter produces), ``translation_gap`` (a construct with no exact equivalent),
``no_attack_mapping``, ``excluded_by_policy`` (status/level outside Core++
scope). Deterministic: archive members are processed in sorted order and all
output is canonically ordered.
"""

from __future__ import annotations

import enum
import hashlib
import io
import json
import zipfile
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from importlib.metadata import version as installed_version
from pathlib import Path
from typing import Any

from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionNOT,
    ConditionOR,
    ConditionValueExpression,
)
from sigma.exceptions import SigmaError
from sigma.rule import SigmaRule
from sigma.types import (
    SigmaCasedString,
    SigmaExists,
    SigmaExpansion,
    SigmaNull,
    SigmaNumber,
    SigmaString,
    SpecialChars,
)

from attribution_platform.attack_knowledge.loader import AttackKnowledge, FrozenStixObject
from attribution_platform.attack_knowledge.traversal import is_active
from attribution_platform.detection_content.sigma_field_map import (
    FIELD_MAP_VERSION,
    FIELD_MAPS,
    LOGSOURCE_SCOPES,
    UNMAPPED_FIELD_REASONS,
)

IMPORTER_METHOD = "sigma-importer"
IMPORTER_VERSION = "1.3"

#: ADR-0007 D6: maximum DNF conjuncts per Sigma rule. A documented,
#: reproducibility-frozen importer input — rules above it are rejected whole.
DEFAULT_DNF_BOUND = 64

#: ADR-0007 D2 Core++ scope.
ELIGIBLE_STATUSES = frozenset({"experimental", "test", "stable"})
ELIGIBLE_LEVELS = frozenset({"medium", "high", "critical"})

_TECHNIQUE_TYPE = "attack-pattern"
_SOFTWARE_TYPES = frozenset({"malware", "tool"})


class GapKind(enum.Enum):
    TELEMETRY = "telemetry_gap"
    TRANSLATION = "translation_gap"


class RuleStatus(enum.Enum):
    IMPORTED = "imported"
    PARTIAL = "partial"
    REJECTED = "rejected"


class RejectionReason(enum.Enum):
    TELEMETRY_GAP = "telemetry_gap"
    TRANSLATION_GAP = "translation_gap"
    NO_ATTACK_MAPPING = "no_attack_mapping"
    EXCLUDED_BY_POLICY = "excluded_by_policy"


class SigmaImportError(ValueError):
    """Fail-closed error for importer inputs (not per-rule outcomes)."""


@dataclass(frozen=True)
class Literal:
    """One translated predicate — the future ``FieldCondition``."""

    field_path: str
    operator: str
    value: str | None
    case_insensitive: bool
    negate: bool

    def to_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {"field_path": self.field_path, "operator": self.operator}
        if self.value is not None:
            out["value"] = self.value
        if self.case_insensitive:
            out["case_insensitive"] = True
        if self.negate:
            out["negate"] = True
        return out


@dataclass(frozen=True)
class Gap:
    """A literal that cannot be translated exactly. Negation keeps it a gap."""

    kind: GapKind
    detail: str


Item = Literal | Gap
Conjunct = tuple[Item, ...]


class DNFBoundExceededError(Exception):
    pass


@dataclass(frozen=True)
class ResolvedMapping:
    stix_id: str
    object_type: str
    external_id: str
    tag: str
    revoked_from: str | None = None


@dataclass
class RuleOutcome:
    """Per-Sigma-rule import record (one row of the import report)."""

    sigma_id: str
    title: str
    path: str
    logsource: str
    status: RuleStatus
    conjuncts_total: int = 0
    conjuncts_imported: int = 0
    reasons: dict[str, int] = field(default_factory=dict)
    rejection: RejectionReason | None = None
    technique_ids: tuple[str, ...] = ()
    ignored_group_tags: tuple[str, ...] = ()
    ignored_software_tags: tuple[str, ...] = ()
    dropped_tags: tuple[str, ...] = ()

    def to_json(self, release_tag: str) -> dict[str, Any]:
        return {
            "sigma_id": self.sigma_id,
            "title": self.title,
            "path": self.path,
            # DRL 1.1: a link to the explicit rule, pinned to the release tag.
            "rule_url": f"https://github.com/SigmaHQ/sigma/blob/{release_tag}/{self.path}",
            "logsource": self.logsource,
            "status": self.status.value,
            "rejection": self.rejection.value if self.rejection else None,
            "conjuncts_total": self.conjuncts_total,
            "conjuncts_imported": self.conjuncts_imported,
            "gap_reasons": dict(sorted(self.reasons.items())),
            "attack_ids": list(self.technique_ids),
            "ignored_group_tags": list(self.ignored_group_tags),
            "ignored_software_tags": list(self.ignored_software_tags),
            "dropped_tags": list(self.dropped_tags),
        }


@dataclass(frozen=True)
class SigmaImportResult:
    pack: dict[str, Any]
    report: dict[str, Any]


# ===========================================================================
# ATT&CK tag resolution
# ===========================================================================


class _AttackIndex:
    """External-id → object index over the pinned KB, with ``revoked-by``."""

    def __init__(self, knowledge: AttackKnowledge) -> None:
        self._knowledge = knowledge
        self._by_external_id: dict[str, list[FrozenStixObject]] = {}
        for obj_type in (_TECHNIQUE_TYPE, *sorted(_SOFTWARE_TYPES)):
            for obj in knowledge.objects_of_type(obj_type):
                for ref in obj.get("external_references") or ():
                    if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
                        self._by_external_id.setdefault(str(ref["external_id"]), []).append(obj)
        self._revoked_by: dict[str, str] = {}
        for rel in knowledge.relationships():
            if rel.get("relationship_type") == "revoked-by":
                self._revoked_by[str(rel["source_ref"])] = str(rel["target_ref"])

    def resolve(self, external_id: str, tag: str) -> ResolvedMapping | None:
        candidates = self._by_external_id.get(external_id, [])
        active = [o for o in candidates if is_active(o)]
        if len(active) == 1:
            return self._mapping(active[0], tag)
        if active:
            return None  # ambiguous: never pick arbitrarily
        revoked = [o for o in candidates if o.get("revoked") is True]
        if len(revoked) != 1:
            return None
        current_id = str(revoked[0]["id"])
        seen = {current_id}
        while current_id in self._revoked_by:
            current_id = self._revoked_by[current_id]
            if current_id in seen:
                return None
            seen.add(current_id)
        target = self._knowledge.get_by_id(current_id)
        if target is None or not is_active(target):
            return None
        return self._mapping(target, tag, revoked_from=external_id)

    @staticmethod
    def _mapping(
        obj: FrozenStixObject, tag: str, revoked_from: str | None = None
    ) -> ResolvedMapping:
        external_id = next(
            str(r["external_id"])
            for r in obj.get("external_references") or ()
            if r.get("source_name") == "mitre-attack" and r.get("external_id")
        )
        return ResolvedMapping(
            stix_id=str(obj["id"]),
            object_type=str(obj["type"]),
            external_id=external_id,
            tag=tag,
            revoked_from=revoked_from,
        )


def load_software_tag_review(path: Path) -> dict[tuple[str, str], bool]:
    """Load the reviewed software-tag decisions (ADR-0007 D3 amendment):
    ``(sigma_id, tag) -> accepted``. Fails closed on a malformed file, a
    duplicate decision, an unknown decision value, or a missing reason."""
    data = json.loads(path.read_text(encoding="utf-8"))
    decisions: dict[tuple[str, str], bool] = {}
    for entry in data.get("decisions", []):
        key = (str(entry["sigma_id"]), str(entry["tag"]).lower())
        if key in decisions:
            raise SigmaImportError(f"{path}: duplicate software-tag decision for {key}")
        if entry.get("decision") not in ("accept", "reject"):
            raise SigmaImportError(f"{path}: decision for {key} must be 'accept' or 'reject'")
        if not str(entry.get("reason", "")).strip():
            raise SigmaImportError(f"{path}: decision for {key} has no reason")
        decisions[key] = entry["decision"] == "accept"
    return decisions


def _resolve_tags(
    tags: Iterable[str],
    index: _AttackIndex,
    *,
    sigma_id: str,
    software_review: Mapping[tuple[str, str], bool],
) -> tuple[list[ResolvedMapping], list[str], list[str], list[str]]:
    mappings: dict[str, ResolvedMapping] = {}
    ignored_groups: list[str] = []
    ignored_software: list[str] = []
    dropped: list[str] = []
    for tag in tags:
        namespace, _, name = tag.partition(".")
        if namespace != "attack" or not name or not name[1:2].isdigit():
            continue  # tactic / CAR / CVE / other tags carry no mapping
        prefix = name[0].lower()
        if prefix == "g":
            ignored_groups.append(tag)
            continue
        if prefix == "s" and not software_review.get((sigma_id, tag.lower()), False):
            # A software tag is the rule author's claim about *which tool*, and
            # tool identity is strong attribution evidence; it counts only when
            # the reviewed decision file accepts it for this rule.
            ignored_software.append(tag)
            continue
        if prefix not in ("t", "s"):
            continue
        resolved = index.resolve(name.upper(), tag)
        if resolved is None:
            dropped.append(tag)
            continue
        expected_types = {_TECHNIQUE_TYPE} if prefix == "t" else _SOFTWARE_TYPES
        if resolved.object_type not in expected_types:
            dropped.append(tag)
            continue
        mappings.setdefault(resolved.stix_id, resolved)
    return (
        [mappings[k] for k in sorted(mappings)],
        sorted(ignored_groups),
        sorted(ignored_software),
        sorted(dropped),
    )


# ===========================================================================
# Condition translation
# ===========================================================================


def _string_literal(field_path: str, value: SigmaString, negate: bool) -> Item:
    parts: list[str | SpecialChars] = []
    for part in value.s:
        if isinstance(part, str) and parts and isinstance(parts[-1], str):
            parts[-1] = parts[-1] + part
        elif isinstance(part, str | SpecialChars):
            parts.append(part)
        else:
            return Gap(GapKind.TRANSLATION, "placeholder")
    case_insensitive = not isinstance(value, SigmaCasedString)
    if any(p is SpecialChars.WILDCARD_SINGLE for p in parts):
        return Gap(GapKind.TRANSLATION, "single_char_wildcard")
    wild = SpecialChars.WILDCARD_MULTI
    texts = [p for p in parts if isinstance(p, str)]
    if parts == [wild]:
        return Literal(field_path, "exists", None, False, negate)
    if len(texts) != 1 or not texts[0].strip():
        return Gap(GapKind.TRANSLATION, "interior_wildcard_or_empty")
    text = texts[0]
    shape = tuple(p is wild for p in parts)
    operator = {
        (False,): "equals",
        (True, False): "endswith",
        (False, True): "startswith",
        (True, False, True): "contains",
    }.get(shape)
    if operator is None:
        return Gap(GapKind.TRANSLATION, "interior_wildcard_or_empty")
    return Literal(field_path, operator, text, case_insensitive, negate)


def _value_literal(field_path: str, value: Any, negate: bool) -> Item:
    if isinstance(value, SigmaString):
        return _string_literal(field_path, value, negate)
    if isinstance(value, SigmaNumber):
        return Literal(field_path, "equals", str(value.number), False, negate)
    if isinstance(value, SigmaNull):
        # "field: null" = field absent -> the positive predicate is "not exists".
        return Literal(field_path, "exists", None, False, not negate)
    if isinstance(value, SigmaExists):
        return Literal(field_path, "exists", None, False, negate if value.exists else not negate)
    return Gap(GapKind.TRANSLATION, f"value_type:{type(value).__name__}")


def _product(left: list[Conjunct], right: list[Conjunct], bound: int) -> list[Conjunct]:
    if len(left) * len(right) > bound:
        raise DNFBoundExceededError
    return [a + b for a in left for b in right]


def _dnf(node: Any, negated: bool, field_map: Mapping[str, str], bound: int) -> list[Conjunct]:
    """DNF of ``node`` (``negated`` pushes a NOT down via De Morgan)."""
    if isinstance(node, ConditionNOT):
        return _dnf(node.args[0], not negated, field_map, bound)
    if isinstance(node, ConditionAND | ConditionOR):
        conjunctive = isinstance(node, ConditionAND) != negated
        children = [_dnf(child, negated, field_map, bound) for child in node.args]
        if not conjunctive:
            result = [c for child in children for c in child]
            if len(result) > bound:
                raise DNFBoundExceededError
            return result
        acc: list[Conjunct] = [()]
        for child in children:
            acc = _product(acc, child, bound)
        return acc
    if isinstance(node, ConditionFieldEqualsValueExpression):
        field_path = field_map.get(node.field)
        if field_path is None:
            return [(Gap(GapKind.TELEMETRY, f"field:{node.field}"),)]
        value = node.value
        if isinstance(value, SigmaExpansion):  # e.g. |windash: OR over variants
            items = [_value_literal(field_path, v, negated) for v in value.values]
            return [tuple(items)] if negated else [(item,) for item in items]
        return [(_value_literal(field_path, value, negated),)]
    if isinstance(node, ConditionValueExpression):
        return [(Gap(GapKind.TRANSLATION, "keyword_search"),)]
    return [(Gap(GapKind.TRANSLATION, f"condition:{type(node).__name__}"),)]


def _dedupe(conjunct: Conjunct) -> Conjunct:
    seen: list[Item] = []
    for item in conjunct:
        if item not in seen:
            seen.append(item)
    return tuple(seen)


# ===========================================================================
# Per-rule import
# ===========================================================================


def _logsource_key(rule: SigmaRule) -> tuple[str, str]:
    ls = rule.logsource
    return (str(ls.product or ""), str(ls.category or ls.service or ""))


def _import_rule(
    rule: SigmaRule,
    path: str,
    *,
    index: _AttackIndex,
    attack_kb_version: str,
    release_tag: str,
    bound: int,
    software_review: Mapping[tuple[str, str], bool],
) -> tuple[RuleOutcome, list[dict[str, Any]]]:
    sigma_id = str(rule.id)
    product, category = _logsource_key(rule)
    outcome = RuleOutcome(
        sigma_id=sigma_id,
        title=str(rule.title),
        path=path,
        logsource=f"{product}/{category}",
        status=RuleStatus.REJECTED,
    )
    status = str(rule.status.name).lower() if rule.status else ""
    level = str(rule.level.name).lower() if rule.level else ""
    if status not in ELIGIBLE_STATUSES or level not in ELIGIBLE_LEVELS:
        outcome.rejection = RejectionReason.EXCLUDED_BY_POLICY
        outcome.reasons = {f"policy:{status or 'none'}/{level or 'none'}": 1}
        return outcome, []

    mappings, ignored_groups, ignored_software, dropped = _resolve_tags(
        (str(t) for t in rule.tags), index, sigma_id=sigma_id, software_review=software_review
    )
    outcome.ignored_software_tags = tuple(ignored_software)
    outcome.technique_ids = tuple(m.external_id for m in mappings)
    outcome.ignored_group_tags = tuple(ignored_groups)
    outcome.dropped_tags = tuple(dropped)
    if not mappings:
        outcome.rejection = RejectionReason.NO_ATTACK_MAPPING
        return outcome, []

    scope = LOGSOURCE_SCOPES.get((product, category))
    field_map = FIELD_MAPS.get((product, category))
    if scope is None or field_map is None:
        outcome.rejection = RejectionReason.TELEMETRY_GAP
        outcome.reasons = {f"logsource:{product}/{category}": 1}
        return outcome, []

    conjuncts: list[Conjunct] = []
    try:
        for condition in rule.detection.parsed_condition:
            conjuncts.extend(_dnf(condition.parsed, False, field_map, bound))
            if len(conjuncts) > bound:
                raise DNFBoundExceededError
    except DNFBoundExceededError:
        outcome.rejection = RejectionReason.TRANSLATION_GAP
        outcome.reasons = {f"dnf_bound_exceeded:>{bound}": 1}
        return outcome, []
    except SigmaError as exc:
        outcome.rejection = RejectionReason.TRANSLATION_GAP
        outcome.reasons = {f"condition_error:{type(exc).__name__}": 1}
        return outcome, []

    outcome.conjuncts_total = len(conjuncts)
    scope_literals = [
        Literal(path_, operator, value, False, False) for path_, operator, value in scope
    ]
    technique_mappings = [
        {
            "stix_id": m.stix_id,
            "object_type": m.object_type,
            "attack_kb_version": attack_kb_version,
            "external_id": m.external_id,
            "mapping_basis": (
                f"Sigma rule {sigma_id} '{rule.title}' (author: {rule.author or 'unknown'}) "
                f"tag {m.tag}"
                + (
                    f"; {m.revoked_from} is revoked, followed ATT&CK revoked-by to "
                    f"{m.external_id}"
                    if m.revoked_from
                    else ""
                )
            ),
            "mapping_source": "sigma",
        }
        for m in mappings
    ]
    rules: list[dict[str, Any]] = []
    for position, raw in enumerate(conjuncts):
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
                "rule_id": f"sigma:{sigma_id}:{position:03d}",
                "rule_version": release_tag,
                "conditions": [lit.to_json() for lit in [*scope_literals, *literals]],
                "technique_mappings": technique_mappings,
                "evidence_type": "behavioral",
                "rule_source": f"sigma:{sigma_id}",
                # Conjuncts of one Sigma rule are one detection (engine dedups).
                "rule_family": f"sigma:{sigma_id}",
            }
        )
    outcome.conjuncts_imported = len(rules)
    if not rules:
        outcome.rejection = (
            RejectionReason.TELEMETRY_GAP
            if all(k.startswith(GapKind.TELEMETRY.value) for k in outcome.reasons)
            else RejectionReason.TRANSLATION_GAP
        )
        return outcome, []
    outcome.status = (
        RuleStatus.IMPORTED if len(rules) == outcome.conjuncts_total else RuleStatus.PARTIAL
    )
    return outcome, rules


# ===========================================================================
# Archive import
# ===========================================================================


def import_sigma_archive(
    archive_path: Path,
    *,
    knowledge: AttackKnowledge,
    release_tag: str,
    archive_sha256: str,
    dnf_bound: int = DEFAULT_DNF_BOUND,
    software_tag_review: Path | None = None,
) -> SigmaImportResult:
    """Import every rule in the pinned archive. Returns the rule pack (loadable
    by ``detection.load_rule_pack``) and the import report. Pure function of
    its inputs; nothing is written here.

    ``software_tag_review`` is the reviewed decision file for Sigma software
    tags (ADR-0007 D3 amendment). Without it, **no** software tag becomes a
    mapping — the safe default."""
    software_review = (
        load_software_tag_review(software_tag_review) if software_tag_review is not None else {}
    )
    if dnf_bound < 1:
        raise SigmaImportError("dnf_bound must be >= 1")
    raw = archive_path.read_bytes()
    actual = hashlib.sha256(raw).hexdigest()
    if actual != archive_sha256:
        raise SigmaImportError(
            f"{archive_path}: SHA-256 {actual} does not match the pinned {archive_sha256}"
        )
    index = _AttackIndex(knowledge)
    outcomes: list[RuleOutcome] = []
    rules: list[dict[str, Any]] = []
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        members = sorted(n for n in archive.namelist() if n.endswith((".yml", ".yaml")))
        for member in members:
            text = archive.read(member).decode("utf-8")
            try:
                rule = SigmaRule.from_yaml(text)
            except SigmaError as exc:
                outcomes.append(
                    RuleOutcome(
                        sigma_id=f"unparsed:{member}",
                        title="",
                        path=member,
                        logsource="",
                        status=RuleStatus.REJECTED,
                        reasons={f"parse_error:{type(exc).__name__}": 1},
                        rejection=RejectionReason.TRANSLATION_GAP,
                    )
                )
                continue
            outcome, rule_dicts = _import_rule(
                rule,
                member,
                index=index,
                attack_kb_version=knowledge.attack_kb_version,
                release_tag=release_tag,
                bound=dnf_bound,
                software_review=software_review,
            )
            outcomes.append(outcome)
            rules.extend(rule_dicts)

    outcomes.sort(key=lambda o: (o.sigma_id, o.path))
    rules.sort(key=lambda r: str(r["rule_id"]))
    provenance = {
        "importer": f"{IMPORTER_METHOD}/{IMPORTER_VERSION}",
        "sigma_release": release_tag,
        "sigma_archive": archive_path.name,
        "sigma_archive_sha256": archive_sha256,
        "pysigma_version": installed_version("pySigma"),
        "field_map_version": FIELD_MAP_VERSION,
        "attack_kb_version": knowledge.attack_kb_version,
        "dnf_bound": dnf_bound,
        "software_tag_review": (
            {
                "file": software_tag_review.name,
                "sha256": hashlib.sha256(software_tag_review.read_bytes()).hexdigest(),
                "accepted": sorted(
                    f"{sid}:{tag}" for (sid, tag), accepted in software_review.items() if accepted
                ),
            }
            if software_tag_review is not None
            else None
        ),
        "license": "Sigma rules: Detection Rule License (DRL) 1.1 — see NOTICE.md",
    }
    pack = {
        "pack_id": f"sigma-{release_tag}-{archive_path.stem}",
        "description": (
            "Generated by the ADR-0007 Sigma importer from the pinned SigmaHQ release. "
            "Do not edit by hand; regenerate with scripts/import_sigma_rules.py."
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
            "sigma_rules_total": len(outcomes),
            "by_status": dict(sorted(status_counts.items())),
            "rejected_by_reason": dict(sorted(rejection_counts.items())),
            "generated_rules": len(rules),
            "attack_ids_with_imported_rule": len(covered),
            "group_tags_ignored": sum(len(o.ignored_group_tags) for o in outcomes),
            "software_tags_ignored": sum(len(o.ignored_software_tags) for o in outcomes),
        },
        "gap_reasons": dict(sorted(reason_counts.items(), key=lambda kv: (-kv[1], kv[0]))),
        "unmapped_field_notes": dict(sorted(UNMAPPED_FIELD_REASONS.items())),
        "attack_ids_with_imported_rule": covered,
        "rules": [o.to_json(release_tag) for o in outcomes],
    }
    return SigmaImportResult(pack=pack, report=report)


__all__ = [
    "IMPORTER_METHOD",
    "IMPORTER_VERSION",
    "DEFAULT_DNF_BOUND",
    "ELIGIBLE_STATUSES",
    "ELIGIBLE_LEVELS",
    "GapKind",
    "RuleStatus",
    "RejectionReason",
    "SigmaImportError",
    "Literal",
    "Gap",
    "RuleOutcome",
    "SigmaImportResult",
    "import_sigma_archive",
]
