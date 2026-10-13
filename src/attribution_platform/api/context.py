"""Reference data the read-model API serves beside stored records (ADR-0016).

The analyst frontend needs three things no investigation record carries: the
names, tactics and Group prevalence of ATT&CK techniques; which detection rule
(title, upstream URL, content tier) produced an Evidence; and the detection
coverage report. All three are **pinned artefacts already in the repository**
(the ATT&CK knowledge base, the two import reports, the coverage report) —
this module reads them once and shapes them for transport. Nothing is computed
that those artefacts do not already state: counts are sums of their rows.

An :class:`ApiContext` is optional. A server created without one serves the
stored records exactly as before and answers the reference routes with 404.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from attribution_platform.attack_knowledge.loader import AttackKnowledge
from attribution_platform.attack_knowledge.traversal import (
    active_groups,
    groups_using_technique,
    is_active,
    software_used_by,
    techniques_used_by,
)

API_CONTEXT_VERSION = "api-context/1"
#: How many rejection reasons of each content source ``/coverage`` lists.
_TOP_REJECTION_REASONS = 20
#: An import-report row states its content tier only when it is not the default
#: (``SigmaRuleOutcome`` / ``ElasticRuleOutcome``: ``content_tier = "core"``).
_DEFAULT_TIER = "core"


@dataclass(frozen=True)
class ApiContext:
    """Pinned reference data, shaped once at start-up.

    - ``knowledge``: the ATT&CK knowledge base the dossier is rendered against.
    - ``techniques``: the ``GET /attack/techniques`` body.
    - ``coverage``: the ``GET /coverage`` body.
    - ``rules``: ``"<origin>:<upstream rule id>"`` -> rule facts, used to label
      Evidence with the rule that produced it.
    - ``static_dir``: the built frontend, served at ``/`` when present.
    """

    knowledge: AttackKnowledge | None = None
    techniques: Mapping[str, Any] | None = None
    coverage: Mapping[str, Any] | None = None
    rules: Mapping[str, Mapping[str, Any]] = field(default_factory=dict)
    static_dir: Path | None = None
    #: the ``GET /validation`` body (ADR-0017): known-answer checks, as measured
    validation: Mapping[str, Any] | None = None
    #: the ``GET /attack/groups`` body (ADR-0021): every active Group's profile
    groups: Mapping[str, Any] | None = None


def _external_id(obj: Mapping[str, Any]) -> str | None:
    for ref in obj.get("external_references") or ():
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return str(ref["external_id"])
    return None


def build_technique_catalogue(knowledge: AttackKnowledge) -> dict[str, Any]:
    """Every active technique and sub-technique with its tactics and the number
    of active Groups ATT&CK records using it; tactics in matrix order."""
    tactics = {str(t["x_mitre_shortname"]): t for t in knowledge.tactics() if is_active(t)}
    by_stix = {str(t["id"]): shortname for shortname, t in tactics.items()}
    order: list[str] = []
    for matrix in knowledge.objects_of_type("x-mitre-matrix"):
        order += [by_stix[ref] for ref in matrix.get("tactic_refs") or () if ref in by_stix]
    order += sorted(set(tactics) - set(order))
    techniques: list[dict[str, Any]] = []
    for obj in (*knowledge.techniques(), *knowledge.sub_techniques()):
        attack_id = _external_id(obj)
        if not is_active(obj) or attack_id is None:
            continue
        phases = [
            str(p["phase_name"])
            for p in obj.get("kill_chain_phases") or ()
            if p.get("kill_chain_name") == "mitre-attack"
        ]
        techniques.append(
            {
                "attack_id": attack_id,
                "stix_id": str(obj["id"]),
                "name": str(obj.get("name", "")),
                "is_subtechnique": bool(obj.get("x_mitre_is_subtechnique")),
                "tactics": [p for p in order if p in phases],
                "platforms": sorted(str(p) for p in obj.get("x_mitre_platforms") or ()),
                "groups_using": len(groups_using_technique(knowledge, str(obj["id"]))),
            }
        )
    techniques.sort(key=lambda t: str(t["attack_id"]))
    return {
        "attack_kb_version": knowledge.attack_kb_version,
        "active_groups": len(active_groups(knowledge)),
        "tactics": [
            {
                "shortname": shortname,
                "name": str(tactics[shortname].get("name", "")),
                "attack_id": _external_id(tactics[shortname]),
            }
            for shortname in order
        ],
        "techniques": techniques,
    }


def _rule_index(
    sigma_report: Mapping[str, Any], elastic_report: Mapping[str, Any]
) -> dict[str, Any]:
    rules: dict[str, Any] = {}
    for row in sigma_report.get("rules") or ():
        if row.get("status") == "rejected":
            continue
        rules[f"sigma:{row['sigma_id']}"] = {
            "origin": "sigma",
            "source_id": row["sigma_id"],
            "title": row.get("title"),
            "url": row.get("rule_url"),
            "content_tier": row.get("content_tier", _DEFAULT_TIER),
            "logsources": [row["logsource"]] if row.get("logsource") else [],
            "translation": row.get("status"),
        }
    for row in elastic_report.get("rules") or ():
        if row.get("status") == "rejected":
            continue
        rules[f"elastic:{row['rule_id']}"] = {
            "origin": "elastic",
            "source_id": row["rule_id"],
            "title": row.get("name"),
            "url": row.get("rule_url"),
            "content_tier": row.get("content_tier", _DEFAULT_TIER),
            "logsources": list(row.get("logsources") or ()),
            "translation": row.get("status"),
        }
    return rules


def _platform_rule_index(pack: Mapping[str, Any]) -> dict[str, Any]:
    """The platform's own rules (ADR-0026) by rule source: written here, so there
    is no upstream rule to link to."""
    tiers: dict[str, str] = {}
    for rule in pack.get("rules") or ():
        if not rule.get("technique_mappings"):
            continue  # a first-stage rule is a precondition: it produces no Evidence
        tier = "enrich" if rule.get("evidence_quality") == "low" else _DEFAULT_TIER
        tiers.setdefault(str(rule["rule_source"]), tier)
    return {
        source: {
            "origin": "platform",
            "source_id": source,
            "title": (pack.get("titles") or {}).get(source),
            "url": None,
            "content_tier": tier,
            "logsources": [],
            "translation": "authored",
        }
        for source, tier in tiers.items()
    }


def _actor_rule_index(actor_report: Mapping[str, Any]) -> dict[str, Any]:
    """Actor-specific rules (ADR-0018) by ``sigma-actor:<sigma id>``."""
    rules: dict[str, Any] = {}
    for row in actor_report.get("rules") or ():
        if row.get("status") == "rejected":
            continue
        rules[f"sigma-actor:{row['sigma_id']}"] = {
            "origin": "sigma",
            "source_id": row["sigma_id"],
            "title": row.get("title"),
            "url": row.get("rule_url"),
            "content_tier": "actor",
            "logsources": [row["logsource"]] if row.get("logsource") else [],
            "translation": row.get("status"),
            "actor_tags": [t for t in row.get("actor_tags") or () if t["decision"] == "accept"],
        }
    return rules


def _actor_view(actor_report: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "summary": actor_report.get("summary"),
        "provenance": actor_report.get("provenance"),
        "rules": [
            {
                "sigma_id": row["sigma_id"],
                "title": row.get("title"),
                "url": row.get("rule_url"),
                "logsource": row.get("logsource"),
                "status": row.get("status"),
                "rejection": row.get("rejection"),
                "actor_tags": row.get("actor_tags"),
            }
            for row in actor_report.get("rules") or ()
        ],
    }


def rule_key(method: str) -> str:
    """The rule-index key of an Evidence's ``provenance.method`` (an engine rule
    id such as ``sigma:<uuid>:000`` or ``elastic:<uuid>:<profile>:000``)."""
    return ":".join(method.split(":")[:2])


def _logsources(rules: Mapping[str, Mapping[str, Any]]) -> list[dict[str, Any]]:
    counts: dict[str, Counter[str]] = {}
    for rule in rules.values():
        for logsource in rule["logsources"]:
            counts.setdefault(str(logsource), Counter())[str(rule["origin"])] += 1
    return [
        {
            "logsource": logsource,
            "product": logsource.split("/", 1)[0],
            "sigma_rules": counter["sigma"],
            "elastic_rules": counter["elastic"],
        }
        for logsource, counter in sorted(counts.items())
    ]


def _top_reasons(report: Mapping[str, Any]) -> list[dict[str, Any]]:
    reasons = dict(report.get("gap_reasons") or {})
    ranked = sorted(reasons.items(), key=lambda kv: (-int(kv[1]), kv[0]))
    return [{"reason": k, "rules": int(v)} for k, v in ranked[:_TOP_REJECTION_REASONS]]


def _provenance(report: Mapping[str, Any]) -> dict[str, Any]:
    """An import report's provenance without its long review list."""
    return {
        k: v for k, v in dict(report.get("provenance") or {}).items() if k != "software_tag_review"
    }


def build_coverage_view(
    coverage_report: Mapping[str, Any],
    sigma_report: Mapping[str, Any],
    elastic_report: Mapping[str, Any],
    rules: Mapping[str, Mapping[str, Any]],
    actor_report: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """The ``GET /coverage`` body: the committed coverage report (per-Group
    uncovered lists dropped — they repeat the technique rows) beside what each
    content source contributed and why its other rules were not offered."""
    provenance = dict(coverage_report.get("provenance") or {})
    return {
        "report_version": coverage_report.get("report_version"),
        "notes": coverage_report.get("notes"),
        "provenance": {
            "attack_kb_version": provenance.get("attack_kb_version"),
            "attack_kb_sha256": provenance.get("attack_kb_sha256"),
            "rule_packs": provenance.get("rule_packs"),
            "sigma_import": _provenance(sigma_report),
            "elastic_import": _provenance(elastic_report),
        },
        "summary": coverage_report.get("summary"),
        "content": {
            "sigma": {
                "summary": sigma_report.get("summary"),
                "top_rejection_reasons": _top_reasons(sigma_report),
            },
            "elastic": {
                "summary": elastic_report.get("summary"),
                "top_rejection_reasons": _top_reasons(elastic_report),
            },
        },
        # ADR-0018: rules specific to one Group — every reviewed tag with its reason.
        "actor_specific": _actor_view(actor_report) if actor_report is not None else None,
        "logsources": _logsources(rules),
        "gap_ranking": coverage_report.get("gap_ranking"),
        "groups": [
            {k: v for k, v in dict(group).items() if k != "uncovered"}
            for group in coverage_report.get("groups") or ()
        ],
        "techniques": coverage_report.get("techniques"),
    }


def _read(path: Path) -> dict[str, Any]:
    data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    return data


def _plain(text: str) -> str:
    """An ATT&CK description's first paragraph as plain text: citations removed,
    Markdown links reduced to their label."""
    paragraph = text.strip().split("\n\n", 1)[0].replace("\n", " ")
    paragraph = re.sub(r"\(Citation:[^)]*\)", "", paragraph)
    paragraph = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", paragraph)
    return " ".join(paragraph.split())


def build_group_catalogue(
    knowledge: AttackKnowledge,
    actor_report: Mapping[str, Any] | None = None,
    advisory_attributions: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Every active ATT&CK Group as ATT&CK records it — aliases, techniques,
    software — and the group-specific evidence this platform holds for it: the
    accepted actor rules that run here (ADR-0018) and the advisory bundles
    attributed to it (ADR-0013). A Group with neither can be compared by
    behaviour but not named."""
    rules: dict[str, list[dict[str, Any]]] = {}
    for row in (actor_report or {}).get("rules") or ():
        if row.get("status") == "rejected":
            continue
        for tag in row.get("actor_tags") or ():
            if tag.get("decision") == "accept" and tag.get("group_id"):
                rules.setdefault(str(tag["group_id"]), []).append(
                    {"title": row.get("title"), "url": row.get("rule_url"), "reason": tag["reason"]}
                )
    advisories: dict[str, list[dict[str, Any]]] = {}
    for entry in (advisory_attributions or {}).get("attributions") or ():
        advisories.setdefault(str(entry["attack_group_id"]), []).append(
            {"report_name": entry["report_name"], "publisher": entry["publisher"]}
        )
    names = {
        str(obj["id"]): (_external_id(obj), str(obj.get("name", "")))
        for obj in (*knowledge.techniques(), *knowledge.sub_techniques(), *knowledge.software())
    }
    groups: list[dict[str, Any]] = []
    for obj in active_groups(knowledge):
        attack_id = _external_id(obj)
        if attack_id is None:
            continue
        stix_id = str(obj["id"])
        techniques = sorted(
            str(names[t][0])
            for t in techniques_used_by(knowledge, stix_id)
            if names.get(t, (None,))[0]
        )
        software = sorted(
            (
                {"attack_id": names[s][0], "name": names[s][1]}
                for s in software_used_by(knowledge, stix_id)
                if names.get(s, (None,))[0]
            ),
            key=lambda item: str(item["name"]).lower(),
        )
        groups.append(
            {
                "attack_id": attack_id,
                "stix_id": stix_id,
                "name": str(obj.get("name", "")),
                "aliases": sorted(
                    str(a) for a in obj.get("aliases") or () if str(a) != str(obj.get("name"))
                ),
                "description": _plain(str(obj.get("description", ""))),
                "technique_ids": techniques,
                "software": software,
                "actor_rules": sorted(rules.get(attack_id, []), key=lambda r: str(r["title"])),
                "advisories": advisories.get(attack_id, []),
            }
        )
    groups.sort(key=lambda g: (str(g["name"]).lower(), str(g["attack_id"])))
    return {
        "attack_kb_version": knowledge.attack_kb_version,
        "active_groups": len(groups),
        "groups_with_specific_evidence": sum(
            1 for g in groups if g["actor_rules"] or g["advisories"]
        ),
        "groups": groups,
    }


def load_api_context(
    knowledge: AttackKnowledge,
    *,
    coverage_report: Path,
    sigma_import_report: Path,
    elastic_import_report: Path,
    static_dir: Path | None = None,
    known_answer_checks: Path | None = None,
    actor_import_report: Path | None = None,
    advisory_attributions: Path | None = None,
    platform_pack: Path | None = None,
) -> ApiContext:
    """Read the pinned artefacts once and shape them for the API. The built
    frontend is served only when ``static_dir`` holds an ``index.html``."""
    sigma, elastic = _read(sigma_import_report), _read(elastic_import_report)
    rules = _rule_index(sigma, elastic)
    actor = (
        _read(actor_import_report)
        if actor_import_report is not None and actor_import_report.is_file()
        else None
    )
    if actor is not None:
        rules.update(_actor_rule_index(actor))
    if platform_pack is not None and platform_pack.is_file():
        rules.update(_platform_rule_index(_read(platform_pack)))
    served = (
        static_dir if static_dir is not None and (static_dir / "index.html").is_file() else None
    )
    return ApiContext(
        knowledge=knowledge,
        techniques=build_technique_catalogue(knowledge),
        coverage=build_coverage_view(_read(coverage_report), sigma, elastic, rules, actor),
        rules=rules,
        static_dir=served,
        validation=(
            _read(known_answer_checks)
            if known_answer_checks is not None and known_answer_checks.is_file()
            else None
        ),
        groups=build_group_catalogue(
            knowledge,
            actor,
            _read(advisory_attributions)
            if advisory_attributions is not None and advisory_attributions.is_file()
            else None,
        ),
    )


__all__ = [
    "API_CONTEXT_VERSION",
    "ApiContext",
    "build_coverage_view",
    "build_group_catalogue",
    "build_technique_catalogue",
    "load_api_context",
    "rule_key",
]
