"""Full-universe detection coverage report (ADR-0007 D9/D10).

For **every** active ATT&CK technique and sub-technique in the pinned KB (no
allowlist), exactly one status; for **every** active Group, how much of its
technique profile the platform can currently detect and why the rest cannot;
and a ranking of telemetry gaps by how many techniques and Groups they block.

Status rules (deterministic, first match wins):

1. ``covered`` — at least one rule in the supplied runtime rule packs maps to it.
2. ``telemetry_gap`` — an eligible Sigma rule tagged with it was rejected, and at
   least one such rule failed **only** for telemetry reasons (a logsource or
   field no adapter produces). Fixable by adapter/domain work.
3. ``translation_gap`` — eligible Sigma rules exist but every one needs a
   construct with no exact translation (regex, CIDR, interior wildcard, ...).
4. ``not_endpoint_observable`` — no eligible Sigma rule, and ATT&CK itself gives
   no data component for it or does not list the Windows platform (v1 scope:
   Windows endpoint, ADR-0001 D13).
5. ``no_sigma_rule`` — observable in principle, but no eligible Sigma rule exists.

Reads no pySigma: inputs are the pinned KB, the loaded rule packs and the
Sigma import report JSON. Pure and deterministic (sorted output).

"Unlocks" in the gap ranking are **upper bounds**: a rule blocked by a missing
logsource may also need a missing field. Counts, never accuracy claims.
"""

from __future__ import annotations

import enum
from collections.abc import Mapping, Sequence
from typing import Any

from attribution_platform.attack_knowledge.loader import AttackKnowledge, FrozenStixObject
from attribution_platform.attack_knowledge.traversal import (
    active_groups,
    is_active,
    required_data_components,
    techniques_used_by,
)
from attribution_platform.detection.rules import RulePack

COVERAGE_REPORT_VERSION = "coverage-report/1"

#: Platform in v1 endpoint scope (ADR-0001 D13, doc 12).
V1_ENDPOINT_PLATFORM = "Windows"

#: Minimum distinct observed features before the engine may attribute at all
#: (ADR-0002 CR / ADR-0005: no attribution from a single technique). Used only
#: to report which Groups clear that *necessary* bar — never sufficiency.
MIN_FEATURES_TO_ATTRIBUTE = 2


class TechniqueStatus(enum.Enum):
    COVERED = "covered"
    TELEMETRY_GAP = "telemetry_gap"
    TRANSLATION_GAP = "translation_gap"
    NOT_ENDPOINT_OBSERVABLE = "not_endpoint_observable"
    NO_SIGMA_RULE = "no_sigma_rule"


_TELEMETRY_PREFIXES = ("telemetry_gap:", "logsource:")


def _external_id(obj: FrozenStixObject) -> str:
    for ref in obj.get("external_references") or ():
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return str(ref["external_id"])
    raise ValueError(f"ATT&CK object {obj.get('id')!r} has no mitre-attack external id")


def _telemetry_units(gap_reasons: Mapping[str, int]) -> tuple[str, ...]:
    """The telemetry blockers named in one rule's gap reasons, normalized to
    ``logsource:<product>/<category>`` or ``field:<Name>``."""
    units = set()
    for key in gap_reasons:
        if key.startswith("logsource:"):
            units.add(key)
        elif key.startswith("telemetry_gap:"):
            units.add(key.removeprefix("telemetry_gap:"))
    return tuple(sorted(units))


def _in_v1_scope(unit: str) -> bool:
    """A blocker is in v1 (Windows endpoint) scope if it is a Windows logsource
    or a field of an already-supported Windows logsource."""
    return unit.startswith(("logsource:windows/", "field:"))


def build_coverage_report(
    knowledge: AttackKnowledge,
    packs: Sequence[RulePack],
    sigma_import_report: Mapping[str, Any],
) -> dict[str, Any]:
    """Build the coverage report (a JSON-ready dict)."""
    if sigma_import_report["provenance"]["attack_kb_version"] != knowledge.attack_kb_version:
        raise ValueError(
            "sigma import report was produced against "
            f"{sigma_import_report['provenance']['attack_kb_version']!r}, "
            f"not the loaded {knowledge.attack_kb_version!r}"
        )

    techniques = sorted(
        (o for o in (*knowledge.techniques(), *knowledge.sub_techniques()) if is_active(o)),
        key=_external_id,
    )
    by_stix = {str(o["id"]): o for o in techniques}

    covered_by: dict[str, set[str]] = {}
    for pack in packs:
        for rule in pack.rules:
            for mapping in rule.technique_mappings:
                if mapping.attack_ref.stix_id in by_stix:
                    covered_by.setdefault(mapping.attack_ref.stix_id, set()).add(rule.rule_source)

    ext_to_stix = {_external_id(o): str(o["id"]) for o in techniques}
    # Per technique: Sigma rules that were rejected, split by why.
    telemetry_only: dict[str, list[tuple[str, ...]]] = {}
    translation: dict[str, int] = {}
    for row in sigma_import_report["rules"]:
        if row["status"] != "rejected" or row["rejection"] not in (
            "telemetry_gap",
            "translation_gap",
        ):
            continue
        reasons: Mapping[str, int] = row["gap_reasons"]
        only_telemetry = bool(reasons) and all(k.startswith(_TELEMETRY_PREFIXES) for k in reasons)
        for attack_id in row["attack_ids"]:
            stix_id = ext_to_stix.get(attack_id)
            if stix_id is None:
                continue  # software ids, or ids outside the active technique set
            if only_telemetry:
                telemetry_only.setdefault(stix_id, []).append(_telemetry_units(reasons))
            else:
                translation[stix_id] = translation.get(stix_id, 0) + 1

    statuses: dict[str, TechniqueStatus] = {}
    technique_rows: list[dict[str, Any]] = []
    for obj in techniques:
        stix_id = str(obj["id"])
        platforms = tuple(obj.get("x_mitre_platforms") or ())
        data_components = required_data_components(knowledge, stix_id)
        if stix_id in covered_by:
            status = TechniqueStatus.COVERED
        elif stix_id in telemetry_only:
            status = TechniqueStatus.TELEMETRY_GAP
        elif stix_id in translation:
            status = TechniqueStatus.TRANSLATION_GAP
        elif not data_components or V1_ENDPOINT_PLATFORM not in platforms:
            status = TechniqueStatus.NOT_ENDPOINT_OBSERVABLE
        else:
            status = TechniqueStatus.NO_SIGMA_RULE
        statuses[stix_id] = status
        technique_rows.append(
            {
                "attack_id": _external_id(obj),
                "name": str(obj.get("name", "")),
                "status": status.value,
                "rule_sources": len(covered_by.get(stix_id, ())),
                # Blockers of *rejected* Sigma rules for this technique (also shown
                # for covered techniques: fixing them would add further rules).
                "rejected_rules_blocked_by": sorted(
                    {u for units in telemetry_only.get(stix_id, []) for u in units}
                ),
                "windows_platform": V1_ENDPOINT_PLATFORM in platforms,
                "has_data_component": bool(data_components),
            }
        )

    group_rows: list[dict[str, Any]] = []
    group_users: dict[str, set[str]] = {}
    for group in sorted(active_groups(knowledge), key=_external_id):
        profile = [t for t in techniques_used_by(knowledge, str(group["id"])) if t in by_stix]
        for t in profile:
            group_users.setdefault(t, set()).add(str(group["id"]))
        counts = {s.value: 0 for s in TechniqueStatus}
        for t in profile:
            counts[statuses[t].value] += 1
        group_rows.append(
            {
                "attack_id": _external_id(group),
                "name": str(group.get("name", "")),
                "profile_techniques": len(profile),
                "covered": counts[TechniqueStatus.COVERED.value],
                "by_status": counts,
                "uncovered": [
                    {"attack_id": _external_id(by_stix[t]), "status": statuses[t].value}
                    for t in sorted(profile, key=lambda s: _external_id(by_stix[s]))
                    if statuses[t] is not TechniqueStatus.COVERED
                ],
            }
        )

    # Telemetry-gap ranking: which missing logsource/field would unblock most.
    unlock_techniques: dict[str, set[str]] = {}
    for stix_id, unit_lists in telemetry_only.items():
        if statuses[stix_id] is not TechniqueStatus.TELEMETRY_GAP:
            continue
        for units in unit_lists:
            for unit in units:
                unlock_techniques.setdefault(unit, set()).add(stix_id)
    ranking_rows: list[dict[str, Any]] = [
        {
            "blocker": unit,
            "in_v1_scope": _in_v1_scope(unit),
            "techniques_upper_bound": len(stix_ids),
            "group_used_techniques_upper_bound": sum(1 for t in stix_ids if group_users.get(t)),
            "groups_touched_upper_bound": len(
                set().union(*(group_users.get(t, set()) for t in stix_ids))
            ),
        }
        for unit, stix_ids in unlock_techniques.items()
    ]
    gap_ranking = sorted(
        ranking_rows,
        key=lambda r: (
            -r["group_used_techniques_upper_bound"],
            -r["techniques_upper_bound"],
            r["blocker"],
        ),
    )

    group_used = set(group_users)
    status_totals = {s.value: 0 for s in TechniqueStatus}
    group_used_totals = {s.value: 0 for s in TechniqueStatus}
    for stix_id, status in statuses.items():
        status_totals[status.value] += 1
        if stix_id in group_used:
            group_used_totals[status.value] += 1
    covered_counts = [g["covered"] for g in group_rows]
    summary = {
        "active_techniques": len(techniques),
        "group_used_techniques": len(group_used),
        "active_groups": len(group_rows),
        "techniques_by_status": status_totals,
        "group_used_techniques_by_status": group_used_totals,
        "groups_with_empty_technique_profile": sum(
            1 for g in group_rows if g["profile_techniques"] == 0
        ),
        "groups_with_zero_covered": sum(1 for c in covered_counts if c == 0),
        f"groups_with_at_least_{MIN_FEATURES_TO_ATTRIBUTE}_covered": sum(
            1 for c in covered_counts if c >= MIN_FEATURES_TO_ATTRIBUTE
        ),
        "groups_with_at_least_5_covered": sum(1 for c in covered_counts if c >= 5),
        "groups_with_at_least_10_covered": sum(1 for c in covered_counts if c >= 10),
    }
    return {
        "report_version": COVERAGE_REPORT_VERSION,
        "provenance": {
            "attack_kb_version": knowledge.attack_kb_version,
            "attack_kb_sha256": knowledge.attack_kb_sha256,
            "rule_packs": [
                {"pack_id": p.pack_id, "content_hash": p.content_hash}
                for p in sorted(packs, key=lambda p: p.pack_id)
            ],
            "sigma_import": dict(sigma_import_report["provenance"]),
            "v1_endpoint_platform": V1_ENDPOINT_PLATFORM,
        },
        "notes": [
            "Counts only; not detection-efficacy or attribution-accuracy claims (ADR-0006 §D14).",
            "'covered' means a rule maps to the technique; Sigma tags are author claims "
            "(ADR-0007 D3 limitation).",
            f"Groups with >= {MIN_FEATURES_TO_ATTRIBUTE} covered techniques clear a necessary, "
            "not sufficient, bar for attribution.",
            "gap_ranking values are upper bounds: an unblocked rule may still need another "
            "missing field.",
        ],
        "summary": summary,
        "gap_ranking": gap_ranking,
        "groups": group_rows,
        "techniques": technique_rows,
    }


def render_coverage_summary(report: Mapping[str, Any], *, top_gaps: int = 15) -> str:
    """A short human-readable Markdown view of the report (generated)."""
    s = report["summary"]
    lines = [
        "# Detection coverage summary",
        "",
        "_Generated by `scripts/build_coverage_report.py` — do not edit by hand. "
        "Source of truth: `coverage-report.json` beside this file._",
        "",
        f"ATT&CK `{report['provenance']['attack_kb_version']}`; Sigma "
        f"`{report['provenance']['sigma_import']['sigma_release']}`; "
        f"v1 endpoint platform: {report['provenance']['v1_endpoint_platform']}.",
        "Counts only — not detection-efficacy or attribution-accuracy claims.",
        "",
        "## Techniques",
        "",
        "| Status | All active techniques | Used by ≥ 1 active Group |",
        "|---|---|---|",
    ]
    for status in TechniqueStatus:
        lines.append(
            f"| `{status.value}` | {s['techniques_by_status'][status.value]} | "
            f"{s['group_used_techniques_by_status'][status.value]} |"
        )
    lines += [
        f"| **total** | **{s['active_techniques']}** | **{s['group_used_techniques']}** |",
        "",
        "## Groups",
        "",
        f"- Active Groups: {s['active_groups']}",
        f"- With 0 covered techniques: {s['groups_with_zero_covered']} "
        f"(of which {s['groups_with_empty_technique_profile']} have no active techniques "
        "in ATT&CK at all, so no detection work can cover them)",
        f"- With ≥ {MIN_FEATURES_TO_ATTRIBUTE} covered (necessary, not sufficient, to "
        f"attribute): {s[f'groups_with_at_least_{MIN_FEATURES_TO_ATTRIBUTE}_covered']}",
        f"- With ≥ 5 covered: {s['groups_with_at_least_5_covered']}",
        f"- With ≥ 10 covered: {s['groups_with_at_least_10_covered']}",
        "",
        f"## Top {top_gaps} telemetry blockers (upper bounds; v1 = Windows endpoint)",
        "",
        "| Blocker | v1 scope | Techniques | Group-used techniques | Groups touched |",
        "|---|---|---|---|---|",
    ]
    for row in report["gap_ranking"][:top_gaps]:
        lines.append(
            f"| `{row['blocker']}` | {'yes' if row['in_v1_scope'] else 'no'} | "
            f"{row['techniques_upper_bound']} | {row['group_used_techniques_upper_bound']} | "
            f"{row['groups_touched_upper_bound']} |"
        )
    lines.append("")
    return "\n".join(lines)


__all__ = [
    "COVERAGE_REPORT_VERSION",
    "V1_ENDPOINT_PLATFORM",
    "MIN_FEATURES_TO_ATTRIBUTE",
    "TechniqueStatus",
    "build_coverage_report",
    "render_coverage_summary",
]
