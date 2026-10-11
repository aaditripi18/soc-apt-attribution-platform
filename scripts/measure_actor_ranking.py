#!/usr/bin/env python3
"""Known-answer checks: what would naming an actor have got right?

The platform names no "most likely actor" (ADR-0009 D3, ADR-0017). This script
is the evidence behind that: on served investigations of recordings whose answer
is known, it records the verdict the platform gave and what each simple,
explainable ordering of ATT&CK technique overlap would have named instead.

    python scripts/measure_actor_ranking.py http://127.0.0.1:8000
    python scripts/measure_actor_ranking.py http://127.0.0.1:8000 --json <out.json>

The tracked copy is ``data/validation/known-answer-checks.json``.

Known answers (the datasets' own descriptions, OTRF Security Datasets):

- ``otrf-apt29-*`` emulate APT29 (G0016); ``otrf-apt3-*`` emulate APT3 (G0022);
- ``otrf-lsass-*`` are single credential-dumping tool runs with **no actor** —
  naming anyone there is a false attribution.

Two levels are measured for an emulation: each unit by itself (ordered by the
stored ADR-0005 ``support_value``), and every unit pooled (several orderings, at
technique level and with sub-techniques folded into parents). Read-only: GET
requests alone. The JSON is what ``GET /validation`` serves.
"""

from __future__ import annotations

import json
import math
import statistics
import sys
import urllib.parse
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import Any

from attribution_platform.attack_knowledge.loader import load_attack_knowledge
from attribution_platform.attack_knowledge.traversal import (
    active_groups,
    groups_using_technique,
    techniques_used_by,
)

CHECKS_VERSION = "known-answer-checks/1"
#: source id prefix -> (ATT&CK Group id the recording emulates, or None for "no actor"; basis)
KNOWN: dict[str, tuple[str | None, str]] = {
    "otrf-apt29": ("G0016", "OTRF Security Datasets: APT29 emulation (ATT&CK Evaluations plan)"),
    "otrf-apt3": ("G0022", "OTRF Security Datasets: APT3 emulation"),
    "otrf-lsass": (None, "OTRF Security Datasets: one credential-dumping tool run; no actor"),
}


def _external(obj: Any) -> str:
    return next(
        str(r["external_id"])
        for r in obj["external_references"]
        if r.get("source_name") == "mitre-attack"
    )


def _orderings(
    observed: set[str], share: Callable[[str], float]
) -> dict[str, Callable[[set[str]], float]]:
    """Simple, explainable orderings of a profile against the observed techniques."""

    def count(profile: set[str]) -> float:
        return float(len(profile & observed))

    def rarity(profile: set[str]) -> float:
        return sum(-math.log(share(t)) for t in profile & observed if share(t) > 0)

    def breadth_normalised(profile: set[str]) -> float:
        return len(profile & observed) / len(profile) if profile else 0.0

    def f1(profile: set[str]) -> float:
        return 2 * len(profile & observed) / (len(profile) + len(observed)) if profile else 0.0

    return {
        "observed techniques in profile (count)": count,
        "rarity-weighted overlap (sum of -ln g)": rarity,
        "overlap / profile size (breadth-normalised)": breadth_normalised,
        "F1 of overlap/profile and overlap/observed": f1,
    }


def measure(base_url: str) -> dict[str, Any]:
    base = base_url.rstrip("/") + "/api"

    def get(path: str) -> Any:
        with urllib.request.urlopen(base + path, timeout=300) as response:  # noqa: S310
            return json.loads(response.read())

    def quote(identifier: str) -> str:
        return urllib.parse.quote(identifier, safe="")

    knowledge = load_attack_knowledge()
    groups = {str(g["id"]): g for g in active_groups(knowledge)}
    total_groups = len(groups)
    attack_id = {
        str(o["id"]): _external(o) for o in (*knowledge.techniques(), *knowledge.sub_techniques())
    }
    profile = {s: set(techniques_used_by(knowledge, s)) for s in groups}
    parent_profile = {s: {attack_id[t].split(".")[0] for t in p} for s, p in profile.items()}
    parent_users: dict[str, int] = {}
    for parents in parent_profile.values():
        for parent in parents:
            parent_users[parent] = parent_users.get(parent, 0) + 1

    def parent_share(technique: str) -> float:
        return parent_users.get(technique, 0) / total_groups

    cases: list[dict[str, Any]] = []
    pins: dict[str, Any] = {}
    for summary in sorted(get("/investigations"), key=lambda i: str(i["source_id"])):
        known = next((v for p, v in KNOWN.items() if summary["source_id"].startswith(p)), None)
        if known is None:
            continue
        truth, basis = known
        investigation = get(f"/investigations/{quote(summary['investigation_id'])}")
        assessment = get(f"/investigations/{quote(summary['investigation_id'])}/assessment")
        pins = {
            "attack_kb_version": investigation["attack_kb_version"],
            "detection_pack_content_hash": investigation["detection_pack_content_hash"],
            "method_versions": investigation["method_versions"],
        }
        true_stix = next((s for s, g in groups.items() if _external(g) == truth), None)
        units = get(f"/investigations/{quote(summary['investigation_id'])}/units?limit=1000")
        pooled: set[str] = set()
        unit_ranks: list[tuple[int, int]] = []
        units_as_candidate = 0
        for unit in units["units"]:
            analysis = get("/units/" + quote(unit["group_id"]))["attribution_analysis"]
            pooled |= set(analysis["observed_feature_technique_ids"])
            by_id = {c["candidate_id"]: c for c in analysis["candidates"]}
            if any(c["attack_external_id"] == truth for c in by_id.values()):
                units_as_candidate += 1
            scores = [
                (h["support_value"], by_id[h["candidate_id"]]["attack_external_id"])
                for h in analysis["hypotheses"]
                if h["candidate_id"] in by_id
            ]
            mine = [value for value, external in scores if external == truth]
            if mine:
                unit_ranks.append((1 + sum(1 for v, _ in scores if v > mine[0]), len(scores)))

        g = {t: len(groups_using_technique(knowledge, t)) / total_groups for t in pooled}
        levels: list[tuple[str, set[str], dict[str, set[str]], Callable[[str], float]]] = [
            ("technique", pooled, profile, g.__getitem__),
            (
                "parent technique",
                {attack_id[t].split(".")[0] for t in pooled},
                parent_profile,
                parent_share,
            ),
        ]
        orderings: list[dict[str, Any]] = []
        for level, observed, profiles, share in levels:
            pool = [s for s in groups if profiles[s] & observed]
            for name, score in _orderings(observed, share).items():
                ordered = sorted(
                    ((score(profiles[s]), str(groups[s]["name"]), s) for s in pool), reverse=True
                )
                row: dict[str, Any] = {
                    "ordering": name,
                    "level": level,
                    "groups_ordered": len(pool),
                    "would_name": ordered[0][1] if ordered else None,
                    "known_actor_position": None,
                }
                if true_stix is not None and true_stix in pool:
                    mine_score = score(profiles[true_stix])
                    row["known_actor_position"] = 1 + sum(
                        1 for v, _, _ in ordered if v > mine_score
                    )
                orderings.append(row)
        case: dict[str, Any] = {
            "source_id": summary["source_id"],
            "source_sha256": investigation["source_sha256"],
            "investigation_id": summary["investigation_id"],
            "kind": "emulation" if truth else "tool_test",
            "known_actor": (
                {"attack_id": truth, "name": str(groups[true_stix]["name"])} if true_stix else None
            ),
            "known_basis": basis,
            "verdict": assessment["verdict"],
            "statement": assessment["statement"],
            "units": len(units["units"]),
            "observed_techniques": len(pooled),
            "candidates": len(assessment["candidates"]),
            "known_actor_profile_techniques": len(profile[true_stix]) if true_stix else None,
            "known_actor_techniques_observed": (
                len(profile[true_stix] & pooled) if true_stix else None
            ),
            "units_with_known_actor_as_candidate": units_as_candidate if true_stix else None,
            "unit_level": (
                {
                    "units_compared": len(unit_ranks),
                    "first": sum(1 for r, _ in unit_ranks if r == 1),
                    "top_10": sum(1 for r, _ in unit_ranks if r <= 10),
                    "median_position": statistics.median(r for r, _ in unit_ranks),
                    "median_candidates": statistics.median(n for _, n in unit_ranks),
                }
                if unit_ranks
                else None
            ),
            "orderings": orderings,
        }
        cases.append(case)

    emulations = [c for c in cases if c["kind"] == "emulation"]
    tool_tests = [c for c in cases if c["kind"] == "tool_test"]
    positions = [
        o["known_actor_position"]
        for c in emulations
        for o in c["orderings"]
        if o["known_actor_position"] is not None
    ]
    return {
        "version": CHECKS_VERSION,
        "pinned": pins,
        "summary": {
            "cases": len(cases),
            "emulations": len(emulations),
            "tool_tests": len(tool_tests),
            "verdicts_naming_an_actor": 0,  # no verdict can (ADR-0017)
            "orderings_measured": len(positions),
            "orderings_naming_the_known_actor_first": sum(1 for p in positions if p == 1),
            "orderings_with_the_known_actor_in_top_10": sum(1 for p in positions if p <= 10),
            "best_position_of_a_known_actor": min(positions) if positions else None,
            "worst_position_of_a_known_actor": max(positions) if positions else None,
            "actors_an_ordering_would_name_on_tool_tests": sum(
                1 for c in tool_tests for o in c["orderings"] if o["would_name"]
            ),
            "orderings_on_tool_tests": sum(len(c["orderings"]) for c in tool_tests),
        },
        "cases": cases,
    }


def main(argv: list[str]) -> int:
    if not argv or len(argv) not in (1, 3) or (len(argv) == 3 and argv[1] != "--json"):
        print(__doc__)
        return 2
    result = measure(argv[0])
    if not result["cases"]:
        print(
            "No served investigation has a known answer (otrf-apt29-*, otrf-apt3-*, otrf-lsass-*)."
        )
        return 1
    for case in result["cases"]:
        actor = case["known_actor"]
        truth = f"{actor['attack_id']} {actor['name']}" if actor else "no actor (tool test)"
        print(f"\n{case['source_id']} — known answer: {truth}")
        print(f"  verdict given: {case['verdict']}")
        if actor:
            seen, profile_size = (
                case["known_actor_techniques_observed"],
                case["known_actor_profile_techniques"],
            )
            print(
                f"  {seen} of {case['observed_techniques']} observed techniques are in its "
                f"profile of {profile_size}; a candidate in "
                f"{case['units_with_known_actor_as_candidate']} of {case['units']} units"
            )
            if case["unit_level"]:
                level = case["unit_level"]
                print(
                    f"  per unit, by stored support: first in {level['first']}, top 10 in "
                    f"{level['top_10']} of {level['units_compared']}; median position "
                    f"{level['median_position']:g} of {level['median_candidates']:g}"
                )
        for row in case["orderings"]:
            position = row["known_actor_position"]
            where = f"position {position:>3} of {row['groups_ordered']}" if position else " " * 19
            named = row["would_name"]
            print(f"    {row['level']:<17} {row['ordering']:<46} {where}  would name {named}")
    summary = result["summary"]
    print(
        f"\n{summary['cases']} known-answer cases; the known actor first under "
        f"{summary['orderings_naming_the_known_actor_first']} of {summary['orderings_measured']} "
        f"orderings, in the top 10 under {summary['orderings_with_the_known_actor_in_top_10']}; "
        f"positions {summary['best_position_of_a_known_actor']}–"
        f"{summary['worst_position_of_a_known_actor']}. On tool tests an ordering would name an "
        f"actor in {summary['actors_an_ordering_would_name_on_tool_tests']} of "
        f"{summary['orderings_on_tool_tests']} cases."
    )
    if len(argv) == 3:
        out = Path(argv[2])
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(
            json.dumps(result, indent=1, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n"
        )
        print(f"written {out}")
    return 0


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[union-attr]
    raise SystemExit(main(sys.argv[1:]))
