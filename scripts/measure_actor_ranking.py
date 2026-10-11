#!/usr/bin/env python3
"""Where would the actor that was really emulated land, if candidates were ordered?

The platform shows no "most likely actor" (ADR-0009 D3). This script measures
what naming one would have got right, on served investigations of recordings
whose emulated actor is known, under simple explainable orderings of ATT&CK
technique overlap. It decides nothing; it is the evidence behind the decision.

    python scripts/measure_actor_ranking.py http://127.0.0.1:8000

Known answers (OTRF's own dataset descriptions): the APT29 recordings emulate
APT29 (G0016), the APT3 recordings APT3 (G0022). Read-only: GET requests alone.

Two levels are measured:

- **unit**: each attribution unit by itself, ordered by the stored ADR-0005
  ``support_value`` — what the per-unit record already contains;
- **investigation**: the decision features of every unit pooled, under several
  orderings, at technique level and with sub-techniques folded into parents.
"""

from __future__ import annotations

import json
import math
import statistics
import sys
import urllib.parse
import urllib.request
from collections.abc import Callable
from typing import Any

from attribution_platform.attack_knowledge.loader import load_attack_knowledge
from attribution_platform.attack_knowledge.traversal import (
    active_groups,
    groups_using_technique,
    techniques_used_by,
)

#: source id prefix -> ATT&CK Group id of the actor the recording emulates.
KNOWN_ACTOR = {"otrf-apt29": "G0016", "otrf-apt3": "G0022"}


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


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print(__doc__)
        return 2
    base = argv[0].rstrip("/") + "/api"

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

    measured = 0
    for investigation in get("/investigations"):
        truth = next(
            (
                g
                for prefix, g in KNOWN_ACTOR.items()
                if investigation["source_id"].startswith(prefix)
            ),
            None,
        )
        if truth is None:
            continue
        measured += 1
        true_stix = next(s for s, g in groups.items() if _external(g) == truth)
        units = get(f"/investigations/{quote(investigation['investigation_id'])}/units?limit=1000")
        pooled: set[str] = set()
        unit_ranks: list[tuple[int, int]] = []
        not_candidate = 0
        for unit in units["units"]:
            analysis = get("/units/" + quote(unit["group_id"]))["attribution_analysis"]
            pooled |= set(analysis["observed_feature_technique_ids"])
            by_id = {c["candidate_id"]: c for c in analysis["candidates"]}
            scores = [
                (h["support_value"], by_id[h["candidate_id"]]["attack_external_id"])
                for h in analysis["hypotheses"]
                if h["candidate_id"] in by_id
            ]
            mine = [value for value, external in scores if external == truth]
            if not mine:
                not_candidate += 1
            else:
                unit_ranks.append((1 + sum(1 for v, _ in scores if v > mine[0]), len(scores)))

        print(
            f"\n{investigation['source_id']} — emulated actor {truth} {groups[true_stix]['name']}"
        )
        print(
            f"  unit level ({len(units['units'])} units): the emulated actor is a candidate in "
            f"{len(unit_ranks)}, not a candidate in {not_candidate}"
        )
        if unit_ranks:
            ranks = [rank for rank, _ in unit_ranks]
            sizes = statistics.median(n for _, n in unit_ranks)
            print(
                f"    ordered by stored support: first in {sum(1 for r in ranks if r == 1)}, "
                f"top 10 in {sum(1 for r in ranks if r <= 10)} of {len(ranks)}; median rank "
                f"{statistics.median(ranks):g} of a median {sizes:g}"
            )

        g = {t: len(groups_using_technique(knowledge, t)) / total_groups for t in pooled}
        parents = {attack_id[t].split(".")[0] for t in pooled}
        levels: list[tuple[str, set[str], dict[str, set[str]], Callable[[str], float]]] = [
            ("technique level", pooled, profile, g.__getitem__),
            (
                "sub-techniques folded into parents",
                parents,
                parent_profile,
                lambda t: parent_users.get(t, 0) / total_groups,
            ),
        ]
        for label, observed, profiles, share in levels:
            matched = profiles[true_stix] & observed
            print(
                f"  investigation level, {label}: {len(observed)} observed; the emulated actor's "
                f"profile has {len(profiles[true_stix])}, of which {len(matched)} were observed"
            )
            orderings = _orderings(observed, share)
            pool = [s for s in groups if profiles[s] & observed]
            for name, score in orderings.items():
                mine_score = score(profiles[true_stix])
                ordered = sorted(((score(profiles[s]), s) for s in pool), reverse=True)
                rank = 1 + sum(1 for value, _ in ordered if value > mine_score)
                first = ", ".join(str(groups[s]["name"]) for _, s in ordered[:3])
                print(f"    {name:<46} rank {rank:>3} of {len(pool)}   first: {first}")
    if measured == 0:
        print("No served investigation has a known emulated actor (otrf-apt29-*, otrf-apt3-*).")
        return 1
    return 0


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[union-attr]
    raise SystemExit(main(sys.argv[1:]))
