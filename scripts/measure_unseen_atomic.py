#!/usr/bin/env python3
"""Measure the served investigations of the unseen OTRF atomic recordings
against their authors' ATT&CK mappings (ADR-0027).

Reads a running read-model API (one investigation per recording, run with the
recordings' cache paths as sources) and the tracked selection; writes
``data/validation/unseen-otrf-atomic/results.json``. Definitions are those of
ADR-0025 Amendment E (``measure_technique_ground_truth.py``), plus *shown*: the
authors' technique is among the recording's technique detections at all
(counted, declared only, or low-level context). Read-only: GET requests.

    python -I scripts/measure_unseen_atomic.py http://127.0.0.1:8004
"""

from __future__ import annotations

import collections
import json
import re
import sys
import urllib.parse
import urllib.request
from pathlib import Path, PurePath
from typing import Any

REPO = Path(__file__).resolve().parents[1]
SELECTION = REPO / "data" / "validation" / "unseen-otrf-atomic" / "selection.json"
OUT = REPO / "data" / "validation" / "unseen-otrf-atomic" / "results.json"
RUN = REPO / "data" / "validation" / "unseen-otrf-atomic" / "run.json"


def related(a: str, b: str) -> bool:
    """Parent and sub-technique of one another (not equal)."""
    return a != b and a.split(".")[0] == b.split(".")[0] and ("." in a) != ("." in b)


def _get(base: str, path: str) -> Any:
    with urllib.request.urlopen(base + "/api" + path, timeout=600) as response:  # noqa: S310
        return json.loads(response.read())


def _matches(technique: str, found: set[str]) -> bool:
    return technique in found or any(related(technique, other) for other in found)


def build(base: str) -> dict[str, Any]:
    selection = json.loads(SELECTION.read_text(encoding="utf-8"))["selected"]
    # run.json lists the recordings in manifest order, which is selection order;
    # joined by position (two selected files share a name), checked by name.
    outcomes = json.loads(RUN.read_text(encoding="utf-8"))["recordings"]
    if len(outcomes) != len(selection):
        raise SystemExit("run.json does not cover the selection")
    cases = []
    for entry, outcome in zip(selection, outcomes, strict=True):
        name = PurePath(entry["path"]).name
        if outcome["recording"] != name:
            raise SystemExit(f"run.json order differs at {name}")
        authors = entry["authors_techniques"]
        if outcome["state"] != "investigated":
            cases.append(
                {
                    "recording": entry["path"],
                    "investigated": False,
                    "state": outcome["state"],
                    "problems": outcome.get("problems", []),
                    "authors_techniques": authors,
                }
            )
            continue
        inv = {"investigation_id": outcome["investigation_id"], "evidence": outcome["evidence"]}
        q = urllib.parse.quote(inv["investigation_id"], safe="")
        assessment = _get(base, f"/investigations/{q}/assessment")
        counted = {
            o["technique_id"] for o in _get(base, f"/investigations/{q}/profile-match")["observed"]
        }
        shown = {
            e["attack_id"]
            for e in _get(base, f"/investigations/{q}/activity")["events"]
            if e["attack_object_type"] == "attack-pattern"
        }
        context = {
            e["attack_id"]
            for e in _get(base, f"/investigations/{q}/context")["items"]
            if e.get("attack_object_type") == "attack-pattern"
        }
        shown |= context
        exact = sorted(t for t in authors if t in counted)
        by_relation = sorted(t for t in authors if t not in counted and _matches(t, counted))
        missed = sorted(t for t in authors if t not in exact and t not in by_relation)
        cases.append(
            {
                "recording": entry["path"],
                "metadata_id": entry["metadata_id"],
                "tactic_folder": entry["path"].split("/")[3],
                "investigated": True,
                "evidence": inv.get("evidence"),
                "authors_techniques": authors,
                "found_exactly": exact,
                "found_as_parent_or_sub": by_relation,
                "missed": missed,
                "missed_but_shown": sorted(t for t in missed if _matches(t, shown)),
                "counted_but_not_listed_by_authors": sorted(
                    c for c in counted if not _matches(c, set(authors))
                ),
                "verdict": assessment["verdict"],
                "named_actors": sorted(
                    {lead["actor_name"] for lead in assessment.get("actor_leads", [])}
                ),
            }
        )

    run = [c for c in cases if c["investigated"]]

    def total(key: str, subset: list[dict[str, Any]] = run) -> int:
        return sum(len(c[key]) for c in subset)

    by_tactic: dict[str, dict[str, int]] = collections.defaultdict(lambda: collections.Counter())
    for c in run:
        row = by_tactic[c["tactic_folder"]]
        row["recordings"] += 1
        row["authors_techniques"] += len(c["authors_techniques"])
        row["found"] += len(c["found_exactly"]) + len(c["found_as_parent_or_sub"])
        row["missed_but_shown"] += len(c["missed_but_shown"])
    return {
        "version": "unseen-results/1",
        "selection": SELECTION.relative_to(REPO).as_posix(),
        "recordings_selected": len(cases),
        "recordings_investigated": len(run),
        "recordings_not_investigated": {
            state: sum(1 for c in cases if c.get("state") == state)
            for state in sorted({c["state"] for c in cases if not c["investigated"]})
        },
        "refusal_reasons": dict(
            collections.Counter(
                re.sub(r"'[^']*'|\d+", "…", problem)
                for c in cases
                if not c["investigated"]
                for problem in c["problems"]
            ).most_common()
        ),
        "authors_techniques_in_refused_recordings": sum(
            len(c["authors_techniques"]) for c in cases if not c["investigated"]
        ),
        "summary": {
            "authors_techniques": total("authors_techniques"),
            "found_exactly": total("found_exactly"),
            "found_as_parent_or_sub": total("found_as_parent_or_sub"),
            "missed": total("missed"),
            "missed_but_shown": total("missed_but_shown"),
            "counted_but_not_listed_by_authors": total("counted_but_not_listed_by_authors"),
            "recordings_with_an_authors_technique_counted": sum(
                1 for c in run if c["found_exactly"] or c["found_as_parent_or_sub"]
            ),
            "recordings_with_no_evidence": sum(1 for c in run if not c["evidence"]),
            "recordings_naming_an_actor": sum(1 for c in run if c["named_actors"]),
        },
        "by_tactic_folder": {k: dict(v) for k, v in sorted(by_tactic.items())},
        "cases": cases,
    }


def main(argv: list[str]) -> int:
    base = argv[0].rstrip("/") if argv else "http://127.0.0.1:8000"
    report = build(base)
    OUT.write_text(json.dumps(report, indent=1) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps(report["summary"], indent=1))
    print(json.dumps(report["by_tactic_folder"], indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
