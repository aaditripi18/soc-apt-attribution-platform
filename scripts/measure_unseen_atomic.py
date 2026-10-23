#!/usr/bin/env python3
"""Measure the served investigations of the unseen OTRF atomic recordings
against their authors' ATT&CK mappings (ADR-0027).

Reads a running read-model API (one investigation per recording, run with the
recordings' cache paths as sources) and the tracked selection; writes
``data/validation/unseen-otrf-atomic/results.json``. Definitions are those of
ADR-0025 Amendment E (``measure_technique_ground_truth.py``), plus *shown*: the
authors' technique is among the recording's technique detections at all
(counted, declared only, or low-level context). Read-only: GET requests.

The authors' labels predate ATT&CK v19's renumbering (e.g. Disable Windows Event
Logging, T1562.002, is T1685.001 in the pinned v19.2): each label is resolved
through the pinned knowledge base's ``revoked-by`` relationships
(``ExternalIdResolver``, as the Linux report does) and compared as resolved; the
label as written is kept beside it. ``--rescore-first-run`` recomputes the
first run's figures from its stored per-recording sets the same way.

    python scripts/measure_unseen_atomic.py http://127.0.0.1:8004

The second unseen set (ADR-0029) is measured the same way; ``--run`` and ``--out`` name the
run record and the results file in the set's directory:

    python scripts/measure_unseen_atomic.py http://127.0.0.1:8005 --set splunk-windows \\
        --run run-baseline.json --out results-baseline.json
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

from attribution_platform.attack_knowledge.external_ids import ExternalIdResolver
from attribution_platform.attack_knowledge.loader import load_attack_knowledge

REPO = Path(__file__).resolve().parents[1]


def file_name(path: str) -> str:
    return PurePath(path).name


def technique_path(path: str) -> str:
    """Every Splunk file is called windows-sysmon.log: keep the technique and run directory."""
    return path.removeprefix("datasets/attack_techniques/")


#: --set NAME -> (results directory, recording name from its path, the name results are grouped
#: by and its segment of the path). The OTRF paths carry a tactic folder
#: (datasets/atomic/windows/<tactic>/…); the Splunk paths a technique directory
#: (datasets/attack_techniques/<technique>/…).
SETS = {
    "otrf-atomic": (
        REPO / "data" / "validation" / "unseen-otrf-atomic",
        file_name,
        "tactic_folder",
        3,
    ),
    "splunk-windows": (
        REPO / "data" / "validation" / "unseen-splunk-windows",
        technique_path,
        "technique_directory",
        2,
    ),
}
SELECTION = REPO / "data" / "validation" / "unseen-otrf-atomic" / "selection.json"
OUT = REPO / "data" / "validation" / "unseen-otrf-atomic" / "results.json"
RUN = REPO / "data" / "validation" / "unseen-otrf-atomic" / "run.json"


def resolver() -> Any:
    """Authors' label -> current ATT&CK id in the pinned knowledge base."""
    resolve = ExternalIdResolver(load_attack_knowledge(), ("attack-pattern",))

    def current(label: str) -> str:
        found = resolve.resolve(label)
        if found is None:
            return label
        for ref in found[0].get("external_references", ()):
            if ref.get("source_name") == "mitre-attack":
                return str(ref["external_id"])
        return label

    return current


def related(a: str, b: str) -> bool:
    """Parent and sub-technique of one another (not equal)."""
    return a != b and a.split(".")[0] == b.split(".")[0] and ("." in a) != ("." in b)


def _get(base: str, path: str) -> Any:
    with urllib.request.urlopen(base + "/api" + path, timeout=600) as response:  # noqa: S310
        return json.loads(response.read())


def _matches(technique: str, found: set[str]) -> bool:
    return technique in found or any(related(technique, other) for other in found)


def build(base: str, set_name: str = "otrf-atomic", run_file: str = "run.json") -> dict[str, Any]:
    current = resolver()
    directory, recording_name, group_key, group_segment = SETS[set_name]
    selection_path = directory / "selection.json"
    selection = json.loads(selection_path.read_text(encoding="utf-8"))["selected"]
    # run.json lists the recordings in manifest order, which is selection order;
    # joined by position (two selected files share a name), checked by name.
    outcomes = json.loads((directory / run_file).read_text(encoding="utf-8"))["recordings"]
    if len(outcomes) != len(selection):
        raise SystemExit(f"{run_file} does not cover the selection")
    cases = []
    for entry, outcome in zip(selection, outcomes, strict=True):
        name = recording_name(entry["path"])
        if outcome["recording"] != name:
            raise SystemExit(f"run.json order differs at {name}")
        labelled = entry["authors_techniques"]
        authors = sorted({current(t) for t in labelled})
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
                **({"metadata_id": entry["metadata_id"]} if "metadata_id" in entry else {}),
                group_key: entry["path"].split("/")[group_segment],
                "investigated": True,
                "evidence": inv.get("evidence"),
                "authors_techniques_as_labelled": labelled,
                "authors_techniques": authors,
                "counted": sorted(counted),
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
        row = by_tactic[c[group_key]]
        row["recordings"] += 1
        row["authors_techniques"] += len(c["authors_techniques"])
        row["found"] += len(c["found_exactly"]) + len(c["found_as_parent_or_sub"])
        row["missed_but_shown"] += len(c["missed_but_shown"])
    return {
        "version": "unseen-results/2",
        "selection": selection_path.relative_to(REPO).as_posix(),
        "run": (directory / run_file).relative_to(REPO).as_posix(),
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
        f"by_{group_key}": {k: dict(v) for k, v in sorted(by_tactic.items())},
        "cases": cases,
    }


def rescore_first_run() -> dict[str, int]:
    """The first run's figures with the authors' labels resolved. Its stored
    cases predate ``counted``; the counted ids recoverable from them (found
    exactly, and counted but not listed) are the ones a renamed label can match,
    because a renamed technique's id differs from its old one in its parent."""
    current = resolver()
    first = json.loads((OUT.parent / "first-run" / "results.json").read_text(encoding="utf-8"))
    found = missed = total = 0
    for case in first["cases"]:
        if not case["investigated"]:
            continue
        counted = set(case["found_exactly"]) | set(case["counted_but_not_listed_by_authors"])
        for label in case["authors_techniques"]:
            total += 1
            hit = label in case["found_exactly"] or label in case["found_as_parent_or_sub"]
            if hit or _matches(current(label), counted):
                found += 1
            else:
                missed += 1
    return {"authors_techniques": total, "found": found, "missed": missed}


def main(argv: list[str]) -> int:
    if argv and argv[0] == "--rescore-first-run":
        print(json.dumps(rescore_first_run(), indent=1))
        return 0
    base = argv[0].rstrip("/") if argv and not argv[0].startswith("--") else "http://127.0.0.1:8000"
    set_name = argv[argv.index("--set") + 1] if "--set" in argv else "otrf-atomic"
    run_file = argv[argv.index("--run") + 1] if "--run" in argv else "run.json"
    out = SETS[set_name][0] / (argv[argv.index("--out") + 1] if "--out" in argv else "results.json")
    report = build(base, set_name, run_file)
    out.write_text(json.dumps(report, indent=1) + "\n", encoding="utf-8", newline="\n")
    if "--quiet" in argv:  # ADR-0029: the baseline is stored, not read, until the build is frozen
        print(f"wrote {out.relative_to(REPO).as_posix()}")
        return 0
    print(json.dumps(report["summary"], indent=1))
    print(json.dumps(report[f"by_{SETS[set_name][2]}"], indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
