"""Counted techniques against the dataset authors' own ATT&CK mappings.

For the seven single-tool recordings of the OTRF LSASS campaigns, the dataset's
metadata (``data/cache/otrf-compound/_metadata/LSASS_campaign_0N.yaml``, written
by its authors, not by this project) lists the techniques the simulation
performed. This compares them with the techniques the platform *counted* in
each recording, taken from stored result snapshots — no investigation is run
and nothing is tuned here.

Reading the result:

- *found*: an authors' technique the platform counted (exactly, or as its parent
  or one of its sub-techniques — reported separately);
- *missed*: an authors' technique not counted. The authors state that the
  recordings do not include the preparation of the malicious files, so the
  Resource Development tactic is reported apart and not counted as a miss;
- *additional*: a counted technique the authors do not list. That is **not** a
  false positive by itself: the authors list the steps of the simulation, not
  everything on the host. It is a list to examine.

Writes ``data/validation/technique-ground-truth.json``. The metadata is
third-party data and is only read (never executed); run with ``python -I``.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any, cast

REPO = Path(__file__).resolve().parents[1]
METADATA = REPO / "data" / "cache" / "otrf-compound" / "_metadata"
HISTORY = REPO / "data" / "validation" / "history"
OUT = REPO / "data" / "validation" / "technique-ground-truth.json"
RESOURCE_DEVELOPMENT = "TA0042"
#: campaign number -> (snapshot file, key in it, whether its results informed development)
RECORDINGS = {
    1: ("investigations.after-review-batch-2.json", "otrf-lsass-01-logonpasswords", True),
    2: ("investigations.after-review-batch-2.json", "sample-windows-credential-dumping.zip", True),
    3: ("investigations.after-review-batch-2.json", "otrf-lsass-03-comsvcs", True),
    4: ("investigations.held-out-from-adr-0025.json", "otrf-lsass-04-out-minidump", False),
    5: ("investigations.held-out-from-adr-0025.json", "otrf-lsass-05-sharpdump", False),
    6: ("investigations.held-out-from-adr-0025.json", "otrf-lsass-06-outflank-dumpert", False),
    7: ("investigations.held-out-from-adr-0025.json", "otrf-lsass-07-nanodump", False),
}
_ENTRY = re.compile(
    r"-\s+technique:\s*(T\d{4})\s*\n\s+sub-technique:\s*\"?(\d{3})?\"?\s*\n\s+tactics:\s*\n((?:\s+-\s+TA\d{4}\s*\n)+)"
)


def authors_mappings(path: Path) -> list[tuple[str, tuple[str, ...]]]:
    """``(technique id, tactics)`` from the ``attack_mappings`` block."""
    text = path.read_text(encoding="utf-8")
    block = text[text.index("attack_mappings:") :]
    block = block[: block.index("\nnotebooks:")] if "\nnotebooks:" in block else block
    found = []
    for technique, sub, tactics in _ENTRY.findall(block + "\n"):
        found.append(
            (f"{technique}.{sub}" if sub else technique, tuple(re.findall(r"TA\d{4}", tactics)))
        )
    if not found or block.count("technique: T") != len(found):
        raise ValueError(f"{path}: could not read every attack mapping")
    return found


def related(a: str, b: str) -> bool:
    """Parent and sub-technique of one another (not equal)."""
    return a != b and a.split(".")[0] == b.split(".")[0] and ("." in a) != ("." in b)


def build() -> dict[str, object]:
    cases = []
    for number, (snapshot, key, used) in RECORDINGS.items():
        mappings = authors_mappings(METADATA / f"LSASS_campaign_{number:02d}.yaml")
        counted = set(
            json.loads((HISTORY / snapshot).read_text(encoding="utf-8"))[key]["counted_techniques"]
        )
        observable = [t for t, tactics in mappings if RESOURCE_DEVELOPMENT not in tactics]
        exact = sorted(t for t in observable if t in counted)
        by_relation = sorted(
            t for t in observable if t not in counted and any(related(t, c) for c in counted)
        )
        missed = sorted(t for t in observable if t not in exact and t not in by_relation)
        additional = sorted(
            c for c in counted if c not in observable and not any(related(c, t) for t in observable)
        )
        cases.append(
            {
                "campaign": f"LSASS_campaign_{number:02d}",
                "recording": key,
                "results_informed_development": used,
                "authors_techniques": sorted(t for t, _ in mappings),
                "not_in_the_recording_per_authors": sorted(
                    t for t, tactics in mappings if RESOURCE_DEVELOPMENT in tactics
                ),
                "found_exactly": exact,
                "found_as_parent_or_sub": by_relation,
                "missed": missed,
                "counted_but_not_listed_by_authors": additional,
            }
        )

    def total(key: str, used: bool | None = None) -> int:
        found = 0
        for c in cases:
            if used is None or c["results_informed_development"] is used:
                found += len(cast(list[str], c[key]))
        return found

    def summary(used: bool | None) -> dict[str, int]:
        return {
            "authors_techniques_in_recordings": total("found_exactly", used)
            + total("found_as_parent_or_sub", used)
            + total("missed", used),
            "found_exactly": total("found_exactly", used),
            "found_as_parent_or_sub": total("found_as_parent_or_sub", used),
            "missed": total("missed", used),
            "counted_but_not_listed_by_authors": total("counted_but_not_listed_by_authors", used),
        }

    return {
        "version": "technique-ground-truth/1",
        "ground_truth": "OTRF Security-Datasets metadata, attack_mappings "
        "(the dataset authors' own)",
        "all": summary(None),
        "used_in_development": summary(True),
        "held_out_from_adr_0025": summary(False),
        "cases": cases,
    }


#: ``--snapshot FILE``: the seven tool runs as investigated together on one build.
CURRENT_KEYS = {
    1: "otrf-lsass-01-logonpasswords",
    2: "otrf-lsass-02-procdump",
    3: "otrf-lsass-03-comsvcs",
    4: "otrf-lsass-04-out-minidump",
    5: "otrf-lsass-05-sharpdump",
    6: "otrf-lsass-06-outflank-dumpert",
    7: "otrf-lsass-07-nanodump",
}


def main() -> int:
    if "--snapshot" in sys.argv:
        # One snapshot of all seven on the current build; "used in development"
        # keeps its Amendment E meaning (whose results informed development).
        snapshot = sys.argv[sys.argv.index("--snapshot") + 1]
        for number, key in CURRENT_KEYS.items():
            RECORDINGS[number] = (snapshot, key, RECORDINGS[number][2])
    report = build()
    if "--snapshot" in sys.argv:
        report["snapshot"] = sys.argv[sys.argv.index("--snapshot") + 1]
    OUT.write_text(json.dumps(report, indent=1) + "\n", encoding="utf-8", newline="\n")
    for name in ("all", "used_in_development", "held_out_from_adr_0025"):
        print(name, report[name])
    for case in cast(list[dict[str, Any]], report["cases"]):
        print(
            case["campaign"][-2:],
            "| found",
            case["found_exactly"],
            "| related",
            case["found_as_parent_or_sub"],
            "| missed",
            case["missed"],
            "| additional",
            case["counted_but_not_listed_by_authors"],
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
