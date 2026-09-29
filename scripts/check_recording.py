#!/usr/bin/env python3
"""Intake check for a recording archive before it enters the corpus.

    python scripts/check_recording.py path/to/recording.zip [--json out.json]

Prints the checked shape, per-host channel coverage, conversion and refusals,
Sysmon clock consistency, blocking problems and warnings, and a draft
``recordings.json`` ``declared_sources`` entry. Exit code 1 when a problem
blocks corpus use. The archive is only read — never extracted or executed.
See docs/operations/lab-recording-guide.md.
"""

from __future__ import annotations

import dataclasses
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from attribution_platform.replay.recording_check import check_recording  # noqa: E402


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__)
        return 2
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    report = check_recording(Path(argv[0]))
    document = dataclasses.asdict(report)
    document["accepted"] = report.accepted
    if "--json" in argv:
        out = Path(argv[argv.index("--json") + 1])
        out.write_text(json.dumps(document, indent=1) + "\n", encoding="utf-8", newline="\n")
    print(f"recording: {report.path}")
    print(f"sha256:    {report.sha256}  ({report.size_bytes:,} bytes)")
    print(f"records:   {report.records:,}  shapes {dict(report.shapes)}")
    print(f"span:      {report.first_event} .. {report.last_event}")
    for host, channels in report.channels_by_host.items():
        print(f"host {host}: {dict(channels)}")
    print(f"converted: {dict(report.converted_by_source)}")
    print(f"sysmon clock vs collector: {dict(report.sysmon_clock_gaps)}")
    for reason, count in report.refused_by_reason.items():
        print(f"refused {count:>7,}  {reason}")
    for warning in report.warnings:
        print(f"WARNING  {warning}")
    for problem in report.problems:
        print(f"PROBLEM  {problem}")
    print("declared_sources draft:")
    print(json.dumps({h: list(s) for h, s in report.declared_sources.items()}, indent=1))
    print("ACCEPTED" if report.accepted else "NOT ACCEPTED — fix the problems above")
    return 0 if report.accepted else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
