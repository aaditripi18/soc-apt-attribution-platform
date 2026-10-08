#!/usr/bin/env python3
"""Copy every real macOS record of the verified cache into a tracked golden file
(ADR-0014 D5).

The macOS set is small (osquery ``es_process_events`` rows: 25 records), so the
golden file holds **all** of it, verbatim, each with its source path and the
dataset's documented ATT&CK label (from its YAML descriptor) — the tests run the
whole real dataset without the git-ignored cache. Re-running on the verified
cache reproduces the file byte-for-byte. Apache-2.0 data (see the NOTICE).

    python scripts/extract_macos_golden_records.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
CACHE = REPO_ROOT / "data" / "cache" / "splunk-attack-data"
SAMPLES = REPO_ROOT / "data" / "telemetry-samples" / "splunk-attack-data-macos"
OUT = SAMPLES / "golden-records.jsonl"


def main() -> int:
    manifest = json.loads((SAMPLES / "manifest.json").read_text(encoding="utf-8"))
    paths = sorted(REPO_ROOT / e["cache_path"] for e in manifest["files"])
    labels: dict[Path, list[str]] = {}
    for path in paths:
        if path.suffix == ".yml":
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            labels.setdefault(path.parent, []).extend(data.get("mitre_technique") or [])
    rows = []
    for path in paths:
        if path.suffix != ".log":
            continue
        source = path.relative_to(CACHE).as_posix()
        for index, line in enumerate(path.read_text(encoding="utf-8").splitlines()):
            if line.strip():
                rows.append(
                    {
                        "golden_id": f"macos-{path.stem}-{index:02d}",
                        "source": source,
                        "documented_techniques": sorted(set(labels.get(path.parent, []))),
                        "record": line,
                    }
                )
    with OUT.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n")
    print(f"wrote {len(rows)} records to {OUT.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
