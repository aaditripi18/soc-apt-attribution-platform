#!/usr/bin/env python3
"""Generate the Elastic-derived rule pack + import report (ADR-0015 D4).

Reads the rule files listed in ``data/detection/elastic/manifest.json`` from the
git-ignored cache (``scripts/acquire_elastic_rules.py`` fills and verifies it)
and writes:

  data/detection/elastic/<commit12>/generated/<pack_id>.rules.json
  data/detection/elastic/<commit12>/generated/<pack_id>.import-report.json

Offline and deterministic: the same rule files, importer, field map, lark and
ATT&CK versions produce byte-identical output. Usage:

    python scripts/import_elastic_rules.py [--out-dir DIR]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from attribution_platform.attack_knowledge.loader import load_attack_knowledge
from attribution_platform.detection_content.elastic_import import import_elastic_rules

REPO_ROOT = Path(__file__).resolve().parents[1]
MANIFEST = REPO_ROOT / "data" / "detection" / "elastic" / "manifest.json"


def _write_json(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(data, indent=1, sort_keys=False, ensure_ascii=False) + "\n"
    path.write_text(text, encoding="utf-8", newline="\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out-dir", type=Path, default=None, help="write elsewhere (e.g. to measure a change)"
    )
    args = parser.parse_args()
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    commit = str(manifest["source_commit"])
    cache = REPO_ROOT / "data" / "cache" / "elastic-detection-rules" / commit[:12]
    result = import_elastic_rules(cache, MANIFEST, knowledge=load_attack_knowledge())
    pack_id = result.pack["pack_id"]
    out_dir = args.out_dir or MANIFEST.parent / commit[:12] / "generated"
    _write_json(out_dir / f"{pack_id}.rules.json", result.pack)
    _write_json(out_dir / f"{pack_id}.import-report.json", result.report)
    print(json.dumps(result.report["summary"], indent=1))
    print(f"Wrote {out_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
