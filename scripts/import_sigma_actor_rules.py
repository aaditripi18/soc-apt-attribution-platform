#!/usr/bin/env python3
"""Generate the actor-specific rule pack + import report (ADR-0018).

Reads the pinned ``sigma_actor_specific.zip`` (``manifest-sigma_actor_specific.json``)
and the reviewed ``actor-tag-review.json`` and writes:

  data/detection/sigma/<tag>/generated/sigma-<tag>-actor-specific.rules.json
  data/detection/sigma/<tag>/generated/sigma-<tag>-actor-specific.import-report.json

Offline and deterministic. Usage:

    python scripts/import_sigma_actor_rules.py [--out-dir DIR]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from attribution_platform.attack_knowledge.loader import load_attack_knowledge
from attribution_platform.detection_content.sigma_actor_import import import_sigma_actor_archive

REPO_ROOT = Path(__file__).resolve().parents[1]
TAG = "r2026-07-01"


def _write_json(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(data, indent=1, sort_keys=False, ensure_ascii=False) + "\n"
    path.write_text(text, encoding="utf-8", newline="\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", type=Path, default=None)
    args = parser.parse_args()
    release_dir = REPO_ROOT / "data" / "detection" / "sigma" / TAG
    manifest = json.loads(
        (release_dir / "manifest-sigma_actor_specific.json").read_text(encoding="utf-8")
    )
    result = import_sigma_actor_archive(
        release_dir / manifest["artifact"]["filename"],
        knowledge=load_attack_knowledge(),
        release_tag=TAG,
        archive_sha256=manifest["artifact"]["sha256"],
        actor_tag_review=release_dir / "actor-tag-review.json",
    )
    pack_id = result.pack["pack_id"]
    out_dir = args.out_dir or release_dir / "generated"
    _write_json(out_dir / f"{pack_id}.rules.json", result.pack)
    _write_json(out_dir / f"{pack_id}.import-report.json", result.report)
    print(json.dumps(result.report["summary"], indent=1))
    for row in result.report["rules"]:
        accepted = [t for t in row["actor_tags"] if t["decision"] == "accept"]
        if accepted:
            names = ", ".join(f"{t['group_id']} {t['group_name']}" for t in accepted)
            why = row["rejection"] or ""
            print(f"  {row['status']:<9} {row['logsource']:<28} {names:<28} {row['title']}  {why}")
    print(f"Wrote {out_dir}")
    return 0


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[union-attr]
    sys.exit(main())
