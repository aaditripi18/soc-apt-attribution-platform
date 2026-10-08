#!/usr/bin/env python3
"""Generate the Sigma-derived rule pack + import report (ADR-0007 D6/D7/D9).

Reads the vendored, SHA-256-pinned archive recorded in
``data/detection/sigma/<tag>/manifest.json`` and writes:

  data/detection/sigma/<tag>/generated/<pack_id>.rules.json    loadable rule pack
  data/detection/sigma/<tag>/generated/<pack_id>.import-report.json

Offline and deterministic: the same archive, importer, field map, pySigma and
ATT&CK versions produce byte-identical output. Usage:

    python scripts/import_sigma_rules.py [--tag r2026-07-01]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from attribution_platform.attack_knowledge.loader import load_attack_knowledge
from attribution_platform.detection_content.sigma_import import import_sigma_archive

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_TAG = "r2026-07-01"


def _write_json(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(data, indent=1, sort_keys=False, ensure_ascii=False) + "\n"
    path.write_text(text, encoding="utf-8", newline="\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", default=DEFAULT_TAG)
    parser.add_argument(
        "--out-dir", type=Path, default=None, help="write elsewhere (e.g. to measure a change)"
    )
    args = parser.parse_args()

    release_dir = REPO_ROOT / "data" / "detection" / "sigma" / args.tag
    manifest = json.loads((release_dir / "manifest.json").read_text(encoding="utf-8"))
    archive = release_dir / manifest["artifact"]["filename"]

    # ADR-0007 Amendment A: the enrich tier, when its pinned archive is vendored.
    enrich_manifest_path = release_dir / "manifest-sigma_enrich_low.json"
    enrich_manifest = (
        json.loads(enrich_manifest_path.read_text(encoding="utf-8"))
        if enrich_manifest_path.is_file()
        else None
    )
    result = import_sigma_archive(
        archive,
        knowledge=load_attack_knowledge(),
        release_tag=args.tag,
        archive_sha256=manifest["artifact"]["sha256"],
        software_tag_review=release_dir / "software-tag-review.json",
        enrich_archive=(
            release_dir / enrich_manifest["artifact"]["filename"] if enrich_manifest else None
        ),
        enrich_archive_sha256=enrich_manifest["artifact"]["sha256"] if enrich_manifest else None,
    )
    pack_id = result.pack["pack_id"]
    out_dir = args.out_dir or release_dir / "generated"
    _write_json(out_dir / f"{pack_id}.rules.json", result.pack)
    _write_json(out_dir / f"{pack_id}.import-report.json", result.report)
    print(json.dumps(result.report["summary"], indent=1))
    print(f"Wrote {out_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
