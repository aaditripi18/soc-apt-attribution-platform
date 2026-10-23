#!/usr/bin/env python3
"""Select the second unseen test set (ADR-0029): every Windows Sysmon recording in
``splunk/attack_data`` at the pinned commit, by a rule fixed before any content is read.

Selected: each ``datasets/attack_techniques/<technique>/[<dir>/]windows-sysmon.log`` at
the commit ``acquire_linux_telemetry.py`` pins, whose Git LFS pointer states a size of at
most 50 MB (a runtime bound, stated in ADR-0029 before any content was fetched). The
authors' techniques are the union of ``mitre_technique`` in the YAML descriptors in the
recording's own directory; with no descriptor there, the technique directory it sits in.
Only pointers and descriptors are read here — no log content.

Writes ``data/validation/unseen-splunk-windows/selection.json`` and the downloader's
``data/telemetry-samples/splunk-attack-data-windows-unseen/selection.txt``.

    python scripts/select_unseen_splunk_windows.py
"""

from __future__ import annotations

import json
import re
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path, PurePosixPath
from typing import Any

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from acquire_linux_telemetry import COMMIT, REPO, _get, _tree_blob_ids  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[1]
OUT = REPO_ROOT / "data" / "validation" / "unseen-splunk-windows" / "selection.json"
SAMPLES = REPO_ROOT / "data" / "telemetry-samples" / "splunk-attack-data-windows-unseen"
MAX_BYTES = 50_000_000
_LOG = re.compile(
    r"\Adatasets/attack_techniques/(T\d{4}(?:\.\d{3})?)/(?:[^/]+/)?windows-sysmon\.log\Z"
)
_POINTER = re.compile(r"oid sha256:([0-9a-f]{64})\nsize (\d+)\n")
_TECHNIQUE = re.compile(r"\AT\d{4}(?:\.\d{3})?\Z")


def _labels(descriptor_paths: list[str], raw: str) -> list[str]:
    found: set[str] = set()
    for path in descriptor_paths:
        doc = yaml.safe_load(_get(raw + path).decode("utf-8"))
        for label in (doc or {}).get("mitre_technique") or []:
            if _TECHNIQUE.match(str(label)):
                found.add(str(label))
    return sorted(found)


def main() -> int:
    blob_ids = _tree_blob_ids()
    raw = f"https://raw.githubusercontent.com/{REPO}/{COMMIT}/"
    used = {
        line.strip()
        for samples in REPO_ROOT.glob("data/telemetry-samples/splunk-attack-data*/selection.txt")
        if samples.parent != SAMPLES
        for line in samples.read_text(encoding="utf-8").splitlines()
        if line.strip()
    }

    def examine(path: str) -> tuple[str, dict[str, Any]]:
        """``("selected", entry)`` or ``("excluded", reason)`` for one recording."""
        if path in used:
            return "excluded", {"path": path, "reason": "already used by the project"}
        match = _POINTER.search(_get(raw + path).decode("utf-8", errors="replace"))
        if match is None:
            return "excluded", {"path": path, "reason": "not a Git LFS pointer"}
        size = int(match[2])
        if size > MAX_BYTES:
            return "excluded", {"path": path, "reason": f"larger than 50 MB ({size:,} bytes)"}
        directory = PurePosixPath(path).parent.as_posix()
        descriptors = sorted(
            p
            for p in blob_ids
            if PurePosixPath(p).parent.as_posix() == directory and p.endswith((".yml", ".yaml"))
        )
        labels = _labels(descriptors, raw) or [_LOG.match(path)[1]]  # type: ignore[index]
        print(f"examined {path}", flush=True)
        return "selected", {
            "path": path,
            "git_blob_id": blob_ids[path],
            "lfs_sha256": match[1],
            "size_bytes": size,
            "descriptors": descriptors,
            "authors_techniques": labels,
            "label_source": "descriptor" if descriptors else "technique directory",
        }

    with ThreadPoolExecutor(max_workers=8) as pool:  # in path order, whatever finishes first
        outcomes = list(pool.map(examine, sorted(p for p in blob_ids if _LOG.match(p))))
    selected = [entry for kind, entry in outcomes if kind == "selected"]
    excluded = [entry for kind, entry in outcomes if kind == "excluded"]
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(
        json.dumps(
            {
                "version": "unseen-selection/1",
                "source_repository": REPO,
                "source_commit": COMMIT,
                "rule": "every datasets/attack_techniques/<technique>/[<dir>/]windows-sysmon.log "
                "at the commit, Git LFS pointer size <= 50,000,000 bytes, not already used by "
                "the project (ADR-0029)",
                "selected": selected,
                "excluded": excluded,
            },
            indent=1,
        )
        + "\n",
        encoding="utf-8",
        newline="\n",
    )
    SAMPLES.mkdir(parents=True, exist_ok=True)
    (SAMPLES / "selection.txt").write_text(
        "".join(entry["path"] + "\n" for entry in selected), encoding="utf-8", newline="\n"
    )
    total = sum(int(e["size_bytes"]) for e in selected)
    print(f"{len(selected)} selected ({total:,} bytes), {len(excluded)} excluded")
    return 0


if __name__ == "__main__":
    sys.exit(main())
