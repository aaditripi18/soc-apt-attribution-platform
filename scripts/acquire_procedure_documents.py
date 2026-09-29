#!/usr/bin/env python3
"""Acquire the documented emulation procedures used to label corpus v2 units.

Runs only when a human invokes it. Every file is downloaded from a
commit-pinned raw URL, its size checked against the GitHub tree API size
reviewed before owner approval, SHA-256 hashed and recorded in
``data/emulation-plans/procedures/manifest.json``. The files are documents
(Markdown, YAML, a spreadsheet) read only as data — nothing is executed. They
serve one purpose: to identify which documented step an attribution unit
corresponds to, so unit labels come from the dataset's procedure, never from
the engine's own detections.

    python scripts/acquire_procedure_documents.py
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import sys
import urllib.parse
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DEST = REPO_ROOT / "data" / "emulation-plans" / "procedures"

#: (repository, commit, license, path, size reported by the tree API).
FILES: tuple[tuple[str, str, str, str, int], ...] = (
    (
        "mitre-attack/attack-arsenal",
        "201db70f403676cc8ec090035f17d98cf9995244",
        "Apache-2.0",
        "LICENSE.txt",
        11348,
    ),
    (
        "mitre-attack/attack-arsenal",
        "201db70f403676cc8ec090035f17d98cf9995244",
        "Apache-2.0",
        "adversary_emulation/APT29/Emulation_Plan/README.md",
        3909,
    ),
    (
        "mitre-attack/attack-arsenal",
        "201db70f403676cc8ec090035f17d98cf9995244",
        "Apache-2.0",
        "adversary_emulation/APT29/Emulation_Plan/Day 1/README.md",
        15456,
    ),
    (
        "mitre-attack/attack-arsenal",
        "201db70f403676cc8ec090035f17d98cf9995244",
        "Apache-2.0",
        "adversary_emulation/APT29/Emulation_Plan/Day 2/README.md",
        12204,
    ),
    (
        "OTRF/Security-Datasets",
        "d9d40ef123d2c87d5d3df28c96bcab4f0faccc87",
        "MIT",
        "datasets/compound/windows/apt3/scope/apt3_mordor_playbook.xlsx",
        82963,
    ),
    (
        "mitre-attack/evals_caldera",
        "8721102af46ad394d0bc7f2596d122c59eb065b6",
        "Apache-2.0",
        "LICENSE",
        10172,
    ),
    *(
        (
            "mitre-attack/evals_caldera",
            "8721102af46ad394d0bc7f2596d122c59eb065b6",
            "Apache-2.0",
            f"data/adversaries/{name}.yml",
            size,
        )
        for name, size in (
            ("148c819b-b022-43cb-a25c-3f6f5c71318d", 277),
            ("3af0e59b-0d2a-48cd-b934-c46d5d1621d6", 259),
            ("80e9c544-c5ea-423d-b4f3-c0de3c2947ba", 884),
            ("842d1d8e-a49d-4f11-9e97-79ce9d2f1732", 179),
            ("c9b6f5d3-ebde-4df1-9c15-ce1f339170c7", 444),
            ("e55da81a-9ce7-4da8-8313-074362fd5dee", 178),
            ("ef93dd1b-809b-4a0b-b686-fef549cabbe4", 1683),
        )
    ),
)


def _download(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "soc-apt-attribution-platform/0.0.0"})
    with urllib.request.urlopen(req, timeout=120) as resp:  # noqa: S310 - fixed https URL, GET only
        if resp.status != 200:
            raise RuntimeError(f"download failed: HTTP {resp.status} for {url}")
        return bytes(resp.read())


def main() -> int:
    entries = []
    for repo, commit, license_id, path, expected in FILES:
        url = f"https://raw.githubusercontent.com/{repo}/{commit}/{urllib.parse.quote(path)}"
        print(f"Downloading {url}")
        data = _download(url)
        if len(data) != expected:
            raise RuntimeError(f"{repo}/{path}: {len(data)} bytes, expected {expected} — refusing")
        dest = DEST / repo.replace("/", "__") / path
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
        entries.append(
            {
                "repository": repo,
                "commit": commit,
                "license": license_id,
                "source_path": path,
                "relative_path": dest.relative_to(REPO_ROOT).as_posix(),
                "size_bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
                "download_url": url,
            }
        )
    manifest = {
        "purpose": "documented emulation procedures used to label corpus v2 attribution units",
        "retrieved_at_utc": dt.datetime.now(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "method": "scripts/acquire_procedure_documents.py (commit-pinned raw URLs, size-checked)",
        "files": entries,
    }
    (DEST / "manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8", newline="\n"
    )
    print(f"{len(entries)} files, {sum(e['size_bytes'] for e in entries):,} bytes")  # type: ignore[misc]
    return 0


if __name__ == "__main__":
    sys.exit(main())
