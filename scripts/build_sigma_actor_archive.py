#!/usr/bin/env python3
"""Build the pinned archive of Sigma rules that name an ATT&CK Group (ADR-0018).

SigmaHQ's Core++ package leaves out ``rules-emerging-threats`` — the rules
written from published reporting on one actor's tooling. They are in the
release's own ``sigma_all_rules.zip`` (acquired 2026-10-01 by
``scripts/acquire_sigma_release.py``; kept in the git-ignored cache). This
script, offline, takes from that archive every rule carrying an ``attack.gNNNN``
tag and writes:

- ``sigma_actor_specific.zip`` beside the Core++ archive — a reproducible zip
  (sorted members, fixed timestamps, fixed compression level);
- ``manifest-sigma_actor_specific.json`` — the source archive's pinned SHA-256,
  every member's path and SHA-256, and the archive's own SHA-256.

The source archive must hash to the value its manifest pins, or the script
refuses. Which of these rules become evidence is decided by
``actor-tag-review.json``, not here.

    python scripts/build_sigma_actor_archive.py
"""

from __future__ import annotations

import hashlib
import io
import json
import re
import sys
import zipfile
from pathlib import Path

import yaml

TAG = "r2026-07-01"
REPO_ROOT = Path(__file__).resolve().parents[1]
CACHE = REPO_ROOT / "data" / "cache" / "sigma" / TAG
SOURCE = CACHE / "sigma_all_rules.zip"
SOURCE_MANIFEST = CACHE / "manifest-sigma_all_rules.json"
OUT_DIR = REPO_ROOT / "data" / "detection" / "sigma" / TAG
ARCHIVE = OUT_DIR / "sigma_actor_specific.zip"
MANIFEST = OUT_DIR / "manifest-sigma_actor_specific.json"
_GROUP_TAG = re.compile(r"attack\.g\d{4}")
_FIXED_TIME = (1980, 1, 1, 0, 0, 0)


def main() -> int:
    source_manifest = json.loads(SOURCE_MANIFEST.read_text(encoding="utf-8"))
    pinned = source_manifest["artifact"]["sha256"]
    raw = SOURCE.read_bytes()
    if hashlib.sha256(raw).hexdigest() != pinned:
        print(f"{SOURCE}: does not match its pinned SHA-256 {pinned} — refusing")
        return 1
    files = []
    buffer = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(raw)) as source, zipfile.ZipFile(buffer, "w") as out:
        for member in sorted(n for n in source.namelist() if n.endswith(".yml")):
            content = source.read(member)
            document = yaml.safe_load(content.decode("utf-8"))
            if not isinstance(document, dict):
                continue
            tags = sorted(
                str(t).lower()
                for t in document.get("tags") or ()
                if _GROUP_TAG.fullmatch(str(t).lower())
            )
            if not tags:
                continue
            info = zipfile.ZipInfo(member, date_time=_FIXED_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            out.writestr(info, content, compresslevel=9)
            files.append(
                {
                    "path": member,
                    "sigma_id": str(document.get("id")),
                    "sha256": hashlib.sha256(content).hexdigest(),
                    "size_bytes": len(content),
                    "group_tags": tags,
                }
            )
    data = buffer.getvalue()
    ARCHIVE.write_bytes(data)
    manifest = {
        "package": ARCHIVE.name,
        "purpose": "ADR-0018 actor-specific evidence: Sigma rules that name an ATT&CK Group",
        "source": {
            "repository": source_manifest["source"]["repository"],
            "release_tag": TAG,
            "archive": source_manifest["artifact"]["filename"],
            "archive_sha256": pinned,
            "download_url": source_manifest["source"]["download_url"],
            "retrieved_at_utc": source_manifest["acquisition"]["retrieved_at_utc"],
            "selection": "every rule in the release archive with an attack.gNNNN tag",
        },
        "artifact": {
            "filename": ARCHIVE.name,
            "relative_path": ARCHIVE.relative_to(REPO_ROOT).as_posix(),
            "size_bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "members": len(files),
        },
        "acquisition": {
            "method": "scripts/build_sigma_actor_archive.py (offline, from the pinned release "
            "archive; reproducible zip)",
            "approval": "owner instruction 2026-10-11 (group-specific evidence)",
        },
        "license": {
            "rules": "Detection Rule License (DRL) 1.1",
            "notice_file": "data/detection/sigma/r2026-07-01/NOTICE.md",
        },
        "files": files,
    }
    MANIFEST.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(f"{len(files)} rules, {len(data):,} bytes -> {ARCHIVE.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
