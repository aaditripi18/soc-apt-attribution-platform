#!/usr/bin/env python3
"""Acquire the pinned SigmaHQ enrich-tier rules (ADR-0007 Amendment A).

SigmaHQ's release packages contain no ``low`` / ``informational`` generic rules;
they exist only in the repository tree. This script, run only by a human (the
owner approved the download on 2026-10-03), takes them from the tree at the
commit the pinned release tag points to:

- **selection:** every ``rules/windows/**.yml`` and ``rules/linux/**.yml`` at that
  commit that is not in the vendored Core++ archive; each must be ``low`` or
  ``informational`` level, else the script refuses (nothing is guessed);
- **verification:** each file's content must hash to the git blob id the tree
  lists for it (``sha1("blob <size>\\0" + content)``) — the commit's own
  statement of the content;
- **archive:** a reproducible zip (sorted members, fixed timestamps, fixed
  compression level) ``sigma_enrich_low.zip`` beside the Core++ archive, with
  ``manifest-sigma_enrich_low.json`` recording the commit, every file's path,
  blob id, SHA-256 and level, and the archive's SHA-256.

    python scripts/acquire_sigma_enrich_rules.py
"""

from __future__ import annotations

import datetime as dt
import hashlib
import io
import json
import sys
import urllib.request
import zipfile
from pathlib import Path

import yaml

REPO = "SigmaHQ/sigma"
TAG = "r2026-07-01"
REPO_ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = REPO_ROOT / "data" / "detection" / "sigma" / TAG
CORE = OUT_DIR / "sigma_core++.zip"
ARCHIVE = OUT_DIR / "sigma_enrich_low.zip"
MANIFEST = OUT_DIR / "manifest-sigma_enrich_low.json"
ENRICH_LEVELS = {"low", "informational"}
PRODUCT_DIRS = ("rules/windows/", "rules/linux/")
_FIXED_TIME = (1980, 1, 1, 0, 0, 0)


def _get(url: str) -> bytes:
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "soc-apt-attribution-platform/0.0.0",
            "Accept": "application/vnd.github+json",
        },
    )
    with urllib.request.urlopen(req, timeout=120) as resp:  # noqa: S310 - fixed https URL, GET only
        if resp.status != 200:
            raise RuntimeError(f"HTTP {resp.status} for {url}")
        return bytes(resp.read())


def _git_blob_id(content: bytes) -> str:
    return hashlib.sha1(b"blob %d\0" % len(content) + content).hexdigest()  # noqa: S324 - git's id


def main() -> int:
    ref = json.loads(_get(f"https://api.github.com/repos/{REPO}/git/ref/tags/{TAG}"))
    commit = ref["object"]["sha"]
    if ref["object"]["type"] == "tag":  # annotated tag -> the commit it names
        commit = json.loads(_get(ref["object"]["url"]))["object"]["sha"]
    tree = json.loads(_get(f"https://api.github.com/repos/{REPO}/git/trees/{commit}?recursive=1"))
    if tree.get("truncated"):
        raise RuntimeError("the tree listing is truncated — refusing an incomplete selection")
    with zipfile.ZipFile(CORE) as core:
        in_core = {n for n in core.namelist() if n.endswith(".yml")}
    selected = sorted(
        (entry["path"], entry["sha"])
        for entry in tree["tree"]
        if entry["type"] == "blob"
        and entry["path"].endswith(".yml")
        and entry["path"].startswith(PRODUCT_DIRS)
        and entry["path"] not in in_core
    )
    files = []
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as out:
        for path, blob_id in selected:
            content = _get(f"https://raw.githubusercontent.com/{REPO}/{commit}/{path}")
            if _git_blob_id(content) != blob_id:
                raise RuntimeError(f"{path}: content does not match git blob {blob_id} — refusing")
            level = (yaml.safe_load(content.decode("utf-8")) or {}).get("level")
            if level not in ENRICH_LEVELS:
                raise RuntimeError(f"{path}: level {level!r} is not low/informational — refusing")
            info = zipfile.ZipInfo(path, date_time=_FIXED_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            out.writestr(info, content, compresslevel=9)
            files.append(
                {
                    "path": path,
                    "git_blob_id": blob_id,
                    "sha256": hashlib.sha256(content).hexdigest(),
                    "size_bytes": len(content),
                    "level": level,
                }
            )
            print(f"verified {path}")
    data = buffer.getvalue()
    ARCHIVE.write_bytes(data)
    manifest = {
        "package": "sigma_enrich_low.zip",
        "purpose": "ADR-0007 Amendment A enrich tier (low / informational generic rules)",
        "source": {
            "repository": REPO,
            "release_tag": TAG,
            "commit": commit,
            "selection": "rules/windows and rules/linux at the commit, minus Core++ members",
        },
        "artifact": {
            "filename": ARCHIVE.name,
            "relative_path": ARCHIVE.relative_to(REPO_ROOT).as_posix(),
            "size_bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "members": len(files),
        },
        "acquisition": {
            "retrieved_at_utc": dt.datetime.now(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "method": "scripts/acquire_sigma_enrich_rules.py (each file verified against the "
            "commit's git blob id; reproducible zip)",
            "approval": "owner, 2026-10-03",
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
