#!/usr/bin/env python3
"""Acquire the pre-registered unseen OTRF atomic recordings (ADR-0027).

Runs only when a human invokes it. Reads the tracked selection
(``data/validation/unseen-otrf-atomic/selection.json``), downloads each host
recording and its metadata from the commit-pinned raw URL into the git-ignored
cache ``data/cache/otrf-atomic-unseen/``, verifies every file against its size
and git blob id at the pinned commit, and lists archive members as data only
(nothing is extracted or executed). Writes the tracked manifest
``data/telemetry-samples/otrf-atomic-unseen/manifest.json``.

    python -I scripts/acquire_unseen_atomic.py            # download + verify
    python -I scripts/acquire_unseen_atomic.py --verify   # verify the cache only
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import sys
import tarfile
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath

REPO_ROOT = Path(__file__).resolve().parents[1]
SELECTION = REPO_ROOT / "data" / "validation" / "unseen-otrf-atomic" / "selection.json"
CACHE = REPO_ROOT / "data" / "cache" / "otrf-atomic-unseen"
MANIFEST = REPO_ROOT / "data" / "telemetry-samples" / "otrf-atomic-unseen" / "manifest.json"
RAW = "https://raw.githubusercontent.com/OTRF/Security-Datasets/{commit}/{path}"


def _git_blob_id(content: bytes) -> str:
    return hashlib.sha1(b"blob %d\0" % len(content) + content).hexdigest()  # noqa: S324 - git id


def _safe(name: str) -> bool:
    path = PurePosixPath(name.replace("\\", "/"))
    return not path.is_absolute() and ".." not in path.parts


def _members(path: Path) -> list[dict[str, object]]:
    """Archive members, read as data only. One published ``.zip`` is in fact a
    gzipped tar archive; the format is read from the content, not the name."""
    members: list[dict[str, object]] = []
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as archive:
            bad = archive.testzip()
            if bad is not None:
                raise ValueError(f"{path.name}: corrupt member {bad!r}")
            for info in archive.infolist():
                if not _safe(info.filename):
                    raise ValueError(f"{path.name}: unsafe member path {info.filename!r}")
                members.append({"name": info.filename, "size_bytes": info.file_size})
        return members
    with tarfile.open(path, "r:gz") as tar:
        for member in tar.getmembers():
            if not _safe(member.name) or member.issym() or member.islnk():
                raise ValueError(f"{path.name}: unsafe member {member.name!r}")
            if member.isfile():
                members.append({"name": member.name, "size_bytes": member.size, "format": "tar.gz"})
    return members


def _fetch(commit: str, repo_path: str, size: int | None, blob: str, verify_only: bool) -> Path:
    target = CACHE / PurePosixPath(repo_path).relative_to("datasets/atomic")
    if not verify_only and not target.exists():
        url = RAW.format(commit=commit, path=repo_path)
        with urllib.request.urlopen(url, timeout=120) as response:  # noqa: S310 - pinned https URL
            content = response.read()
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
    content = target.read_bytes()
    if size is not None and len(content) != size:
        raise ValueError(f"{repo_path}: {len(content)} bytes, expected {size}")
    if _git_blob_id(content) != blob:
        raise ValueError(f"{repo_path}: git blob id does not match the pinned commit")
    return target


def main(argv: list[str]) -> int:
    verify_only = "--verify" in argv
    selection = json.loads(SELECTION.read_text(encoding="utf-8"))
    commit = selection["source_commit"]
    files = []
    for entry in selection["selected"]:
        recording = _fetch(
            commit, entry["path"], entry["size_bytes"], entry["git_blob"], verify_only
        )
        metadata = _fetch(
            commit, entry["metadata_path"], None, entry["metadata_git_blob"], verify_only
        )
        files.append(
            {
                "metadata_id": entry["metadata_id"],
                "source_path": entry["path"],
                "cache_path": recording.relative_to(REPO_ROOT).as_posix(),
                "size_bytes": recording.stat().st_size,
                "sha256": hashlib.sha256(recording.read_bytes()).hexdigest(),
                "git_blob": entry["git_blob"],
                "members": _members(recording),
                "metadata_cache_path": metadata.relative_to(REPO_ROOT).as_posix(),
            }
        )
    if not verify_only:
        MANIFEST.parent.mkdir(parents=True, exist_ok=True)
        manifest = {
            "source": selection["source"],
            "source_commit": commit,
            "selection": SELECTION.relative_to(REPO_ROOT).as_posix(),
            "retrieved_at_utc": dt.datetime.now(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "files": files,
            "total_bytes": sum(int(f["size_bytes"]) for f in files),
        }
        MANIFEST.write_text(json.dumps(manifest, indent=1) + "\n", encoding="utf-8", newline="\n")
    print(f"{len(files)} recordings verified ({'cache only' if verify_only else 'downloaded'})")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
