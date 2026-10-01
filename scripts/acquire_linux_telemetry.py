#!/usr/bin/env python3
"""Acquire pinned, real Linux telemetry from ``splunk/attack_data`` (ADR-0010 D6).

Runs only when a human invokes it — never at application runtime. The owner
approved this download on 2026-10-01: the reviewed file list is
``data/telemetry-samples/splunk-attack-data/selection.txt`` (149 Sysmon for
Linux / auditd logs, ~238 MiB, plus their 115 YAML dataset descriptors, which
carry each dataset's ATT&CK technique label).

The repository stores logs in Git LFS. For every log the script first reads its
LFS pointer **at the pinned commit** (``oid sha256:…``, ``size …``), then fetches
the content from GitHub's LFS media endpoint and refuses it unless both its
size and its SHA-256 equal the pointer's — the pointer is the commit's own
statement of the content. Descriptors are plain git blobs, fetched raw at the
same commit. Files go to the git-ignored cache ``data/cache/splunk-attack-data/``;
the tracked manifest pins every file's URL, size and SHA-256. Nothing is
executed; logs are opened only as UTF-8 text.

    python scripts/acquire_linux_telemetry.py            # download + verify
    python scripts/acquire_linux_telemetry.py --verify   # verify the cache only
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import re
import sys
import urllib.request
from pathlib import Path, PurePosixPath

REPO_ROOT = Path(__file__).resolve().parents[1]
REPO = "splunk/attack_data"
COMMIT = "a28608b53aa3d8222052e8f3ada59e2d9a4adfff"
SAMPLES = REPO_ROOT / "data" / "telemetry-samples" / "splunk-attack-data"
SELECTION = SAMPLES / "selection.txt"
MANIFEST = SAMPLES / "manifest.json"
CACHE = REPO_ROOT / "data" / "cache" / "splunk-attack-data"
_POINTER = re.compile(
    r"\Aversion https://git-lfs\.github\.com/spec/v1\noid sha256:([0-9a-f]{64})\nsize (\d+)\n\Z"
)


def _get(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "soc-apt-attribution-platform/0.0.0"})
    with urllib.request.urlopen(req, timeout=600) as resp:  # noqa: S310 - fixed https URL, GET only
        if resp.status != 200:
            raise RuntimeError(f"download failed: HTTP {resp.status} for {url}")
        return bytes(resp.read())


def _safe(path: str) -> str:
    pure = PurePosixPath(path)
    if pure.is_absolute() or ".." in pure.parts or not path.startswith("datasets/"):
        raise ValueError(f"unsafe selection path {path!r}")
    return path


def _verify() -> int:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    for entry in manifest["files"]:
        digest = hashlib.sha256((REPO_ROOT / entry["cache_path"]).read_bytes()).hexdigest()
        if digest != entry["sha256"]:
            print(f"MISMATCH {entry['cache_path']}")
            return 1
    print(f"{len(manifest['files'])} cached files verified")
    return 0


def main(argv: list[str]) -> int:
    if "--verify" in argv:
        return _verify()
    paths = [_safe(line.strip()) for line in SELECTION.read_text(encoding="utf-8").splitlines()]
    raw = f"https://raw.githubusercontent.com/{REPO}/{COMMIT}/"
    media = f"https://media.githubusercontent.com/media/{REPO}/{COMMIT}/"
    entries = []
    for path in paths:
        dest = CACHE / path.removeprefix("datasets/")
        if path.endswith(".yml"):
            url, expected_sha, expected_size = raw + path, None, None
        else:
            pointer = _get(raw + path).decode("ascii")
            match = _POINTER.match(pointer)
            if match is None:
                raise RuntimeError(f"{path}: not a Git LFS pointer at {COMMIT}")
            url, expected_sha, expected_size = media + path, match[1], int(match[2])
        if not (
            dest.is_file()
            and expected_sha is not None
            and hashlib.sha256(dest.read_bytes()).hexdigest() == expected_sha
        ):
            data = _get(url)
            if expected_size is not None and len(data) != expected_size:
                raise RuntimeError(f"{path}: {len(data)} bytes, pointer says {expected_size}")
            if expected_sha is not None and hashlib.sha256(data).hexdigest() != expected_sha:
                raise RuntimeError(f"{path}: SHA-256 differs from the LFS pointer — refusing")
            data.decode("utf-8")  # text only
            dest.parent.mkdir(parents=True, exist_ok=True)
            tmp = dest.with_name(dest.name + ".part")
            tmp.write_bytes(data)
            tmp.replace(dest)
            print(f"fetched {path}")
        content = dest.read_bytes()
        entries.append(
            {
                "source_path": path,
                "cache_path": dest.relative_to(REPO_ROOT).as_posix(),
                "size_bytes": len(content),
                "sha256": hashlib.sha256(content).hexdigest(),
                "lfs": expected_sha is not None,
                "download_url": url,
            }
        )
    manifest = {
        "source": "splunk/attack_data (Linux: Sysmon for Linux and auditd)",
        "license": "Apache-2.0",
        "license_url": f"https://github.com/{REPO}/blob/{COMMIT}/LICENSE",
        "source_repository": REPO,
        "source_commit": COMMIT,
        "retrieved_at_utc": dt.datetime.now(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "method": "scripts/acquire_linux_telemetry.py (commit-pinned; LFS content verified "
        "against each pointer's SHA-256 and size)",
        "approval": "owner, 2026-10-01 (ADR-0010 D6)",
        "cache": "data/cache/splunk-attack-data/ (git-ignored; rebuild with this script)",
        "files": entries,
    }
    MANIFEST.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8", newline="\n")
    total = sum(int(e["size_bytes"]) for e in entries)  # type: ignore[call-overload]
    print(f"{len(entries)} files, {total:,} bytes; manifest {MANIFEST.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
