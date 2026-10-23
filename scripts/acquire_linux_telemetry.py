#!/usr/bin/env python3
"""Acquire pinned, real telemetry from ``splunk/attack_data`` (ADR-0010 D6, ADR-0011).

``--set linux`` (default), ``--set cloud``, ``--set macos`` or ``--set windows-unseen`` selects an
owner-approved file set, each with its own ``selection.txt`` and ``manifest.json``.

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
import http.client
import json
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path, PurePosixPath

REPO_ROOT = Path(__file__).resolve().parents[1]
REPO = "splunk/attack_data"
COMMIT = "a28608b53aa3d8222052e8f3ada59e2d9a4adfff"
CACHE = REPO_ROOT / "data" / "cache" / "splunk-attack-data"
#: Reviewed, owner-approved file sets: --set NAME -> (samples dir, description, approval).
SETS = {
    "linux": (
        REPO_ROOT / "data" / "telemetry-samples" / "splunk-attack-data",
        "splunk/attack_data (Linux: Sysmon for Linux and auditd)",
        "owner, 2026-10-01 (ADR-0010 D6)",
    ),
    "cloud": (
        REPO_ROOT / "data" / "telemetry-samples" / "splunk-attack-data-cloud",
        "splunk/attack_data (cloud: AWS CloudTrail, Azure / Entra ID, Office 365, Okta, "
        "GitHub, GCP / Google Workspace, Kubernetes)",
        "owner, 2026-10-06 (ADR-0011)",
    ),
    "macos": (
        REPO_ROOT / "data" / "telemetry-samples" / "splunk-attack-data-macos",
        "splunk/attack_data (macOS: osquery Endpoint Security process events)",
        "owner standing instruction, 2026-10-08 (ADR-0014; recommended path)",
    ),
    "windows-unseen": (
        REPO_ROOT / "data" / "telemetry-samples" / "splunk-attack-data-windows-unseen",
        "splunk/attack_data (Windows Sysmon: the second unseen test set)",
        "owner, 2026-10-23 (ADR-0029; selection by scripts/select_unseen_splunk_windows.py)",
    ),
}
_POINTER = re.compile(
    r"\Aversion https://git-lfs\.github\.com/spec/v1\noid sha256:([0-9a-f]{64})\nsize (\d+)\n\Z"
)


def _get(url: str, attempts: int = 4) -> bytes:
    """GET ``url``; a dropped or stalled connection is retried, an HTTP error is not."""
    req = urllib.request.Request(url, headers={"User-Agent": "soc-apt-attribution-platform/0.0.0"})
    for attempt in range(1, attempts + 1):
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:  # noqa: S310 - fixed https URL
                if resp.status != 200:
                    raise RuntimeError(f"download failed: HTTP {resp.status} for {url}")
                return bytes(resp.read())
        except urllib.error.HTTPError:
            raise
        except (
            http.client.IncompleteRead,
            TimeoutError,
            ConnectionError,
            urllib.error.URLError,
        ) as exc:
            if attempt == attempts:
                raise RuntimeError(f"download failed after {attempts} attempts: {url}") from exc
            time.sleep(2 * attempt)
    raise AssertionError("unreachable")


def _safe(path: str) -> str:
    pure = PurePosixPath(path)
    if pure.is_absolute() or ".." in pure.parts or not path.startswith("datasets/"):
        raise ValueError(f"unsafe selection path {path!r}")
    return path


def _git_blob_id(content: bytes) -> str:
    return hashlib.sha1(b"blob %d\0" % len(content) + content).hexdigest()  # noqa: S324 - git's id


def _tree_blob_ids() -> dict[str, str]:
    """``path -> git blob id`` for every file at the pinned commit."""
    tree = json.loads(_get(f"https://api.github.com/repos/{REPO}/git/trees/{COMMIT}?recursive=1"))
    if tree.get("truncated"):
        raise RuntimeError("the tree listing is truncated — refusing to verify against it")
    return {e["path"]: e["sha"] for e in tree["tree"] if e["type"] == "blob"}


def _verify(manifest_path: Path) -> int:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for entry in manifest["files"]:
        digest = hashlib.sha256((REPO_ROOT / entry["cache_path"]).read_bytes()).hexdigest()
        if digest != entry["sha256"]:
            print(f"MISMATCH {entry['cache_path']}")
            return 1
    print(f"{len(manifest['files'])} cached files verified")
    return 0


def main(argv: list[str]) -> int:
    name = argv[argv.index("--set") + 1] if "--set" in argv else "linux"
    samples, description, approval = SETS[name]
    selection, manifest_path = samples / "selection.txt", samples / "manifest.json"
    if "--verify" in argv:
        return _verify(manifest_path)
    paths = [
        _safe(line.strip())
        for line in selection.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    blob_ids = _tree_blob_ids()
    raw = f"https://raw.githubusercontent.com/{REPO}/{COMMIT}/"
    media = f"https://media.githubusercontent.com/media/{REPO}/{COMMIT}/"
    entries = []
    for path in paths:
        dest = CACHE / path.removeprefix("datasets/")
        stored = _get(raw + path)  # the git blob: an LFS pointer, or the file itself
        if _git_blob_id(stored) != blob_ids.get(path):
            raise RuntimeError(f"{path}: content does not match the commit's git blob — refusing")
        match = _POINTER.match(stored.decode("utf-8", errors="replace"))
        if match is None:  # a plain git file (descriptors, small logs): verified above
            url, expected_sha, expected_size = raw + path, None, None
            if not (dest.is_file() and dest.read_bytes() == stored):
                stored.decode("utf-8")  # text only
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(stored)
                print(f"fetched {path}")
        else:
            url, expected_sha, expected_size = media + path, match[1], int(match[2])
        if expected_sha is not None and not (
            dest.is_file() and hashlib.sha256(dest.read_bytes()).hexdigest() == expected_sha
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
        "source": description,
        "license": "Apache-2.0",
        "license_url": f"https://github.com/{REPO}/blob/{COMMIT}/LICENSE",
        "source_repository": REPO,
        "source_commit": COMMIT,
        "retrieved_at_utc": dt.datetime.now(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "method": "scripts/acquire_linux_telemetry.py (commit-pinned; LFS content verified "
        "against each pointer's SHA-256 and size)",
        "approval": approval,
        "cache": "data/cache/splunk-attack-data/ (git-ignored; rebuild with this script)",
        "files": entries,
    }
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8", newline="\n")
    total = sum(int(e["size_bytes"]) for e in entries)  # type: ignore[call-overload]
    print(f"{len(entries)} files, {total:,} bytes; manifest {manifest_path.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
