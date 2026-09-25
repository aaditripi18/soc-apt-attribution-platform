#!/usr/bin/env python3
"""Acquire pinned, real recorded emulation telemetry for calibration corpus v2
(doc 15 DC-3: S2 blind actor APT29, plus APT3 and real LSASS hard negatives).

Runs only when a human invokes it — never at application runtime. The archives
(~120 MB) are too large to vendor in git, so they go to a git-ignored local
cache, ``data/cache/otrf-compound/``; the **tracked** manifest
``data/telemetry-samples/otrf-compound/manifest.json`` pins each file's URL
(commit-pinned, never a moving branch), size and SHA-256, so the cache can be
rebuilt and verified byte-for-byte.

Every file's size is checked against the GitHub tree API size reviewed before
approval. Archives are opened as data only: member paths are checked for
traversal / absolute paths / links, nothing is extracted to disk, nothing is
executed.

    python scripts/acquire_corpus_telemetry.py            # download + verify
    python scripts/acquire_corpus_telemetry.py --verify   # verify the cache only
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
OTRF_REPO = "OTRF/Security-Datasets"
OTRF_COMMIT = "d9d40ef123d2c87d5d3df28c96bcab4f0faccc87"
CACHE = REPO_ROOT / "data" / "cache" / "otrf-compound"
MANIFEST = REPO_ROOT / "data" / "telemetry-samples" / "otrf-compound" / "manifest.json"

#: (repository path, size in bytes reported by the GitHub tree API at review).
FILES: tuple[tuple[str, int], ...] = (
    (
        "datasets/compound/LSASS_campaign_01/metasploit_logonpasswords_lsass_memory_dump.zip",
        3405389,
    ),
    ("datasets/compound/LSASS_campaign_02/metasploit_procdump_lsass_memory_dump.zip", 2551462),
    ("datasets/compound/LSASS_campaign_03/metasploit_comsvcs_lsass_memory_dump.zip", 2332754),
    ("datasets/compound/LSASS_campaign_04/metasploit_out-minidump_lsass_memory_dump.zip", 2431111),
    ("datasets/compound/LSASS_campaign_05/metasploit_sharpdump_lsass_memory_dump.zip", 3428302),
    (
        "datasets/compound/LSASS_campaign_06/metasploit_outflank-dumpert_lsass_memory_dump.zip",
        3326923,
    ),
    ("datasets/compound/LSASS_campaign_07/metasploit_nanodump_lsass_memory_dump.zip", 3545590),
    ("datasets/compound/_metadata/LSASS_campaign_01.yaml", 32691),
    ("datasets/compound/_metadata/LSASS_campaign_02.yaml", 30600),
    ("datasets/compound/_metadata/LSASS_campaign_03.yaml", 45697),
    ("datasets/compound/_metadata/LSASS_campaign_04.yaml", 34075),
    ("datasets/compound/_metadata/LSASS_campaign_05.yaml", 47804),
    ("datasets/compound/_metadata/LSASS_campaign_06.yaml", 38517),
    ("datasets/compound/_metadata/LSASS_campaign_07.yaml", 33180),
    ("datasets/compound/apt29/README.md", 6391),
    ("datasets/compound/apt29/day1/README.md", 3952),
    ("datasets/compound/apt29/day1/apt29_evals_day1_manual.zip", 13944973),
    ("datasets/compound/apt29/day2/apt29_evals_day2_manual.zip", 43033041),
    ("datasets/compound/windows/apt3/README.md", 2361),
    (
        "datasets/compound/windows/apt3/caldera_attack_evals_round1_day1_2019-10-20201108.tar.gz",
        12608123,
    ),
    ("datasets/compound/windows/apt3/empire_apt3.tar.gz", 28948319),
)


def _safe_member(name: str) -> bool:
    path = PurePosixPath(name.replace("\\", "/"))
    return not path.is_absolute() and ".." not in path.parts


def _inspect(path: Path) -> list[dict[str, object]]:
    """Member listing of an archive, read as data only (no extraction)."""
    members: list[dict[str, object]] = []
    if path.suffix == ".zip":
        with zipfile.ZipFile(path) as archive:
            bad = archive.testzip()
            if bad is not None:
                raise ValueError(f"{path.name}: corrupt member {bad!r}")
            for info in archive.infolist():
                if not _safe_member(info.filename):
                    raise ValueError(f"{path.name}: unsafe member path {info.filename!r}")
                members.append({"name": info.filename, "size_bytes": info.file_size})
    elif path.name.endswith(".tar.gz"):
        with tarfile.open(path, "r:gz") as archive:
            for member in archive.getmembers():
                if not _safe_member(member.name) or member.issym() or member.islnk():
                    raise ValueError(f"{path.name}: unsafe member {member.name!r}")
                if member.isfile():
                    members.append({"name": member.name, "size_bytes": member.size})
    else:
        path.read_bytes().decode("utf-8")  # text documents only
    return members


def _download(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "soc-apt-attribution-platform/0.0.0"})
    with urllib.request.urlopen(req, timeout=600) as resp:  # noqa: S310 - fixed https URL, GET only
        if resp.status != 200:
            raise RuntimeError(f"download failed: HTTP {resp.status} for {url}")
        return bytes(resp.read())


def _verify() -> int:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    for entry in manifest["files"]:
        path = REPO_ROOT / entry["cache_path"]
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest != entry["sha256"]:
            print(f"MISMATCH {entry['cache_path']}")
            return 1
    print(f"{len(manifest['files'])} cached files verified")
    return 0


def main(argv: list[str]) -> int:
    if "--verify" in argv:
        return _verify()
    entries = []
    for repo_path, expected_size in FILES:
        url = f"https://raw.githubusercontent.com/{OTRF_REPO}/{OTRF_COMMIT}/{repo_path}"
        dest = CACHE / repo_path.removeprefix("datasets/compound/")
        if dest.is_file() and dest.stat().st_size == expected_size:
            print(f"cached   {repo_path}")
        else:
            print(f"download {url}")
            data = _download(url)
            if len(data) != expected_size:
                raise RuntimeError(
                    f"{repo_path}: {len(data)} bytes, expected {expected_size} — refusing"
                )
            dest.parent.mkdir(parents=True, exist_ok=True)
            tmp = dest.with_name(dest.name + ".part")
            tmp.write_bytes(data)
            tmp.replace(dest)
        entries.append(
            {
                "source_path": repo_path,
                "cache_path": dest.relative_to(REPO_ROOT).as_posix(),
                "size_bytes": dest.stat().st_size,
                "sha256": hashlib.sha256(dest.read_bytes()).hexdigest(),
                "members": _inspect(dest),
                "download_url": url,
            }
        )
    manifest = {
        "source": "OTRF Security-Datasets (compound datasets)",
        "license": "MIT",
        "license_url": f"https://github.com/{OTRF_REPO}/blob/{OTRF_COMMIT}/LICENSE",
        "source_repository": OTRF_REPO,
        "source_commit": OTRF_COMMIT,
        "retrieved_at_utc": dt.datetime.now(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "method": "scripts/acquire_corpus_telemetry.py (commit-pinned raw URLs, size-checked "
        "against the GitHub tree API; archives inspected as data, never extracted)",
        "cache": "data/cache/otrf-compound/ (git-ignored; rebuild with this script)",
        "files": entries,
    }
    MANIFEST.parent.mkdir(parents=True, exist_ok=True)
    MANIFEST.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8", newline="\n")
    total = sum(int(e["size_bytes"]) for e in entries)  # type: ignore[call-overload]
    print(f"{len(entries)} files, {total:,} bytes; manifest {MANIFEST.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
