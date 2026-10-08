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

``--set zeek`` (ADR-0012 D1) acquires the Zeek logs OTRF recorded during the
same runs (APT29 days 1-2, LSASS campaigns 1-7) into their own manifest,
``data/telemetry-samples/otrf-zeek/manifest.json``; each of those files is also
checked against its **git blob id** at the pinned commit.

    python scripts/acquire_corpus_telemetry.py [--set zeek]            # download + verify
    python scripts/acquire_corpus_telemetry.py [--set zeek] --verify   # verify the cache only
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

#: ADR-0012 D1: (repository path, tree size, git blob id) at the pinned commit.
ZEEK_FILES: tuple[tuple[str, int, str], ...] = (
    (
        "datasets/compound/LSASS_campaign_01/metasploit_logonpasswords_lsass_memory_dump_zeek_logs.zip",
        14474,
        "6d7e74e5f2336a4558dc7816b1abb9d6eb292d94",
    ),
    (
        "datasets/compound/LSASS_campaign_02/metasploit_procdump_lsass_memory_dump_zeek_logs.zip",
        10874,
        "92c66b436a739d1a583417528b56b2489945bd4c",
    ),
    (
        "datasets/compound/LSASS_campaign_03/metasploit_comsvcs_lsass_memory_dump_zeek_logs.zip",
        13648,
        "a002cd388afe4199abf96be9722126eb2ca9e5a1",
    ),
    (
        "datasets/compound/LSASS_campaign_04/metasploit_out-minidump_lsass_memory_dump_zeek_logs.zip",
        12512,
        "53e450137a08dbbf2db05f80c897683e542809e9",
    ),
    (
        "datasets/compound/LSASS_campaign_05/metasploit_sharpdump_lsass_memory_dump_zeek_logs.zip",
        70351,
        "fa8f0879a3b1f362d0f364066ee255b7c82af5d9",
    ),
    (
        "datasets/compound/LSASS_campaign_06/metasploit_outflank-dumpert_lsass_memory_dump_zeek_logs.zip",
        62094,
        "8bae26afa6cf16b9c02a4d2cbbdf7cdbfb8252aa",
    ),
    (
        "datasets/compound/LSASS_campaign_07/metasploit_nanodump_lsass_memory_dump_zeek_logs.zip",
        47103,
        "f54af280220235badbd1b3fecc89165e632a610d",
    ),
    (
        "datasets/compound/apt29/day1/zeek/NASHUA-zeek_logs.zip",
        71772,
        "75b3398216360715a09f4358177decff64d4e12e",
    ),
    (
        "datasets/compound/apt29/day1/zeek/SCRANTON-zeek_logs.zip",
        24653,
        "738f2537a6d32fea52d2d2a259a4fd3d45b917e6",
    ),
    (
        "datasets/compound/apt29/day1/zeek/combined_zeek.log",
        1243861,
        "277c706a50a33affb4f2ee1458406cc17a6222e9",
    ),
    (
        "datasets/compound/apt29/day2/zeek/NEWYORK-zeek_logs.zip",
        44042,
        "96793882a52e31f332bb69af2c4c2499df6087b0",
    ),
    (
        "datasets/compound/apt29/day2/zeek/SCRANTON-zeek_logs.zip",
        13071,
        "9835de98fae2297f227931ec67972755391423ee",
    ),
    (
        "datasets/compound/apt29/day2/zeek/UTICA-A-zeek_logs.zip",
        42753,
        "ba7ccaec21ef8c2503314901213eb91b1cfbc709",
    ),
    (
        "datasets/compound/apt29/day2/zeek/UTICA-C-zeek_logs.zip",
        9859,
        "fa87aef5c66219d7f6bee22786468b48b5392774",
    ),
    (
        "datasets/compound/apt29/day2/zeek/UTICA-D-zeek_logs.zip",
        35682,
        "75f8515cb752af72ace3decb33e336712ee5a3a5",
    ),
    (
        "datasets/compound/apt29/day2/zeek/UTICA-ONE-DRIVE-zeek_logs.zip",
        17017,
        "c085533e4d8eb0ff0b9ea935e5633eaf95098689",
    ),
    (
        "datasets/compound/apt29/day2/zeek/combined_zeek.log",
        1542562,
        "50779c3896946bc2208c075db2f5a84c58ac764e",
    ),
)
ZEEK_MANIFEST = REPO_ROOT / "data" / "telemetry-samples" / "otrf-zeek" / "manifest.json"


def _git_blob_id(content: bytes) -> str:
    return hashlib.sha1(b"blob %d\0" % len(content) + content).hexdigest()  # noqa: S324 - git id


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


def _verify(manifest_path: Path) -> int:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for entry in manifest["files"]:
        path = REPO_ROOT / entry["cache_path"]
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest != entry["sha256"]:
            print(f"MISMATCH {entry['cache_path']}")
            return 1
    print(f"{len(manifest['files'])} cached files verified")
    return 0


def main(argv: list[str]) -> int:
    zeek = "--set" in argv and argv[argv.index("--set") + 1] == "zeek"
    manifest_path = ZEEK_MANIFEST if zeek else MANIFEST
    if "--verify" in argv:
        return _verify(manifest_path)
    files: list[tuple[str, int, str | None]] = (
        list(ZEEK_FILES) if zeek else [(path, size, None) for path, size in FILES]
    )
    entries = []
    for repo_path, expected_size, blob_id in files:
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
            if blob_id is not None and _git_blob_id(data) != blob_id:
                raise RuntimeError(
                    f"{repo_path}: content differs from the commit's blob — refusing"
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
        "source": "OTRF Security-Datasets (compound datasets"
        + (": Zeek logs recorded during the corpus runs)" if zeek else ")"),
        "license": "MIT",
        "license_url": f"https://github.com/{OTRF_REPO}/blob/{OTRF_COMMIT}/LICENSE",
        "source_repository": OTRF_REPO,
        "source_commit": OTRF_COMMIT,
        "retrieved_at_utc": dt.datetime.now(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "method": "scripts/acquire_corpus_telemetry.py (commit-pinned raw URLs, size-checked "
        "against the GitHub tree API; archives inspected as data, never extracted)",
        "cache": "data/cache/otrf-compound/ (git-ignored; rebuild with this script)",
        **(
            {
                "approval": "owner standing instruction, 2026-10-06 (ADR-0012 D1)",
                "verification": "each file's size and git blob id equal the pinned commit's tree",
            }
            if zeek
            else {}
        ),
        "files": entries,
    }
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8", newline="\n")
    total = sum(int(e["size_bytes"]) for e in entries)  # type: ignore[call-overload]
    print(f"{len(entries)} files, {total:,} bytes; manifest {manifest_path.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
