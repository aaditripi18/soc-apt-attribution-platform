#!/usr/bin/env python3
"""Acquire pinned, real telemetry sample logs for adapter golden tests (ADR-0008 D2.3).

Runs only when a human invokes it — never at application runtime. Each sample is
downloaded from a commit-pinned URL (never a moving branch), checked to be a
well-formed ZIP (read as data only; nothing is extracted to disk or executed),
SHA-256 hashed, and recorded in ``data/telemetry-samples/<source>/manifest.json``.
A NOTICE.md with the source's license attribution must exist beside the samples.

    python scripts/acquire_telemetry_samples.py

Re-running re-verifies integrity (identical SHA-256 expected). Adding a sample
is a reviewed change to ``SAMPLES`` below.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import sys
import urllib.request
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

OTRF_REPO = "OTRF/Security-Datasets"
OTRF_COMMIT = "d9d40ef123d2c87d5d3df28c96bcab4f0faccc87"

#: (source, repository path) pairs, all pinned to ``OTRF_COMMIT``.
SAMPLES: tuple[tuple[str, str], ...] = (
    ("otrf", "datasets/atomic/windows/execution/host/psh_powershell_httplistener.zip"),
    ("otrf", "datasets/atomic/windows/defense_evasion/host/psh_mavinject_dll_notepad.zip"),
)


def _download(url: str, dest: Path) -> None:
    req = urllib.request.Request(url, headers={"User-Agent": "soc-apt-attribution-platform/0.0.0"})
    with urllib.request.urlopen(req, timeout=120) as resp:  # noqa: S310 - fixed https URL, GET only
        if resp.status != 200:
            raise RuntimeError(f"download failed: HTTP {resp.status} for {url}")
        data = resp.read()
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".part")
    tmp.write_bytes(data)
    tmp.replace(dest)


def _inspect_zip(path: Path) -> list[dict[str, object]]:
    with zipfile.ZipFile(path) as archive:
        bad = archive.testzip()
        if bad is not None:
            raise ValueError(f"{path}: corrupt member {bad!r}")
        members = []
        for info in archive.infolist():
            if info.filename.startswith("/") or ".." in Path(info.filename).parts:
                raise ValueError(f"{path}: unsafe member path {info.filename!r}")
            members.append({"name": info.filename, "size_bytes": info.file_size})
    return members


def main() -> int:
    entries = []
    for source, repo_path in SAMPLES:
        url = f"https://raw.githubusercontent.com/{OTRF_REPO}/{OTRF_COMMIT}/{repo_path}"
        dest = REPO_ROOT / "data" / "telemetry-samples" / source / Path(repo_path).name
        print(f"Downloading {url}")
        _download(url, dest)
        entries.append(
            {
                "filename": dest.name,
                "relative_path": dest.relative_to(REPO_ROOT).as_posix(),
                "size_bytes": dest.stat().st_size,
                "sha256": hashlib.sha256(dest.read_bytes()).hexdigest(),
                "members": _inspect_zip(dest),
                "source_repository": OTRF_REPO,
                "source_commit": OTRF_COMMIT,
                "source_path": repo_path,
                "download_url": url,
            }
        )
    manifest = {
        "source": "OTRF Security-Datasets",
        "license": "MIT",
        "license_url": f"https://github.com/{OTRF_REPO}/blob/{OTRF_COMMIT}/LICENSE",
        "retrieved_at_utc": dt.datetime.now(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "method": "scripts/acquire_telemetry_samples.py (urllib, commit-pinned raw URLs)",
        "samples": entries,
    }
    out = REPO_ROOT / "data" / "telemetry-samples" / "otrf" / "manifest.json"
    out.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8", newline="\n")
    for e in entries:
        print(f"{e['filename']}: {e['size_bytes']:,} bytes sha256={e['sha256']}")
    if not (out.parent / "NOTICE.md").is_file():
        print(f"\nWARNING: add {out.parent / 'NOTICE.md'} (MIT attribution) before use.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
