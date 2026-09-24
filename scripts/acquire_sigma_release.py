#!/usr/bin/env python3
"""Acquire and hash-verify one pinned SigmaHQ rule-package release (ADR-0007 D2/D7).

Like ``scripts/acquire_attack_bundle.py``, this talks to GitHub only when a
human runs it — never at application runtime. Default usage acquires the
ADR-0007 baseline, the Core++ package of release ``r2026-07-01``:

    python scripts/acquire_sigma_release.py

It downloads the tag-pinned release asset (never a floating "latest"), checks
it is a well-formed ZIP of YAML rule files (read as data only — nothing is
extracted to disk or executed), computes its SHA-256, and writes:

  data/detection/sigma/<tag>/<asset>          the vendored, immutable archive
  data/detection/sigma/<tag>/manifest.json    the frozen acquisition record

A NOTICE.md (Detection Rule License 1.1 attribution) must already exist beside
the archive; this script does not create or overwrite it. Re-running for the
same tag re-verifies integrity (same SHA-256 expected). A different tag is the
start of a deliberate, reviewed Sigma upgrade, not something done here.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import sys
import urllib.request
import zipfile
from pathlib import Path

REPO = "SigmaHQ/sigma"
DEFAULT_TAG = "r2026-07-01"
DEFAULT_ASSET = "sigma_core++.zip"

REPO_ROOT = Path(__file__).resolve().parents[1]


def release_asset_url(tag: str, asset: str) -> str:
    return f"https://github.com/{REPO}/releases/download/{tag}/{asset}"


def download(url: str, dest: Path) -> None:
    print(f"Downloading:\n  {url}\n  -> {dest}")
    req = urllib.request.Request(url, headers={"User-Agent": "soc-apt-attribution-platform/0.0.0"})
    with urllib.request.urlopen(req, timeout=120) as resp:  # noqa: S310 - fixed https URL, GET only
        if resp.status != 200:
            raise RuntimeError(f"download failed: HTTP {resp.status} for {url}")
        dest.parent.mkdir(parents=True, exist_ok=True)
        tmp = dest.with_suffix(dest.suffix + ".part")
        with tmp.open("wb") as f:
            while chunk := resp.read(1024 * 1024):
                f.write(chunk)
        tmp.replace(dest)


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(1024 * 1024):
            h.update(chunk)
    return h.hexdigest()


def inspect_archive(path: Path) -> dict[str, int]:
    """Validate ZIP structure and count members without extracting anything."""
    with zipfile.ZipFile(path) as archive:
        bad = archive.testzip()
        if bad is not None:
            raise ValueError(f"{path}: corrupt member {bad!r}")
        names = archive.namelist()
    for name in names:
        if name.startswith("/") or ".." in Path(name).parts:
            raise ValueError(f"{path}: unsafe member path {name!r}")
    yaml_members = [n for n in names if n.endswith((".yml", ".yaml"))]
    if not yaml_members:
        raise ValueError(f"{path}: archive contains no YAML rule files")
    return {"members": len(names), "yaml_rule_files": len(yaml_members)}


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--tag", default=DEFAULT_TAG, help=f"release tag (default: {DEFAULT_TAG})")
    parser.add_argument(
        "--asset", default=DEFAULT_ASSET, help=f"release asset (default: {DEFAULT_ASSET})"
    )
    args = parser.parse_args()

    url = release_asset_url(args.tag, args.asset)
    out_dir = REPO_ROOT / "data" / "detection" / "sigma" / args.tag
    artifact_path = out_dir / args.asset
    manifest_path = out_dir / "manifest.json"
    notice_path = out_dir / "NOTICE.md"

    download(url, artifact_path)
    size = artifact_path.stat().st_size
    digest = sha256_of(artifact_path)
    counts = inspect_archive(artifact_path)

    manifest = {
        "sigma_release": args.tag,
        "package": args.asset,
        "artifact": {
            "filename": args.asset,
            "relative_path": f"data/detection/sigma/{args.tag}/{args.asset}",
            "size_bytes": size,
            "sha256": digest,
        },
        "archive_contents": counts,
        "source": {
            "repository": REPO,
            "release_tag": args.tag,
            "download_url": url,
            "github_release_url": f"https://github.com/{REPO}/releases/tag/{args.tag}",
        },
        "acquisition": {
            "retrieved_at_utc": dt.datetime.now(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "method": "scripts/acquire_sigma_release.py (urllib, tag-pinned release asset)",
        },
        "license": {
            "rules": "Detection Rule License (DRL) 1.1",
            "license_url": "https://github.com/SigmaHQ/Detection-Rule-License",
            "notice_file": f"data/detection/sigma/{args.tag}/NOTICE.md",
        },
    }
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    print(f"\nArtifact: {artifact_path} ({size:,} bytes)")
    print(f"SHA-256:  {digest}")
    print(f"Contents: {counts}")
    print(f"Manifest written: {manifest_path}")
    if not notice_path.is_file():
        print(
            f"\nWARNING: {notice_path} does not exist. Add the DRL 1.1 attribution NOTICE "
            "before treating this archive as attribution-complete (ADR-0007 D8)."
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
