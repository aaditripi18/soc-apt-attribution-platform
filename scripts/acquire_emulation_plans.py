#!/usr/bin/env python3
"""Acquire pinned CTID Adversary Emulation Library documents (doc 15 DC-3 S1/S3).

Runs only when a human invokes it — never at application runtime. Every file is
downloaded from a commit-pinned raw URL (never a moving branch), its size is
checked against the size GitHub's tree API reported at review time, and it is
SHA-256 hashed and recorded in ``data/emulation-plans/ctid/manifest.json``. The
files are plain text (YAML / Markdown / license) and are only ever parsed as
data — nothing is executed.

    python scripts/acquire_emulation_plans.py

Re-running re-verifies integrity (identical SHA-256 expected). Adding a file is
a reviewed change to ``FILES`` below.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import sys
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
CTID_REPO = "center-for-threat-informed-defense/adversary_emulation_library"
CTID_COMMIT = "4467a6eed6e67d25009704130e1d27d1a8007f57"
DEST = REPO_ROOT / "data" / "emulation-plans" / "ctid"

#: (repository path, size in bytes reported by the GitHub tree API at review,
#: purpose). S1 = full emulation plans (calibration / held-out / blind); S3 =
#: micro plans of behaviours shared by many actors (hard negatives).
FILES: tuple[tuple[str, int, str], ...] = (
    ("LICENSE", 11357, "license"),
    ("structure/format_dictionary.yaml", 2660, "plan format"),
    ("carbanak/Emulation_Plan/yaml/Carbanak.yaml", 31520, "S1"),
    ("fin6/Emulation_Plan/yaml/FIN6.yaml", 40373, "S1"),
    ("fin7/Emulation_Plan/yaml/Fin7.yaml", 12283, "S1"),
    ("menu_pass/Emulation_Plan/yaml/menupass.yaml", 21126, "S1"),
    ("oilrig/Emulation_Plan/yaml/oilrig.yaml", 29045, "S1"),
    ("sandworm/Emulation_Plan/yaml/sandworm.yaml", 38777, "S1"),
    ("turla/Emulation_Plan/yaml/turla_carbon.yaml", 41479, "S1"),
    ("turla/Emulation_Plan/yaml/turla_snake.yaml", 47973, "S1"),
    ("wizard_spider/Emulation_Plan/yaml/wizard_spider.yaml", 35945, "S1"),
    ("apt29/Emulation_Plan/yaml/APT29.yaml", 101876, "S1 blind-actor only"),
    ("micro_emulation_plans/README.md", 11994, "S3"),
    ("micro_emulation_plans/src/ad_enum/README.md", 9497, "S3"),
    ("micro_emulation_plans/src/log_clearing/README.md", 5076, "S3"),
    ("micro_emulation_plans/src/named_pipes/README.md", 10989, "S3"),
    ("micro_emulation_plans/src/process_injection/README.md", 7272, "S3"),
    ("micro_emulation_plans/src/file_access/README.md", 5596, "S3"),
    ("micro_emulation_plans/src/windows_registry/README.md", 7388, "S3"),
    ("micro_emulation_plans/src/dll_sideloading/README.md", 8878, "S3"),
    ("micro_emulation_plans/src/user_execution/README_user_execution.md", 5021, "S3"),
    ("micro_emulation_plans/src/reflective_loading/README.md", 4896, "S3"),
    ("micro_emulation_plans/src/data_exfil/README.md", 5881, "S3"),
)


def _download(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "soc-apt-attribution-platform/0.0.0"})
    with urllib.request.urlopen(req, timeout=120) as resp:  # noqa: S310 - fixed https URL, GET only
        if resp.status != 200:
            raise RuntimeError(f"download failed: HTTP {resp.status} for {url}")
        return bytes(resp.read())


def main() -> int:
    entries = []
    for repo_path, expected_size, purpose in FILES:
        url = f"https://raw.githubusercontent.com/{CTID_REPO}/{CTID_COMMIT}/{repo_path}"
        print(f"Downloading {url}")
        data = _download(url)
        if len(data) != expected_size:
            raise RuntimeError(
                f"{repo_path}: {len(data)} bytes, expected {expected_size} (tree API) — refusing"
            )
        data.decode("utf-8")  # text only; raises on anything else
        dest = DEST / repo_path
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
        entries.append(
            {
                "relative_path": dest.relative_to(REPO_ROOT).as_posix(),
                "source_path": repo_path,
                "purpose": purpose,
                "size_bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
                "download_url": url,
            }
        )
    manifest = {
        "source": (
            "MITRE Engenuity Center for Threat-Informed Defense — Adversary Emulation Library"
        ),
        "license": "Apache-2.0",
        "license_url": f"https://github.com/{CTID_REPO}/blob/{CTID_COMMIT}/LICENSE",
        "source_repository": CTID_REPO,
        "source_commit": CTID_COMMIT,
        "retrieved_at_utc": dt.datetime.now(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "method": "scripts/acquire_emulation_plans.py (urllib, commit-pinned raw URLs, "
        "size-checked against the GitHub tree API)",
        "files": entries,
    }
    out = DEST / "manifest.json"
    out.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8", newline="\n")
    total = sum(e["size_bytes"] for e in entries)  # type: ignore[misc]
    print(f"{len(entries)} files, {total:,} bytes; manifest at {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
