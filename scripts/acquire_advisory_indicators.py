#!/usr/bin/env python3
"""Acquire pinned government-advisory indicator bundles (ADR-0013 D2).

Runs only when a human invokes it — never at application runtime. Each entry is
a STIX 2.1 bundle a government agency published with an advisory, marked TLP:CLEAR
(public distribution), pinned by URL **and** SHA-256: a download whose hash
differs is refused, so a silently re-published file can never change results.
Bundles are small and are vendored under ``data/intel/advisories/``; the manifest
records the source, licence statement, size and hash of each.

    python scripts/acquire_advisory_indicators.py            # download + verify
    python scripts/acquire_advisory_indicators.py --verify   # verify vendored files
    python scripts/acquire_advisory_indicators.py --from-file NAME=PATH

Some publishers' CDNs refuse Python's HTTP client (cisa.gov answers 403 to it,
not to curl). ``--from-file`` vendors a copy fetched with another client
instead — accepted only if its SHA-256 equals the pin, so the result is the
same bytes either way. Bot-detection is never worked around.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import sys
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = REPO_ROOT / "data" / "intel" / "advisories"
MANIFEST = OUT_DIR / "manifest.json"

#: (file name, URL, SHA-256, advisory, publisher statement on reuse).
BUNDLES: tuple[tuple[str, str, str, str, str], ...] = (
    (
        "MAR-10448362.c1.v1.CLEAR_stix2.json",
        "https://www.cisa.gov/sites/default/files/2024-02/MAR-10448362.c1.v1.CLEAR_stix2.json",
        "bcccd68d135277f7e94a8832e863b973311bb534d443027ab592f7945ed36266",
        "CISA MAR-10448362.c1 (with joint advisory AA24-038A, PRC state-sponsored actors)",
        "TLP:CLEAR (disclosure not limited); a work of the U.S. Government",
    ),
)


def _get(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "soc-apt-attribution-platform/0.0.0"})
    with urllib.request.urlopen(req, timeout=120) as resp:  # noqa: S310 - fixed https URL, GET only
        if resp.status != 200:
            raise RuntimeError(f"HTTP {resp.status} for {url}")
        return bytes(resp.read())


def main(argv: list[str]) -> int:
    local: dict[str, str] = {}
    if "--from-file" in argv:
        name_, _, path_ = argv[argv.index("--from-file") + 1].partition("=")
        local[name_] = path_
    entries = []
    for name, url, sha256, advisory, reuse in BUNDLES:
        path = OUT_DIR / name
        if "--verify" not in argv:
            data = Path(local[name]).read_bytes() if name in local else _get(url)
            digest = hashlib.sha256(data).hexdigest()
            if digest != sha256:
                raise RuntimeError(f"{name}: SHA-256 {digest} differs from the pin — refusing")
            bundle = json.loads(data)
            if bundle.get("type") != "bundle":
                raise RuntimeError(f"{name}: not a STIX bundle")
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest != sha256:
            print(f"MISMATCH {name}")
            return 1
        entries.append(
            {
                "file": name,
                "download_url": url,
                "sha256": sha256,
                "size_bytes": path.stat().st_size,
                "advisory": advisory,
                "reuse": reuse,
                **(
                    {"obtained_via": "--from-file (fetched with another client; SHA-256 verified)"}
                    if name in local
                    else {}
                ),
            }
        )
    if "--verify" in argv:
        print(f"{len(entries)} bundle(s) verified")
        return 0
    manifest = {
        "source": "Government advisory STIX 2.1 indicator bundles (ADR-0013)",
        "retrieved_at_utc": dt.datetime.now(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "method": "scripts/acquire_advisory_indicators.py (URL + SHA-256 pinned)",
        "approval": "owner instruction 2026-10-09 ('finish all other tasks'; ADR-0013 D1-D2)",
        "bundles": entries,
    }
    MANIFEST.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(f"{len(entries)} bundle(s) acquired; manifest {MANIFEST.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
