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
    python scripts/acquire_advisory_indicators.py --from-file NAME=PATH [--from-file ...]

A vendored file that already matches its pin is kept and not fetched again. The file
name is the vendored name (short: the published names exceed Windows path limits);
the manifest records the published URL.

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
    (
        "AA23-144A.stix.json",
        "https://www.cisa.gov/sites/default/files/STIX/AA23-144A_PRC_State-Sponsored_Cyber_Actor_Living_Off_the_Land_to_Evade_Detection.stix.json",
        "a44ae1fff3f239877a663cae1ba244d1c15bbc013e1cc5a6338f1d5d2c1cb789",
        "CISA joint advisory AA23-144A (PRC state-sponsored actor living off the land)",
        "TLP:CLEAR (disclosure not limited); a work of the U.S. Government and partner agencies",
    ),
    (
        "AA23-347A.stix.json",
        "https://www.cisa.gov/sites/default/files/2023-12/aa23-347a-russian-foreign-intelligence-service-svr-exploiting-jetbrains-teamcity-cve-globally.json",
        "2b0b6cdb06bb4e6fc596d753f90d855311b5fd35bbcdcf8d95cc61e84b0d0297",
        "CISA joint advisory AA23-347A (SVR exploiting JetBrains TeamCity)",
        "TLP:CLEAR (disclosure not limited); a work of the U.S. Government and partner agencies",
    ),
    (
        "AA24-207A.stix.json",
        "https://www.cisa.gov/sites/default/files/2024-07/AA24-207A-North-Korea-Cyber-Group-Conducts-Global-Espionage-Campaign-to-Advance-Regimes-Military-and-Nuclear-Programs.stix_.json",
        "130898d5a0baff1aefc1e378fbfda16d76fc889ad6268ae2032d9e5150274f6e",
        "CISA joint advisory AA24-207A (DPRK RGB 3rd Bureau espionage campaign)",
        "TLP:CLEAR (disclosure not limited); a work of the U.S. Government and partner agencies",
    ),
    (
        "AA24-241A.stix.json",
        "https://www.cisa.gov/sites/default/files/2024-08/AA24-241A-Iran-based-Cyber-Actors-Enabling-Ransomware-Attacks-on-US-Organizations.stix_.json",
        "3439082a0064a753b9bc55c3502860796bc2e0aed34e16aaeb0ac50fb085fc54",
        "CISA joint advisory AA24-241A (Iran-based actors enabling ransomware attacks)",
        "TLP:CLEAR (disclosure not limited); a work of the U.S. Government and partner agencies",
    ),
    (
        "AA24-249A.stix.json",
        "https://www.cisa.gov/sites/default/files/2024-09/AA24-249A-Russian-Military-Cyber-Actors-Target-US-and-Global-Critical-Infrastructure.stix_.json",
        "02ef014a32c3fd747c5029a4c4bf6cc02adc3d6d32e30ada5d79e65ec3bafbac",
        "CISA joint advisory AA24-249A (GRU Unit 29155)",
        "TLP:CLEAR (disclosure not limited); a work of the U.S. Government and partner agencies",
    ),
    (
        "AA25-141A.stix.json",
        "https://www.cisa.gov/sites/default/files/AA25-141A_Russian_GRU_Targeting_Western_Logistics_Entities_and_Technology_Companies.stix.json",
        "c6102ca1da59c0865a4671f406f36c74a7ed1783c004a0641296655bb7c80dea",
        "CISA joint advisory AA25-141A (GRU unit 26165 targeting logistics entities)",
        "TLP:CLEAR (disclosure not limited); a work of the U.S. Government and partner agencies",
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
    for position, argument in enumerate(argv):
        if argument == "--from-file":
            name_, _, path_ = argv[position + 1].partition("=")
            local[name_] = path_
    previous = (
        {b["file"]: b for b in json.loads(MANIFEST.read_text(encoding="utf-8"))["bundles"]}
        if MANIFEST.is_file()
        else {}
    )
    entries = []
    for name, url, sha256, advisory, reuse in BUNDLES:
        path = OUT_DIR / name
        kept = (
            name not in local
            and path.is_file()
            and hashlib.sha256(path.read_bytes()).hexdigest() == sha256
        )
        if "--verify" not in argv and not kept:
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
                    else {"obtained_via": previous[name]["obtained_via"]}
                    if kept and "obtained_via" in previous.get(name, {})
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
        "approval": "owner instructions 2026-10-09 ('finish all other tasks'; ADR-0013 D1-D2) and "
        "2026-10-11 (advisory bundles for group-specific evidence; ADR-0013 Amendment A)",
        "bundles": entries,
    }
    MANIFEST.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(f"{len(entries)} bundle(s) acquired; manifest {MANIFEST.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
