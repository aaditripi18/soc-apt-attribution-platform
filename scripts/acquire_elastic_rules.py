#!/usr/bin/env python3
"""Acquire Elastic's prebuilt detection rules at a pinned commit (ADR-0015).

Runs only when a human invokes it — never at application runtime. The rules live
in ``elastic/detection-rules`` (Elastic License 2.0) as TOML files under
``rules/`` and ``rules_building_block/``; tagged releases stop at v8.6.0 (2023),
so a ``main`` commit is pinned. Every file is fetched raw **at that commit** and
refused unless its content hashes to the git blob id the commit's tree lists for
it (``sha1("blob <size>\\0" + content)``). Deprecated rules (``rules/_deprecated``)
are not taken. Files go to the git-ignored cache
``data/cache/elastic-detection-rules/``; the tracked manifest
``data/detection/elastic/manifest.json`` records the commit, licence, and every
file's path, blob id, size and SHA-256. Nothing is executed: rules are text.

    python scripts/acquire_elastic_rules.py            # download + verify
    python scripts/acquire_elastic_rules.py --verify   # verify the cache only
"""

from __future__ import annotations

import concurrent.futures
import datetime as dt
import hashlib
import json
import sys
import urllib.request
from pathlib import Path

REPO = "elastic/detection-rules"
COMMIT = "195f15c0bac84540bfe47abb8e26dbf8184eb69a"
REPO_ROOT = Path(__file__).resolve().parents[1]
CACHE = REPO_ROOT / "data" / "cache" / "elastic-detection-rules" / COMMIT[:12]
MANIFEST = REPO_ROOT / "data" / "detection" / "elastic" / "manifest.json"
PREFIXES = ("rules/", "rules_building_block/")
#: Elastic's own KQL parser and KQL-to-EQL converter (``lib/kql``, same licence and
#: commit), used by the build-time importer so every rule is parsed by Elastic's code.
KQL_LIB = "lib/kql/"
EXCLUDED = ("rules/_deprecated/",)


def _get(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "soc-apt-attribution-platform/0.0.0"})
    with urllib.request.urlopen(req, timeout=120) as resp:  # noqa: S310 - fixed https URL, GET only
        if resp.status != 200:
            raise RuntimeError(f"HTTP {resp.status} for {url}")
        return bytes(resp.read())


def _blob_id(content: bytes) -> str:
    return hashlib.sha1(b"blob %d\0" % len(content) + content).hexdigest()  # noqa: S324 - git id


def _fetch(entry: dict[str, str]) -> dict[str, object]:
    path = entry["path"]
    dest = CACHE / path
    if dest.is_file() and _blob_id(dest.read_bytes()) == entry["sha"]:
        content = dest.read_bytes()
    else:
        content = _get(f"https://raw.githubusercontent.com/{REPO}/{COMMIT}/{path}")
        if _blob_id(content) != entry["sha"]:
            raise RuntimeError(f"{path}: content differs from the commit's blob — refusing")
        content.decode("utf-8")  # text only (rules, parser source, grammar)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(content)
    return {
        "path": path,
        "blob_id": entry["sha"],
        "size_bytes": len(content),
        "sha256": hashlib.sha256(content).hexdigest(),
    }


def main(argv: list[str]) -> int:
    if "--verify" in argv:
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        for item in manifest["files"]:
            if hashlib.sha256((CACHE / item["path"]).read_bytes()).hexdigest() != item["sha256"]:
                print(f"MISMATCH {item['path']}")
                return 1
        print(f"{len(manifest['files'])} cached rule files verified")
        return 0
    tree = json.loads(_get(f"https://api.github.com/repos/{REPO}/git/trees/{COMMIT}?recursive=1"))
    if tree.get("truncated"):
        raise RuntimeError("the tree listing is truncated — refusing to verify against it")
    entries = [
        e
        for e in tree["tree"]
        if e["type"] == "blob"
        and (
            (
                e["path"].endswith(".toml")
                and e["path"].startswith(PREFIXES)
                and not e["path"].startswith(EXCLUDED)
            )
            or (e["path"].startswith(KQL_LIB) and e["path"].endswith((".py", ".toml", ".g")))
        )
    ]
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        files = sorted(pool.map(_fetch, entries), key=lambda f: str(f["path"]))
    licence = _get(f"https://raw.githubusercontent.com/{REPO}/{COMMIT}/LICENSE.txt")
    manifest = {
        "source": f"{REPO} (Elastic prebuilt detection rules)",
        "source_commit": COMMIT,
        "license": "Elastic License 2.0",
        "license_url": f"https://github.com/{REPO}/blob/{COMMIT}/LICENSE.txt",
        "license_sha256": hashlib.sha256(licence).hexdigest(),
        "retrieved_at_utc": dt.datetime.now(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "method": "scripts/acquire_elastic_rules.py (commit-pinned; each file verified against "
        "its git blob id)",
        "approval": "owner request 2026-10-09 ('add elastic prebuilt rules to increase coverage')",
        "selection": "rules/** and rules_building_block/** *.toml, minus rules/_deprecated; "
        "lib/kql/** (Elastic's KQL parser)",
        "cache": "data/cache/elastic-detection-rules/ (git-ignored; rebuild with this script)",
        "files": files,
    }
    MANIFEST.parent.mkdir(parents=True, exist_ok=True)
    MANIFEST.write_text(json.dumps(manifest, indent=1) + "\n", encoding="utf-8", newline="\n")
    total = sum(int(f["size_bytes"]) for f in files)  # type: ignore[call-overload]
    print(f"{len(files)} rule files, {total:,} bytes; manifest {MANIFEST.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
