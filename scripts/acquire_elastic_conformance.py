#!/usr/bin/env python3
"""Acquire Elastic's ingest pipelines and pipeline test fixtures (ADR-0015).

Runs only when a human invokes it. For each data stream this platform translates
Elastic rules for, Elastic's integration ships the ingest pipeline and
``_dev/test/pipeline`` fixtures: raw input events and the ECS documents the
pipeline must produce. They are the conformance oracle for the derived views in
``attribution_platform.detection`` (``tests/test_elastic_*_conformance.py``).

Every file is fetched raw from ``elastic/integrations`` **at the pinned commit**
and refused unless its content hashes to the git blob id the commit's tree lists.
Files go to ``data/detection/elastic/conformance/<stream>/`` (tracked) with a
``manifest.json`` recording path, blob id, size and SHA-256. Nothing is executed.

    python scripts/acquire_elastic_conformance.py <stream> [...]
    python scripts/acquire_elastic_conformance.py --verify
"""

from __future__ import annotations

import concurrent.futures
import datetime as dt
import hashlib
import json
import sys
import urllib.request
from pathlib import Path

REPO = "elastic/integrations"
COMMIT = "ff5328128a30c75046130ae58ddba450caa1f2dc"
REPO_ROOT = Path(__file__).resolve().parents[1]
OUT = REPO_ROOT / "data" / "detection" / "elastic" / "conformance"

#: stream -> (pipeline directory, fixture directory) in the integrations repo.
STREAMS: dict[str, tuple[str, str]] = {
    "aws_cloudtrail": (
        "packages/aws/data_stream/cloudtrail/elasticsearch/ingest_pipeline",
        "packages/aws/data_stream/cloudtrail/_dev/test/pipeline",
    ),
    "o365_audit": (
        "packages/o365/data_stream/audit/elasticsearch/ingest_pipeline",
        "packages/o365/data_stream/audit/_dev/test/pipeline",
    ),
    "azure_auditlogs": (
        "packages/azure/data_stream/auditlogs/elasticsearch/ingest_pipeline",
        "packages/azure/data_stream/auditlogs/_dev/test/pipeline",
    ),
    "azure_signinlogs": (
        "packages/azure/data_stream/signinlogs/elasticsearch/ingest_pipeline",
        "packages/azure/data_stream/signinlogs/_dev/test/pipeline",
    ),
    "okta_system": (
        "packages/okta/data_stream/system/elasticsearch/ingest_pipeline",
        "packages/okta/data_stream/system/_dev/test/pipeline",
    ),
    "github_audit": (
        "packages/github/data_stream/audit/elasticsearch/ingest_pipeline",
        "packages/github/data_stream/audit/_dev/test/pipeline",
    ),
    "kubernetes_audit_logs": (
        "packages/kubernetes/data_stream/audit_logs/elasticsearch/ingest_pipeline",
        "packages/kubernetes/data_stream/audit_logs/_dev/test/pipeline",
    ),
    "system_security": (
        "packages/system/data_stream/security/elasticsearch/ingest_pipeline",
        "packages/system/data_stream/security/_dev/test/pipeline",
    ),
}


def _get(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "soc-apt-attribution-platform/0.0.0"})
    with urllib.request.urlopen(req, timeout=120) as resp:  # noqa: S310 - fixed https URL, GET only
        if resp.status != 200:
            raise RuntimeError(f"HTTP {resp.status} for {url}")
        return bytes(resp.read())


def _blob_id(content: bytes) -> str:
    return hashlib.sha1(b"blob %d\0" % len(content) + content).hexdigest()  # noqa: S324 - git id


def _listing(directory: str) -> list[dict[str, str]]:
    listing = json.loads(
        _get(f"https://api.github.com/repos/{REPO}/contents/{directory}?ref={COMMIT}")
    )
    return [e for e in listing if e["type"] == "file"]


def _fetch(args: tuple[str, str, dict[str, str]]) -> dict[str, object]:
    stream, kind, entry = args
    content = _get(f"https://raw.githubusercontent.com/{REPO}/{COMMIT}/{entry['path']}")
    if _blob_id(content) != entry["sha"]:
        raise RuntimeError(f"{entry['path']}: content differs from the commit's blob — refusing")
    content.decode("utf-8")  # text only
    relative = f"{kind}/{entry['name']}"
    dest = OUT / stream / relative
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(content)
    return {
        "path": relative,
        "upstream_path": entry["path"],
        "blob_id": entry["sha"],
        "size_bytes": len(content),
        "sha256": hashlib.sha256(content).hexdigest(),
    }


def acquire(stream: str) -> None:
    pipeline_dir, fixture_dir = STREAMS[stream]
    jobs = [(stream, "pipeline", e) for e in _listing(pipeline_dir)] + [
        (stream, "fixtures", e) for e in _listing(fixture_dir)
    ]
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        files = sorted(pool.map(_fetch, jobs), key=lambda f: str(f["path"]))
    manifest = {
        "source": f"{REPO} (Elastic integration ingest pipeline and pipeline test fixtures)",
        "source_commit": COMMIT,
        "license": "Elastic License 2.0",
        "license_url": f"https://github.com/{REPO}/blob/{COMMIT}/LICENSE.txt",
        "retrieved_at_utc": dt.datetime.now(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "method": "scripts/acquire_elastic_conformance.py (commit-pinned; each file verified "
        "against its git blob id)",
        "approval": "owner instruction 2026-10-10 (extend Elastic rules to further log sources)",
        "purpose": "Conformance oracle for the derived ECS views of this data stream (ADR-0015).",
        "files": files,
    }
    (OUT / stream / "manifest.json").write_text(
        json.dumps(manifest, indent=1) + "\n", encoding="utf-8", newline="\n"
    )
    total = sum(int(f["size_bytes"]) for f in files)  # type: ignore[call-overload]
    print(f"{stream}: {len(files)} files, {total:,} bytes")


def verify() -> int:
    count = 0
    for manifest_path in sorted(OUT.glob("*/manifest.json")):
        for item in json.loads(manifest_path.read_text(encoding="utf-8"))["files"]:
            raw = (manifest_path.parent / item["path"]).read_bytes()
            if hashlib.sha256(raw).hexdigest() != item["sha256"]:
                print(f"MISMATCH {manifest_path.parent.name}/{item['path']}")
                return 1
            count += 1
    print(f"{count} conformance files verified")
    return 0


def main(argv: list[str]) -> int:
    if "--verify" in argv:
        return verify()
    for stream in argv:
        if stream not in STREAMS:
            print(f"unknown stream {stream!r}; known: {sorted(STREAMS)}")
            return 2
    for stream in argv:
        acquire(stream)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
