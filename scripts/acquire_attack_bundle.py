#!/usr/bin/env python3
"""Acquire and hash-verify an official MITRE ATT&CK STIX 2.1 release bundle.

This is the ONE place in this repository that talks to a live MITRE/GitHub
service, and it runs only when explicitly invoked by a human — never at
application runtime. It exists to make artifact acquisition reproducible and
auditable (see docs/architecture/11-attack-knowledge-versioning.md), not to
be part of the running system.

Default usage (acquires the pinned C0.1 baseline, MITRE ATT&CK Enterprise
v19.0):

    python scripts/acquire_attack_bundle.py

This downloads the *tag-pinned* raw file from `mitre-attack/attack-stix-data`
(never the floating unversioned `enterprise-attack.json`, never a live TAXII
endpoint), verifies it is well-formed JSON (no code execution of any kind —
the file is treated as untrusted input throughout), computes its SHA-256 and
STIX/object-fingerprint metadata, and writes:

  data/attack/<domain>/<tag>/<filename>   the vendored, immutable artifact
  data/attack/<domain>/<tag>/manifest.json  the frozen acquisition record

A NOTICE.md (MITRE ATT&CK Terms of Use attribution) must already exist
alongside the artifact — this script does not create or overwrite it.

Re-running this script for the SAME tag is a legitimate way to independently
verify a previously vendored artifact's integrity (a fresh download should
reproduce the identical SHA-256). Running it for a DIFFERENT tag is how a
future, deliberate ATT&CK version upgrade begins — per
docs/architecture/11-attack-knowledge-versioning.md §G, that is a reviewed
process (KB-diff, recalibration, corpus validation, explicit approval), not
something this script performs automatically. This script only acquires and
verifies; it does not decide to upgrade anything.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
import urllib.request
from collections import Counter
from pathlib import Path
from typing import Any

REPO = "mitre-attack/attack-stix-data"
DEFAULT_TAG = "v19.0"
DEFAULT_DOMAIN = "enterprise"
DEFAULT_STIX_SPEC = "2.1"

REPO_ROOT = Path(__file__).resolve().parents[1]


def artifact_filename(domain: str, version: str) -> str:
    return f"{domain}-attack-{version}.json"


def raw_download_url(tag: str, domain: str, filename: str) -> str:
    # Pinned to the git TAG ref — never the "master" branch and never the
    # unversioned floating bundle — so re-fetching reproduces the same
    # immutable tagged content.
    return f"https://raw.githubusercontent.com/{REPO}/{tag}/{domain}-attack/{filename}"


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
        tmp.replace(dest)  # atomic on the same filesystem; avoids a half-written artifact


def load_and_validate_bundle(path: Path) -> dict[str, Any]:
    """Parse as JSON only (no exec/eval/pickle) and validate minimal STIX shape."""
    with path.open("r", encoding="utf-8") as f:
        bundle = json.load(f)
    if not isinstance(bundle, dict) or bundle.get("type") != "bundle":
        raise ValueError(f"{path}: not a STIX 'bundle' object")
    objects = bundle.get("objects")
    if not isinstance(objects, list) or not objects:
        raise ValueError(f"{path}: STIX bundle has no non-empty 'objects' array")
    return bundle


def extract_collection(objects: list[dict[str, Any]]) -> dict[str, Any]:
    collections = [o for o in objects if o.get("type") == "x-mitre-collection"]
    if len(collections) != 1:
        raise ValueError(f"expected exactly 1 x-mitre-collection object, found {len(collections)}")
    return collections[0]


def compute_fingerprint(objects: list[dict[str, Any]]) -> dict[str, int]:
    type_counts: Counter[str] = Counter(str(o.get("type")) for o in objects)
    techniques = [o for o in objects if o.get("type") == "attack-pattern"]
    sub_techniques = sum(1 for t in techniques if t.get("x_mitre_is_subtechnique") is True)
    return {
        "total_objects": len(objects),
        "tactics": type_counts.get("x-mitre-tactic", 0),
        "techniques": len(techniques) - sub_techniques,
        "sub_techniques": sub_techniques,
        "groups": type_counts.get("intrusion-set", 0),
        "software_malware": type_counts.get("malware", 0),
        "software_tool": type_counts.get("tool", 0),
        "campaigns": type_counts.get("campaign", 0),
        "relationships": type_counts.get("relationship", 0),
        "mitigations": type_counts.get("course-of-action", 0),
        "data_sources": type_counts.get("x-mitre-data-source", 0),
        "data_components": type_counts.get("x-mitre-data-component", 0),
        "marking_definitions": type_counts.get("marking-definition", 0),
        "identity": type_counts.get("identity", 0),
    }


def sha256_of(path: Path) -> str:
    import hashlib

    h = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(1024 * 1024):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--tag", default=DEFAULT_TAG, help=f"release tag to acquire (default: {DEFAULT_TAG})"
    )
    parser.add_argument(
        "--domain", default=DEFAULT_DOMAIN, help=f"ATT&CK domain (default: {DEFAULT_DOMAIN})"
    )
    parser.add_argument(
        "--version",
        default=None,
        help=(
            "version string for the filename, e.g. '19.0' "
            "(default: derived by stripping a leading 'v' from --tag)"
        ),
    )
    args = parser.parse_args()

    version = args.version or args.tag.lstrip("v")
    filename = artifact_filename(args.domain, version)
    url = raw_download_url(args.tag, args.domain, filename)

    out_dir = REPO_ROOT / "data" / "attack" / args.domain / args.tag
    artifact_path = out_dir / filename
    manifest_path = out_dir / "manifest.json"
    notice_path = out_dir / "NOTICE.md"

    download(url, artifact_path)

    actual_size = artifact_path.stat().st_size
    actual_sha256 = sha256_of(artifact_path)
    bundle = load_and_validate_bundle(artifact_path)
    objects = bundle["objects"]
    collection = extract_collection(objects)
    fingerprint = compute_fingerprint(objects)

    manifest = {
        "attack_kb_version": f"{args.domain}-attack-{version}",
        "attack_domain": args.domain,
        "stix_spec": DEFAULT_STIX_SPEC,
        "artifact": {
            "filename": filename,
            "relative_path": f"data/attack/{args.domain}/{args.tag}/{filename}",
            "size_bytes": actual_size,
            "sha256": actual_sha256,
        },
        "stix_collection": {
            "id": collection.get("id"),
            "name": collection.get("name"),
            "x_mitre_version": collection.get("x_mitre_version"),
            "spec_version": collection.get("spec_version"),
            "created": collection.get("created"),
            "modified": collection.get("modified"),
        },
        "object_fingerprint": fingerprint,
        "source": {
            "repository": REPO,
            "release_tag": args.tag,
            "repo_path": f"{args.domain}-attack/{filename}",
            "download_url": url,
            "github_release_url": f"https://github.com/{REPO}/releases/tag/{args.tag}",
        },
        "acquisition": {
            "retrieved_at_utc": dt.datetime.now(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "method": "scripts/acquire_attack_bundle.py (urllib, tag-pinned raw URL)",
        },
        "attribution": {
            "terms_of_use_url": "https://attack.mitre.org/resources/terms-of-use/",
            "notice_file": f"data/attack/{args.domain}/{args.tag}/NOTICE.md",
        },
    }

    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    print(f"\nArtifact:  {artifact_path}  ({actual_size:,} bytes)")
    print(f"SHA-256:   {actual_sha256}")
    print(
        f"Collection: {collection.get('name')} v{collection.get('x_mitre_version')} "
        f"(STIX {collection.get('spec_version')})"
    )
    print(f"Fingerprint: {fingerprint}")
    print(f"Manifest written: {manifest_path}")
    if not notice_path.is_file():
        print(
            f"\nWARNING: {notice_path} does not exist. This script does not create it — "
            "add an ATT&CK Terms of Use NOTICE manually before treating this artifact as "
            "attribution-complete (see docs/architecture/11-attack-knowledge-versioning.md §0)."
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
