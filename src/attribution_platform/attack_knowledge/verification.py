"""Offline, fail-closed integrity verification for the vendored ATT&CK artifact.

Scope (gate G0.1 only — see docs/architecture/13-phase-0-implementation-plan.md):
verifies that the vendored MITRE ATT&CK Enterprise v19.0 STIX 2.1 bundle
(data/attack/enterprise/v19.0/enterprise-attack-19.0.json) matches its
recorded manifest (SHA-256, STIX collection metadata, object fingerprint).

This module is deliberately NOT the ATT&CK loader/query abstraction —
there is no technique/group/software lookup API here. That is gate G0.2's
job (docs/architecture/13-phase-0-implementation-plan.md). This module only
answers one question: "is the vendored artifact exactly what it claims to
be?" — and fails closed (raises) if not.

Design note on "no hard-coded ATT&CK vocabulary": ``EXPECTED_ATTACK_KB_VERSION``
below is a *pin identifier* — our own deliberate, documented choice of which
release to trust (recorded in docs/architecture/11-attack-knowledge-versioning.md,
C0.1) — analogous to a lockfile version pin. It is not ATT&CK *content*
(no technique ID, tactic name, or group name is hard-coded anywhere here or
downstream); the actual knowledge content is always read from the bundle.

No network access occurs anywhere in this module.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

#: The ATT&CK knowledge-base version this codebase is pinned to (C0.1,
#: ACCEPTED). Changing this is a deliberate upgrade decision, never a
#: silent/automatic one — see docs/architecture/11-attack-knowledge-versioning.md §G.
EXPECTED_ATTACK_KB_VERSION = "enterprise-attack-19.0"
EXPECTED_ATTACK_DOMAIN = "enterprise"
EXPECTED_STIX_SPEC = "2.1"

#: The versioned (non-floating) artifact filename we require. Guards against
#: ever accidentally loading the unversioned "latest" bundle under this path.
EXPECTED_ARTIFACT_FILENAME = "enterprise-attack-19.0.json"

_ARTIFACT_TYPE_TAG = "attack-pattern"


class ArtifactIntegrityError(Exception):
    """Raised when the vendored ATT&CK artifact fails integrity verification.

    This is a fail-closed signal: callers (this gate's tests, and later
    gate G0.2's loader) must treat this as fatal and refuse to proceed —
    never silently fall back to a different artifact or a live service.
    """


@dataclass(frozen=True)
class ObjectFingerprint:
    """Raw (unfiltered) object-type counts over the STIX bundle.

    Deliberately counts *every* object of each type, including any marked
    ``revoked`` or ``x_mitre_deprecated`` — the simplest, least-ambiguous
    definition for a tamper/format sanity gate (see the manifest's
    ``fingerprint_notes`` for the independent active-only cross-check used
    only as a sanity check against published figures, not as the
    reproducibility-critical value).
    """

    total_objects: int
    tactics: int
    techniques: int
    sub_techniques: int
    groups: int
    software_malware: int
    software_tool: int
    campaigns: int
    relationships: int
    mitigations: int
    data_sources: int
    data_components: int
    marking_definitions: int
    identity: int


@dataclass(frozen=True)
class StixCollectionInfo:
    """The bundle's single ``x-mitre-collection`` object, as recorded."""

    id: str
    name: str
    x_mitre_version: str
    spec_version: str
    created: str
    modified: str


@dataclass(frozen=True)
class ArtifactManifest:
    """The frozen, recorded acquisition metadata for the vendored artifact."""

    attack_kb_version: str
    attack_domain: str
    stix_spec: str
    artifact_filename: str
    artifact_relative_path: str
    artifact_size_bytes: int
    artifact_sha256: str
    stix_collection: StixCollectionInfo
    object_fingerprint: ObjectFingerprint


def compute_sha256(path: Path) -> str:
    """Compute the SHA-256 of a file's raw bytes (streamed, no size limit)."""
    digest = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def load_bundle_objects(path: Path) -> list[dict[str, Any]]:
    """Parse the STIX bundle's ``objects`` array using only ``json.load``.

    The file is treated as untrusted input: this performs a plain JSON
    parse (no ``eval``, no ``pickle``, no dynamic code execution of any
    kind) and validates the minimal STIX bundle shape before returning the
    object list.
    """
    with path.open("r", encoding="utf-8") as f:
        bundle = json.load(f)

    if not isinstance(bundle, dict):
        raise ArtifactIntegrityError(f"{path}: top-level JSON value is not an object")
    if bundle.get("type") != "bundle":
        raise ArtifactIntegrityError(
            f"{path}: expected a STIX 'bundle' object, got type={bundle.get('type')!r}"
        )
    objects = bundle.get("objects")
    if not isinstance(objects, list) or not objects:
        raise ArtifactIntegrityError(f"{path}: STIX bundle has no non-empty 'objects' array")
    return objects


def compute_object_fingerprint(objects: list[dict[str, Any]]) -> ObjectFingerprint:
    """Compute the raw object-type fingerprint from parsed STIX objects."""
    type_counts: Counter[str] = Counter(str(o.get("type")) for o in objects)

    techniques = [o for o in objects if o.get("type") == _ARTIFACT_TYPE_TAG]
    sub_techniques = sum(1 for t in techniques if t.get("x_mitre_is_subtechnique") is True)
    base_techniques = len(techniques) - sub_techniques

    return ObjectFingerprint(
        total_objects=len(objects),
        tactics=type_counts.get("x-mitre-tactic", 0),
        techniques=base_techniques,
        sub_techniques=sub_techniques,
        groups=type_counts.get("intrusion-set", 0),
        software_malware=type_counts.get("malware", 0),
        software_tool=type_counts.get("tool", 0),
        campaigns=type_counts.get("campaign", 0),
        relationships=type_counts.get("relationship", 0),
        mitigations=type_counts.get("course-of-action", 0),
        data_sources=type_counts.get("x-mitre-data-source", 0),
        data_components=type_counts.get("x-mitre-data-component", 0),
        marking_definitions=type_counts.get("marking-definition", 0),
        identity=type_counts.get("identity", 0),
    )


def extract_collection_info(objects: list[dict[str, Any]]) -> StixCollectionInfo:
    """Extract the single ``x-mitre-collection`` object's identifying fields."""
    collections = [o for o in objects if o.get("type") == "x-mitre-collection"]
    if len(collections) != 1:
        raise ArtifactIntegrityError(
            f"expected exactly 1 x-mitre-collection object, found {len(collections)}"
        )
    c = collections[0]
    try:
        return StixCollectionInfo(
            id=str(c["id"]),
            name=str(c["name"]),
            x_mitre_version=str(c["x_mitre_version"]),
            spec_version=str(c["spec_version"]),
            created=str(c["created"]),
            modified=str(c["modified"]),
        )
    except KeyError as exc:
        raise ArtifactIntegrityError(
            f"x-mitre-collection object missing required field: {exc}"
        ) from exc


def load_manifest(manifest_path: Path) -> ArtifactManifest:
    """Load and parse the recorded ``manifest.json`` for a vendored artifact."""
    if not manifest_path.is_file():
        raise ArtifactIntegrityError(f"manifest not found: {manifest_path}")

    with manifest_path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    try:
        artifact = data["artifact"]
        collection = data["stix_collection"]
        fingerprint = data["object_fingerprint"]
        return ArtifactManifest(
            attack_kb_version=data["attack_kb_version"],
            attack_domain=data["attack_domain"],
            stix_spec=data["stix_spec"],
            artifact_filename=artifact["filename"],
            artifact_relative_path=artifact["relative_path"],
            artifact_size_bytes=artifact["size_bytes"],
            artifact_sha256=artifact["sha256"],
            stix_collection=StixCollectionInfo(
                id=collection["id"],
                name=collection["name"],
                x_mitre_version=collection["x_mitre_version"],
                spec_version=collection["spec_version"],
                created=collection["created"],
                modified=collection["modified"],
            ),
            object_fingerprint=ObjectFingerprint(
                total_objects=fingerprint["total_objects"],
                tactics=fingerprint["tactics"],
                techniques=fingerprint["techniques"],
                sub_techniques=fingerprint["sub_techniques"],
                groups=fingerprint["groups"],
                software_malware=fingerprint["software_malware"],
                software_tool=fingerprint["software_tool"],
                campaigns=fingerprint["campaigns"],
                relationships=fingerprint["relationships"],
                mitigations=fingerprint["mitigations"],
                data_sources=fingerprint["data_sources"],
                data_components=fingerprint["data_components"],
                marking_definitions=fingerprint["marking_definitions"],
                identity=fingerprint["identity"],
            ),
        )
    except KeyError as exc:
        raise ArtifactIntegrityError(f"{manifest_path}: missing required field: {exc}") from exc


def verify_artifact(artifact_dir: Path) -> ArtifactManifest:
    """Fail-closed verification of the vendored ATT&CK artifact in ``artifact_dir``.

    Checks, in order (raising :class:`ArtifactIntegrityError` with a specific
    message on the first failure):

    1. the manifest and the artifact file both exist at the expected paths;
    2. the manifest's recorded ``attack_kb_version``/``attack_domain``/
       ``stix_spec`` match the pinned baseline this codebase expects;
    3. the artifact filename is the *versioned* filename (never the floating
       unversioned bundle);
    4. the artifact's actual size matches the manifest;
    5. the artifact's freshly recomputed SHA-256 matches the manifest;
    6. the artifact parses as a valid STIX 2.1 bundle (safe ``json.load`` only);
    7. the bundle's actual ``x-mitre-collection`` metadata (id, version,
       spec_version) matches the manifest;
    8. the bundle's freshly recomputed object fingerprint matches the manifest.

    Performs no network access. Returns the validated manifest on success.
    """
    manifest_path = artifact_dir / "manifest.json"
    manifest = load_manifest(manifest_path)

    if manifest.attack_kb_version != EXPECTED_ATTACK_KB_VERSION:
        raise ArtifactIntegrityError(
            f"manifest attack_kb_version={manifest.attack_kb_version!r} does not match "
            f"the pinned baseline {EXPECTED_ATTACK_KB_VERSION!r} this codebase expects"
        )
    if manifest.attack_domain != EXPECTED_ATTACK_DOMAIN:
        raise ArtifactIntegrityError(
            f"manifest attack_domain={manifest.attack_domain!r} != {EXPECTED_ATTACK_DOMAIN!r}"
        )
    if manifest.stix_spec != EXPECTED_STIX_SPEC:
        raise ArtifactIntegrityError(
            f"manifest stix_spec={manifest.stix_spec!r} != {EXPECTED_STIX_SPEC!r}"
        )
    if manifest.artifact_filename != EXPECTED_ARTIFACT_FILENAME:
        raise ArtifactIntegrityError(
            f"manifest artifact_filename={manifest.artifact_filename!r} is not the expected "
            f"versioned filename {EXPECTED_ARTIFACT_FILENAME!r} — refusing to trust an "
            "unversioned/floating bundle under this path"
        )

    artifact_path = artifact_dir / manifest.artifact_filename
    if not artifact_path.is_file():
        raise ArtifactIntegrityError(f"vendored artifact not found: {artifact_path}")

    actual_size = artifact_path.stat().st_size
    if actual_size != manifest.artifact_size_bytes:
        raise ArtifactIntegrityError(
            f"{artifact_path}: size {actual_size} bytes != manifest-recorded "
            f"{manifest.artifact_size_bytes} bytes"
        )

    actual_sha256 = compute_sha256(artifact_path)
    if actual_sha256 != manifest.artifact_sha256:
        raise ArtifactIntegrityError(
            f"{artifact_path}: SHA-256 mismatch — recomputed {actual_sha256}, "
            f"manifest records {manifest.artifact_sha256}. The artifact may have been "
            "modified, corrupted, or substituted."
        )

    objects = load_bundle_objects(artifact_path)

    actual_collection = extract_collection_info(objects)
    if (
        actual_collection.id != manifest.stix_collection.id
        or actual_collection.x_mitre_version != manifest.stix_collection.x_mitre_version
        or actual_collection.spec_version != manifest.stix_collection.spec_version
    ):
        raise ArtifactIntegrityError(
            f"{artifact_path}: x-mitre-collection metadata does not match manifest "
            f"(actual={actual_collection!r}, manifest={manifest.stix_collection!r})"
        )

    actual_fingerprint = compute_object_fingerprint(objects)
    if actual_fingerprint != manifest.object_fingerprint:
        raise ArtifactIntegrityError(
            f"{artifact_path}: object fingerprint does not match manifest "
            f"(actual={actual_fingerprint!r}, manifest={manifest.object_fingerprint!r})"
        )

    return manifest
