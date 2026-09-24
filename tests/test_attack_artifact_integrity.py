"""Automated verification for gate G0.1: vendored ATT&CK artifact integrity.

Two groups of tests:

1. End-to-end tests against the REAL vendored MITRE ATT&CK Enterprise v19.0
   artifact committed under data/attack/enterprise/v19.0/ — proving the
   actual artifact is exactly what it claims to be.
2. Fail-closed tests against small, self-consistent SYNTHETIC fixtures
   (not the 50MB real file, for speed) — proving verify_artifact() rejects
   every kind of tampering/mismatch with a specific error, one deliberate
   corruption at a time.

All tests are offline and deterministic: no network access, no Docker, no
Windows-specific APIs, no dependency on Elasticsearch. See
docs/architecture/13-phase-0-implementation-plan.md (G0.1 tests/verify).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from attribution_platform.attack_knowledge.verification import (
    EXPECTED_ARTIFACT_FILENAME,
    EXPECTED_ATTACK_DOMAIN,
    EXPECTED_ATTACK_KB_VERSION,
    EXPECTED_STIX_SPEC,
    VENDORED_ATTACK_ARTIFACTS,
    ArtifactIntegrityError,
    compute_object_fingerprint,
    compute_sha256,
    extract_collection_info,
    load_bundle_objects,
    verify_artifact,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
ATTACK_DATA_DIR = REPO_ROOT / "data" / "attack" / "enterprise"

#: Every vendored release is verified, not only the current pin: artifacts
#: frozen against an older release (calibration corpus v1, fixture rule
#: packs) depend on it staying intact (doc 11 §G retained bundles).
VENDORED = sorted(VENDORED_ATTACK_ARTIFACTS.items())


def _paths(version: str, filename: str) -> tuple[Path, Path, Path]:
    artifact_dir = ATTACK_DATA_DIR / f"v{version.removeprefix('enterprise-attack-')}"
    return artifact_dir, artifact_dir / filename, artifact_dir / "manifest.json"


# ===========================================================================
# Group 1 — the real, vendored artifacts (every registered release)
# ===========================================================================


def test_current_pin_is_a_vendored_release() -> None:
    assert EXPECTED_ATTACK_KB_VERSION in VENDORED_ATTACK_ARTIFACTS
    assert VENDORED_ATTACK_ARTIFACTS[EXPECTED_ATTACK_KB_VERSION] == EXPECTED_ARTIFACT_FILENAME


@pytest.mark.parametrize(("version", "filename"), VENDORED)
def test_1_vendored_artifact_exists_at_expected_project_path(version: str, filename: str) -> None:
    """(1) The artifact, its manifest and its attribution NOTICE exist."""
    artifact_dir, artifact_path, manifest_path = _paths(version, filename)
    assert artifact_path.is_file(), f"missing: {artifact_path}"
    assert manifest_path.is_file(), f"missing: {manifest_path}"
    assert (artifact_dir / "NOTICE.md").is_file(), "missing ATT&CK attribution NOTICE"


@pytest.mark.parametrize(("version", "filename"), VENDORED)
def test_2_sha256_matches_recorded_hash_independently(version: str, filename: str) -> None:
    """(2) A freshly recomputed SHA-256 matches the manifest's recorded hash,
    read from the raw manifest JSON (not echoed back by the code under test)."""
    _, artifact_path, manifest_path = _paths(version, filename)
    manifest_data = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert compute_sha256(artifact_path) == manifest_data["artifact"]["sha256"]


@pytest.mark.parametrize(("version", "filename"), VENDORED)
def test_4_collection_metadata_matches_release(version: str, filename: str) -> None:
    """(3)(4) The bundle parses and carries its own release's collection metadata."""
    _, artifact_path, _ = _paths(version, filename)
    collection = extract_collection_info(load_bundle_objects(artifact_path))
    assert collection.name == "Enterprise ATT&CK"
    assert collection.x_mitre_version == version.removeprefix("enterprise-attack-")
    assert collection.spec_version == "2.1"


@pytest.mark.parametrize(("version", "filename"), VENDORED)
def test_5_artifact_is_not_the_floating_latest_bundle(version: str, filename: str) -> None:
    """(5) Only the versioned filename is vendored, never the floating
    unversioned `enterprise-attack.json` that always tracks "latest"."""
    artifact_dir, _, _ = _paths(version, filename)
    filenames = {p.name for p in artifact_dir.iterdir() if p.is_file()}
    assert "enterprise-attack.json" not in filenames
    assert filename in filenames and filename != "enterprise-attack.json"


@pytest.mark.parametrize(("version", "filename"), VENDORED)
def test_6_object_fingerprint_is_reproducible(version: str, filename: str) -> None:
    """(6) The recorded object fingerprint is reproducible from the raw file."""
    _, artifact_path, manifest_path = _paths(version, filename)
    fingerprint = compute_object_fingerprint(load_bundle_objects(artifact_path))
    recorded = json.loads(manifest_path.read_text(encoding="utf-8"))["object_fingerprint"]
    assert fingerprint.total_objects == recorded["total_objects"]
    assert fingerprint.techniques == recorded["techniques"]
    assert fingerprint.sub_techniques == recorded["sub_techniques"]
    assert fingerprint.groups == recorded["groups"]
    assert fingerprint.relationships == recorded["relationships"]


@pytest.mark.parametrize(("version", "filename"), VENDORED)
def test_full_verify_artifact_passes_end_to_end(version: str, filename: str) -> None:
    """The complete, ordered verification pipeline succeeds on each real artifact."""
    artifact_dir, _, _ = _paths(version, filename)
    manifest = verify_artifact(artifact_dir)
    assert manifest.attack_kb_version == version
    assert manifest.attack_domain == EXPECTED_ATTACK_DOMAIN
    assert manifest.stix_spec == EXPECTED_STIX_SPEC
    assert manifest.artifact_filename == filename
    assert verify_artifact(artifact_dir) == manifest  # deterministic


# ===========================================================================
# Group 2 — fail-closed behavior, via small self-consistent synthetic fixtures
# ===========================================================================


def _build_self_consistent_fixture(tmp_path: Path) -> Path:
    """Build a tiny, internally self-consistent artifact_dir that
    ``verify_artifact`` accepts as-is — a known-good baseline that each
    negative test corrupts in exactly one place."""
    objects: list[dict[str, Any]] = [
        {
            "type": "x-mitre-collection",
            "id": "x-mitre-collection--fixture",
            "name": "Enterprise ATT&CK",
            "x_mitre_version": "19.0",
            "spec_version": "2.1",
            "created": "2020-01-01T00:00:00.000Z",
            "modified": "2020-01-01T00:00:00.000Z",
        },
        {"type": "x-mitre-tactic", "id": "x-mitre-tactic--1"},
        {"type": "attack-pattern", "id": "attack-pattern--1", "x_mitre_is_subtechnique": False},
        {"type": "attack-pattern", "id": "attack-pattern--2", "x_mitre_is_subtechnique": True},
        {"type": "intrusion-set", "id": "intrusion-set--1"},
        {"type": "malware", "id": "malware--1"},
        {"type": "campaign", "id": "campaign--1"},
        {"type": "relationship", "id": "relationship--1"},
    ]
    bundle = {"type": "bundle", "id": "bundle--fixture", "objects": objects}

    artifact_dir = tmp_path / "fixture"
    artifact_dir.mkdir()
    artifact_path = artifact_dir / EXPECTED_ARTIFACT_FILENAME
    artifact_path.write_text(json.dumps(bundle), encoding="utf-8")

    fingerprint = compute_object_fingerprint(objects)
    collection = extract_collection_info(objects)
    manifest = {
        "attack_kb_version": EXPECTED_ATTACK_KB_VERSION,
        "attack_domain": EXPECTED_ATTACK_DOMAIN,
        "stix_spec": EXPECTED_STIX_SPEC,
        "artifact": {
            "filename": EXPECTED_ARTIFACT_FILENAME,
            "relative_path": str(artifact_path),
            "size_bytes": artifact_path.stat().st_size,
            "sha256": compute_sha256(artifact_path),
        },
        "stix_collection": {
            "id": collection.id,
            "name": collection.name,
            "x_mitre_version": collection.x_mitre_version,
            "spec_version": collection.spec_version,
            "created": collection.created,
            "modified": collection.modified,
        },
        "object_fingerprint": {
            "total_objects": fingerprint.total_objects,
            "tactics": fingerprint.tactics,
            "techniques": fingerprint.techniques,
            "sub_techniques": fingerprint.sub_techniques,
            "groups": fingerprint.groups,
            "software_malware": fingerprint.software_malware,
            "software_tool": fingerprint.software_tool,
            "campaigns": fingerprint.campaigns,
            "relationships": fingerprint.relationships,
            "mitigations": fingerprint.mitigations,
            "data_sources": fingerprint.data_sources,
            "data_components": fingerprint.data_components,
            "marking_definitions": fingerprint.marking_definitions,
            "identity": fingerprint.identity,
        },
    }
    (artifact_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return artifact_dir


def test_synthetic_fixture_baseline_is_valid(tmp_path: Path) -> None:
    """Sanity check: the fixture builder itself produces a passing baseline."""
    artifact_dir = _build_self_consistent_fixture(tmp_path)
    manifest = verify_artifact(artifact_dir)
    assert manifest.attack_kb_version == EXPECTED_ATTACK_KB_VERSION


def test_7_fails_closed_on_missing_artifact(tmp_path: Path) -> None:
    """(7) Missing artifact file -> fails closed."""
    artifact_dir = _build_self_consistent_fixture(tmp_path)
    (artifact_dir / EXPECTED_ARTIFACT_FILENAME).unlink()
    with pytest.raises(ArtifactIntegrityError, match="not found"):
        verify_artifact(artifact_dir)


def test_7_fails_closed_on_missing_manifest(tmp_path: Path) -> None:
    """(7) Missing manifest -> fails closed."""
    artifact_dir = _build_self_consistent_fixture(tmp_path)
    (artifact_dir / "manifest.json").unlink()
    with pytest.raises(ArtifactIntegrityError, match="manifest not found"):
        verify_artifact(artifact_dir)


def test_7_fails_closed_on_tampered_artifact_bytes_same_size(tmp_path: Path) -> None:
    """(7) Same-length content change after recording -> SHA-256 mismatch -> fails closed.

    Flips one character in place (rather than appending) so the file size
    stays identical to the manifest-recorded size, specifically exercising
    the SHA-256 check rather than the earlier, cheaper size check.
    """
    artifact_dir = _build_self_consistent_fixture(tmp_path)
    artifact_path = artifact_dir / EXPECTED_ARTIFACT_FILENAME
    original = artifact_path.read_bytes()
    # Flip the last byte (a closing brace/bracket) to a same-length, still
    # differently-hashing byte — content changes, size does not.
    tampered = original[:-1] + (b"0" if original[-1:] != b"0" else b"1")
    artifact_path.write_bytes(tampered)
    assert len(tampered) == len(original)

    with pytest.raises(ArtifactIntegrityError, match="SHA-256 mismatch"):
        verify_artifact(artifact_dir)


def test_7_fails_closed_on_tampered_artifact_size(tmp_path: Path) -> None:
    """(7) Artifact size changed after recording -> fails closed (caught by the size check)."""
    artifact_dir = _build_self_consistent_fixture(tmp_path)
    artifact_path = artifact_dir / EXPECTED_ARTIFACT_FILENAME
    with artifact_path.open("a", encoding="utf-8") as f:
        f.write(" ")  # a single appended byte changes both size and hash
    with pytest.raises(ArtifactIntegrityError, match="bytes != manifest-recorded"):
        verify_artifact(artifact_dir)


def test_7_fails_closed_on_wrong_recorded_hash(tmp_path: Path) -> None:
    """(7) Manifest records a hash that does not match the real artifact -> fails closed."""
    artifact_dir = _build_self_consistent_fixture(tmp_path)
    manifest_path = artifact_dir / "manifest.json"
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    data["artifact"]["sha256"] = "0" * 64
    manifest_path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ArtifactIntegrityError, match="SHA-256 mismatch"):
        verify_artifact(artifact_dir)


def test_7_fails_closed_on_wrong_attack_kb_version(tmp_path: Path) -> None:
    """(7) Manifest claims a different pinned version than this codebase expects -> fails closed."""
    artifact_dir = _build_self_consistent_fixture(tmp_path)
    manifest_path = artifact_dir / "manifest.json"
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    data["attack_kb_version"] = "enterprise-attack-19.1"  # a real release, but not vendored
    manifest_path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ArtifactIntegrityError, match="is not a vendored release"):
        verify_artifact(artifact_dir)


def test_7_fails_closed_on_floating_filename(tmp_path: Path) -> None:
    """(7) Manifest claims the floating/unversioned filename -> rejected outright."""
    artifact_dir = _build_self_consistent_fixture(tmp_path)
    manifest_path = artifact_dir / "manifest.json"
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    data["artifact"]["filename"] = "enterprise-attack.json"
    manifest_path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ArtifactIntegrityError, match="not the expected versioned filename"):
        verify_artifact(artifact_dir)


def test_7_fails_closed_on_tampered_object_fingerprint(tmp_path: Path) -> None:
    """(7) Manifest's recorded fingerprint disagrees with the real bundle -> fails closed."""
    artifact_dir = _build_self_consistent_fixture(tmp_path)
    manifest_path = artifact_dir / "manifest.json"
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    data["object_fingerprint"]["groups"] = 99999
    manifest_path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ArtifactIntegrityError, match="object fingerprint does not match manifest"):
        verify_artifact(artifact_dir)


def test_7_fails_closed_on_tampered_collection_metadata(tmp_path: Path) -> None:
    """(7) Manifest's recorded STIX collection metadata disagrees with reality -> fails closed."""
    artifact_dir = _build_self_consistent_fixture(tmp_path)
    manifest_path = artifact_dir / "manifest.json"
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    data["stix_collection"]["x_mitre_version"] = "1.0"
    manifest_path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(
        ArtifactIntegrityError, match="x-mitre-collection metadata does not match manifest"
    ):
        verify_artifact(artifact_dir)


def test_7_fails_closed_on_wrong_domain(tmp_path: Path) -> None:
    """(7) Manifest claims a non-enterprise domain -> fails closed."""
    artifact_dir = _build_self_consistent_fixture(tmp_path)
    manifest_path = artifact_dir / "manifest.json"
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    data["attack_domain"] = "mobile"
    manifest_path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ArtifactIntegrityError, match="attack_domain"):
        verify_artifact(artifact_dir)


def test_7_fails_closed_on_wrong_stix_spec(tmp_path: Path) -> None:
    """(7) Manifest claims a non-2.1 STIX spec version -> fails closed."""
    artifact_dir = _build_self_consistent_fixture(tmp_path)
    manifest_path = artifact_dir / "manifest.json"
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    data["stix_spec"] = "2.0"
    manifest_path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ArtifactIntegrityError, match="stix_spec"):
        verify_artifact(artifact_dir)


def test_load_bundle_objects_rejects_non_bundle_json() -> None:
    """Untrusted-input handling: a syntactically valid JSON file that is not
    a STIX bundle is rejected, not silently accepted."""
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "not-a-bundle.json"
        path.write_text(json.dumps({"hello": "world"}), encoding="utf-8")
        with pytest.raises(ArtifactIntegrityError, match="not a STIX 'bundle'|expected a STIX"):
            load_bundle_objects(path)
