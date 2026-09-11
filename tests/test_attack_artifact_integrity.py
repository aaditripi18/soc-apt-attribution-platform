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
    ArtifactIntegrityError,
    compute_object_fingerprint,
    compute_sha256,
    extract_collection_info,
    load_bundle_objects,
    verify_artifact,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
VENDORED_ARTIFACT_DIR = REPO_ROOT / "data" / "attack" / "enterprise" / "v19.0"
VENDORED_ARTIFACT_PATH = VENDORED_ARTIFACT_DIR / EXPECTED_ARTIFACT_FILENAME
VENDORED_MANIFEST_PATH = VENDORED_ARTIFACT_DIR / "manifest.json"


# ===========================================================================
# Group 1 — the real, vendored v19.0 artifact
# ===========================================================================


def test_1_vendored_artifact_exists_at_expected_project_path() -> None:
    """(1) The artifact exists at the expected, explicit project path."""
    assert VENDORED_ARTIFACT_PATH.is_file(), f"missing: {VENDORED_ARTIFACT_PATH}"
    assert VENDORED_MANIFEST_PATH.is_file(), f"missing: {VENDORED_MANIFEST_PATH}"
    assert (VENDORED_ARTIFACT_DIR / "NOTICE.md").is_file(), "missing ATT&CK attribution NOTICE"


def test_2_sha256_matches_recorded_hash_independently() -> None:
    """(2) A freshly recomputed SHA-256 matches the manifest's recorded hash.

    Reads the manifest's raw JSON directly (bypassing verify_artifact's own
    comparison) as an independent double-check that the recorded value is
    not simply being echoed back by the code under test.
    """
    manifest_data = json.loads(VENDORED_MANIFEST_PATH.read_text(encoding="utf-8"))
    recorded_sha256 = manifest_data["artifact"]["sha256"]
    assert compute_sha256(VENDORED_ARTIFACT_PATH) == recorded_sha256
    # Recomputing twice must be deterministic.
    assert compute_sha256(VENDORED_ARTIFACT_PATH) == compute_sha256(VENDORED_ARTIFACT_PATH)


def test_3_bundle_parses_successfully_as_stix() -> None:
    """(3) The STIX bundle parses successfully (safe json.load only)."""
    objects = load_bundle_objects(VENDORED_ARTIFACT_PATH)
    assert len(objects) > 0
    assert any(o.get("type") == "x-mitre-collection" for o in objects)


def test_4_collection_metadata_is_enterprise_v19_0() -> None:
    """(4) The expected Enterprise ATT&CK v19.0 collection/version metadata is present."""
    objects = load_bundle_objects(VENDORED_ARTIFACT_PATH)
    collection = extract_collection_info(objects)
    assert collection.name == "Enterprise ATT&CK"
    assert collection.x_mitre_version == "19.0"
    assert collection.spec_version == "2.1"


def test_5_artifact_is_not_the_floating_latest_bundle() -> None:
    """(5) The vendored file is the versioned filename, never the floating
    unversioned `enterprise-attack.json` that always tracks "latest"."""
    filenames = {p.name for p in VENDORED_ARTIFACT_DIR.iterdir() if p.is_file()}
    assert (
        "enterprise-attack.json" not in filenames
    ), "the floating/unversioned bundle must never be vendored alongside the pinned artifact"
    assert EXPECTED_ARTIFACT_FILENAME in filenames
    assert EXPECTED_ARTIFACT_FILENAME != "enterprise-attack.json"


def test_6_object_fingerprint_is_reproducible() -> None:
    """(6) The recorded object-count/fingerprint is reproducible from the raw file."""
    objects = load_bundle_objects(VENDORED_ARTIFACT_PATH)
    fingerprint_a = compute_object_fingerprint(objects)
    fingerprint_b = compute_object_fingerprint(objects)
    assert fingerprint_a == fingerprint_b, "fingerprint computation must be deterministic"

    manifest_data = json.loads(VENDORED_MANIFEST_PATH.read_text(encoding="utf-8"))
    recorded = manifest_data["object_fingerprint"]
    assert fingerprint_a.total_objects == recorded["total_objects"]
    assert fingerprint_a.tactics == recorded["tactics"]
    assert fingerprint_a.techniques == recorded["techniques"]
    assert fingerprint_a.sub_techniques == recorded["sub_techniques"]
    assert fingerprint_a.groups == recorded["groups"]
    assert fingerprint_a.relationships == recorded["relationships"]


def test_full_verify_artifact_passes_end_to_end() -> None:
    """The complete, ordered verification pipeline succeeds on the real artifact."""
    manifest = verify_artifact(VENDORED_ARTIFACT_DIR)
    assert manifest.attack_kb_version == EXPECTED_ATTACK_KB_VERSION
    assert manifest.attack_domain == EXPECTED_ATTACK_DOMAIN
    assert manifest.stix_spec == EXPECTED_STIX_SPEC
    assert manifest.artifact_filename == EXPECTED_ARTIFACT_FILENAME


def test_verify_artifact_is_deterministic() -> None:
    """Running verification twice on the same artifact yields an identical result."""
    m1 = verify_artifact(VENDORED_ARTIFACT_DIR)
    m2 = verify_artifact(VENDORED_ARTIFACT_DIR)
    assert m1 == m2


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
    data["attack_kb_version"] = "enterprise-attack-19.1"
    manifest_path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ArtifactIntegrityError, match="does not match the pinned baseline"):
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
