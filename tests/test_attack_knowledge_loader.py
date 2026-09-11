"""Tests for gate G0.2: the deterministic runtime ATT&CK knowledge loader.

Covers: successful loading of the pinned v19.0 bundle, use of the expected
versioned artifact, deterministic repeated loading, fail-closed behavior on
invalid/tampered artifacts (via the existing G0.1 verification contract),
no-network-required operation, sanity checks on STIX object counts/types
and Enterprise collection metadata, and a guard against hard-coded ATT&CK
vocabulary in the loader source.

Does NOT modify or weaken tests/test_attack_artifact_integrity.py (G0.1) —
that file is untouched. This file additionally does not assert anything
about specific APT groups, actor names, or attribution — only structural/
count-based facts about the loaded knowledge base.

All tests are offline and deterministic: no network access, no Docker, no
Windows-specific APIs, no dependency on Elasticsearch.
"""

from __future__ import annotations

import inspect
import json
from pathlib import Path
from types import MappingProxyType
from typing import Any

import pytest

from attribution_platform.attack_knowledge import loader as loader_module
from attribution_platform.attack_knowledge import verification as verification_module
from attribution_platform.attack_knowledge.loader import (
    DEFAULT_ATTACK_ARTIFACT_DIR,
    AttackKnowledge,
    _load_from_dir,
    load_attack_knowledge,
)
from attribution_platform.attack_knowledge.verification import (
    EXPECTED_ARTIFACT_FILENAME,
    EXPECTED_ATTACK_DOMAIN,
    EXPECTED_ATTACK_KB_VERSION,
    EXPECTED_STIX_SPEC,
    ArtifactIntegrityError,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
VENDORED_ARTIFACT_DIR = REPO_ROOT / "data" / "attack" / "enterprise" / "v19.0"
VENDORED_MANIFEST_PATH = VENDORED_ARTIFACT_DIR / "manifest.json"


# ===========================================================================
# 1. The pinned v19.0 bundle loads successfully
# ===========================================================================


def test_default_artifact_dir_resolves_to_the_pinned_vendored_location() -> None:
    """The loader's hard-wired path resolves to the exact vendored G0.1 artifact dir."""
    assert DEFAULT_ATTACK_ARTIFACT_DIR == VENDORED_ARTIFACT_DIR
    assert DEFAULT_ATTACK_ARTIFACT_DIR.is_dir()


def test_load_attack_knowledge_succeeds() -> None:
    """The public, zero-argument runtime entrypoint loads successfully."""
    kb = load_attack_knowledge()
    assert isinstance(kb, AttackKnowledge)
    assert kb.object_fingerprint.total_objects > 0


def test_load_attack_knowledge_takes_no_path_argument() -> None:
    """(constraint 2) The public entrypoint cannot be redirected to an arbitrary bundle."""
    sig = inspect.signature(load_attack_knowledge)
    assert len(sig.parameters) == 0, (
        "load_attack_knowledge() must accept no arguments — callers must not be able to "
        "point the runtime loader at an arbitrary external bundle path"
    )


# ===========================================================================
# 2. The loader uses the expected versioned artifact
# ===========================================================================


def test_loaded_knowledge_reports_the_expected_pinned_version() -> None:
    kb = load_attack_knowledge()
    assert kb.attack_kb_version == EXPECTED_ATTACK_KB_VERSION
    assert kb.attack_domain == EXPECTED_ATTACK_DOMAIN
    assert kb.stix_spec == EXPECTED_STIX_SPEC


def test_loaded_knowledge_sha256_matches_the_manifest_on_disk() -> None:
    """The version+hash the loader exposes matches what G0.1 recorded (not fabricated)."""
    manifest_data = json.loads(VENDORED_MANIFEST_PATH.read_text(encoding="utf-8"))
    kb = load_attack_knowledge()
    assert kb.attack_kb_sha256 == manifest_data["artifact"]["sha256"]


def test_loaded_knowledge_collection_metadata_is_enterprise_v19_0() -> None:
    kb = load_attack_knowledge()
    assert kb.stix_collection.name == "Enterprise ATT&CK"
    assert kb.stix_collection.x_mitre_version == "19.0"
    assert kb.stix_collection.spec_version == "2.1"


def test_loaded_knowledge_has_no_calibration_version_attribute() -> None:
    """(constraint 7) attack_kb_version and calibration_version stay distinct;
    calibration does not exist yet and must never be fabricated."""
    kb = load_attack_knowledge()
    assert not hasattr(kb, "calibration_version")


# ===========================================================================
# 3. Deterministic loading / repeated loading
# ===========================================================================


def test_repeated_loading_produces_the_same_logical_result() -> None:
    kb1 = load_attack_knowledge()
    kb2 = load_attack_knowledge()

    assert kb1.attack_kb_version == kb2.attack_kb_version
    assert kb1.attack_kb_sha256 == kb2.attack_kb_sha256
    assert kb1.object_fingerprint == kb2.object_fingerprint
    assert kb1.stix_collection == kb2.stix_collection

    # Order-independent: the SET of object ids must be identical across loads,
    # regardless of any incidental iteration/ordering differences.
    assert set(kb1.objects_by_id.keys()) == set(kb2.objects_by_id.keys())
    assert set(kb1.objects_by_type.keys()) == set(kb2.objects_by_type.keys())


def test_accessor_counts_match_the_recorded_object_fingerprint() -> None:
    """Sanity check: convenience accessors agree with the independently
    computed fingerprint (gate G0.1), for the SAME loaded object set —
    catches accidental drift between the two categorization paths."""
    kb = load_attack_knowledge()
    fp = kb.object_fingerprint

    assert len(kb.tactics()) == fp.tactics
    assert len(kb.techniques()) == fp.techniques
    assert len(kb.sub_techniques()) == fp.sub_techniques
    assert len(kb.groups()) == fp.groups
    assert len(kb.software()) == fp.software_malware + fp.software_tool
    assert len(kb.campaigns()) == fp.campaigns
    assert len(kb.mitigations()) == fp.mitigations
    assert len(kb.relationships()) == fp.relationships


def test_get_by_id_and_objects_of_type_are_consistent() -> None:
    kb = load_attack_knowledge()
    some_technique = kb.techniques()[0]
    stix_id = some_technique["id"]

    assert kb.get_by_id(stix_id) == some_technique
    assert kb.get_by_id("not-a-real-stix-id--00000000-0000-0000-0000-000000000000") is None
    assert kb.objects_of_type("this-type-does-not-exist") == ()


def test_loaded_containers_are_read_only() -> None:
    """Structural immutability: callers cannot add/remove entries from the
    top-level collections."""
    kb = load_attack_knowledge()
    assert isinstance(kb.objects_by_id, MappingProxyType)
    assert isinstance(kb.objects_by_type, MappingProxyType)
    with pytest.raises(TypeError):
        kb.objects_by_id["new-id"] = {}  # type: ignore[index]
    with pytest.raises(TypeError):
        kb.objects_by_type["new-type"] = ()  # type: ignore[index]


# ===========================================================================
# Deep immutability audit — every exposed level, on the REAL loaded bundle.
#
# Verifies the claim in the loader module docstring is actually true, not
# merely asserted: an object returned by `objects_by_id`, an object returned
# through the type index, and any nested dict/list inside either, must all
# reject mutation. This directly tests the exact pattern
# `knowledge.objects_by_id[some_id]["name"] = "modified"` from the G0.2
# immutability audit, plus its nested equivalents.
# ===========================================================================


def test_object_returned_by_id_rejects_top_level_field_mutation() -> None:
    """The exact audited pattern: knowledge.objects_by_id[id]["field"] = x."""
    kb = load_attack_knowledge()
    some_id = next(iter(kb.objects_by_id))
    obj = kb.objects_by_id[some_id]
    assert isinstance(obj, MappingProxyType)
    with pytest.raises(TypeError):
        obj["name"] = "modified"  # type: ignore[index]


def test_object_returned_through_type_index_rejects_mutation() -> None:
    """Same guarantee via the objects_of_type()/objects_by_type path, not
    just objects_by_id — both must be equally immutable."""
    kb = load_attack_knowledge()
    some_type = next(iter(kb.objects_by_type))
    obj = kb.objects_of_type(some_type)[0]
    assert isinstance(obj, MappingProxyType)
    with pytest.raises(TypeError):
        obj["injected_field"] = "modified"  # type: ignore[index]


def test_by_id_and_by_type_return_the_identical_frozen_object() -> None:
    """The same STIX id must resolve to the SAME frozen instance via both
    access paths (proves indexing doesn't silently fork/copy an object into
    a mutable-vs-immutable pair)."""
    kb = load_attack_knowledge()
    some_id = next(iter(kb.objects_by_id))
    via_by_id = kb.objects_by_id[some_id]
    stix_type = via_by_id["type"]
    matches = [o for o in kb.objects_of_type(stix_type) if o["id"] == some_id]
    assert len(matches) == 1
    assert matches[0] is via_by_id


def test_nested_dict_fields_are_recursively_frozen() -> None:
    """Any nested dict inside a loaded object (e.g. a kill_chain_phases
    entry, an external_reference entry) must itself be a MappingProxyType,
    and reject mutation — not merely the outer object."""
    kb = load_attack_knowledge()
    found_nested_dict = False
    for obj in kb.objects_by_id.values():
        for value in obj.values():
            if isinstance(value, tuple):
                for element in value:
                    if isinstance(element, MappingProxyType):
                        found_nested_dict = True
                        with pytest.raises(TypeError):
                            element["injected"] = "modified"  # type: ignore[index]
                        break
            if found_nested_dict:
                break
        if found_nested_dict:
            break
    assert (
        found_nested_dict
    ), "expected at least one nested dict-in-list field in the real ATT&CK bundle"


def test_nested_list_fields_are_tuples_not_lists() -> None:
    """Any nested JSON array inside a loaded object must be a tuple (no
    .append()/item-assignment), never a plain list."""
    kb = load_attack_knowledge()
    found_nested_sequence = False
    for obj in kb.objects_by_id.values():
        for value in obj.values():
            if isinstance(value, list | tuple):
                found_nested_sequence = True
                assert isinstance(
                    value, tuple
                ), f"nested sequence field is a {type(value)}, not a tuple"
                assert not isinstance(value, list)
        if found_nested_sequence:
            break
    assert (
        found_nested_sequence
    ), "expected at least one nested array field in the real ATT&CK bundle"


def test_no_plain_dict_or_list_survives_anywhere_in_a_loaded_object() -> None:
    """Exhaustive recursive scan of one real loaded object: at no depth may
    a plain (mutable) dict or list appear — everything must be
    MappingProxyType / tuple / an already-immutable scalar."""

    def assert_frozen(value: Any, path: str) -> None:
        if isinstance(value, MappingProxyType):
            for k, v in value.items():
                assert_frozen(v, f"{path}.{k}")
        elif isinstance(value, tuple):
            for i, v in enumerate(value):
                assert_frozen(v, f"{path}[{i}]")
        elif isinstance(value, dict):
            pytest.fail(f"found a plain (mutable) dict at {path}: {value!r}")
        elif isinstance(value, list):
            pytest.fail(f"found a plain (mutable) list at {path}: {value!r}")
        # else: scalar (str/int/float/bool/None) — already immutable, fine.

    kb = load_attack_knowledge()
    # The x-mitre-collection object is known to have nested content and is
    # present in every valid bundle (verify_artifact requires exactly one).
    collection = next(o for o in kb.objects_by_id.values() if o["type"] == "x-mitre-collection")
    assert_frozen(collection, "collection")

    # Also scan a representative sample across object types for depth
    # coverage, without scanning all ~25,000 objects (slow, unnecessary).
    for stix_type, objects in kb.objects_by_type.items():
        assert_frozen(objects[0], f"{stix_type}[0]")


# ===========================================================================
# Deep immutability audit — deterministic synthetic fixture with a
# DELIBERATELY constructed nested dict-in-list-in-dict structure, so the
# guarantee does not depend on what the real bundle happens to contain.
# ===========================================================================


def test_deep_immutability_on_a_deliberately_nested_synthetic_fixture(tmp_path: Path) -> None:
    """Builds a fixture with a 3-level-deep structure (dict -> list -> dict
    -> list -> scalar) and proves every level is frozen and every mutation
    attempt raises TypeError — including the exact audited pattern."""
    objects: list[dict[str, Any]] = [
        {
            "type": "x-mitre-collection",
            "id": "x-mitre-collection--nested-fixture",
            "name": "Enterprise ATT&CK",
            "x_mitre_version": "19.0",
            "spec_version": "2.1",
            "created": "2020-01-01T00:00:00.000Z",
            "modified": "2020-01-01T00:00:00.000Z",
        },
        {
            "type": "intrusion-set",
            "id": "intrusion-set--nested-fixture",
            "name": "Fixture Group",
            "external_references": [
                {
                    "source_name": "fixture-source",
                    "url": "https://example.invalid/fixture",
                    "tags": ["a", "b", "c"],
                },
            ],
        },
    ]
    bundle = {"type": "bundle", "id": "bundle--nested-fixture", "objects": objects}

    artifact_dir = tmp_path / "nested-fixture"
    artifact_dir.mkdir()
    artifact_path = artifact_dir / EXPECTED_ARTIFACT_FILENAME
    artifact_path.write_text(json.dumps(bundle), encoding="utf-8")

    fingerprint = verification_module.compute_object_fingerprint(objects)
    collection = verification_module.extract_collection_info(objects)
    manifest = {
        "attack_kb_version": EXPECTED_ATTACK_KB_VERSION,
        "attack_domain": EXPECTED_ATTACK_DOMAIN,
        "stix_spec": EXPECTED_STIX_SPEC,
        "artifact": {
            "filename": EXPECTED_ARTIFACT_FILENAME,
            "relative_path": str(artifact_path),
            "size_bytes": artifact_path.stat().st_size,
            "sha256": verification_module.compute_sha256(artifact_path),
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

    kb = _load_from_dir(artifact_dir)
    group = kb.get_by_id("intrusion-set--nested-fixture")
    assert group is not None

    # Level 1: the object itself.
    assert isinstance(group, MappingProxyType)
    with pytest.raises(TypeError):
        group["name"] = "modified"  # type: ignore[index]

    # Level 2: the nested list (external_references) must be a tuple —
    # tuples have no .append() at all (AttributeError) and reject item
    # assignment (TypeError); both prove it is not a mutable list.
    refs = group["external_references"]
    assert isinstance(refs, tuple)
    assert not hasattr(refs, "append")
    with pytest.raises(TypeError):
        refs[0] = {}  # type: ignore[index]

    # Level 3: the dict INSIDE that list must itself be frozen.
    ref = refs[0]
    assert isinstance(ref, MappingProxyType)
    with pytest.raises(TypeError):
        ref["url"] = "https://example.invalid/hijacked"  # type: ignore[index]

    # Level 4: a list nested inside that nested dict must also be a tuple.
    tags = ref["tags"]
    assert isinstance(tags, tuple)
    assert not hasattr(tags, "append")
    with pytest.raises(TypeError):
        tags[0] = "z"  # type: ignore[index]


# ===========================================================================
# 4. Fail-closed behavior via the existing G0.1 verification contract
# ===========================================================================


def _write_tiny_valid_fixture(tmp_path: Path) -> Path:
    """A minimal, self-consistent fixture the loader accepts as-is — reuses
    G0.1's own compute_* functions so the fixture and the manifest are
    guaranteed consistent, mirroring test_attack_artifact_integrity.py."""
    objects: list[dict[str, Any]] = [
        {
            "type": "x-mitre-collection",
            "id": "x-mitre-collection--loader-fixture",
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
        {"type": "tool", "id": "tool--1"},
        {"type": "campaign", "id": "campaign--1"},
        {"type": "course-of-action", "id": "course-of-action--1"},
        {
            "type": "relationship",
            "id": "relationship--1",
            "relationship_type": "uses",
            "source_ref": "intrusion-set--1",
            "target_ref": "attack-pattern--1",
        },
    ]
    bundle = {"type": "bundle", "id": "bundle--loader-fixture", "objects": objects}

    artifact_dir = tmp_path / "fixture"
    artifact_dir.mkdir()
    artifact_path = artifact_dir / EXPECTED_ARTIFACT_FILENAME
    artifact_path.write_text(json.dumps(bundle), encoding="utf-8")

    fingerprint = verification_module.compute_object_fingerprint(objects)
    collection = verification_module.extract_collection_info(objects)
    manifest = {
        "attack_kb_version": EXPECTED_ATTACK_KB_VERSION,
        "attack_domain": EXPECTED_ATTACK_DOMAIN,
        "stix_spec": EXPECTED_STIX_SPEC,
        "artifact": {
            "filename": EXPECTED_ARTIFACT_FILENAME,
            "relative_path": str(artifact_path),
            "size_bytes": artifact_path.stat().st_size,
            "sha256": verification_module.compute_sha256(artifact_path),
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


def test_loader_accepts_a_valid_self_consistent_fixture(tmp_path: Path) -> None:
    """Proves the loader actually invokes verify_artifact() and, when it
    passes, exposes correctly indexed objects — not just that a happy path
    exists for the real artifact."""
    artifact_dir = _write_tiny_valid_fixture(tmp_path)
    kb = _load_from_dir(artifact_dir)

    assert len(kb.tactics()) == 1
    assert len(kb.techniques()) == 1
    assert len(kb.sub_techniques()) == 1
    assert len(kb.groups()) == 1
    assert len(kb.software()) == 2  # 1 malware + 1 tool
    assert len(kb.campaigns()) == 1
    assert len(kb.mitigations()) == 1
    assert len(kb.relationships()) == 1
    assert kb.get_by_id("intrusion-set--1") is not None


def test_loader_fails_closed_on_tampered_manifest_hash(tmp_path: Path) -> None:
    """(constraints 3, 9) An integrity failure must propagate through the
    loader as ArtifactIntegrityError — never silently repaired/substituted,
    and no AttackKnowledge object is ever returned."""
    artifact_dir = _write_tiny_valid_fixture(tmp_path)
    manifest_path = artifact_dir / "manifest.json"
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    data["artifact"]["sha256"] = "0" * 64
    manifest_path.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ArtifactIntegrityError, match="SHA-256 mismatch"):
        _load_from_dir(artifact_dir)


def test_loader_fails_closed_on_wrong_pinned_version(tmp_path: Path) -> None:
    """A fixture claiming a different ATT&CK version than this codebase is
    pinned to must be rejected outright — no silent version substitution."""
    artifact_dir = _write_tiny_valid_fixture(tmp_path)
    manifest_path = artifact_dir / "manifest.json"
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    data["attack_kb_version"] = "enterprise-attack-19.1"
    manifest_path.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ArtifactIntegrityError, match="does not match the pinned baseline"):
        _load_from_dir(artifact_dir)


def test_loader_fails_closed_on_missing_artifact_directory(tmp_path: Path) -> None:
    nonexistent = tmp_path / "does-not-exist"
    with pytest.raises(ArtifactIntegrityError):
        _load_from_dir(nonexistent)


# ===========================================================================
# 5. No network access required
# ===========================================================================


def test_loader_module_imports_no_networking_libraries() -> None:
    """Static check: the loader's own module namespace never binds a
    networking primitive (socket, urllib, http.client, requests)."""
    for name in ("socket", "urllib", "http", "requests"):
        assert not hasattr(loader_module, name), f"loader.py must not import {name!r}"


def test_load_attack_knowledge_works_with_network_forcibly_blocked() -> None:
    """Actually blocks socket connections (not just static inspection) and
    confirms load_attack_knowledge() still succeeds — proving no runtime
    network dependency, mirroring the G0.1 network-disabled verification."""
    import socket

    original_connect = socket.socket.connect
    original_connect_ex = socket.socket.connect_ex

    def _blocked(self: Any, *_args: Any, **_kwargs: Any) -> Any:
        raise RuntimeError("NETWORK ACCESS BLOCKED FOR TEST")

    socket.socket.connect = _blocked  # type: ignore[method-assign]
    socket.socket.connect_ex = _blocked  # type: ignore[method-assign]
    try:
        kb = load_attack_knowledge()
        assert kb.object_fingerprint.total_objects > 0
    finally:
        socket.socket.connect = original_connect  # type: ignore[method-assign]
        socket.socket.connect_ex = original_connect_ex  # type: ignore[method-assign]


# ===========================================================================
# 6. Guard: no hard-coded ATT&CK vocabulary in the loader source
# ===========================================================================

_TECHNIQUE_ID_PATTERN = r"\bT\d{4}(\.\d{3})?\b"
_TACTIC_ID_PATTERN = r"\bTA\d{4}\b"


def test_loader_source_contains_no_hard_coded_technique_or_tactic_ids() -> None:
    """(doc 13 guard requirement) grep-style check: the loader source must
    never contain a literal ATT&CK technique ID (e.g. a Txxxx pattern) or
    tactic ID (TAxxxx) — every such identifier must come from the loaded
    bundle at runtime, never from source code."""
    import re

    source_path = Path(loader_module.__file__)
    source_text = source_path.read_text(encoding="utf-8")

    technique_matches = re.findall(_TECHNIQUE_ID_PATTERN, source_text)
    tactic_matches = re.findall(_TACTIC_ID_PATTERN, source_text)

    assert not technique_matches, f"found hard-coded technique-ID-shaped token(s) in {source_path}"
    assert not tactic_matches, f"found hard-coded tactic-ID-shaped token(s) in {source_path}"


def test_loader_derives_tactics_from_the_bundle_not_a_literal_list() -> None:
    """Structural guard: tactics() must be computed from loaded objects
    (objects_of_type), never returned from a hard-coded Python list/tuple
    literal of tactic names.

    tactics() delegates to objects_of_type(_TYPE_TACTIC) using a named
    module constant (not a literal repeated inline), so this checks both
    the delegation shape and the constant's actual bound value rather than
    grepping the method's own source text for the STIX type-tag string.
    """
    source = inspect.getsource(AttackKnowledge.tactics)
    assert "objects_of_type" in source
    assert loader_module._TYPE_TACTIC == "x-mitre-tactic"
