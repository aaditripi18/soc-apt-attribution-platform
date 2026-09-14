"""Tests for gate G1.1: the Elastic Detection Engine alert adapter.

Covers: valid alert normalization; rule id/version extraction; matched-field
extraction (both the ECS-fields-present case and the honest fallback when
none are present); supporting-Observation/raw-reference provenance; valid
technique AND sub-technique mapping against the real pinned v19.0 KB;
nonexistent/unresolvable ("wrong version") ATT&CK mappings failing closed;
every missing-required-field rejection path; deterministic output; that no
Elastic-specific field name leaks into the serialized core detection
contracts; the normalized DetectionResult -> Evidence path via the existing,
unmodified `derive_evidence_from_detection`; the bounded read
(`fetch_recent_alerts`) against both `FakeElasticClient` and a mocked HTTP
response; and architecture guards (detection/ never imports
elastic_detections/ or dataplane/; elastic_detections/ never imports
sources/).

Does NOT touch the G0.0-G1.0 test files. Offline (loads only the vendored
KB; Elastic access is via FakeElasticClient or a patched urlopen), no Docker,
no Windows, no network required.
"""

from __future__ import annotations

import ast
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from attribution_platform.attack_knowledge.loader import AttackKnowledge, load_attack_knowledge
from attribution_platform.dataplane import FakeElasticClient
from attribution_platform.dataplane.http_client import ElasticsearchHttpClient
from attribution_platform.detection import (
    DetectionError,
    DetectionResult,
    MatchBasis,
    MatchedField,
    TechniqueMapping,
    derive_evidence_from_detection,
)
from attribution_platform.domain import (
    AttackRef,
    Evidence,
    Observation,
    ProcessRef,
    SourceRef,
    to_canonical_json,
)
from attribution_platform.elastic_detections import (
    DEFAULT_ALERTS_INDEX,
    ELASTIC_ALERT_SOURCE,
    fetch_recent_alerts,
    normalize_elastic_alert,
)
from attribution_platform.extraction.detection_match import RuleRef

REPO_ROOT = Path(__file__).resolve().parents[1]
DETECTION_DIR = REPO_ROOT / "src" / "attribution_platform" / "detection"
ELASTIC_DETECTIONS_DIR = REPO_ROOT / "src" / "attribution_platform" / "elastic_detections"


@pytest.fixture(scope="module")
def knowledge() -> AttackKnowledge:
    return load_attack_knowledge()


def _alert(**overrides: Any) -> dict[str, Any]:
    alert: dict[str, Any] = {
        "@timestamp": "2026-01-01T12:00:00.000Z",
        "kibana.alert.uuid": "alert-abc-123",
        "kibana.alert.rule.rule_id": "elastic-encoded-powershell",
        "kibana.alert.rule.version": 3,
        "kibana.alert.ancestors": [
            {"id": "obs-1", "type": "event", "index": "logs-endpoint", "depth": 0}
        ],
    }
    alert.update(overrides)
    return alert


def _alert_with_technique(
    external_id: str, *, sub_external_id: str | None = None
) -> dict[str, Any]:
    technique: dict[str, Any] = {"id": external_id, "name": "x", "reference": "x"}
    if sub_external_id is not None:
        technique["subtechnique"] = [{"id": sub_external_id, "name": "x", "reference": "x"}]
    return _alert(
        **{
            "kibana.alert.rule.threat": [
                {
                    "framework": "MITRE ATT&CK",
                    "tactic": {"id": "TA0002", "name": "Execution", "reference": "x"},
                    "technique": [technique],
                }
            ]
        }
    )


# ===========================================================================
# 1. Valid alert normalization + rule id/version extraction
# ===========================================================================


def test_valid_alert_normalizes_to_detection_result(knowledge: AttackKnowledge) -> None:
    detection = normalize_elastic_alert(_alert(), knowledge=knowledge)
    assert isinstance(detection, DetectionResult)
    assert detection.detection_source == ELASTIC_ALERT_SOURCE == "elastic"
    assert detection.detection_id == "elastic::alert-abc-123"


def test_rule_id_and_version_extracted_into_rule_ref(knowledge: AttackKnowledge) -> None:
    detection = normalize_elastic_alert(
        _alert(**{"kibana.alert.rule.rule_id": "my-rule", "kibana.alert.rule.version": 7}),
        knowledge=knowledge,
    )
    assert detection.rule_ref.rule_id == "my-rule"
    assert detection.rule_ref.rule_version == "7"  # coerced to str, preserved


# ===========================================================================
# 2. Matched-field extraction
# ===========================================================================


def test_matched_fields_extracted_from_ecs_entities_present_on_alert(
    knowledge: AttackKnowledge,
) -> None:
    detection = normalize_elastic_alert(
        _alert(
            process={"name": "powershell.exe", "command_line": "powershell.exe -enc AAAA"},
            host={"name": "WIN-1"},
        ),
        knowledge=knowledge,
    )
    field_paths = {mf.field_path for mf in detection.match_basis.matched_fields}
    assert field_paths == {"process.name", "process.command_line", "host.name"}
    observed = {mf.field_path: mf.observed for mf in detection.match_basis.matched_fields}
    assert observed["process.name"] == "powershell.exe"


def test_matched_fields_falls_back_to_rule_id_when_no_ecs_fields_present(
    knowledge: AttackKnowledge,
) -> None:
    """Honest fallback: no fabricated field-level precision when Elastic
    gives none for this alert/rule type."""
    detection = normalize_elastic_alert(_alert(), knowledge=knowledge)
    assert len(detection.match_basis.matched_fields) == 1
    only = detection.match_basis.matched_fields[0]
    assert only.field_path == "kibana.alert.rule.rule_id"
    assert only.observed == "elastic-encoded-powershell"


# ===========================================================================
# 3. Supporting Observation / raw-reference provenance
# ===========================================================================


def test_supporting_observation_id_comes_from_first_ancestor(knowledge: AttackKnowledge) -> None:
    detection = normalize_elastic_alert(
        _alert(**{"kibana.alert.ancestors": [{"id": "the-source-event-id"}]}), knowledge=knowledge
    )
    assert detection.supporting_observation_ids == ("the-source-event-id",)


def test_multi_ancestor_alert_fails_closed_not_multi_event_correlation(
    knowledge: AttackKnowledge,
) -> None:
    with pytest.raises(DetectionError, match="single-event alerts"):
        normalize_elastic_alert(
            _alert(**{"kibana.alert.ancestors": [{"id": "o1"}, {"id": "o2"}]}), knowledge=knowledge
        )


# ===========================================================================
# 4. Valid technique AND sub-technique mapping (real pinned v19.0 KB)
# ===========================================================================


def test_valid_technique_mapping_resolves(knowledge: AttackKnowledge) -> None:
    detection = normalize_elastic_alert(_alert_with_technique("T1059"), knowledge=knowledge)
    assert len(detection.technique_mappings) == 1
    mapping = detection.technique_mappings[0]
    assert mapping.attack_ref.external_id == "T1059"
    assert mapping.attack_ref.attack_kb_version == knowledge.attack_kb_version
    assert mapping.mapping_source == "elastic"


def test_valid_technique_and_subtechnique_mapping_resolve(knowledge: AttackKnowledge) -> None:
    detection = normalize_elastic_alert(
        _alert_with_technique("T1059", sub_external_id="T1059.001"), knowledge=knowledge
    )
    external_ids = {m.attack_ref.external_id for m in detection.technique_mappings}
    assert external_ids == {"T1059", "T1059.001"}


def test_alert_with_no_threat_field_has_no_technique_mappings(knowledge: AttackKnowledge) -> None:
    detection = normalize_elastic_alert(_alert(), knowledge=knowledge)
    assert detection.technique_mappings == ()


# ===========================================================================
# 5. Invalid / nonexistent / "wrong version" ATT&CK mappings fail closed
# ===========================================================================


def test_nonexistent_technique_id_fails_closed(knowledge: AttackKnowledge) -> None:
    with pytest.raises(DetectionError, match="does not exist in the pinned KB"):
        normalize_elastic_alert(_alert_with_technique("T9999-DOES-NOT-EXIST"), knowledge=knowledge)


def test_technique_from_a_different_kb_version_fails_closed(knowledge: AttackKnowledge) -> None:
    """A technique id valid only in a *different* ATT&CK release than the
    one pinned (renamed/retired/never existed in v19.0) is indistinguishable
    from "nonexistent" from the currently-loaded KB's point of view -- our
    adapter always resolves against whichever KB version is loaded, so this
    necessarily fails the same way. (Mirrors the G0.6 audit finding that a
    genuine KB-version mismatch is not reachable through a normally
    constructed, legitimately-sourced reference -- see
    tests/test_evidence_derivation.py's _StubKnowledge test for the
    defense-in-depth path.)"""
    with pytest.raises(DetectionError, match="does not exist in the pinned KB"):
        normalize_elastic_alert(_alert_with_technique("T0000.999"), knowledge=knowledge)


def test_duplicate_technique_ids_in_one_alert_fail_closed(knowledge: AttackKnowledge) -> None:
    """This adapter has no duplicate-mapping check of its own (a G1.1
    provenance-review finding moved that invariant onto DetectionResult
    itself, since this adapter is a second DetectionResult producer that
    bypasses DetectionRule) -- the rejection below comes from
    DetectionResult.__post_init__, not from this module."""
    alert = _alert(
        **{
            "kibana.alert.rule.threat": [
                {"technique": [{"id": "T1059"}, {"id": "T1059"}]},
            ]
        }
    )
    with pytest.raises(DetectionError, match="duplicate attack_ref.stix_id"):
        normalize_elastic_alert(alert, knowledge=knowledge)


def test_detection_result_itself_rejects_duplicate_technique_mapping(
    knowledge: AttackKnowledge,
) -> None:
    """G1.1 provenance-review finding: the duplicate-stix_id invariant now
    lives on DetectionResult.__post_init__ itself (contracts.py), not only
    on DetectionRule -- proven here by constructing a DetectionResult
    directly, the same way this adapter does, with no DetectionRule
    involved at all."""
    technique = knowledge.techniques()[0]
    ref = AttackRef(
        stix_id=technique["id"],
        object_type=technique["type"],
        attack_kb_version=knowledge.attack_kb_version,
    )
    with pytest.raises(DetectionError, match="duplicate attack_ref.stix_id"):
        DetectionResult(
            detection_id="d1",
            rule_ref=RuleRef(rule_id="r1", rule_version="1.0"),
            detection_source="elastic",
            supporting_observation_ids=("obs-1",),
            match_basis=MatchBasis(
                matched_fields=(
                    MatchedField(field_path="host.name", operator="exists", observed="H"),
                )
            ),
            technique_mappings=(
                TechniqueMapping(attack_ref=ref, mapping_basis="basis A"),
                TechniqueMapping(attack_ref=ref, mapping_basis="basis B (duplicate technique)"),
            ),
        )


def test_malformed_threat_structure_fails_closed(knowledge: AttackKnowledge) -> None:
    alert = _alert(**{"kibana.alert.rule.threat": "not-a-list"})
    with pytest.raises(DetectionError, match="'kibana.alert.rule.threat' must be a list"):
        normalize_elastic_alert(alert, knowledge=knowledge)


# ===========================================================================
# 6. Missing required alert fields fail closed
# ===========================================================================


@pytest.mark.parametrize(
    ("missing_key", "match"),
    [
        ("kibana.alert.uuid", "kibana.alert.uuid"),
        ("@timestamp", "@timestamp"),
        ("kibana.alert.rule.rule_id", "kibana.alert.rule.rule_id"),
        ("kibana.alert.rule.version", "kibana.alert.rule.version"),
        ("kibana.alert.ancestors", "kibana.alert.ancestors"),
    ],
)
def test_missing_required_field_fails_closed(
    knowledge: AttackKnowledge, missing_key: str, match: str
) -> None:
    alert = _alert()
    del alert[missing_key]
    with pytest.raises(DetectionError, match=match):
        normalize_elastic_alert(alert, knowledge=knowledge)


def test_invalid_timestamp_fails_closed(knowledge: AttackKnowledge) -> None:
    with pytest.raises(DetectionError, match="not a valid ISO-8601"):
        normalize_elastic_alert(_alert(**{"@timestamp": "not-a-timestamp"}), knowledge=knowledge)


def test_empty_ancestors_fails_closed(knowledge: AttackKnowledge) -> None:
    with pytest.raises(DetectionError, match="non-empty list"):
        normalize_elastic_alert(_alert(**{"kibana.alert.ancestors": []}), knowledge=knowledge)


def test_non_mapping_alert_fails_closed(knowledge: AttackKnowledge) -> None:
    with pytest.raises(DetectionError, match="requires a Mapping"):
        normalize_elastic_alert("not-an-alert", knowledge=knowledge)  # type: ignore[arg-type]


# ===========================================================================
# 7. Deterministic output
# ===========================================================================


def test_normalization_is_deterministic(knowledge: AttackKnowledge) -> None:
    alert = _alert_with_technique("T1059.001")
    first = normalize_elastic_alert(alert, knowledge=knowledge)
    second = normalize_elastic_alert(alert, knowledge=knowledge)
    assert to_canonical_json(first) == to_canonical_json(second)
    assert first.detection_id == second.detection_id


# ===========================================================================
# 8. Elastic-specific fields never leak into the serialized core contract
# ===========================================================================


def test_elastic_field_names_do_not_leak_into_serialized_detection_result(
    knowledge: AttackKnowledge,
) -> None:
    detection = normalize_elastic_alert(
        _alert_with_technique("T1059", sub_external_id="T1059.001"), knowledge=knowledge
    )
    body = json.loads(to_canonical_json(detection))

    def _flatten_keys(obj: Any) -> set[str]:
        keys: set[str] = set()
        if isinstance(obj, dict):
            for k, v in obj.items():
                keys.add(k)
                keys |= _flatten_keys(v)
        elif isinstance(obj, list):
            for item in obj:
                keys |= _flatten_keys(item)
        return keys

    all_keys = _flatten_keys(body)
    for forbidden in (
        "kibana.alert.uuid",
        "kibana.alert.rule.rule_id",
        "kibana.alert.ancestors",
        "kibana",
    ):
        assert (
            forbidden not in all_keys
        ), f"Elastic-native key {forbidden!r} leaked into DetectionResult"


# ===========================================================================
# 9. Normalized DetectionResult -> Evidence, via the existing, unmodified fan-out
# ===========================================================================


def test_normalized_detection_flows_through_existing_evidence_fan_out(
    knowledge: AttackKnowledge,
) -> None:
    alert = _alert_with_technique("T1059.001", sub_external_id=None)
    detection = normalize_elastic_alert(alert, knowledge=knowledge)
    observation = Observation(
        observation_id="obs-1",
        timestamp=datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC),
        raw_reference=SourceRef(source_type="elastic-endpoint", source_event_id="obs-1"),
        process=ProcessRef(name="powershell.exe"),
    )

    evidences = derive_evidence_from_detection(detection, observation, knowledge=knowledge)

    assert len(evidences) == 1
    evidence = evidences[0]
    assert isinstance(evidence, Evidence)
    assert evidence.attack_ref is not None
    assert evidence.attack_ref.external_id == "T1059.001"
    assert evidence.provenance.method == detection.rule_ref.rule_id
    assert evidence.provenance.method_version == detection.rule_ref.rule_version
    assert evidence.provenance.source_observation_ids == ("obs-1",)


def test_evidence_fan_out_rejects_mismatched_observation(knowledge: AttackKnowledge) -> None:
    detection = normalize_elastic_alert(
        _alert(**{"kibana.alert.ancestors": [{"id": "obs-1"}]}), knowledge=knowledge
    )
    wrong_observation = Observation(
        observation_id="totally-different-id",
        timestamp=datetime(2026, 1, 1, tzinfo=UTC),
        raw_reference=SourceRef(source_type="elastic-endpoint", source_event_id="x"),
    )
    with pytest.raises(DetectionError, match="is not among detection"):
        derive_evidence_from_detection(detection, wrong_observation, knowledge=knowledge)


# ===========================================================================
# 10. Rule-pack content-hash pass-through (never fabricated)
# ===========================================================================


def test_rule_pack_content_hash_absent_by_default(knowledge: AttackKnowledge) -> None:
    detection = normalize_elastic_alert(_alert(), knowledge=knowledge)
    assert detection.rule_pack_content_hash is None


def test_rule_pack_content_hash_preserved_when_present(knowledge: AttackKnowledge) -> None:
    detection = normalize_elastic_alert(
        _alert(rule_pack_content_hash="a" * 64), knowledge=knowledge
    )
    assert detection.rule_pack_content_hash == "a" * 64


# ===========================================================================
# 11. Bounded read: fetch_recent_alerts (FakeElasticClient + mocked HTTP)
# ===========================================================================


def test_fetch_recent_alerts_against_fake_client_is_bounded() -> None:
    client = FakeElasticClient()
    client.ensure_index(DEFAULT_ALERTS_INDEX, {})
    for i in range(10):
        client.index_document(DEFAULT_ALERTS_INDEX, f"a{i}", {"kibana.alert.uuid": f"a{i}"})

    alerts = fetch_recent_alerts(client, size=4)
    assert len(alerts) == 4


def test_fetch_recent_alerts_rejects_non_positive_size() -> None:
    client = FakeElasticClient()
    with pytest.raises(DetectionError, match="size must be positive"):
        fetch_recent_alerts(client, size=0)


def test_fetch_recent_alerts_against_real_http_client_request_shape() -> None:
    """No live Elasticsearch: patches urllib.request.urlopen and checks the
    exact bounded search request this adapter issues."""
    from unittest.mock import patch

    class _FakeResponse:
        def __init__(self, status: int, body: dict[str, Any]) -> None:
            self.status = status
            self._body = json.dumps(body).encode("utf-8")

        def read(self) -> bytes:
            return self._body

        def __enter__(self) -> _FakeResponse:
            return self

        def __exit__(self, *exc: object) -> None:
            return None

    client = ElasticsearchHttpClient(
        "https://localhost:9200", username="elastic", password="secret", verify_tls=False
    )
    response = {"hits": {"hits": [{"_source": {"kibana.alert.uuid": "a1"}}]}}
    with patch("urllib.request.urlopen", return_value=_FakeResponse(200, response)) as mock_urlopen:
        alerts = fetch_recent_alerts(client, size=5)

    request = mock_urlopen.call_args[0][0]
    assert request.full_url == f"https://localhost:9200/{DEFAULT_ALERTS_INDEX}/_search"
    assert request.get_method() == "POST"
    assert json.loads(request.data) == {"query": {"match_all": {}}, "size": 5}
    assert alerts == ({"kibana.alert.uuid": "a1"},)


# ===========================================================================
# 12. Architecture guards
# ===========================================================================


def _ast_import_offenders(directory: Path, forbidden_substrings: tuple[str, ...]) -> list[str]:
    offending: list[str] = []
    for path in sorted(directory.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.ImportFrom)
                and node.module
                and any(s in node.module for s in forbidden_substrings)
            ):
                offending.append(f"{path.name}: from {node.module} import ...")
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if any(s in alias.name for s in forbidden_substrings):
                        offending.append(f"{path.name}: import {alias.name}")
    return offending


def test_detection_core_never_imports_elastic_detections_or_dataplane() -> None:
    """The G1.0 detection core must stay Elastic-free: nothing under
    detection/ may import elastic_detections/ or dataplane/ directly."""
    offenders = _ast_import_offenders(
        DETECTION_DIR, ("elastic_detections", "attribution_platform.dataplane")
    )
    assert (
        not offenders
    ), f"detection/ must not import elastic_detections/ or dataplane/: {offenders}"


def test_elastic_detections_never_imports_sources() -> None:
    """No parallel telemetry-ingestion path: this adapter must never import
    attribution_platform.sources (it references existing Observation ids,
    never parses raw source events itself)."""
    offenders = _ast_import_offenders(ELASTIC_DETECTIONS_DIR, ("attribution_platform.sources",))
    assert not offenders, f"elastic_detections/ must not import sources/: {offenders}"


def test_elastic_detections_never_imports_replay_or_api() -> None:
    offenders = _ast_import_offenders(
        ELASTIC_DETECTIONS_DIR, ("attribution_platform.replay", "attribution_platform.api")
    )
    assert not offenders, f"elastic_detections/ must not import replay/ or api/: {offenders}"
