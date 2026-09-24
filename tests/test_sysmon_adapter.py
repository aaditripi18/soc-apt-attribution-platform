"""Tests for gate G0.11: the Windows/Sysmon SourceAdapter.

Covers: valid conversion for both supported event types (Process Create,
Network Connection); provenance preservation (SourceRef.source_type is
"sysmon", source_event_id is the Windows Event Log record id); fail-closed
rejection of malformed events, missing required fields (event id, timestamp,
record id, computer name), invalid timestamps, and bad-typed fields;
rejection of an unsupported event id; the NDJSON file-input loader (valid
file, missing file, blank lines skipped, invalid JSON line, non-object line,
empty file); reuse of the *same* G0.5 extraction / G0.6 evidence derivation /
G0.8 persistence pipeline with no parallel path; source-agnosticism (no
Sysmon-native field name survives into the produced Observation); and the
dependency-direction guard (extraction never imports sources).

Entirely deterministic synthetic data (the checked-in
fixtures/sysmon_sample_events.ndjson, itself hand-authored and static) — no
Windows APIs, no Docker, no live Elasticsearch, no network. Runs on
non-Windows CI like every other test in this suite.
"""

from __future__ import annotations

import ast
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from attribution_platform.dataplane import (
    FakeElasticClient,
    load_evidence,
    load_observation,
    persist_evidence,
    persist_observation,
)
from attribution_platform.domain import EvidenceType, Observation
from attribution_platform.extraction import (
    DetectionMatchRecord,
    MatchedEvent,
    RuleRef,
    derive_evidence,
    extract_observations,
)
from attribution_platform.sources.adapter import convert
from attribution_platform.sources.errors import SourceAdapterError
from attribution_platform.sources.sysmon import (
    NETWORK_CONNECT_EVENT_ID,
    PROCESS_CREATE_EVENT_ID,
    SYSMON_SOURCE_TYPE,
    SysmonSourceAdapter,
    load_ndjson_events,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_PATH = REPO_ROOT / "fixtures" / "sysmon_sample_events.ndjson"
EXTRACTION_DIR = REPO_ROOT / "src" / "attribution_platform" / "extraction"


def _process_create_event(**overrides: object) -> dict[str, Any]:
    event: dict[str, Any] = {
        "@timestamp": "2026-01-01T12:00:00+00:00",
        "event": {"code": "1"},
        "winlog": {"event_id": 1, "record_id": 1, "computer_name": "WIN-HOST"},
        "host": {"name": "WIN-HOST", "ip": ["10.0.0.5"]},
        "user": {"name": "alice", "domain": "CORP"},
        "process": {
            "pid": 111,
            "name": "cmd.exe",
            "executable": "C:\\Windows\\System32\\cmd.exe",
            "command_line": "cmd.exe /c whoami",
            "entity_id": "proc-111",
            "parent": {"pid": 100, "name": "explorer.exe", "entity_id": "proc-100"},
        },
    }
    event.update(overrides)
    return event


# ===========================================================================
# 1. Valid conversion, both supported event types
# ===========================================================================


def test_process_create_event_converts_to_observation() -> None:
    adapter = SysmonSourceAdapter()
    (obs,) = convert(adapter, _process_create_event())
    assert isinstance(obs, Observation)
    assert obs.observation_id == "sysmon:WIN-HOST:1"
    assert obs.timestamp == datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
    assert obs.process is not None
    assert obs.process.pid == 111
    assert obs.process.parent_pid == 100
    assert obs.host is not None
    assert obs.host.name == "WIN-HOST"
    assert obs.user is not None
    assert obs.user.name == "alice"
    assert obs.network is None
    assert obs.event is not None
    assert obs.event.category == ("process",)


def test_network_connect_event_converts_to_observation() -> None:
    events = load_ndjson_events(FIXTURE_PATH)
    network_event = next(e for e in events if e["winlog"]["event_id"] == NETWORK_CONNECT_EVENT_ID)
    adapter = SysmonSourceAdapter()
    (obs,) = convert(adapter, network_event)
    assert obs.network is not None
    assert obs.network.source is not None
    assert obs.network.source.ip == "10.0.0.5"
    assert obs.network.source.port == 51234
    assert obs.network.destination is not None
    assert obs.network.destination.ip == "93.184.216.34"
    assert obs.network.transport == "tcp"
    assert obs.event is not None
    assert obs.event.category == ("network",)


def test_checked_in_fixture_events_all_convert() -> None:
    events = load_ndjson_events(FIXTURE_PATH)
    adapter = SysmonSourceAdapter()
    for event in events:
        observations = convert(adapter, event)
        assert len(observations) == 1


def test_observation_id_uses_supplied_value_when_present() -> None:
    adapter = SysmonSourceAdapter()
    (obs,) = convert(adapter, _process_create_event(observation_id="custom-id"))
    assert obs.observation_id == "custom-id"


# ===========================================================================
# 2. Provenance preservation
# ===========================================================================


def test_provenance_source_type_and_record_id_preserved() -> None:
    adapter = SysmonSourceAdapter()
    (obs,) = convert(
        adapter,
        _process_create_event(winlog={"event_id": 1, "record_id": 555, "computer_name": "H"}),
    )
    assert obs.raw_reference.source_type == SYSMON_SOURCE_TYPE == "sysmon"
    assert obs.raw_reference.source_event_id == "555"


# ===========================================================================
# 3. Fail-closed: malformed events, missing fields, invalid timestamps
# ===========================================================================


def test_non_mapping_raw_record_rejected() -> None:
    adapter = SysmonSourceAdapter()
    with pytest.raises(SourceAdapterError, match="expects a Mapping"):
        adapter.to_observations("not-a-mapping")


@pytest.mark.parametrize(
    ("overrides", "match"),
    [
        ({"winlog": {"record_id": 1, "computer_name": "H"}, "event": {}}, "winlog.event_id"),
        ({"@timestamp": None}, "@timestamp"),
        ({"@timestamp": "not-a-timestamp"}, "not a valid ISO-8601"),
        ({"winlog": {"event_id": 1, "computer_name": "H"}}, "winlog.record_id"),
        ({"winlog": {"event_id": 1, "record_id": 1}, "host": {}}, "computer_name"),
    ],
)
def test_missing_or_malformed_required_fields_rejected(
    overrides: dict[str, Any], match: str
) -> None:
    adapter = SysmonSourceAdapter()
    with pytest.raises(SourceAdapterError, match=match):
        adapter.to_observations(_process_create_event(**overrides))


def test_unsupported_event_id_fails_closed() -> None:
    adapter = SysmonSourceAdapter()
    # Event 10 (process access) is not supported yet (ADR-0008 Wave 1, next batch).
    event = _process_create_event(winlog={"event_id": 10, "record_id": 1, "computer_name": "H"})
    with pytest.raises(SourceAdapterError, match="unsupported winlog.event_id"):
        adapter.to_observations(event)


def test_non_integer_pid_fails_closed() -> None:
    adapter = SysmonSourceAdapter()
    event = _process_create_event(process={"pid": "not-an-int"})
    with pytest.raises(SourceAdapterError, match="process.pid"):
        adapter.to_observations(event)


# ===========================================================================
# 4. NDJSON file-input loader
# ===========================================================================


def test_load_ndjson_events_reads_the_checked_in_fixture() -> None:
    events = load_ndjson_events(FIXTURE_PATH)
    assert len(events) == 2
    assert events[0]["winlog"]["event_id"] == PROCESS_CREATE_EVENT_ID


def test_load_ndjson_events_missing_file(tmp_path: Path) -> None:
    with pytest.raises(SourceAdapterError, match="could not read"):
        load_ndjson_events(tmp_path / "does-not-exist.ndjson")


def test_load_ndjson_events_skips_blank_lines(tmp_path: Path) -> None:
    path = tmp_path / "events.ndjson"
    path.write_text('{"a": 1}\n\n   \n{"b": 2}\n', encoding="utf-8")
    events = load_ndjson_events(path)
    assert events == ({"a": 1}, {"b": 2})


def test_load_ndjson_events_rejects_invalid_json_line(tmp_path: Path) -> None:
    path = tmp_path / "events.ndjson"
    path.write_text('{"a": 1}\nnot json\n', encoding="utf-8")
    with pytest.raises(SourceAdapterError, match="not valid JSON"):
        load_ndjson_events(path)


def test_load_ndjson_events_rejects_non_object_line(tmp_path: Path) -> None:
    path = tmp_path / "events.ndjson"
    path.write_text("[1, 2, 3]\n", encoding="utf-8")
    with pytest.raises(SourceAdapterError, match="not a JSON object"):
        load_ndjson_events(path)


def test_load_ndjson_events_rejects_empty_file(tmp_path: Path) -> None:
    path = tmp_path / "events.ndjson"
    path.write_text("", encoding="utf-8")
    with pytest.raises(SourceAdapterError, match="no events found"):
        load_ndjson_events(path)


# ===========================================================================
# 5. Reuses the same G0.5/G0.6/G0.8 pipeline -- no parallel ingestion path
# ===========================================================================


def test_sysmon_observation_flows_through_the_same_extraction_boundary() -> None:
    events = load_ndjson_events(FIXTURE_PATH)
    adapter = SysmonSourceAdapter()
    (adapter_observation,) = convert(adapter, events[0])

    matched_event = MatchedEvent(
        observation_id=adapter_observation.observation_id,
        source_ref=adapter_observation.raw_reference,
        timestamp=adapter_observation.timestamp,
        event=adapter_observation.event,
        host=adapter_observation.host,
        user=adapter_observation.user,
        process=adapter_observation.process,
        network=adapter_observation.network,
        file=adapter_observation.file,
    )
    record = DetectionMatchRecord(
        rule_ref=RuleRef(rule_id="r1", rule_version="1.0"), matched_events=(matched_event,)
    )
    (extracted_observation,) = extract_observations(record)
    assert extracted_observation == adapter_observation


def test_sysmon_observation_flows_through_evidence_derivation_and_persistence() -> None:
    events = load_ndjson_events(FIXTURE_PATH)
    adapter = SysmonSourceAdapter()
    (observation,) = convert(adapter, events[0])
    rule_ref = RuleRef(rule_id="r1", rule_version="1.0")

    evidence = derive_evidence(
        evidence_id="ev1",
        evidence_type=EvidenceType.BEHAVIORAL,
        claim="benign process creation observed via Sysmon (synthetic)",
        observations=(observation,),
        rule_ref=rule_ref,
    )

    client = FakeElasticClient()
    persist_observation(client, observation)
    persist_evidence(client, evidence)

    assert load_observation(client, observation.observation_id) == observation
    assert load_evidence(client, "ev1") == evidence
    assert evidence.provenance.source_observation_ids == (observation.observation_id,)


# ===========================================================================
# 6. Source-agnosticism: no Sysmon-native field name survives into Observation
# ===========================================================================


def test_observation_carries_no_sysmon_native_field_names() -> None:
    """The produced Observation's own serialized form must not contain any
    Sysmon/winlog-native key -- only G0.3 domain field names."""
    from attribution_platform.domain import to_serializable

    events = load_ndjson_events(FIXTURE_PATH)
    adapter = SysmonSourceAdapter()
    for event in events:
        (obs,) = convert(adapter, event)
        serialized_keys = set(to_serializable(obs).keys())
        assert "winlog" not in serialized_keys
        assert "event_id" not in serialized_keys
        assert "record_id" not in serialized_keys
        assert "computer_name" not in serialized_keys


# ===========================================================================
# 7. Guard: extraction never imports sources (Sysmon specifics stay confined)
# ===========================================================================


def test_extraction_package_never_imports_from_sources() -> None:
    extraction_files = sorted(EXTRACTION_DIR.glob("*.py"))
    assert extraction_files, "expected to find extraction/*.py files"

    offending: list[str] = []
    for path in extraction_files:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module and "sources" in node.module:
                offending.append(f"{path.name}: from {node.module} import ...")
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if "sources" in alias.name:
                        offending.append(f"{path.name}: import {alias.name}")

    assert not offending, f"extraction/ must not import from sources/: {offending}"
