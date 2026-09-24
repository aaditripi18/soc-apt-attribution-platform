"""ADR-0007 D10 step 1: completed process-creation telemetry.

Covers the new ``ProcessRef`` fields (parent executable/command line, working
directory, integrity level, PE metadata) end to end: Sysmon adapter (raw
``winlog.event_data`` preferred, ECS fallback, ``parent_name`` always a bare
name), replay-fixture parsing, persistence round trip, the Sigma field map
(every mapped path really exists on an Observation), and a real Sigma rule that
can only fire with the parent-executable field.
"""

from __future__ import annotations

import copy
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from attribution_platform.attack_knowledge.loader import AttackKnowledge, load_attack_knowledge
from attribution_platform.dataplane import FakeElasticClient, load_observation, persist_observation
from attribution_platform.detection import DetectionEngine, load_rule_pack
from attribution_platform.detection.rules import _resolve_field
from attribution_platform.detection_content.sigma_field_map import FIELD_MAPS
from attribution_platform.domain import (
    CodeSignature,
    DllRef,
    DnsRef,
    EventMetadata,
    FileRef,
    NetworkEndpoint,
    NetworkInfo,
    Observation,
    PeInfo,
    ProcessAccessRef,
    ProcessRef,
    RegistryRef,
    RemoteThreadRef,
    SourceRef,
)
from attribution_platform.replay.detection_fixtures import _process_ref_from_dict
from attribution_platform.sources.sysmon import SysmonSourceAdapter

REPO_ROOT = Path(__file__).resolve().parents[1]
SIGMA_PACK = (
    REPO_ROOT
    / "data"
    / "detection"
    / "sigma"
    / "r2026-07-01"
    / "generated"
    / "sigma-r2026-07-01-sigma_core++.rules.json"
)
OFFICE_SPAWN_FAMILY = "sigma:aa3a6f94-890e-4e22-b634-ffdfd54792cc"
WINWORD = "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"


@pytest.fixture(scope="module")
def knowledge() -> AttackKnowledge:
    return load_attack_knowledge()


def _sysmon_process_create(
    event_data: dict[str, Any] | None = None, process: dict[str, Any] | None = None
) -> dict[str, Any]:
    record: dict[str, Any] = {
        "@timestamp": "2026-01-01T12:00:00+00:00",
        "winlog": {"event_id": 1, "record_id": 7, "computer_name": "WIN-HOST"},
        "process": process
        or {
            "pid": 222,
            "name": "invoice.exe",
            "executable": "C:\\Users\\bob\\AppData\\Local\\Temp\\invoice.exe",
            "command_line": "invoice.exe",
            "entity_id": "proc-222",
            "parent": {"pid": 200, "entity_id": "proc-200"},
        },
    }
    if event_data is not None:
        record["winlog"]["event_data"] = event_data
    return record


FULL_EVENT_DATA = {
    "ParentImage": WINWORD,
    "ParentCommandLine": '"WINWORD.EXE" /n "C:\\Users\\bob\\Downloads\\invoice.docm"',
    "CurrentDirectory": "C:\\Users\\bob\\Documents\\",
    "IntegrityLevel": "Medium",
    "OriginalFileName": "invoice.exe",
    "Description": "Invoice Viewer",
    "Product": "Invoice Tools",
    "Company": "Example Ltd",
}


# ===========================================================================
# Sysmon adapter
# ===========================================================================


def test_sysmon_maps_event_data_fields() -> None:
    (obs,) = SysmonSourceAdapter().to_observations(_sysmon_process_create(FULL_EVENT_DATA))
    process = obs.process
    assert process is not None
    assert process.parent_executable == WINWORD
    assert process.parent_name == "WINWORD.EXE"  # bare name derived from the path
    assert process.parent_command_line == FULL_EVENT_DATA["ParentCommandLine"]
    assert process.working_directory == "C:\\Users\\bob\\Documents\\"
    assert process.integrity_level == "Medium"
    assert process.pe == PeInfo(
        original_file_name="invoice.exe",
        description="Invoice Viewer",
        product="Invoice Tools",
        company="Example Ltd",
    )


def test_sysmon_falls_back_to_ecs_fields() -> None:
    process = {
        "pid": 222,
        "executable": "C:\\x.exe",
        "working_directory": "C:\\work",
        "pe": {"original_file_name": "x.exe"},
        "parent": {"executable": WINWORD, "command_line": "winword"},
    }
    (obs,) = SysmonSourceAdapter().to_observations(_sysmon_process_create(process=process))
    assert obs.process is not None
    assert obs.process.parent_executable == WINWORD
    assert obs.process.parent_name == "WINWORD.EXE"
    assert obs.process.parent_command_line == "winword"
    assert obs.process.working_directory == "C:\\work"
    assert obs.process.pe == PeInfo(original_file_name="x.exe")
    assert obs.process.integrity_level is None  # no ECS equivalent exists


def test_event_data_wins_over_ecs() -> None:
    record = _sysmon_process_create({"ParentImage": WINWORD})
    record["process"]["parent"]["executable"] = "C:\\ecs\\other.exe"
    (obs,) = SysmonSourceAdapter().to_observations(record)
    assert obs.process is not None and obs.process.parent_executable == WINWORD


def test_parent_name_prefers_ecs_name_and_is_never_a_path() -> None:
    record = _sysmon_process_create({"ParentImage": WINWORD})
    record["process"]["parent"]["name"] = "winword.exe"
    (obs,) = SysmonSourceAdapter().to_observations(record)
    assert obs.process is not None and obs.process.parent_name == "winword.exe"
    # Previously parent_name fell back to the full parent executable path.
    (obs2,) = SysmonSourceAdapter().to_observations(_sysmon_process_create({}))
    assert obs2.process is not None and obs2.process.parent_name is None


def test_no_pe_fields_means_no_pe_object() -> None:
    (obs,) = SysmonSourceAdapter().to_observations(_sysmon_process_create())
    assert obs.process is not None
    assert obs.process.pe is None
    assert obs.process.parent_executable is None


def test_adapter_does_not_mutate_record() -> None:
    record = _sysmon_process_create(FULL_EVENT_DATA)
    before = copy.deepcopy(record)
    SysmonSourceAdapter().to_observations(record)
    assert record == before


# ===========================================================================
# Replay fixtures and persistence
# ===========================================================================


def test_replay_fixture_parses_new_fields() -> None:
    process = _process_ref_from_dict(
        {
            "executable": "C:\\x.exe",
            "parent_executable": WINWORD,
            "parent_command_line": "winword",
            "working_directory": "C:\\w",
            "integrity_level": "High",
            "pe": {"original_file_name": "x.exe", "company": "C"},
        },
        where="t",
    )
    assert process is not None
    assert process.parent_executable == WINWORD
    assert process.integrity_level == "High"
    assert process.pe == PeInfo(original_file_name="x.exe", company="C")


def test_persistence_round_trips_new_fields() -> None:
    (obs,) = SysmonSourceAdapter().to_observations(_sysmon_process_create(FULL_EVENT_DATA))
    client = FakeElasticClient()
    persist_observation(client, obs)
    assert load_observation(client, obs.observation_id) == obs


# ===========================================================================
# Sigma field map and a real rule that needs the new fields
# ===========================================================================


def _full_observation() -> Observation:
    return Observation(
        observation_id="o",
        timestamp=datetime(2026, 1, 1, tzinfo=UTC),
        raw_reference=SourceRef(source_type="synthetic", source_event_id="r"),
        event=EventMetadata(kind="event", category=("process",), type=("start",), action="a"),
        file=FileRef(path="a"),
        dll=DllRef(
            path="a",
            pe=PeInfo(original_file_name="a", description="a", product="a", company="a"),
            code_signature=CodeSignature(signed=True, subject_name="a", status="a"),
        ),
        registry=RegistryRef(path="a", data="a"),
        target_process=ProcessRef(executable="a"),
        process_access=ProcessAccessRef(granted_access="a", call_trace="a"),
        remote_thread=RemoteThreadRef(start_address="a", start_module="a", start_function="a"),
        dns=DnsRef(question_name="a", query_status="a", results="a"),
        process=ProcessRef(
            executable="a",
            command_line="a",
            parent_executable="a",
            parent_command_line="a",
            working_directory="a",
            integrity_level="a",
            pe=PeInfo(original_file_name="a", description="a", product="a", company="a"),
        ),
        network=NetworkInfo(
            source=NetworkEndpoint(ip="a", port=1),
            destination=NetworkEndpoint(ip="a", port=1),
            transport="a",
        ),
    )


def test_every_mapped_field_path_resolves_on_a_real_observation() -> None:
    obs = _full_observation()
    for field_map in FIELD_MAPS.values():
        for sigma_field, field_path in field_map.items():
            assert _resolve_field(obs, field_path) is not None, (sigma_field, field_path)


def test_office_spawn_rule_fires_only_with_parent_executable(knowledge: AttackKnowledge) -> None:
    pack = load_rule_pack(SIGMA_PACK, knowledge=knowledge)
    rules = tuple(r for r in pack.rules if r.rule_family == OFFICE_SPAWN_FAMILY)
    assert rules
    engine = DetectionEngine(rules=rules)

    (with_parent,) = SysmonSourceAdapter().to_observations(
        _sysmon_process_create({"ParentImage": WINWORD})
    )
    # the adapter supplies the event scope imported Sigma rules require
    assert with_parent.event is not None
    assert (with_parent.event.category, with_parent.event.type) == (("process",), ("start",))
    (detection,) = engine.evaluate([with_parent])
    assert [m.attack_ref.external_id for m in detection.technique_mappings] == ["T1204.002"]

    (without_parent,) = SysmonSourceAdapter().to_observations(_sysmon_process_create({}))
    assert engine.evaluate([without_parent]) == ()
