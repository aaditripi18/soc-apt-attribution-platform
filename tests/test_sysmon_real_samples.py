"""Sysmon adapter golden tests on real telemetry (ADR-0008 D2 acceptance standard).

Uses the commit-pinned OTRF Security-Datasets samples under
``data/telemetry-samples/otrf`` (flat Windows-EventData JSON). Covers: sample
integrity; every supported record converts and every other record is refused
with an explicit reason (golden counts); exact field mapping for event IDs 1, 7,
11, 12, 13; Sysmon ``UtcTime`` as event time; deterministic derived record ids;
registry fail-closed rules; ECS-shaped collector records for the new event
types; source-agnostic output; the process identity/lineage facts correlation
relies on; and the detections the production Sigma pack raises on the real data.
"""

from __future__ import annotations

import collections
import hashlib
import json
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from attribution_platform.attack_knowledge.loader import AttackKnowledge, load_attack_knowledge
from attribution_platform.detection import DetectionEngine, load_rule_pack
from attribution_platform.domain import (
    CodeSignature,
    EvidenceQuality,
    Observation,
    PeInfo,
    to_canonical_json,
)
from attribution_platform.sources.errors import SourceAdapterError
from attribution_platform.sources.sysmon import SysmonSourceAdapter

REPO_ROOT = Path(__file__).resolve().parents[1]
SAMPLES_DIR = REPO_ROOT / "data" / "telemetry-samples" / "otrf"
MANIFEST = json.loads((SAMPLES_DIR / "manifest.json").read_text(encoding="utf-8"))
HTTPLISTENER = SAMPLES_DIR / "psh_powershell_httplistener.zip"
MAVINJECT = SAMPLES_DIR / "psh_mavinject_dll_notepad.zip"
SIGMA_PACK = (
    REPO_ROOT
    / "data"
    / "detection"
    / "sigma"
    / "r2026-07-01"
    / "generated"
    / "sigma-r2026-07-01-sigma_core++.rules.json"
)
ADAPTER = SysmonSourceAdapter()


def _records(path: Path) -> list[dict[str, Any]]:
    with zipfile.ZipFile(path) as archive:
        (member,) = archive.namelist()
        text = archive.read(member).decode("utf-8")
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def _convert_all(path: Path) -> tuple[list[Observation], collections.Counter[str]]:
    observations: list[Observation] = []
    refusals: collections.Counter[str] = collections.Counter()
    for record in _records(path):
        try:
            observations.extend(ADAPTER.to_observations(record))
        except SourceAdapterError as exc:
            refusals[f"{record['Channel']}:{record['EventID']}:{str(exc).split(' (')[0]}"] += 1
    return observations, refusals


def _first(path: Path, event_id: int, **match: str) -> dict[str, Any]:
    return next(
        r
        for r in _records(path)
        if r["EventID"] == event_id
        and r["Channel"] == "Microsoft-Windows-Sysmon/Operational"
        and all(r.get(k) == v for k, v in match.items())
    )


# ===========================================================================
# Sample integrity
# ===========================================================================


@pytest.mark.parametrize("entry", MANIFEST["samples"], ids=lambda e: e["filename"])
def test_sample_matches_pinned_hash(entry: dict[str, Any]) -> None:
    data = (REPO_ROOT / entry["relative_path"]).read_bytes()
    assert len(data) == entry["size_bytes"]
    assert hashlib.sha256(data).hexdigest() == entry["sha256"]
    assert entry["source_commit"] == "d9d40ef123d2c87d5d3df28c96bcab4f0faccc87"


# ===========================================================================
# Golden conversion counts: supported converts, everything else is refused
# ===========================================================================


def test_every_supported_sysmon_record_converts_and_the_rest_are_refused() -> None:
    supported = (1, 3, 7, 8, 10, 11, 12, 13, 22)
    converted: collections.Counter[int] = collections.Counter()
    refusals: collections.Counter[str] = collections.Counter()
    for path in (HTTPLISTENER, MAVINJECT):
        observations, refused = _convert_all(path)
        refusals.update(refused)
        expected = [
            r
            for r in _records(path)
            if r["Channel"] == "Microsoft-Windows-Sysmon/Operational" and r["EventID"] in supported
        ]
        assert len(observations) == len(expected)  # nothing supported is lost
        converted.update(r["EventID"] for r in expected)
    assert converted == {10: 309, 7: 108, 12: 85, 13: 52, 11: 4, 22: 3, 1: 2, 3: 2, 8: 1}
    sysmon_refusals = {k for k in refusals if k.startswith("Microsoft-Windows-Sysmon")}
    assert {k.split(":")[1] for k in sysmon_refusals} == {"9", "24"}
    for key in sysmon_refusals:
        assert key.endswith("unsupported winlog.event_id " + key.split(":")[1])
    other = {k for k in refusals if not k.startswith("Microsoft-Windows-Sysmon")}
    assert {k.split(":")[0] for k in other} == {"Security", "System"}
    assert all("is not 'Microsoft-Windows-Sysmon/Operational'" in k for k in other)


# ===========================================================================
# Exact field mapping per event type (golden values from the real records)
# ===========================================================================


def test_process_create_golden_fields() -> None:
    record = _first(MAVINJECT, 1, Image="C:\\Windows\\System32\\notepad.exe")
    (obs,) = ADAPTER.to_observations(record)
    p = obs.process
    assert p is not None
    assert p.executable == "C:\\Windows\\System32\\notepad.exe"
    assert p.name == "notepad.exe"
    assert p.pid == 3440
    assert p.entity_id == "{39e4a257-e321-5f90-d210-000000000700}"
    assert p.parent_entity_id == "{39e4a257-e287-5f90-cc10-000000000700}"
    assert p.parent_pid == 3904
    assert p.parent_name == "powershell.exe"
    assert p.integrity_level == "High"
    assert p.working_directory == "C:\\Users\\wardog\\"
    assert p.pe is not None and p.pe.original_file_name == "NOTEPAD.EXE"
    assert obs.user is not None and (obs.user.domain, obs.user.name) == ("WORKSTATION5", "wardog")
    assert obs.host is not None and obs.host.name == "WORKSTATION5"
    assert obs.event is not None and obs.event.category == ("process",)


def test_image_load_golden_fields() -> None:
    record = _first(HTTPLISTENER, 7, ImageLoaded="C:\\Windows\\System32\\edputil.dll")
    (obs,) = ADAPTER.to_observations(record)
    assert obs.dll is not None
    assert obs.dll.path == "C:\\Windows\\System32\\edputil.dll"
    assert obs.dll.name == "edputil.dll"
    assert obs.dll.pe is not None and obs.dll.pe.original_file_name == "EDPUTIL.DLL"
    assert obs.dll.code_signature == CodeSignature(
        signed=True, subject_name="Microsoft Windows", status="Valid"
    )
    # The loading process keeps no PE metadata: those EventData fields describe the DLL.
    assert obs.process is not None and obs.process.pe is None
    assert obs.process.executable == "C:\\Windows\\System32\\conhost.exe"
    assert obs.event is not None
    assert (obs.event.category, obs.event.type) == (("library",), ("start",))


def test_file_create_golden_fields() -> None:
    record = _first(MAVINJECT, 11, TargetFilename="C:\\ProgramData\\T1055.dll")
    (obs,) = ADAPTER.to_observations(record)
    assert obs.file is not None
    assert (obs.file.path, obs.file.name, obs.file.directory) == (
        "C:\\ProgramData\\T1055.dll",
        "T1055.dll",
        "C:\\ProgramData",
    )
    assert obs.process is not None and obs.process.name == "powershell.exe"
    assert obs.event is not None
    assert (obs.event.category, obs.event.type) == (("file",), ("creation",))


@pytest.mark.parametrize(
    ("event_id", "event_type", "ecs_type"),
    [(12, "CreateKey", "creation"), (13, "SetValue", "change")],
)
def test_registry_golden_fields(event_id: int, event_type: str, ecs_type: str) -> None:
    record = _first(MAVINJECT, event_id, EventType=event_type)
    (obs,) = ADAPTER.to_observations(record)
    assert obs.registry is not None
    assert obs.registry.path == record["TargetObject"]
    assert obs.registry.data == (record["Details"] if event_id == 13 else None)
    assert obs.event is not None
    assert obs.event.category == ("registry",)
    assert obs.event.type == (ecs_type,)
    assert obs.event.action == event_type


# ===========================================================================
# Time, identity, fail-closed rules
# ===========================================================================


def test_event_time_is_sysmons_utctime_not_the_collector_timestamp() -> None:
    record = _first(MAVINJECT, 1, Image="C:\\Windows\\System32\\notepad.exe")
    (obs,) = ADAPTER.to_observations(record)
    assert obs.timestamp == datetime(2020, 10, 22, 1, 40, 49, 684000, tzinfo=UTC)
    assert record["@timestamp"].startswith("2020-10-21T09:40")  # disagrees by 16 hours


def test_derived_record_ids_are_deterministic_and_unique() -> None:
    ids = []
    for path in (HTTPLISTENER, MAVINJECT):
        observations, _ = _convert_all(path)
        again, _ = _convert_all(path)
        assert [o.raw_reference.source_event_id for o in observations] == [
            o.raw_reference.source_event_id for o in again
        ]
        ids += [o.observation_id for o in observations]
    # Flat records carry no record id: byte-identical records (here 26 repeated
    # Sysmon 12/10 records) are indistinguishable and share one id, i.e.
    # they are one observation. Repetition never changes the decision basis
    # (distinct features, ADR-0005 Amendment B); this is recorded in ADR-0008.
    assert (len(ids), len(set(ids))) == (566, 540)
    assert all(i.startswith("sysmon:WORKSTATION5:sha256:") for i in ids)


def test_identical_flat_records_share_one_observation_id() -> None:
    records = [r for r in _records(HTTPLISTENER) if r["EventID"] == 12]
    lines = collections.Counter(json.dumps(r, sort_keys=True) for r in records)
    repeated = json.loads(next(line for line, n in lines.items() if n > 1))
    (a,) = ADAPTER.to_observations(repeated)
    (b,) = ADAPTER.to_observations(dict(repeated))
    assert a == b
    changed = {**repeated, "UtcTime": "2020-11-02 09:13:01.791"}
    (c,) = ADAPTER.to_observations(changed)
    assert c.observation_id != a.observation_id


def _flat(event_id: int, **fields: Any) -> dict[str, Any]:
    return {
        "EventID": event_id,
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "Hostname": "H",
        "UtcTime": "2026-01-01 00:00:00.000",
        "Image": "C:\\x.exe",
        "ProcessId": "1",
        **fields,
    }


@pytest.mark.parametrize(
    ("record", "match"),
    [
        (_flat(13, EventType="CreateKey", TargetObject="HKLM\\x"), "EventType 'CreateKey'"),
        (_flat(12, EventType="SetValue", TargetObject="HKLM\\x"), "EventType 'SetValue'"),
        (_flat(12, TargetObject="HKLM\\x"), "EventType None"),
        (_flat(12, EventType="CreateKey"), "without TargetObject"),
        (_flat(7), "without ImageLoaded"),
        (_flat(7, ImageLoaded="C:\\a.dll", Signed="maybe"), "Signed 'maybe'"),
        (_flat(11), "without TargetFilename"),
        ({**_flat(1), "Channel": "Security"}, "channel 'Security'"),
        ({k: v for k, v in _flat(1).items() if k != "UtcTime"}, "missing required field UtcTime"),
        (_flat(1, UtcTime="2026-01-01T00:00:00+05:00"), "must not carry an offset"),
    ],
)
def test_fail_closed(record: dict[str, Any], match: str) -> None:
    with pytest.raises(SourceAdapterError, match=match):
        ADAPTER.to_observations(record)


def test_ecs_collector_records_for_new_event_types() -> None:
    def ecs(event_id: int, event_data: dict[str, Any]) -> dict[str, Any]:
        return {
            "@timestamp": "2026-01-01T00:00:00+00:00",
            "winlog": {
                "event_id": event_id,
                "record_id": event_id,
                "computer_name": "H",
                "event_data": event_data,
            },
            "process": {"pid": 5, "executable": "C:\\p.exe", "entity_id": "g"},
        }

    (image_load,) = ADAPTER.to_observations(
        ecs(7, {"ImageLoaded": "C:\\a.dll", "Signed": "false", "OriginalFileName": "a.dll"})
    )
    assert image_load.dll is not None
    assert image_load.dll.code_signature == CodeSignature(signed=False)
    assert image_load.dll.pe == PeInfo(original_file_name="a.dll")
    (registry,) = ADAPTER.to_observations(
        ecs(13, {"EventType": "SetValue", "TargetObject": "HKLM\\k\\v", "Details": "1"})
    )
    assert registry.registry is not None and registry.registry.data == "1"
    assert registry.process is not None and registry.process.entity_id == "g"


# ===========================================================================
# Source-agnostic output and correlation facts
# ===========================================================================


def test_no_sysmon_native_names_leave_the_adapter() -> None:
    observations, _ = _convert_all(MAVINJECT)
    for obs in observations:
        text = to_canonical_json(obs)
        for native in ('"EventID"', '"Channel"', '"winlog"', '"TargetObject"', '"ImageLoaded"'):
            assert native not in text


def test_process_identity_and_lineage_are_preserved_for_correlation() -> None:
    """ADR-0003 correlates on process.entity_id / parent_entity_id. The real
    sample's chain powershell -> (writes T1055.dll) -> mavinject -> notepad must
    be expressible through those identifiers."""
    observations, _ = _convert_all(MAVINJECT)
    by_image: dict[str, list[Observation]] = collections.defaultdict(list)
    for obs in observations:
        if obs.process is not None and obs.process.executable:
            by_image[obs.process.executable.lower()].append(obs)
    mavinject = next(
        o
        for o in by_image["c:\\windows\\system32\\mavinject.exe"]
        if o.event is not None and o.event.category == ("process",)
    )
    dropper = next(o for o in observations if o.file and o.file.name == "T1055.dll")
    assert mavinject.process is not None and dropper.process is not None
    # the process that wrote the DLL is the parent that launched mavinject
    assert mavinject.process.parent_entity_id == dropper.process.entity_id


# ===========================================================================
# Detections the production Sigma pack raises on the real data
# ===========================================================================


@pytest.fixture(scope="module")
def knowledge() -> AttackKnowledge:
    return load_attack_knowledge()


def test_production_sigma_pack_detects_the_documented_injection(
    knowledge: AttackKnowledge,
) -> None:
    engine = DetectionEngine(rules=load_rule_pack(SIGMA_PACK, knowledge=knowledge).rules)
    observations, _ = _convert_all(MAVINJECT)
    detections = engine.evaluate(observations)
    techniques = {m.attack_ref.external_id for d in detections for m in d.technique_mappings}
    assert {"T1218.013", "T1055.001"} <= techniques
    # every core-tier detection is on the mavinject process creation; anything
    # else is enrich-tier (ADR-0007 Amendment A) and LOW quality
    core = [d for d in detections if d.evidence_quality is None]
    assert len({d.supporting_observation_ids for d in core}) == 1
    assert all(d.evidence_quality is EvidenceQuality.LOW for d in detections if d.evidence_quality)
    listener, _ = _convert_all(HTTPLISTENER)
    assert [d for d in engine.evaluate(listener) if d.evidence_quality is None] == []


# ===========================================================================
# Batch B — process access (10), remote thread (8), DNS (22)
# ===========================================================================


def test_remote_thread_golden_fields_and_injection_chain() -> None:
    record = _first(MAVINJECT, 8)
    (obs,) = ADAPTER.to_observations(record)
    assert obs.process is not None and obs.target_process is not None
    assert obs.process.executable == "C:\\Windows\\System32\\mavinject.exe"
    assert obs.process.entity_id == "{39e4a257-e328-5f90-d310-000000000700}"  # Source*Guid
    assert obs.target_process.executable == "C:\\Windows\\System32\\notepad.exe"
    assert obs.target_process.entity_id == "{39e4a257-e321-5f90-d210-000000000700}"
    assert obs.remote_thread is not None
    assert obs.remote_thread.start_function == "LoadLibraryW"
    assert obs.remote_thread.start_module == "C:\\windows\\System32\\KERNEL32.DLL"
    assert obs.event is not None
    assert (obs.event.category, obs.event.type, obs.event.action) == (
        ("process",),
        ("change",),
        "create_remote_thread",
    )
    # Both ends are the same process instances their own process-start events describe.
    starts = {
        o.process.executable: o.process.entity_id
        for o in _convert_all(MAVINJECT)[0]
        if o.event is not None
        and o.event.category == ("process",)
        and o.event.type == ("start",)
        and o.process is not None
    }
    assert starts["C:\\Windows\\System32\\mavinject.exe"] == obs.process.entity_id
    assert starts["C:\\Windows\\System32\\notepad.exe"] == obs.target_process.entity_id


def test_process_access_golden_fields_use_event_10_guid_spelling() -> None:
    record = _first(HTTPLISTENER, 10)
    assert "SourceProcessGUID" in record and "SourceProcessGuid" not in record
    (obs,) = ADAPTER.to_observations(record)
    assert obs.process is not None and obs.target_process is not None
    assert obs.process.entity_id == record["SourceProcessGUID"]
    assert obs.target_process.entity_id == record["TargetProcessGUID"]
    assert obs.process.pid == int(record["SourceProcessId"])
    assert obs.target_process.executable == record["TargetImage"]
    assert obs.process_access is not None
    assert obs.process_access.granted_access == record["GrantedAccess"]
    assert obs.process_access.call_trace == record["CallTrace"]
    assert obs.event is not None and obs.event.type == ("access",)


def test_dns_query_golden_fields() -> None:
    names = sorted(
        o.dns.question_name
        for path in (HTTPLISTENER, MAVINJECT)
        for o in _convert_all(path)[0]
        if o.dns is not None and o.dns.question_name is not None
    )
    assert names == ["WORKSTATION5", "github.com", "raw.githubusercontent.com"]
    record = _first(HTTPLISTENER, 22)
    (obs,) = ADAPTER.to_observations(record)
    assert obs.dns is not None
    assert (obs.dns.query_status, obs.dns.results) == ("0", record["QueryResults"])
    assert obs.event is not None
    assert "connection" not in obs.event.type  # a lookup is not a network connection


@pytest.mark.parametrize(
    ("record", "match"),
    [
        (_flat(10, SourceImage="C:\\a.exe", SourceProcessId="1"), "without any target process"),
        (_flat(8, SourceImage="C:\\a.exe", SourceProcessId="1"), "without any target process"),
        (_flat(22), "without QueryName"),
    ],
)
def test_batch_b_fail_closed(record: dict[str, Any], match: str) -> None:
    with pytest.raises(SourceAdapterError, match=match):
        ADAPTER.to_observations(record)


def test_lsass_dump_via_comsvcs_is_detected(knowledge: AttackKnowledge) -> None:
    """Hand-built (the OTRF samples contain no LSASS access): a flat Sysmon 10
    record of rundll32 reading LSASS through comsvcs.dll MiniDump — a common
    real-world credential-theft procedure — must fire the real Sigma rule
    'Lsass Memory Dump via Comsvcs DLL' and map to T1003.001."""
    record = _flat(
        10,
        SourceImage="C:\\Windows\\System32\\rundll32.exe",
        SourceProcessId="4242",
        SourceProcessGUID="{00000000-0000-0000-0000-000000004242}",
        TargetImage="C:\\Windows\\system32\\lsass.exe",
        TargetProcessId="700",
        TargetProcessGUID="{00000000-0000-0000-0000-000000000700}",
        GrantedAccess="0x1fffff",
        CallTrace="C:\\Windows\\SYSTEM32\\ntdll.dll+9d234|C:\\Windows\\System32\\comsvcs.dll+3c3f5",
    )
    (obs,) = ADAPTER.to_observations(record)
    pack = load_rule_pack(SIGMA_PACK, knowledge=knowledge)
    family = "sigma:a49fa4d5-11db-418c-8473-1e014a8dd462"
    engine = DetectionEngine(rules=tuple(r for r in pack.rules if r.rule_family == family))
    (detection,) = engine.evaluate([obs])
    assert [m.attack_ref.external_id for m in detection.technique_mappings] == ["T1003.001"]
    benign = {**record, "CallTrace": "C:\\Windows\\SYSTEM32\\ntdll.dll+9d234"}
    assert engine.evaluate(ADAPTER.to_observations(benign)) == ()


# ===========================================================================
# Real LSASS credential dumps (round-2 samples)
# ===========================================================================

COMSVCS = SAMPLES_DIR / "psh_lsass_memory_dump_comsvcs.zip"
DUMPERT = SAMPLES_DIR / "cmd_lsass_memory_dumpert_syscalls.zip"


def _detections(knowledge: AttackKnowledge, path: Path) -> list[tuple[str, frozenset[str]]]:
    engine = DetectionEngine(rules=load_rule_pack(SIGMA_PACK, knowledge=knowledge).rules)
    observations, _ = _convert_all(path)
    return sorted(
        (d.detection_source, frozenset(m.attack_ref.external_id or "" for m in mappings))
        for d in engine.evaluate(observations)
        for mappings in [d.technique_mappings]
    )


@pytest.mark.parametrize("path", [COMSVCS, DUMPERT], ids=["comsvcs", "dumpert"])
def test_real_lsass_dumps_are_detected_as_t1003_001(knowledge: AttackKnowledge, path: Path) -> None:
    detections = _detections(knowledge, path)
    assert len(detections) >= 4  # several independent rules, over different evidence
    assert all("T1003.001" in techniques for _, techniques in detections)


def test_real_lsass_access_events_are_converted() -> None:
    for path, source in (
        (COMSVCS, "C:\\Windows\\System32\\rundll32.exe"),
        (DUMPERT, "C:\\Users\\wardog\\Desktop\\Outflank-Dumpert.exe"),
    ):
        observations, _ = _convert_all(path)
        accesses = [
            o
            for o in observations
            if o.target_process is not None
            and (o.target_process.executable or "").lower().endswith("\\lsass.exe")
            and o.process is not None
            and o.process.executable == source
        ]
        assert accesses
        assert any(
            o.process_access is not None and o.process_access.granted_access == "0x1fffff"
            for o in accesses
        )


def test_dumpert_is_not_mislabelled_as_mimikatz(knowledge: AttackKnowledge) -> None:
    """The Sigma rule 'LSASS Memory Access by Tool With Dump Keyword In Name'
    carries a Mimikatz (S0002) tag, but this real tool is Outflank Dumpert. The
    reviewed software-tag policy keeps the false tool identity out of evidence."""
    detections = _detections(knowledge, DUMPERT)
    assert detections
    assert not any("S0002" in techniques for _, techniques in detections)
