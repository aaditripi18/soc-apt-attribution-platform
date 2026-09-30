"""Windows Security log adapter (ADR-0008 Wave 1, Security batch A).

Golden tests on real telemetry (OTRF Empire exports, NXLog flat variant):
conversion counts and explicit refusals; exact field mapping per event; the
exact event time; fail-closed cases; collector records; source-agnostic
output; the D3 source-precedence filter on real Sysmon + Security data; the
field map / importer event-code guard; the engine's dataset index; and
detection.

On these samples the production Sigma pack raises **no** Security-log
detection: the real Security events are benign system activity (svchost
reading LSA keys, Kerberos network logons, DC ``samr``/``lsarpc`` pipe
queries), pinned below as a zero-false-positive result. That the wiring
fires is proven on real records with one clearly labelled field changed.
"""

from __future__ import annotations

import collections
import contextlib
import copy
import json
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest

from attribution_platform.attack_knowledge.loader import AttackKnowledge, load_attack_knowledge
from attribution_platform.detection import DetectionEngine, load_rule_pack
from attribution_platform.detection_content.sigma_field_map import (
    FIELD_MAPS,
    SUPPORTED_EVENT_CODES,
)
from attribution_platform.domain import Observation, TimePrecision, to_canonical_json
from attribution_platform.sources.errors import SourceAdapterError
from attribution_platform.sources.precedence import apply_source_precedence, observation_kind
from attribution_platform.sources.sysmon import SysmonSourceAdapter
from attribution_platform.sources.windows_security import (
    SUPPORTED_EVENT_IDS,
    WindowsSecuritySourceAdapter,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
SAMPLES = REPO_ROOT / "data" / "telemetry-samples" / "otrf"
MIMIKATZ = SAMPLES / "empire_mimikatz_logonpasswords.zip"
SMBEXEC = SAMPLES / "empire_smbexec_dcerpc_smb_svcctl.zip"
WMI = SAMPLES / "empire_wmi_local_event_subscriptions_elevated_user.zip"
DUMPERT = SAMPLES / "cmd_lsass_memory_dumpert_syscalls.zip"
ROUND_2 = (MIMIKATZ, SMBEXEC, WMI)
SIGMA_PACK = (
    REPO_ROOT
    / "data"
    / "detection"
    / "sigma"
    / "r2026-07-01"
    / "generated"
    / "sigma-r2026-07-01-sigma_core++.rules.json"
)
ADAPTER = WindowsSecuritySourceAdapter()
_CACHE: dict[Path, list[dict[str, Any]]] = {}


def _all_records(path: Path) -> list[dict[str, Any]]:
    if path not in _CACHE:
        with zipfile.ZipFile(path) as archive:
            (member,) = archive.namelist()
            text = archive.read(member).decode("utf-8", "replace")
        _CACHE[path] = [json.loads(line) for line in text.splitlines() if line.strip()]
    return _CACHE[path]


def _records(path: Path, event_id: int | None = None) -> list[dict[str, Any]]:
    return [
        r
        for r in _all_records(path)
        if r.get("Channel") == "Security" and (event_id is None or int(r["EventID"]) == event_id)
    ]


def _first(path: Path, event_id: int, **match: str) -> dict[str, Any]:
    return next(r for r in _records(path, event_id) if all(r.get(k) == v for k, v in match.items()))


def _convert(paths: tuple[Path, ...] = ROUND_2) -> list[Observation]:
    out: list[Observation] = []
    for path in paths:
        for record in _records(path):
            with contextlib.suppress(SourceAdapterError):
                out.extend(ADAPTER.to_observations(record))
    return out


@pytest.fixture(scope="module")
def knowledge() -> AttackKnowledge:
    return load_attack_knowledge()


@pytest.fixture(scope="module")
def engine(knowledge: AttackKnowledge) -> DetectionEngine:
    return DetectionEngine(rules=load_rule_pack(SIGMA_PACK, knowledge=knowledge).rules)


# ===========================================================================
# Golden conversion counts
# ===========================================================================


def test_real_conversion_counts_and_refusals() -> None:
    converted: collections.Counter[str] = collections.Counter()
    refused: collections.Counter[str] = collections.Counter()
    for path in sorted(SAMPLES.glob("*.zip")):
        for record in _records(path):
            try:
                (obs,) = ADAPTER.to_observations(record)
                assert obs.event is not None and obs.event.code is not None
                converted[obs.event.code] += 1
            except SourceAdapterError as exc:
                refused[str(exc).split(" (")[0].split(": ", 1)[1]] += 1
    assert converted == {
        "4624": 73,
        "4656": 268,
        "4658": 499,
        "4663": 170,
        "4688": 23,
        "4776": 2,
        "5140": 10,
        "5145": 30,
        # batch B
        "4661": 31,
        "4662": 1,
        "4672": 37,
        "4673": 41,
        "4702": 6,
        "4768": 8,
        "4769": 20,
    }
    # round-1 exports: TimeCreated only (no zone, 16 h off UtcTime) -> refused
    no_time = [k for k in refused if k.startswith("flat record has no EventTime")]
    assert len(no_time) == 1 and refused[no_time[0]] == 55
    assert refused["unsupported event id 5156"] == 640  # WFP connections: D3 vs Sysmon 3
    assert refused["unsupported event id 1102"] == 4  # round-1 exports only (no event time)
    assert sum(converted.values()) == 1219


def test_record_numbers_are_unique_ids() -> None:
    ids = [o.observation_id for o in _convert()]
    assert len(ids) == len(set(ids)) == 1219


def test_supported_ids_equal_the_field_map_guard() -> None:
    assert SUPPORTED_EVENT_CODES[("windows", "security")] == {str(i) for i in SUPPORTED_EVENT_IDS}


# ===========================================================================
# Golden fields
# ===========================================================================


def test_process_creation_golden_fields() -> None:
    record = _records(WMI, 4688)[0]
    (obs,) = ADAPTER.to_observations(record)
    process = obs.process
    assert process is not None and obs.event is not None
    assert (obs.event.category, obs.event.type, obs.event.action) == (
        ("process",),
        ("start",),
        "process_start",
    )
    assert (obs.event.code, obs.event.dataset, obs.event.provider) == (
        "4688",
        "system.security",
        "Microsoft-Windows-Security-Auditing",
    )
    assert process.executable == record["NewProcessName"]
    assert process.pid == int(record["NewProcessId"], 16)
    assert process.parent_executable == record["ParentProcessName"]
    assert process.parent_pid == int(record["ProcessId"], 16)
    assert process.entity_id is None  # no GUID in 4688: no structural link (ADR-0003)
    assert observation_kind(obs) == "process_start"


def test_logon_golden_fields() -> None:
    record = _first(MIMIKATZ, 4624, LogonType="3")
    (obs,) = ADAPTER.to_observations(record)
    assert obs.logon is not None and obs.target_user is not None and obs.event is not None
    assert obs.logon.logon_type == "3"
    assert obs.logon.logon_process == record["LogonProcessName"]
    assert obs.logon.authentication_package == "Kerberos"
    assert obs.logon.impersonation_level == "%%1833"  # unrendered, exactly as logged
    assert obs.logon.logon_id == record["TargetLogonId"]
    assert obs.target_user.name == record["TargetUserName"]
    assert obs.target_user.id == record["TargetUserSid"]
    assert obs.network is not None and obs.network.source is not None
    assert obs.network.source.ip == record["IpAddress"]
    assert obs.network.source.port == int(record["IpPort"])
    assert obs.process is None  # ProcessName '-' / ProcessId 0x0 = no process
    assert (obs.event.category, obs.event.outcome) == (("authentication",), "success")


def test_credential_validation_golden_fields() -> None:
    record = _records(SMBEXEC, 4776)[0]
    (obs,) = ADAPTER.to_observations(record)
    assert obs.logon is not None and obs.target_user is not None
    assert obs.logon.package_name == "MICROSOFT_AUTHENTICATION_PACKAGE_V1_0"
    assert obs.logon.authentication_package is None  # a different source field
    assert obs.logon.workstation == "WORKSTATION5"
    assert obs.logon.status == "0x0"
    assert obs.target_user.name == "pgustavo"


def test_object_access_golden_fields() -> None:
    record = _first(MIMIKATZ, 4663)
    (obs,) = ADAPTER.to_observations(record)
    access = obs.object_access
    assert access is not None and obs.process is not None and obs.event is not None
    assert (access.server, access.type, access.name) == (
        record["ObjectServer"],
        record["ObjectType"],
        record["ObjectName"],
    )
    assert access.access_mask == record["AccessMask"]
    assert access.access_list == record["AccessList"]  # '%%4432\r\n\t...' kept verbatim
    assert obs.process.executable == record["ProcessName"]
    assert obs.process.pid == int(record["ProcessId"], 16)
    assert obs.event.category == ()  # no invented ECS category


def test_share_golden_fields() -> None:
    record = _first(WMI, 5145, RelativeTargetName="samr")
    (obs,) = ADAPTER.to_observations(record)
    assert obs.share is not None and obs.object_access is not None
    assert obs.share.name == "\\\\*\\IPC$"
    assert obs.share.relative_target_name == "samr"
    assert obs.object_access.access_mask == record["AccessMask"]
    assert obs.network is not None and obs.network.source is not None
    assert obs.network.source.ip == record["IpAddress"]


def test_event_time_is_exact() -> None:
    record = _records(SMBEXEC, 4776)[0]
    (obs,) = ADAPTER.to_observations(record)
    local = datetime.fromisoformat(record["EventTime"])
    assert (obs.timestamp.replace(tzinfo=None) - local).total_seconds() == 4 * 3600
    assert obs.timestamp_precision is TimePrecision.SECOND


# ===========================================================================
# Fail closed, collector records, source-agnostic
# ===========================================================================


def test_round_1_time_created_records_are_refused() -> None:
    record = _records(DUMPERT, 4663)[0]
    with pytest.raises(SourceAdapterError, match="no EventTime"):
        ADAPTER.to_observations(record)


@pytest.mark.parametrize(
    ("change", "match"),
    [
        ({"Channel": "System"}, "channel"),
        ({"EventID": 5156}, "unsupported event id 5156"),
        ({"RecordNumber": None}, "record id"),
        ({"Hostname": ""}, "host name"),
        ({"NewProcessId": "1234"}, "not a hex process id"),
        ({"EventReceivedTime": None}, "missing required field EventReceivedTime"),
    ],
)
def test_fail_closed(change: dict[str, Any], match: str) -> None:
    record = {**_records(WMI, 4688)[0], **change}
    record = {k: v for k, v in record.items() if v is not None}
    with pytest.raises(SourceAdapterError, match=match):
        ADAPTER.to_observations(record)


def test_collector_record_converts() -> None:
    record = {
        "@timestamp": "2026-01-01T12:00:00.250+00:00",
        "event": {"outcome": "success"},
        "winlog": {
            "channel": "Security",
            "event_id": 4624,
            "record_id": 99,
            "computer_name": "WIN-HOST",
            "provider_name": "Microsoft-Windows-Security-Auditing",
            "event_data": {
                "LogonType": "9",
                "LogonProcessName": "seclogo",
                "AuthenticationPackageName": "Negotiate",
                "TargetUserName": "bob",
                "IpAddress": "::1",
                "IpPort": "0",
            },
        },
    }
    (obs,) = ADAPTER.to_observations(record)
    assert obs.observation_id == "windows_security:WIN-HOST:99"
    assert obs.timestamp_precision is None
    assert obs.logon is not None and obs.logon.logon_type == "9"
    assert obs.event is not None and obs.event.outcome == "success"


def test_no_native_field_names_leave_the_adapter() -> None:
    for obs in _convert()[:300]:
        text = to_canonical_json(obs)
        for native in ('"NewProcessName"', '"ObjectName"', '"LogonType"', '"RecordNumber"'):
            assert native not in text


def test_adapter_does_not_mutate_records() -> None:
    record = _records(WMI, 4688)[0]
    before = copy.deepcopy(record)
    ADAPTER.to_observations(record)
    assert record == before


# ===========================================================================
# ADR-0008 D3: source precedence on real Sysmon + Security data
# ===========================================================================


def _sysmon_and_security(path: Path) -> list[Observation]:
    sysmon = SysmonSourceAdapter()
    out: list[Observation] = []
    for record in _all_records(path):
        adapter: Any = (
            sysmon if record.get("Channel") == "Microsoft-Windows-Sysmon/Operational" else ADAPTER
        )
        if record.get("Channel") not in ("Security", "Microsoft-Windows-Sysmon/Operational"):
            continue
        with contextlib.suppress(SourceAdapterError):
            out.extend(adapter.to_observations(record))
    return out


def test_every_real_4688_duplicates_a_sysmon_process_start() -> None:
    """Why D3 exists: on hosts running both, each 4688 has a Sysmon 1 for the
    same process (same host, pid and image) — ingesting both double-counts."""
    observations = _sysmon_and_security(WMI)
    sysmon_starts = {
        (o.host.name if o.host else None, o.process.pid, (o.process.executable or "").lower())
        for o in observations
        if o.raw_reference.source_type == "sysmon"
        and observation_kind(o) == "process_start"
        and o.process is not None
    }
    security_starts = [
        o
        for o in observations
        if o.raw_reference.source_type == "windows_security"
        and o.process is not None
        and observation_kind(o) == "process_start"
    ]
    assert len(security_starts) == 18
    for o in security_starts:
        assert o.process is not None
        key = (o.host.name if o.host else None, o.process.pid, (o.process.executable or "").lower())
        assert key in sysmon_starts


def test_precedence_suppresses_4688_where_sysmon_is_declared() -> None:
    observations = _sysmon_and_security(WMI)
    hosts = {o.host.name for o in observations if o.host is not None and o.host.name}
    result = apply_source_precedence(
        observations, {h: ("sysmon", "windows_security") for h in hosts}
    )
    assert {s.source_type for s in result.suppressed} == {"windows_security"}
    assert {s.suppressed_by for s in result.suppressed} == {"sysmon"}
    assert len(result.suppressed) == 18
    assert sum(result.suppressed_counts().values()) == 18
    # only process starts are suppressed; logons, object and share events stay
    kept_security = [o for o in result.kept if o.raw_reference.source_type == "windows_security"]
    assert kept_security and all(observation_kind(o) is None for o in kept_security)
    assert len(result.kept) + len(result.suppressed) == len(observations)


def test_precedence_keeps_4688_where_only_security_is_declared() -> None:
    observations = [
        o for o in _sysmon_and_security(WMI) if o.raw_reference.source_type == "windows_security"
    ]
    hosts = {o.host.name for o in observations if o.host is not None and o.host.name}
    result = apply_source_precedence(observations, {h: ("windows_security",) for h in hosts})
    assert result.suppressed == ()
    assert result.kept == tuple(observations)


def test_precedence_fails_closed_without_a_declaration() -> None:
    observations = _sysmon_and_security(WMI)
    with pytest.raises(SourceAdapterError, match="no source declaration"):
        apply_source_precedence(observations, {})
    hosts = {o.host.name for o in observations if o.host is not None and o.host.name}
    with pytest.raises(SourceAdapterError, match="not declared"):
        apply_source_precedence(observations, {h: ("sysmon",) for h in hosts})


# ===========================================================================
# Detection
# ===========================================================================


def test_field_map_fields_resolve_on_security_observations() -> None:
    assert FIELD_MAPS[("windows", "security")]["EventID"] == "event.code"
    assert FIELD_MAPS[("windows", "security")]["Provider_Name"] == "event.provider"


def test_detections_on_the_real_security_events(engine: DetectionEngine) -> None:
    """The batch A events raise nothing. Batch B adds one noisy rule, measured
    rather than suppressed (ADR-0007: imported-rule noise is left to the
    diagnosticity / calibration machinery): Password Policy Enumerated (T1201)
    matches 13 SAM-domain handle requests on the DC — 11 by the DC's own
    machine account (routine), 2 in the user session ``pgustavo``."""
    observations = _convert()
    assert len(observations) == 1219
    by_id = {o.observation_id: o for o in observations}
    detections = engine.evaluate(observations)
    assert {d.rule_ref.rule_id.rsplit(":", 1)[0] for d in detections} == {
        "sigma:12ba6a38-adb3-4d6b-91ba-a7fb248e3199"
    }
    subjects = collections.Counter(
        by_id[d.supporting_observation_ids[0]].user.name  # type: ignore[union-attr]
        for d in detections
    )
    assert subjects == {"MORDORDC$": 11, "pgustavo": 2}


def _fired(engine: DetectionEngine, record: dict[str, Any]) -> dict[str, set[str]]:
    (obs,) = ADAPTER.to_observations(record)
    out: dict[str, set[str]] = {}
    for detection in engine.evaluate([obs]):
        out[detection.rule_ref.rule_id.rsplit(":", 1)[0]] = {
            m.attack_ref.external_id
            for m in detection.technique_mappings
            if m.attack_ref.external_id is not None
        }
    return out


def test_modified_real_share_event_detects_an_unusual_remote_pipe(engine: DetectionEngine) -> None:
    # real 5145 on IPC$ with the pipe name changed from samr to PsExec's service pipe
    record = {**_first(WMI, 5145, RelativeTargetName="samr"), "RelativeTargetName": "PSEXESVC"}
    fired = _fired(engine, record)
    assert "T1021.002" in fired["sigma:52d8b0c6-53d6-439a-9e41-52ad442ad9ad"]
    # the unmodified real event (samr, a normal DC pipe) raises nothing
    assert _fired(engine, _first(WMI, 5145, RelativeTargetName="samr")) == {}


def test_rendered_access_list_rules_are_gaps_not_coverage() -> None:
    """Sigma's SVCCTL rule matches AccessList 'WriteData' (rendered text);
    Windows logs '%%4417'. Such a conjunct can never fire on real telemetry,
    so it is a telemetry gap, never imported coverage."""
    report = json.loads(
        (SIGMA_PACK.parent / "sigma-r2026-07-01-sigma_core++.import-report.json").read_text(
            encoding="utf-8"
        )
    )
    (row,) = [r for r in report["rules"] if r["sigma_id"] == "586a8d6b-6bfe-4ad9-9d78-888cd2fe50c3"]
    assert row["status"] == "rejected"
    assert "telemetry_gap:rendered_value:object_access.access_list" in row["gap_reasons"]
    assert any("%%" in r["AccessList"] for r in _records(WMI, 5145))  # the real, coded form


def test_modified_real_logon_detects_overpass_the_hash_without_software_tag(
    engine: DetectionEngine,
) -> None:
    # real 4624 changed to the LogonType 9 / seclogo / Negotiate pattern
    record = {
        **_first(MIMIKATZ, 4624, LogonType="3"),
        "LogonType": "9",
        "LogonProcessName": "seclogo",
        "AuthenticationPackageName": "Negotiate",
    }
    fired = _fired(engine, record)
    overpass = fired["sigma:192a0330-c20b-4356-90b6-7b7049ae0b87"]
    assert "T1550.002" in overpass
    assert "S0002" not in overpass  # Mimikatz tag reviewed and rejected (runas /netonly)


def test_modified_real_object_access_detects_wce_with_software_tag(
    engine: DetectionEngine,
) -> None:
    record = {**_first(MIMIKATZ, 4663), "ObjectName": "C:\\Users\\a\\wceaux.dll"}
    fired = _fired(engine, record)
    assert "S0005" in fired["sigma:1de68c67-af5c-4097-9c85-fe5578e09e67"]  # accepted tag
