"""ADR-0008 Wave 1 batch C: Sysmon 15, 17/18, 19/20/21, 23 on real telemetry.

Uses the round-2 OTRF samples (Empire SMBExec, Mimikatz, WMI persistence), which
arrive in the NXLog/Logstash flat variant. Covers: the NXLog envelope (real
``RecordNumber`` as record id, pipeline fields never leaking into Observations);
exact field mapping for stream hash, pipes, WMI and file delete; the registry
``EventType`` rules for this export (event 13 derives ``SetValue``; event 12
without it is refused); fail-closed cases; the ``file_event`` / ``create_stream_hash``
scope separation; and the detections the production Sigma pack raises on the
real WMI persistence and SMBExec data.
"""

from __future__ import annotations

import collections
import contextlib
import json
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from attribution_platform.attack_knowledge.loader import AttackKnowledge, load_attack_knowledge
from attribution_platform.detection import DetectionEngine, load_rule_pack
from attribution_platform.domain import Observation, to_canonical_json
from attribution_platform.sources.errors import SourceAdapterError
from attribution_platform.sources.sysmon import SysmonSourceAdapter

REPO_ROOT = Path(__file__).resolve().parents[1]
SAMPLES = REPO_ROOT / "data" / "telemetry-samples" / "otrf"
SMBEXEC = SAMPLES / "empire_smbexec_dcerpc_smb_svcctl.zip"
MIMIKATZ = SAMPLES / "empire_mimikatz_logonpasswords.zip"
WMI = SAMPLES / "empire_wmi_local_event_subscriptions_elevated_user.zip"
SIGMA_PACK = (
    REPO_ROOT
    / "data"
    / "detection"
    / "sigma"
    / "r2026-07-01"
    / "generated"
    / "sigma-r2026-07-01-sigma_core++.rules.json"
)
SYSMON = "Microsoft-Windows-Sysmon/Operational"
ADAPTER = SysmonSourceAdapter()
_CACHE: dict[Path, list[dict[str, Any]]] = {}


def _sysmon_records(path: Path) -> list[dict[str, Any]]:
    if path not in _CACHE:
        with zipfile.ZipFile(path) as archive:
            (member,) = archive.namelist()
            text = archive.read(member).decode("utf-8", "replace")
        _CACHE[path] = [
            r
            for r in (json.loads(line) for line in text.splitlines() if line.strip())
            if r.get("Channel") == SYSMON
        ]
    return _CACHE[path]


def _first(path: Path, event_id: int, **match: str) -> dict[str, Any]:
    return next(
        r
        for r in _sysmon_records(path)
        if int(r["EventID"]) == event_id and all(r.get(k) == v for k, v in match.items())
    )


def _convert(path: Path, event_ids: set[int] | None = None) -> list[Observation]:
    out: list[Observation] = []
    for record in _sysmon_records(path):
        if event_ids is not None and int(record["EventID"]) not in event_ids:
            continue
        with contextlib.suppress(SourceAdapterError):  # unsupported/refused records
            out.extend(ADAPTER.to_observations(record))
    return out


@pytest.fixture(scope="module")
def knowledge() -> AttackKnowledge:
    return load_attack_knowledge()


@pytest.fixture(scope="module")
def engine(knowledge: AttackKnowledge) -> DetectionEngine:
    return DetectionEngine(rules=load_rule_pack(SIGMA_PACK, knowledge=knowledge).rules)


# ===========================================================================
# NXLog / Logstash flat variant
# ===========================================================================


def test_nxlog_records_use_the_real_record_number() -> None:
    record = _first(WMI, 19)
    (obs,) = ADAPTER.to_observations(record)
    assert obs.raw_reference.source_event_id == str(record["RecordNumber"])  # a JSON number
    assert obs.observation_id == f"sysmon:{record['Hostname']}:{record['RecordNumber']}"
    # UtcTime is the event time; the collector-local EventTime is ignored.
    assert obs.timestamp == datetime.fromisoformat(record["UtcTime"]).replace(tzinfo=UTC)


def test_nxlog_ids_are_unique_so_no_records_collapse() -> None:
    ids = [o.observation_id for o in _convert(SMBEXEC)]
    assert len(ids) == len(set(ids)) > 4000


def test_pipeline_fields_never_leak_into_observations() -> None:
    for obs in _convert(WMI, {15, 17, 18, 19, 20, 21, 23})[:300]:
        text = to_canonical_json(obs)
        for leaked in ("RecordNumber", "EventReceivedTime", "mordorDataset", "EventTypeOrignal"):
            assert leaked not in text


# ===========================================================================
# Registry EventType handling in this export
# ===========================================================================


def test_event_13_without_eventtype_derives_setvalue() -> None:
    record = _first(SMBEXEC, 13)
    assert "EventType" not in record  # dropped by the export pipeline
    (obs,) = ADAPTER.to_observations(record)
    assert obs.event is not None
    assert (obs.event.type, obs.event.action) == (("change",), "SetValue")


def test_event_12_without_eventtype_is_refused() -> None:
    records = [r for r in _sysmon_records(SMBEXEC) if int(r["EventID"]) == 12]
    assert len(records) == 680 and all("EventType" not in r for r in records)
    with pytest.raises(SourceAdapterError, match="EventType None"):
        ADAPTER.to_observations(records[0])


def test_event_13_with_a_wrong_eventtype_is_still_refused() -> None:
    record = {**_first(SMBEXEC, 13), "EventType": "CreateKey"}
    with pytest.raises(SourceAdapterError, match="EventType 'CreateKey'"):
        ADAPTER.to_observations(record)


# ===========================================================================
# Golden fields per event type
# ===========================================================================


def test_wmi_persistence_filter_consumer_binding() -> None:
    (flt,) = ADAPTER.to_observations(_first(WMI, 19))
    (consumer,) = ADAPTER.to_observations(_first(WMI, 20))
    (binding,) = ADAPTER.to_observations(_first(WMI, 21))
    assert flt.wmi is not None and consumer.wmi is not None and binding.wmi is not None
    assert flt.wmi.name == ' "Updater"'  # kept exactly as Sysmon/the export rendered it
    assert flt.wmi.query is not None and "__InstanceModificationEvent" in flt.wmi.query
    assert consumer.wmi.consumer_type == "Command Line"
    assert consumer.wmi.destination is not None and "powershell.exe" in consumer.wmi.destination
    assert binding.wmi.filter is not None and "Updater" in binding.wmi.filter
    assert binding.wmi.consumer is not None and "CommandLineEventConsumer" in binding.wmi.consumer
    for obs, action in ((flt, "wmi_filter"), (consumer, "wmi_consumer"), (binding, "wmi_binding")):
        assert obs.event is not None
        assert (obs.event.category, obs.event.type, obs.event.action) == (
            ("configuration",),
            ("creation",),
            action,
        )
        assert obs.wmi is not None and obs.wmi.operation == "Created"
        assert obs.user is not None and (obs.user.domain, obs.user.name) == ("THESHIRE", "pgustavo")
        assert obs.process is None  # Sysmon WMI events carry no process


def test_pipe_create_and_connect() -> None:
    (created,) = ADAPTER.to_observations(_first(MIMIKATZ, 17))
    (connected,) = ADAPTER.to_observations(_first(MIMIKATZ, 18, PipeName="\\lsass"))
    assert created.event is not None and connected.event is not None
    assert (created.event.type, created.event.action) == (("creation",), "pipe_create")
    assert (connected.event.type, connected.event.action) == (("access",), "pipe_connect")
    assert connected.pipe is not None and connected.pipe.name == "\\lsass"
    assert connected.process is not None and connected.process.name == "svchost.exe"


def test_pipe_connect_by_system_without_pid_or_eventtype_converts() -> None:
    record = _first(SMBEXEC, 18, PipeName="\\ntsvcs")
    assert "EventType" not in record and "ProcessId" not in record
    (obs,) = ADAPTER.to_observations(record)
    assert obs.event is not None and obs.event.action == "pipe_connect"
    assert obs.process is not None and obs.process.executable == "System"


def test_pipe_names_are_kept_as_exported() -> None:
    """The export HTML-escaped '<Anonymous Pipe>'; the adapter does not guess
    which values a pipeline escaped (recorded in ADR-0008 as a data artefact)."""
    names = {o.pipe.name for o in _convert(MIMIKATZ, {17, 18}) if o.pipe is not None}
    assert "&lt;Anonymous Pipe&gt;" in names


def test_file_stream_and_file_delete() -> None:
    (stream,) = ADAPTER.to_observations(_first(WMI, 15))
    assert stream.file is not None
    assert stream.file.path == "C:\\WindowsAzure\\Logs\\WaAppAgent_000003.etl"
    assert stream.file_stream is not None
    assert stream.file_stream.contents == "-"
    assert stream.file_stream.hashes is not None and stream.file_stream.hashes.startswith("SHA1=")
    assert stream.event is not None and stream.event.action == "file_stream_create"
    record = next(
        r
        for r in _sysmon_records(SMBEXEC)
        if int(r["EventID"]) == 23 and "__PSScriptPolicyTest_" in r["TargetFilename"]
    )
    (deleted,) = ADAPTER.to_observations(record)
    assert deleted.file is not None and deleted.file.path == record["TargetFilename"]
    assert deleted.event is not None
    assert (deleted.event.type, deleted.event.action) == (("deletion",), "file_delete")


def test_real_batch_c_counts() -> None:
    counts: collections.Counter[int] = collections.Counter()
    for path in (SMBEXEC, MIMIKATZ, WMI):
        for obs in _convert(path, {15, 17, 18, 19, 20, 21, 23}):
            assert obs.event is not None
            counts[
                {
                    "file_stream_create": 15,
                    "pipe_create": 17,
                    "pipe_connect": 18,
                    "wmi_filter": 19,
                    "wmi_consumer": 20,
                    "wmi_binding": 21,
                    "file_delete": 23,
                }[str(obs.event.action)]
            ] += 1
    assert counts == {15: 18, 17: 36, 18: 101, 19: 1, 20: 1, 21: 1, 23: 174}


# ===========================================================================
# Fail-closed
# ===========================================================================


def _flat(event_id: int, **fields: Any) -> dict[str, Any]:
    return {
        "EventID": event_id,
        "Channel": SYSMON,
        "Hostname": "H",
        "UtcTime": "2026-01-01 00:00:00.000",
        **fields,
    }


@pytest.mark.parametrize(
    ("record", "match"),
    [
        (_flat(19, Operation="Modified", Name="x"), "Operation 'Modified'"),
        (_flat(20, Name="x"), "Operation None"),
        (_flat(17, Image="C:\\a.exe"), "without PipeName"),
        (_flat(23, Image="C:\\a.exe"), "without TargetFilename"),
        (_flat(15, Image="C:\\a.exe"), "without TargetFilename"),
    ],
)
def test_batch_c_fail_closed(record: dict[str, Any], match: str) -> None:
    with pytest.raises(SourceAdapterError, match=match):
        ADAPTER.to_observations(record)


# ===========================================================================
# Scope separation and real-data detections
# ===========================================================================


def test_file_event_rules_never_fire_on_stream_events(knowledge: AttackKnowledge) -> None:
    pack = load_rule_pack(SIGMA_PACK, knowledge=knowledge)
    rules = tuple(
        r for r in pack.rules if r.rule_family == "sigma:93d94efc-d7ad-4161-ad7d-1638c4f908d8"
    )  # "HackTool - Dumpert Process Dumper Default File" (file_event)
    engine = DetectionEngine(rules=rules)
    base = _flat(
        11, Image="C:\\x.exe", ProcessId="1", TargetFilename="C:\\Windows\\Temp\\dumpert.dmp"
    )
    assert len(engine.evaluate(ADAPTER.to_observations(base))) == 1
    stream = {**base, "EventID": 15, "Contents": "-", "Hash": "SHA1=00"}
    assert engine.evaluate(ADAPTER.to_observations(stream)) == ()


def _techniques(engine: DetectionEngine, observations: list[Observation]) -> set[str]:
    return {
        m.attack_ref.external_id or ""
        for d in engine.evaluate(observations)
        for m in d.technique_mappings
    }


def test_real_wmi_persistence_is_detected(engine: DetectionEngine) -> None:
    observations = _convert(WMI, {1, 7, 19, 20, 21})
    techniques = _techniques(engine, observations)
    assert "T1546.003" in techniques  # Event Triggered Execution: WMI Event Subscription
    assert "T1059.005" in techniques  # scripting inside the WMI consumer
    wmi_only = _convert(WMI, {19, 20, 21})
    assert _techniques(engine, wmi_only) >= {"T1059.005"}  # fired on a WMI event itself


def test_real_smbexec_detections(engine: DetectionEngine) -> None:
    techniques = _techniques(engine, _convert(SMBEXEC))
    assert {"T1059.001", "T1569.002"} <= techniques  # Empire PowerShell, service execution
