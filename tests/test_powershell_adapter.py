"""PowerShell logging adapter (ADR-0008 Wave 1) — golden tests on real telemetry.

Real samples: the OTRF Empire exports (NXLog flat variant) carrying
PowerShell/Operational 4103 (module logging) and 4104 (script block). Covers:
golden conversion counts and explicit refusals; exact field mapping; the exact
event-time derivation for NXLog exports (and its fail-closed cases); collector
(Winlogbeat) records; source-agnostic output; ps_script / ps_module scope
separation; and the detections the production Sigma pack raises on the real
Empire script-block logging bypass.
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
from attribution_platform.domain import Observation, TimePrecision, to_canonical_json
from attribution_platform.sources.errors import SourceAdapterError
from attribution_platform.sources.powershell import PowerShellSourceAdapter

REPO_ROOT = Path(__file__).resolve().parents[1]
SAMPLES = REPO_ROOT / "data" / "telemetry-samples" / "otrf"
MIMIKATZ = SAMPLES / "empire_mimikatz_logonpasswords.zip"
SMBEXEC = SAMPLES / "empire_smbexec_dcerpc_smb_svcctl.zip"
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
CHANNEL = "Microsoft-Windows-PowerShell/Operational"
AMSI_BYPASS_FAMILY = "sigma:e0d6c087-2d1c-47fd-8799-3904103c5a98"  # ps_script
GENERIC_MODULE_FAMILY = "sigma:bbb80e91-5746-4fbe-8898-122e2cafdbf4"  # ps_module
ADAPTER = PowerShellSourceAdapter()
_CACHE: dict[Path, list[dict[str, Any]]] = {}


def _records(path: Path) -> list[dict[str, Any]]:
    if path not in _CACHE:
        with zipfile.ZipFile(path) as archive:
            (member,) = archive.namelist()
            text = archive.read(member).decode("utf-8", "replace")
        _CACHE[path] = [
            r
            for r in (json.loads(line) for line in text.splitlines() if line.strip())
            if r.get("Channel") == CHANNEL
        ]
    return _CACHE[path]


def _convert(path: Path) -> list[Observation]:
    out: list[Observation] = []
    for record in _records(path):
        with contextlib.suppress(SourceAdapterError):  # refused records
            out.extend(ADAPTER.to_observations(record))
    return out


def _script_block() -> dict[str, Any]:
    return next(r for r in _records(SMBEXEC) if int(r["EventID"]) == 4104)


@pytest.fixture(scope="module")
def knowledge() -> AttackKnowledge:
    return load_attack_knowledge()


# ===========================================================================
# Golden conversion counts
# ===========================================================================


def test_real_conversion_counts_and_refusals() -> None:
    converted: collections.Counter[str] = collections.Counter()
    refused: collections.Counter[str] = collections.Counter()
    for path in (MIMIKATZ, SMBEXEC, WMI):
        for record in _records(path):
            try:
                (obs,) = ADAPTER.to_observations(record)
                assert obs.event is not None
                converted[str(obs.event.action)] += 1
            except SourceAdapterError as exc:
                refused[str(exc).split(" (")[0].split(": ", 1)[1]] += 1
    assert converted == {"powershell_module": 2321, "powershell_script_block": 2}
    assert refused["module logging event without Payload"] == 33  # payload only in Message
    assert {k for k in refused if k.startswith("unsupported event id")} == {
        "unsupported event id 40961",
        "unsupported event id 40962",
        "unsupported event id 53504",
    }


def test_real_record_numbers_are_unique_ids() -> None:
    ids = [o.observation_id for path in (MIMIKATZ, SMBEXEC, WMI) for o in _convert(path)]
    assert len(ids) == len(set(ids)) == 2323


# ===========================================================================
# Golden fields
# ===========================================================================


def test_script_block_golden_fields() -> None:
    record = _script_block()
    (obs,) = ADAPTER.to_observations(record)
    ps = obs.powershell
    assert ps is not None
    assert ps.script_block_text == record["ScriptBlockText"]
    assert "cachedGroupPolicySettings" in (ps.script_block_text or "")  # logging bypass
    assert ps.script_block_id == "9f63c3d4-dd42-47f7-86c1-4076ce091501"
    assert (ps.message_number, ps.message_total) == (1, 1)
    assert ps.payload is None
    assert obs.event is not None
    assert (obs.event.category, obs.event.type, obs.event.action) == (
        ("process",),
        ("info",),
        "powershell_script_block",
    )
    assert obs.host is not None and obs.host.name == "WORKSTATION6.theshire.local"
    assert obs.user is not None and obs.user.id == record["UserID"]
    assert obs.process is not None and obs.process.pid == int(record["ExecutionProcessID"])
    assert obs.process.entity_id is None  # no GUID: forms no structural link (ADR-0003)
    assert obs.observation_id == f"powershell:{record['Hostname']}:{record['RecordNumber']}"


def test_module_logging_golden_fields() -> None:
    record = next(r for r in _records(MIMIKATZ) if int(r["EventID"]) == 4103 and "Payload" in r)
    (obs,) = ADAPTER.to_observations(record)
    assert obs.powershell is not None
    assert obs.powershell.payload == record["Payload"]
    assert obs.powershell.context_info == record["ContextInfo"]
    assert obs.powershell.script_block_text is None
    assert obs.event is not None and obs.event.action == "powershell_module"


# ===========================================================================
# Event time
# ===========================================================================


def test_event_time_is_derived_exactly_from_the_record() -> None:
    record = _script_block()
    (obs,) = ADAPTER.to_observations(record)
    local = datetime.fromisoformat(record["EventTime"])
    # EventReceivedTime (local) vs @timestamp (UTC) => host offset -4h (EDT),
    # so the event happened at local EventTime + 4h in UTC.
    assert obs.timestamp.utcoffset() is not None
    assert (obs.timestamp.replace(tzinfo=None) - local).total_seconds() == 4 * 3600
    assert obs.timestamp_precision is TimePrecision.SECOND


def test_every_real_record_derives_a_minus_four_hour_offset() -> None:
    for path in (MIMIKATZ, SMBEXEC, WMI):
        for record in _records(path)[:200]:
            with contextlib.suppress(SourceAdapterError):
                (obs,) = ADAPTER.to_observations(record)
                local = datetime.fromisoformat(record["EventTime"])
                assert (obs.timestamp.replace(tzinfo=None) - local).total_seconds() == 14400


@pytest.mark.parametrize(
    ("change", "match"),
    [
        ({"EventReceivedTime": None}, "missing required field EventReceivedTime"),
        ({"@timestamp": None}, "missing required field @timestamp"),
        ({"@timestamp": "2020-09-20T06:57:17.371"}, "must carry a UTC zone"),
        ({"EventTime": "2020-09-20T02:57:14+00:00"}, "unexpectedly carry a zone"),
    ],
)
def test_time_derivation_fails_closed(change: dict[str, Any], match: str) -> None:
    record = {**_script_block(), **change}
    with pytest.raises(SourceAdapterError, match=match):
        ADAPTER.to_observations(record)


def test_implausible_offset_is_refused() -> None:
    record = dict(_script_block())
    received = datetime.fromisoformat(record["EventReceivedTime"])
    stamp = datetime.fromisoformat(record["@timestamp"].replace("Z", "+00:00"))
    # 20 minutes off any 15-minute zone step => cannot be a real zone
    record["@timestamp"] = (
        (received.replace(tzinfo=UTC) + (stamp - received.replace(tzinfo=UTC)))
        .replace(minute=(stamp.minute + 7) % 60)
        .isoformat()
    )
    with pytest.raises(SourceAdapterError, match="cannot derive the host UTC offset"):
        ADAPTER.to_observations(record)


# ===========================================================================
# Collector records, refusals, source-agnostic output
# ===========================================================================


def _collector(event_id: int, event_data: dict[str, Any]) -> dict[str, Any]:
    return {
        "@timestamp": "2026-01-01T12:00:00.123+00:00",
        "winlog": {
            "channel": CHANNEL,
            "event_id": event_id,
            "record_id": 42,
            "computer_name": "WIN-HOST",
            "event_data": event_data,
            "process": {"pid": 1234},
            "user": {"identifier": "S-1-5-21-1-2-3-1001"},
        },
    }


def test_collector_record_converts() -> None:
    (obs,) = ADAPTER.to_observations(
        _collector(4104, {"ScriptBlockText": "IEX (New-Object Net.WebClient)", "Path": "C:\\a.ps1"})
    )
    assert obs.timestamp == datetime(2026, 1, 1, 12, 0, 0, 123000, tzinfo=UTC)
    assert obs.timestamp_precision is None
    assert obs.powershell is not None and obs.powershell.script_path == "C:\\a.ps1"
    assert obs.process is not None and obs.process.pid == 1234
    assert obs.user is not None and obs.user.id == "S-1-5-21-1-2-3-1001"
    assert obs.observation_id == "powershell:WIN-HOST:42"


@pytest.mark.parametrize(
    ("record", "match"),
    [
        (_collector(4105, {"ScriptBlockText": "x"}), "unsupported event id 4105"),
        (_collector(4104, {}), "without ScriptBlockText"),
        (_collector(4103, {"ContextInfo": "x"}), "without Payload"),
        (
            {**_collector(4104, {"ScriptBlockText": "x"}), "winlog": {"channel": "Security"}},
            "channel",
        ),
    ],
)
def test_refusals(record: dict[str, Any], match: str) -> None:
    with pytest.raises(SourceAdapterError, match=match):
        ADAPTER.to_observations(record)


def test_no_native_field_names_leave_the_adapter() -> None:
    for obs in _convert(SMBEXEC)[:100]:
        text = to_canonical_json(obs)
        for native in ('"ScriptBlockText"', '"Payload"', '"EventReceivedTime"', '"RecordNumber"'):
            assert native not in text


# ===========================================================================
# Detection: scopes and the real Empire logging bypass
# ===========================================================================


def _engine(knowledge: AttackKnowledge, family: str) -> DetectionEngine:
    pack = load_rule_pack(SIGMA_PACK, knowledge=knowledge)
    return DetectionEngine(rules=tuple(r for r in pack.rules if r.rule_family == family))


def test_real_empire_logging_bypass_is_detected(knowledge: AttackKnowledge) -> None:
    (obs,) = ADAPTER.to_observations(_script_block())
    (detection,) = _engine(knowledge, AMSI_BYPASS_FAMILY).evaluate([obs])
    assert "T1685" in {m.attack_ref.external_id for m in detection.technique_mappings}


def test_script_rules_never_fire_on_module_events_and_vice_versa(
    knowledge: AttackKnowledge,
) -> None:
    text = _script_block()["ScriptBlockText"]
    (as_module,) = ADAPTER.to_observations(_collector(4103, {"Payload": text}))
    assert _engine(knowledge, AMSI_BYPASS_FAMILY).evaluate([as_module]) == ()
    module_record = next(r for r in _records(WMI) if int(r["EventID"]) == 4103 and "Payload" in r)
    module_engine = _engine(knowledge, GENERIC_MODULE_FAMILY)
    fired = [
        obs
        for record in _records(WMI)
        if int(record["EventID"]) == 4103 and "Payload" in record
        for obs in ADAPTER.to_observations(record)
        if module_engine.evaluate([obs])
    ]
    assert fired  # the module rule fires on real module events...
    as_script = ADAPTER.to_observations(
        _collector(4104, {"ScriptBlockText": fired[0].powershell.payload or ""})  # type: ignore[union-attr]
    )
    assert module_engine.evaluate(as_script) == ()  # ...but never on script-block events
    assert module_record  # the WMI sample has real module-logging events
