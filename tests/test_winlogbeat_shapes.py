"""Winlogbeat 6 records, case-insensitive channels, Sysmon channel check and
Sysmon event time — golden tests on real OTRF records
(``data/telemetry-samples/otrf-compound/golden-records.jsonl``,
``scripts/extract_golden_records.py``)."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from attribution_platform.sources.errors import SourceAdapterError
from attribution_platform.sources.powershell import PowerShellSourceAdapter
from attribution_platform.sources.sysmon import SysmonSourceAdapter
from attribution_platform.sources.windows_security import WindowsSecuritySourceAdapter

GOLDEN = (
    Path(__file__).resolve().parents[1]
    / "data"
    / "telemetry-samples"
    / "otrf-compound"
    / "golden-records.jsonl"
)
RECORDS: dict[str, dict[str, Any]] = {
    row["golden_id"]: row["record"]
    for row in (json.loads(line) for line in GOLDEN.read_text(encoding="utf-8").splitlines())
}


@pytest.mark.parametrize(
    ("golden_id", "adapter"),
    [
        ("wlb6-sysmon-1", SysmonSourceAdapter()),
        ("wlb6-sysmon-10", SysmonSourceAdapter()),
        ("wlb6-sysmon-13", SysmonSourceAdapter()),
        ("wlb6-security-4624", WindowsSecuritySourceAdapter()),
        ("wlb6-security-4688", WindowsSecuritySourceAdapter()),
        ("wlb6-security-5145", WindowsSecuritySourceAdapter()),
        ("wlb6-powershell-4103", PowerShellSourceAdapter()),
    ],
)
def test_winlogbeat6_records_convert_on_the_real_host(golden_id: str, adapter: Any) -> None:
    record = RECORDS[golden_id]
    (obs,) = adapter.to_observations(record)
    assert obs.host is not None and obs.host.name == record["computer_name"]
    assert obs.host.name != "WECserver"  # the forwarder is never the event host
    assert obs.raw_reference.source_event_id == str(record["record_number"])


def test_sysmon_time_is_utctime_not_the_forwarder_clock() -> None:
    record = RECORDS["wlb6-sysmon-3-late"]
    (obs,) = SysmonSourceAdapter().to_observations(record)
    utc = datetime.fromisoformat(record["event_data"]["UtcTime"]).replace(tzinfo=UTC)
    assert obs.timestamp == utc
    stamp = datetime.fromisoformat(record["@timestamp"].replace("Z", "+00:00"))
    assert (stamp - utc).total_seconds() > 3600  # the real 272.8 h gap
    late = RECORDS["wlb7-sysmon-late"]
    (obs7,) = SysmonSourceAdapter().to_observations(late)
    assert obs7.timestamp == datetime.fromisoformat(
        late["winlog"]["event_data"]["UtcTime"]
    ).replace(tzinfo=UTC)


def test_sysmon_adapter_refuses_other_channels() -> None:
    with pytest.raises(SourceAdapterError, match="channel"):
        SysmonSourceAdapter().to_observations(RECORDS["wlb6-system-7"])


@pytest.mark.parametrize("golden_id", ["wlb7-security-lower", "nxlog-security-lower"])
def test_lower_case_security_channel_is_accepted(golden_id: str) -> None:
    (obs,) = WindowsSecuritySourceAdapter().to_observations(RECORDS[golden_id])
    assert obs.event is not None and obs.event.code == "4663"
