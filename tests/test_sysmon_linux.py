"""Sysmon for Linux (ADR-0010 D1–D3, D7).

Golden tests on real records from ``splunk/attack_data`` (Apache-2.0,
``data/telemetry-samples/splunk-attack-data/golden-records.jsonl``): the XML
record shape, exact fields with POSIX semantics, a command line spanning
several physical lines, the hardened XML parser, and the operating-system scope
— no Windows rule fires on a Linux Observation, nor a Linux rule on a Windows
one. A real-data check over the whole verified cache runs when it is present.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from attribution_platform.attack_knowledge.loader import load_attack_knowledge
from attribution_platform.detection import DetectionEngine, load_rule_pack
from attribution_platform.detection_content.sigma_field_map import (
    FIELD_MAPS,
    LOGSOURCE_SCOPES,
    PRODUCT_OS_SCOPES,
)
from attribution_platform.domain import Observation
from attribution_platform.replay.recording_pipeline import (
    DEFAULT_CHANNEL_ADAPTERS,
    _channel,
    iter_recording_records,
)
from attribution_platform.sources.errors import SourceAdapterError
from attribution_platform.sources.sysmon import SysmonSourceAdapter
from attribution_platform.sources.sysmon_xml import parse_sysmon_event_xml
from attribution_platform.sources.windows_security import WindowsSecuritySourceAdapter

REPO_ROOT = Path(__file__).resolve().parents[1]
SAMPLES = REPO_ROOT / "data" / "telemetry-samples"
LINUX_GOLDEN = SAMPLES / "splunk-attack-data" / "golden-records.jsonl"
WINDOWS_GOLDEN = SAMPLES / "otrf-compound" / "golden-records.jsonl"
GENERATED = REPO_ROOT / "data" / "detection" / "sigma" / "r2026-07-01" / "generated"
PACK = GENERATED / "sigma-r2026-07-01-sigma_core++.rules.json"
REPORT = GENERATED / "sigma-r2026-07-01-sigma_core++.import-report.json"
ADAPTER = SysmonSourceAdapter()


def _golden(path: Path) -> dict[str, Any]:
    rows = (json.loads(line) for line in path.read_text(encoding="utf-8").splitlines())
    return {row["golden_id"]: row["record"] for row in rows}


LINUX = {g: r for g, r in _golden(LINUX_GOLDEN).items() if g.startswith("linux-sysmon")}
WINDOWS = _golden(WINDOWS_GOLDEN)


def _convert(record: Any) -> Observation:
    (obs,) = ADAPTER.to_observations(record)
    return obs


@pytest.fixture(scope="module")
def engine() -> DetectionEngine:
    return DetectionEngine(rules=load_rule_pack(PACK, knowledge=load_attack_knowledge()).rules)


@pytest.fixture(scope="module")
def products() -> dict[str, str]:
    report = json.loads(REPORT.read_text(encoding="utf-8"))
    return {row["sigma_id"]: row["logsource"].split("/")[0] for row in report["rules"]}


def _fired_products(
    engine: DetectionEngine, products: dict[str, str], obs: list[Observation]
) -> set[str]:
    return {products[d.rule_ref.rule_id.split(":")[1]] for d in engine.evaluate(obs)}


# ===========================================================================
# Conversion and exact fields
# ===========================================================================


@pytest.mark.parametrize("golden_id", sorted(LINUX))
def test_every_linux_golden_record_converts_as_linux(golden_id: str) -> None:
    obs = _convert(LINUX[golden_id])
    assert obs.host is not None and obs.host.os_type == "linux"
    assert obs.event is not None and obs.event.code is None  # Sysmon IDs are not event.code
    assert obs.timestamp.tzinfo is not None


def test_process_create_fields_are_exact_posix() -> None:
    obs = _convert(LINUX["linux-sysmon-1"])
    assert obs.observation_id == "sysmon:sysmonlinux-tcontreras-attack-range-643:723343"
    assert obs.timestamp.isoformat() == "2021-12-21T12:50:27.384000+00:00"  # Sysmon's UtcTime
    process = obs.process
    assert process is not None
    assert (process.executable, process.name, process.command_line) == (
        "/usr/bin/clear",
        "clear",
        "clear",
    )
    assert (process.parent_executable, process.parent_name) == ("/bin/bash", "bash")
    assert process.entity_id == "{ec2b6afe-cd93-61c1-08f6-50cc6f550000}"
    assert process.parent_entity_id == "{ec2b6afe-aacb-61c1-0834-fdd63c560000}"
    assert process.working_directory == "/home/ubuntu"
    assert obs.user is not None and (obs.user.name, obs.user.domain) == ("ubuntu", None)


@pytest.mark.parametrize("golden_id", ["linux-sysmon-1-acidrain", "linux-sysmon-1-cyclopsblink"])
def test_sandworm_detonation_records_convert(golden_id: str) -> None:
    obs = _convert(LINUX[golden_id])
    assert obs.process is not None and (obs.process.executable or "").startswith("/")


def test_multi_line_command_line_is_kept_exactly() -> None:
    """Sysmon for Linux writes a command line's own newlines verbatim (17 here)."""
    record = LINUX["linux-sysmon-1-multiline"]
    obs = _convert(record)
    assert obs.process is not None and obs.process.command_line is not None
    assert obs.process.command_line.count("\n") >= 2
    assert parse_sysmon_event_xml(record)["winlog"]["event_data"]["CommandLine"] == (
        obs.process.command_line
    )


def test_reader_reassembles_events_that_span_lines(tmp_path: Path) -> None:
    lines = LINUX["linux-sysmon-1-multiline"] + "\n" + LINUX["linux-sysmon-3"] + "\n"
    path = tmp_path / "sysmon_linux.log"
    path.write_text(lines, encoding="utf-8", newline="\n")
    records = list(iter_recording_records(path))
    assert records == [LINUX["linux-sysmon-1-multiline"], LINUX["linux-sysmon-3"]]
    assert {_channel(r) for r in records} == {"<sysmon-xml>"}
    assert all(DEFAULT_CHANNEL_ADAPTERS[_channel(r)] is not None for r in records)


def test_unterminated_event_is_refused_not_cut(tmp_path: Path) -> None:
    path = tmp_path / "sysmon_linux.log"
    path.write_text(LINUX["linux-sysmon-3"][:200] + "\n", encoding="utf-8")
    (record,) = list(iter_recording_records(path))
    with pytest.raises(SourceAdapterError, match="not well-formed"):
        ADAPTER.to_observations(record)


# ===========================================================================
# Fail closed
# ===========================================================================


@pytest.mark.parametrize(
    ("change", "match"),
    [
        (lambda r: r.replace("<System>", '<!DOCTYPE x [<!ENTITY a "b">]><System>', 1), "DTD"),
        (lambda r: r.replace("Linux-Sysmon/Operational", "Application"), "channel"),
        (lambda r: r.replace('<Data Name="Image">', '<Data Name="RuleName">', 1), "duplicate"),
        (lambda r: r.replace("<EventID>1</EventID>", "<EventID>9</EventID>"), "unsupported"),
    ],
)
def test_malformed_or_foreign_xml_fails_closed(change: Any, match: str) -> None:
    with pytest.raises(SourceAdapterError, match=match):
        ADAPTER.to_observations(change(LINUX["linux-sysmon-1"]))


def test_parser_refuses_a_root_other_than_event() -> None:
    record = (
        LINUX["linux-sysmon-1"].replace("<Event>", "<Other>", 1).replace("</Event>", "</Other>")
    )
    with pytest.raises(SourceAdapterError, match="root element"):
        parse_sysmon_event_xml(record)


def test_windows_sysmon_records_are_windows() -> None:
    obs = _convert(WINDOWS["wlb6-sysmon-1"])
    assert obs.host is not None and obs.host.os_type == "windows"


# ===========================================================================
# Operating-system scope (ADR-0010 D2)
# ===========================================================================


def test_every_product_with_a_logsource_has_an_os_scope() -> None:
    assert {product for product, _ in LOGSOURCE_SCOPES} == set(PRODUCT_OS_SCOPES)
    assert {("linux", c) for c in ("process_creation", "file_event", "network_connection")} <= set(
        FIELD_MAPS
    )


def test_no_windows_rule_fires_on_linux_and_no_linux_rule_on_windows(
    engine: DetectionEngine, products: dict[str, str]
) -> None:
    linux = [_convert(record) for record in LINUX.values()]
    windows = [_convert(WINDOWS[g]) for g in ("wlb6-sysmon-1", "wlb6-sysmon-10", "wlb6-sysmon-13")]
    assert _fired_products(engine, products, linux) <= {"linux"}
    assert _fired_products(engine, products, windows) <= {"windows"}


def test_a_windows_detection_stops_when_the_host_is_linux(
    engine: DetectionEngine, products: dict[str, str]
) -> None:
    """The same real Windows Observation (a 4661 the production pack detects),
    re-labelled as a Linux host: the Windows rule must stop firing — the scope,
    not luck."""
    (windows,) = WindowsSecuritySourceAdapter().to_observations(WINDOWS["b-4661"])
    assert _fired_products(engine, products, [windows]) == {"windows"}
    assert windows.host is not None
    as_linux = dataclasses.replace(windows, host=dataclasses.replace(windows.host, os_type="linux"))
    assert _fired_products(engine, products, [as_linux]) <= {"linux"}


def test_a_linux_rule_fires_on_a_modified_real_record(
    engine: DetectionEngine, products: dict[str, str]
) -> None:
    """Real crontab process start with the loaded file moved to /tmp (one
    labelled change): the Linux cron rule fires; the unmodified record (the
    file in /var/log) does not — as measured on the real dataset."""
    record = LINUX["linux-sysmon-1"].replace(
        '<Data Name="Image">/usr/bin/clear</Data>', '<Data Name="Image">/usr/bin/crontab</Data>'
    )
    loaded_from_tmp = record.replace(
        '<Data Name="CommandLine">clear</Data>',
        '<Data Name="CommandLine">crontab /tmp/tasks</Data>',
    )
    loaded_from_var = record.replace(
        '<Data Name="CommandLine">clear</Data>',
        '<Data Name="CommandLine">crontab /var/log/tasks</Data>',
    )
    assert _fired_products(engine, products, [_convert(loaded_from_tmp)]) == {"linux"}
    assert _fired_products(engine, products, [_convert(loaded_from_var)]) == set()


# ===========================================================================
# Real data (runs when the verified cache is present)
# ===========================================================================


LINUX_REPORT = SAMPLES / "splunk-attack-data" / "conversion-report.json"


def test_real_linux_report_conversion_and_os_scope() -> None:
    """The whole verified cache (``scripts/report_linux_telemetry.py``, ~15 min,
    regenerated whenever the data or the pack changes — enforced below):
    every real event converts or is refused for a stated reason, every
    Observation is Linux, and only Linux rules ever fire on it."""
    report = json.loads(LINUX_REPORT.read_text(encoding="utf-8"))
    manifest = SAMPLES / "splunk-attack-data" / "manifest.json"
    assert report["source_manifest_sha256"] == hashlib.sha256(manifest.read_bytes()).hexdigest()
    assert report["sigma_pack_sha256"] == hashlib.sha256(PACK.read_bytes()).hexdigest()
    sysmon, auditd = report["sysmon_for_linux"], report["auditd"]
    assert sysmon["observations"] == 246717  # unique ids; 157 events appear in two dataset files
    assert sysmon["refused_by_reason"] == {"SysmonSourceAdapter: unsupported winlog.event_id 9": 52}
    assert auditd["observations"] == 837
    assert set(auditd["refused_by_reason"].values()) == {6348, 2}  # ausearch -i; post-processed
    for section in (sysmon, auditd):
        assert section["os_types"] == ["linux"]
        assert section["fired_rules"]
        assert {r["product"] for r in section["fired_rules"]} == {"linux"}
    # measured, documented-label recall (labels resolved through ATT&CK revoked-by)
    assert (
        sysmon["labelled_datasets_with_observations"],
        sysmon["labelled_datasets_with_documented_technique_detected"],
    ) == (45, 1)
    assert (
        auditd["labelled_datasets_with_observations"],
        auditd["labelled_datasets_with_documented_technique_detected"],
    ) == (48, 4)
