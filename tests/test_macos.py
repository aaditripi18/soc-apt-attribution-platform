"""macOS telemetry (ADR-0014): osquery ``es_process_events`` exec rows (Apple
Endpoint Security) — the adapter, its routing and persistence.

The golden file holds every real macOS record of the pinned selection
(``splunk/attack_data``, Apache-2.0, 25 rows), so these tests run the whole real
dataset: exact fields, osquery's argument separator, refusals, routing and
persistence.
"""

from __future__ import annotations

import dataclasses
import json
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from attribution_platform.attack_knowledge.external_ids import ExternalIdResolver
from attribution_platform.attack_knowledge.loader import load_attack_knowledge
from attribution_platform.dataplane.persistence import _observation_from_document
from attribution_platform.detection import DetectionEngine, load_rule_pack
from attribution_platform.detection_content.sigma_field_map import FIELD_MAPS, PRODUCT_OS_SCOPES
from attribution_platform.domain import (
    EvidenceQuality,
    Observation,
    TimePrecision,
    to_serializable,
)
from attribution_platform.replay.recording_pipeline import (
    DEFAULT_CHANNEL_ADAPTERS,
    OSQUERY_ES_CHANNEL,
    _channel,
)
from attribution_platform.sources.errors import SourceAdapterError
from attribution_platform.sources.osquery_es import OsqueryEsSourceAdapter

REPO_ROOT = Path(__file__).resolve().parents[1]
MACOS = REPO_ROOT / "data" / "telemetry-samples" / "splunk-attack-data-macos"
GENERATED = REPO_ROOT / "data" / "detection" / "sigma" / "r2026-07-01" / "generated"
PACK = GENERATED / "sigma-r2026-07-01-sigma_core++.rules.json"
IMPORT_REPORT = GENERATED / "sigma-r2026-07-01-sigma_core++.import-report.json"
ROWS: list[dict[str, Any]] = [
    json.loads(line)
    for line in (MACOS / "golden-records.jsonl").read_text(encoding="utf-8").splitlines()
]
RECORDS: dict[str, dict[str, Any]] = {r["golden_id"]: json.loads(r["record"]) for r in ROWS}
ADAPTER = OsqueryEsSourceAdapter()


def _convert(record: dict[str, Any]) -> Observation:
    (obs,) = ADAPTER.to_observations(record)
    return obs


def _with_columns(golden_id: str, **changes: Any) -> dict[str, Any]:
    record: dict[str, Any] = json.loads(json.dumps(RECORDS[golden_id]))
    record["columns"].update(changes)
    return record


# ===========================================================================
# Exact fields
# ===========================================================================


def test_every_real_record_converts_as_a_macos_process_start() -> None:
    observations = [_convert(record) for record in RECORDS.values()]
    assert len(observations) == 25
    assert len({o.observation_id for o in observations}) == 25
    for obs in observations:
        assert obs.host is not None and obs.host.os_type == "macos"
        assert obs.event is not None
        assert (obs.event.category, obs.event.type) == (("process",), ("start",))
        assert obs.process is not None and obs.process.command_line is not None
        assert not obs.process.command_line.endswith(" ")  # osquery's separator removed


def test_plistbuddy_record_is_exact() -> None:
    golden_id = next(g for g in RECORDS if "LSFileQuarantineEnabled" in g)
    record = RECORDS[golden_id]
    obs = _convert(record)
    columns = record["columns"]
    # the Endpoint Security event time, not the query's run time
    assert obs.timestamp == datetime.fromtimestamp(int(columns["time"]), tz=UTC)
    assert int(columns["time"]) != record["unixTime"]
    assert obs.timestamp_precision is TimePrecision.SECOND
    process = obs.process
    assert process is not None
    assert process.executable == "/usr/libexec/PlistBuddy"
    assert process.name == "PlistBuddy"
    assert process.command_line == columns["cmdline"][:-1]
    assert process.command_line.endswith("/Contents/Info.plist")
    assert (process.pid, process.parent_pid) == (int(columns["pid"]), int(columns["parent"]))
    assert obs.host is not None and obs.host.name == record["hostIdentifier"]


@pytest.mark.parametrize(
    ("changes", "match"),
    [
        ({"event_type": "fork"}, "is not a process start"),
        ({"cmdline": "xattr -c myapp.app"}, "lacks osquery's argument separator"),
        ({"time": "2025-12-15"}, "not a non-negative integer"),
        ({"pid": "-1"}, "not a non-negative integer"),
    ],
)
def test_records_fail_closed(changes: dict[str, Any], match: str) -> None:
    golden_id = next(iter(RECORDS))
    with pytest.raises(SourceAdapterError, match=match):
        _convert(_with_columns(golden_id, **changes))


def test_query_name_does_not_matter_but_columns_do() -> None:
    golden_id = next(iter(RECORDS))
    renamed = {**RECORDS[golden_id], "name": "any_operator_name"}
    assert _convert(renamed) == _convert(RECORDS[golden_id])
    record = json.loads(json.dumps(RECORDS[golden_id]))
    del record["columns"]["global_seq_num"]
    with pytest.raises(SourceAdapterError, match="not an osquery es_process_events row"):
        _convert(record)


@pytest.mark.parametrize("golden_id", sorted(RECORDS))
def test_records_route_and_round_trip(golden_id: str) -> None:
    assert _channel(RECORDS[golden_id]) == OSQUERY_ES_CHANNEL
    assert isinstance(DEFAULT_CHANNEL_ADAPTERS[OSQUERY_ES_CHANNEL], OsqueryEsSourceAdapter)
    obs = _convert(RECORDS[golden_id])
    assert _observation_from_document(json.loads(json.dumps(to_serializable(obs)))) == obs


@pytest.fixture(scope="module")
def engine() -> DetectionEngine:
    return DetectionEngine(rules=load_rule_pack(PACK, knowledge=load_attack_knowledge()).rules)


@pytest.fixture(scope="module")
def products() -> dict[str, str]:
    rows = json.loads(IMPORT_REPORT.read_text(encoding="utf-8"))["rules"]
    return {r["sigma_id"]: r["logsource"].split("/")[0] for r in rows}


def _fired(engine: DetectionEngine, observations: list[Observation]) -> set[str]:
    return {
        m.attack_ref.external_id
        for d in engine.evaluate(observations)
        for m in d.technique_mappings
        if m.attack_ref.external_id
    }


def _fired_products(
    engine: DetectionEngine, products: dict[str, str], observations: list[Observation]
) -> set[str]:
    return {products[d.rule_ref.rule_id.split(":")[1]] for d in engine.evaluate(observations)}


# ===========================================================================
# Detection and the macOS scope (ADR-0014 D4)
# ===========================================================================


def test_macos_scope_and_field_map() -> None:
    assert PRODUCT_OS_SCOPES["macos"][0] == ("host.os_type", "equals", "macos", False)
    assert ("host.os_type", "equals", "macos", True) in PRODUCT_OS_SCOPES["windows"]
    assert FIELD_MAPS[("macos", "process_creation")]["CommandLine"] == "process.command_line"
    assert "ParentImage" not in FIELD_MAPS[("macos", "process_creation")]


def test_only_macos_rules_fire_on_macos_records(
    engine: DetectionEngine, products: dict[str, str]
) -> None:
    observations = [_convert(record) for record in RECORDS.values()]
    fired = _fired_products(engine, products, observations)
    assert fired == {"macos"}
    # all of it low-level (enrich tier): such Evidence alone forms no unit (ADR-0003 H)
    assert {d.evidence_quality for d in engine.evaluate(observations)} == {EvidenceQuality.LOW}


def test_a_macos_detection_stops_when_the_host_is_not_macos(
    engine: DetectionEngine, products: dict[str, str]
) -> None:
    golden_id = next(
        g
        for g, r in RECORDS.items()
        if "com.apple.quarantine" in r["columns"]["cmdline"]  # the -d quarantine removal
    )
    obs = _convert(RECORDS[golden_id])
    assert _fired_products(engine, products, [obs]) == {"macos"}
    assert obs.host is not None
    for os_type in ("linux", "windows"):
        moved = dataclasses.replace(obs, host=dataclasses.replace(obs.host, os_type=os_type))
        assert "macos" not in _fired_products(engine, products, [moved])


def test_documented_labels_on_the_real_datasets(engine: DetectionEngine) -> None:
    """Per dataset: its documented ATT&CK label (resolved through ATT&CK
    revoked-by), against what the pack detects on that dataset's real rows."""
    resolver = ExternalIdResolver(load_attack_knowledge(), ("attack-pattern",))
    by_dataset: dict[str, list[dict[str, Any]]] = {}
    for row in ROWS:
        by_dataset.setdefault(row["source"].rsplit("/", 1)[0], []).append(row)
    outcome: Counter[str] = Counter()
    detected_by_dataset = {}
    for dataset, rows in sorted(by_dataset.items()):
        documented = {
            resolver.current_external_id(t) or t for t in rows[0]["documented_techniques"]
        }
        detected = _fired(engine, [_convert(json.loads(r["record"])) for r in rows])
        detected_by_dataset[dataset.rsplit("/", 1)[-1]] = sorted(detected)
        if not documented:
            outcome["unlabelled"] += 1
        elif any(
            d == t or d.startswith(t + ".") or t.startswith(d + ".")
            for t in documented
            for d in detected
        ):
            outcome["detected"] += 1
        else:
            outcome["missed"] += 1
    assert detected_by_dataset == EXPECTED_DETECTIONS
    assert dict(outcome) == EXPECTED_OUTCOME


#: Measured on the real rows (ADR-0014 record). Every detection here comes from the
#: enrich tier (quality LOW): the macOS discovery / Gatekeeper rules are low-level.
EXPECTED_DETECTIONS: dict[str, list[str]] = {
    "macos_gatekeeper_bypass_LSFileQuarantineEnabled": [],  # no rule for PlistBuddy
    "macos_gatekeeper_bypass_xattr": ["T1553.001"],
    "macos_lolbin": ["T1083", "T1113"],
    "macos_net_discovery": ["T1018", "T1049"],  # its T1016 rule needs ParentImage
}
EXPECTED_OUTCOME: dict[str, int] = {"detected": 1, "missed": 2, "unlabelled": 1}
