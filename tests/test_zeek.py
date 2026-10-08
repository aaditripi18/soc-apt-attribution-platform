"""Zeek network telemetry (ADR-0012): readers (JSON, field-name-map JSON, TSV),
the adapter, the sensor product scope, and the whole-cache report.

Golden tests on real records from OTRF Security-Datasets (MIT,
``otrf-zeek/golden-records.jsonl``): APT29 day-1 JSON records and a real TSV
header block from an LSASS campaign archive.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from attribution_platform.attack_knowledge.loader import load_attack_knowledge
from attribution_platform.dataplane.persistence import _observation_from_document
from attribution_platform.detection import DetectionEngine, load_rule_pack
from attribution_platform.detection_content.sigma_field_map import (
    LOGSOURCE_SCOPES,
    PRODUCT_OS_SCOPES,
)
from attribution_platform.domain import (
    HostRef,
    Observation,
    ObserverRef,
    TimePrecision,
    to_serializable,
)
from attribution_platform.sources.errors import SourceAdapterError
from attribution_platform.sources.windows_security import WindowsSecuritySourceAdapter
from attribution_platform.sources.zeek import ZeekSourceAdapter, iter_zeek_lines, iter_zeek_tsv

REPO_ROOT = Path(__file__).resolve().parents[1]
SAMPLES = REPO_ROOT / "data" / "telemetry-samples"
ZEEK = SAMPLES / "otrf-zeek"
GENERATED = REPO_ROOT / "data" / "detection" / "sigma" / "r2026-07-01" / "generated"
PACK = GENERATED / "sigma-r2026-07-01-sigma_core++.rules.json"
IMPORT_REPORT = GENERATED / "sigma-r2026-07-01-sigma_core++.import-report.json"
RECORDS: dict[str, str] = {
    row["golden_id"]: row["record"]
    for row in (
        json.loads(line)
        for line in (ZEEK / "golden-records.jsonl").read_text(encoding="utf-8").splitlines()
    )
}
ADAPTER = ZeekSourceAdapter()


def _records(golden_id: str) -> list[dict[str, Any]]:
    return list(iter_zeek_lines(RECORDS[golden_id].split("\n")))


def _convert(record: dict[str, Any]) -> Observation:
    (obs,) = ADAPTER.to_observations(record)
    return obs


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
# Readers and exact fields
# ===========================================================================


def test_json_conn_record_is_exact() -> None:
    (record,) = _records("zeek-json-conn")
    obs = _convert(record)
    assert record["ts"] == 1588205199.827696  # epoch seconds, read from its exact text
    assert obs.timestamp == datetime(2020, 4, 30, 0, 6, 39, 827696, tzinfo=UTC)
    assert obs.timestamp_precision is TimePrecision.MICROSECOND
    assert obs.host is None  # a sensor is not the host (ADR-0012 D5)
    assert obs.observer == ObserverRef(product="zeek", hostname="bobs.bigwheel.local")
    assert obs.event is not None
    assert (obs.event.dataset, obs.event.action) == ("zeek.connection", "conn")
    network = obs.network
    assert network is not None and network.source is not None and network.destination is not None
    assert (network.source.ip, network.source.port) == ("10.0.1.6", 56880)
    assert (network.destination.ip, network.destination.port) == ("10.0.0.4", 445)
    assert network.transport == "tcp"
    zeek = obs.zeek
    assert zeek is not None
    assert (zeek.uid, zeek.service, zeek.conn_state, zeek.history) == (
        "CJ21Le4zsTUcyKKi98",
        "gssapi,smb,krb",
        "RSTO",
        "ShADdaR",
    )


@pytest.mark.parametrize(
    ("golden_id", "expected"),
    [
        ("zeek-json-dns", {"query": "newyork.dmevals.local", "qtype_name": "A", "z": "0"}),
        ("zeek-json-dce-rpc", {"endpoint": "drsuapi", "operation": "DRSCrackNames"}),
        (
            "zeek-json-kerberos",
            {
                "request_type": "TGS",
                "krb_service": "host/nashua.dmevals.local",
                "cipher": "aes256-cts-hmac-sha1-96",
                "success": "true",
            },
        ),
        ("zeek-json-smb-files", {"smb_action": "SMB::FILE_OPEN"}),
        ("zeek-json-http", {"method": "OPTIONS", "uri": "/", "status_code": "403"}),
        ("zeek-json-ssl", {"ssl_version": "TLSv12", "ja3": "e0fe397a5edfba9a6facc7c7b341f4eb"}),
        ("zeek-json-files", {"file_source": "SMB", "conn_uids": "CF37FuG0Jho600cAa"}),
    ],
)
def test_log_fields_are_kept_as_logged(golden_id: str, expected: dict[str, str]) -> None:
    (record,) = _records(golden_id)
    zeek = _convert(record).zeek
    assert zeek is not None
    assert {k: getattr(zeek, k) for k in expected} == expected


def test_dotted_and_field_name_map_forms_are_one_observation() -> None:
    """Zeek's native ``id.orig_h`` and the ``Log::default_field_name_map``
    ``id_orig_h`` spell the same field: the same record in either form is the
    same Observation (content-digest id)."""
    (record,) = _records("zeek-json-conn")
    dotted = {
        k.replace("id_", "id.", 1) if k.startswith("id_") else k: v for k, v in record.items()
    }
    assert "id.orig_h" in dotted
    assert _convert(dotted) == _convert(record)


def test_tsv_reader_on_a_real_header() -> None:
    (dns,) = _records("zeek-tsv-dns")
    assert dns["@stream"] == "dns" and dns["@proc"] == "zeek"
    obs = _convert(dns)
    assert obs.timestamp == datetime(2023, 9, 6, 4, 51, 46, 500310, tzinfo=UTC)
    assert obs.observer == ObserverRef(product="zeek")  # TSV names no sensor
    assert obs.zeek is not None
    assert (obs.zeek.rcode_name, obs.zeek.query) == ("REFUSED", None)  # "-" is unset
    (conn,) = _records("zeek-tsv-conn")
    assert _convert(conn).zeek.uid == obs.zeek.uid  # type: ignore[union-attr]


def test_tsv_escapes_sets_and_empty_values() -> None:
    lines = [
        "#separator \\x09",
        "#set_separator\t,",
        "#empty_field\t(empty)",
        "#unset_field\t-",
        "#path\tdns",
        "#fields\tts\tuid\tquery\tanswers\tqtype_name",
        "1588205198.899710\tCabc\ta\\x09b.example\t10.0.0.1,10.0.0.2\t(empty)",
    ]
    (record,) = iter_zeek_tsv(lines)
    assert record["query"] == "a\tb.example"  # \xHH undone
    assert record["answers"] == ["10.0.0.1", "10.0.0.2"]
    assert record["qtype_name"] == ""
    zeek = _convert(record).zeek
    assert zeek is not None
    assert (zeek.answers, zeek.qtype_name) == ("10.0.0.1,10.0.0.2", None)


@pytest.mark.parametrize(
    ("lines", "match"),
    [
        (["1588205198.1\tCabc"], "before its #path"),
        (["#separator \\x09", "#path\tdns", "#fields\tts\tuid", "1.0"], "columns"),
    ],
)
def test_malformed_tsv_fails_closed(lines: list[str], match: str) -> None:
    with pytest.raises(SourceAdapterError, match=match):
        list(iter_zeek_tsv(lines))


@pytest.mark.parametrize(
    ("change", "match"),
    [
        ({"ts": "2020-04-30T00:06:39Z"}, "not epoch seconds"),
        ({"ts": "1588205199.8276961"}, "not epoch seconds"),  # finer than microseconds
        ({"id_resp_p": 70000}, "not a port"),
        ({"@stream": "loaded_scripts"}, "not a traffic log"),
        ({"@proc": "suricata"}, "not a Zeek log record"),
    ],
)
def test_records_fail_closed(change: dict[str, Any], match: str) -> None:
    (record,) = _records("zeek-json-conn")
    with pytest.raises(SourceAdapterError, match=match):
        _convert({**record, **change})


def test_non_traffic_logs_are_refused() -> None:
    (record,) = _records("zeek-json-x509")
    with pytest.raises(SourceAdapterError, match="'x509' is not a traffic log"):
        _convert(record)


@pytest.mark.parametrize("golden_id", sorted(g for g in RECORDS if g != "zeek-json-x509"))
def test_zeek_observations_round_trip_through_persistence(golden_id: str) -> None:
    for record in _records(golden_id):
        obs = _convert(record)
        assert _observation_from_document(json.loads(json.dumps(to_serializable(obs)))) == obs


# ===========================================================================
# Detection and the sensor scope (ADR-0012 D5)
# ===========================================================================


def test_zeek_logsources_and_sensor_scope() -> None:
    assert LOGSOURCE_SCOPES[("zeek", "dce_rpc")] == (("event.dataset", "equals", "zeek.dce_rpc"),)
    assert PRODUCT_OS_SCOPES["zeek"] == (("observer.product", "equals", "zeek", False),)
    for product in ("windows", "linux"):
        assert ("observer.product", "exists", None, True) in PRODUCT_OS_SCOPES[product]


@pytest.mark.parametrize(
    ("golden_id", "changes", "technique"),
    [
        # BZAR: remote task registration over ITaskSchedulerService
        (
            "zeek-json-dce-rpc",
            {"endpoint": "ITaskSchedulerService", "operation": "SchRpcRegisterTask"},
            "T1053.002",
        ),
        # Kerberoasting signal: an RC4 service ticket for a non-computer account
        ("zeek-json-kerberos", {"cipher": "rc4-hmac"}, "T1558.003"),
        # credential material copied over SMB
        ("zeek-json-smb-files", {"name": "\\lsass"}, "T1003.001"),
    ],
)
def test_zeek_rules_fire_on_a_modified_real_record(
    engine: DetectionEngine, golden_id: str, changes: dict[str, str], technique: str
) -> None:
    (record,) = _records(golden_id)
    assert technique not in _fired(engine, [_convert(record)])
    assert technique in _fired(engine, [_convert({**record, **changes})])


def test_only_zeek_rules_fire_on_zeek_records(
    engine: DetectionEngine, products: dict[str, str]
) -> None:
    (record,) = _records("zeek-json-dce-rpc")
    obs = _convert(
        {**record, "endpoint": "ITaskSchedulerService", "operation": "SchRpcRegisterTask"}
    )
    assert _fired_products(engine, products, [obs]) == {"zeek"}
    every = [_convert(r) for g in sorted(RECORDS) if g != "zeek-json-x509" for r in _records(g)]
    assert _fired_products(engine, products, every) <= {"zeek"}


def test_an_endpoint_detection_stops_on_a_sensor_record(
    engine: DetectionEngine, products: dict[str, str]
) -> None:
    golden = SAMPLES / "otrf-compound" / "golden-records.jsonl"
    rows = [json.loads(line) for line in golden.read_text(encoding="utf-8").splitlines()]
    record = next(r["record"] for r in rows if r["golden_id"] == "b-4661")
    (windows,) = WindowsSecuritySourceAdapter().to_observations(record)
    assert _fired_products(engine, products, [windows]) == {"windows"}
    as_sensor = dataclasses.replace(windows, observer=ObserverRef(product="zeek"))
    assert _fired_products(engine, products, [as_sensor]) == set()
    assert isinstance(windows.host, HostRef)


# ===========================================================================
# Real data (the whole verified cache)
# ===========================================================================


def test_real_zeek_report() -> None:
    """``scripts/report_zeek_telemetry.py`` over all 17 files: every record
    converts or is refused for a stated reason, files that publish the same
    records collapse to one Observation each, and no rule fires on the corpus
    traffic (APT29: SAMR / LSARPC / DRSUAPI discovery and AES Kerberos — no
    Sigma Zeek rule covers it)."""
    report = json.loads((ZEEK / "conversion-report.json").read_text(encoding="utf-8"))
    manifest = ZEEK / "manifest.json"
    assert report["source_manifest_sha256"] == hashlib.sha256(manifest.read_bytes()).hexdigest()
    assert report["sigma_pack_sha256"] == hashlib.sha256(PACK.read_bytes()).hexdigest()
    observations = {k: v["observations"] for k, v in report["recordings"].items()}
    assert observations == {
        "otrf-apt29-day1": 1737,
        "otrf-apt29-day2": 2649,
        "otrf-lsass-01-logonpasswords": 230,
        "otrf-lsass-02-procdump": 270,
        "otrf-lsass-03-comsvcs": 283,
        "otrf-lsass-04-out-minidump": 246,
        "otrf-lsass-05-sharpdump": 3749,
        "otrf-lsass-06-outflank-dumpert": 3074,
        "otrf-lsass-07-nanodump": 2085,
    }
    for section in report["recordings"].values():
        assert section["fired_rules"] == []
        assert all("is not a traffic log read here" in r for r in section["refused_by_reason"])
