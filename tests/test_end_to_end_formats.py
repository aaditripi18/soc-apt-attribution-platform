"""Final validation: every telemetry family added after the Windows corpus work
runs **end to end** — intake check → investigation (the CLI's own entry point)
→ persisted read model → HTTP API — not just through its adapter.

Each recording here is written from real golden records (verbatim; the Zeek TSV
block is a real header block with its record). Expected counts are what the
production pipeline produces on them; where a family yields no Evidence (public
Zeek and macOS data has no Core++ match — ADR-0012 / ADR-0014 records), the test
says so and checks the records were still read.
"""

from __future__ import annotations

import json
import threading
import urllib.request
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from attribution_platform.api import create_server
from attribution_platform.dataplane import FakeElasticClient
from attribution_platform.investigation.__main__ import investigate
from attribution_platform.investigation.records import load_attribution_analysis
from attribution_platform.replay.recording_check import check_recording

REPO_ROOT = Path(__file__).resolve().parents[1]
SAMPLES = REPO_ROOT / "data" / "telemetry-samples"
NO_PINNED_RECORDINGS = REPO_ROOT / "no-such-recordings.json"


def _golden(name: str) -> dict[str, Any]:
    rows = (SAMPLES / name / "golden-records.jsonl").read_text(encoding="utf-8").splitlines()
    return {r["golden_id"]: r["record"] for r in map(json.loads, rows)}


def _lines(records: list[Any]) -> str:
    return "\n".join(r if isinstance(r, str) else json.dumps(r) for r in records) + "\n"


CLOUD = _golden("splunk-attack-data-cloud")
ZEEK = _golden("otrf-zeek")
MACOS = _golden("splunk-attack-data-macos")
LINUX = _golden("splunk-attack-data")

#: family -> (file name, file text).
RECORDINGS: dict[str, tuple[str, str]] = {
    "cloud": (
        "cloud.jsonl",
        _lines(
            [
                CLOUD[g]
                for g in (
                    "entra-audit-disable-strong-auth",
                    "entra-signin-mfa-interrupted",
                    "o365-aad-disable-strong-auth",
                    "aws-stop-logging",
                    "aws-console-login-root",
                    "okta-mfa-deactivate",
                    "github-repo-destroy",
                    "k8s-create-pod",
                    "azure-activity-runbook-write",
                )
            ]
        ),
    ),
    "zeek": (
        "zeek.log",
        _lines([v for g, v in sorted(ZEEK.items()) if g.startswith("zeek-json")])
        + ZEEK["zeek-tsv-dns"]
        + "\n#close\t2023-09-06-05-00-00\n",
    ),
    "macos": ("macos.jsonl", _lines(list(MACOS.values()))),
    "linux": (
        "linux.log",
        _lines([v for g, v in sorted(LINUX.items()) if g.startswith("linux-sysmon")]),
    ),
}


@pytest.fixture(scope="module")
def investigated(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    out: dict[str, Any] = {}
    client = FakeElasticClient()
    for family, (name, text) in RECORDINGS.items():
        path = tmp_path_factory.mktemp(family) / name
        path.write_text(text, encoding="utf-8", newline="\n")
        report = check_recording(path)
        session = investigate(str(path), client=client, recordings=NO_PINNED_RECORDINGS)
        out[family] = (report, session.record)
    out["client"] = client
    return out


@pytest.mark.parametrize("family", sorted(RECORDINGS))
def test_intake_accepts_and_routes_every_family(investigated: dict[str, Any], family: str) -> None:
    report, _ = investigated[family]
    assert report.accepted, report.problems
    assert report.unparseable_lines == 0
    assert report.converted_by_source  # read by the family's own adapter(s)


def test_each_family_is_read_by_its_own_adapters(investigated: dict[str, Any]) -> None:
    sources = {f: set(investigated[f][0].converted_by_source) for f in RECORDINGS}
    assert sources["cloud"] == {
        "entra_id",
        "o365_management_activity",
        "aws_cloudtrail",
        "okta_system_log",
        "github_audit",
        "kubernetes_audit",
        "azure_activity",
    }
    assert sources["zeek"] == {"zeek"}
    assert sources["macos"] == {"osquery_es_process_events"}
    assert sources["linux"] == {"sysmon"}
    # the Zeek TSV block was read through the recording reader, not skipped
    assert investigated["zeek"][0].records_by_channel == {"<zeek>": 10}  # 9 JSON + 1 TSV


def test_cloud_investigation_forms_units_from_real_records(investigated: dict[str, Any]) -> None:
    """No structural link joins cloud records (ADR-0011 D6): each detected record is
    its own unit; several rules matching one record share its Observation, so
    they share its unit (10 Evidence on 7 records)."""
    _, record = investigated["cloud"]
    assert (record.evidence, len(record.units)) == (10, 7)


def test_families_without_core_detections_form_no_units(investigated: dict[str, Any]) -> None:
    """Measured, not assumed: the real Zeek and Linux records here match no rule
    (their reports: no Zeek detection on the corpus traffic; Linux recall is a
    Sigma content gap), and the real macOS records match only low-level (enrich)
    rules, whose Evidence never forms a unit (ADR-0003 Amendment H). They are
    still read end to end (intake test above)."""
    assert (investigated["zeek"][1].evidence, investigated["zeek"][1].units) == (0, ())
    assert (investigated["linux"][1].evidence, investigated["linux"][1].units) == (0, ())
    assert (investigated["macos"][1].evidence, investigated["macos"][1].units) == (12, ())


# ===========================================================================
# Served unchanged by the read-model API
# ===========================================================================


@pytest.fixture(scope="module")
def base_url(investigated: dict[str, Any]) -> Iterator[str]:
    server = create_server(investigated["client"])
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    server.server_close()


def _get(url: str) -> Any:
    with urllib.request.urlopen(url, timeout=10) as response:  # noqa: S310 - local test server
        return json.loads(response.read())


def test_api_lists_every_investigation(base_url: str, investigated: dict[str, Any]) -> None:
    listed = {i["investigation_id"]: i for i in _get(f"{base_url}/investigations")}
    for family in RECORDINGS:
        record = investigated[family][1]
        assert listed[record.investigation_id]["units"] == len(record.units)


def test_api_serves_a_cloud_unit_with_its_uncalibrated_analysis(
    base_url: str, investigated: dict[str, Any]
) -> None:
    record = investigated["cloud"][1]
    for unit_id in record.units:
        unit = _get(f"{base_url}/units/{unit_id}")
        assert unit["group"]["group_id"] == unit_id
        assert unit["attribution_analysis"] == dict(
            load_attribution_analysis(investigated["client"], unit_id) or {}
        )
        assert not _keys(unit["attribution_analysis"]) & FORBIDDEN_KEYS  # uncalibrated
        # ADR-0005 Amendment E: collection guidance is served with every analysis
        guidance = unit["attribution_analysis"]["collection_guidance"]
        assert guidance["candidates_total"] == len(unit["attribution_analysis"]["candidates"])
        for question in guidance["questions"]:
            assert question["split"] == min(
                len(question["candidates_using"]),
                guidance["candidates_total"] - len(question["candidates_using"]),
            )


FORBIDDEN_KEYS = {"likelihood", "confidence", "wep", "verdict", "rank", "probability"}


def _keys(value: Any) -> set[str]:
    """Every key at any depth (a note *mentioning* "confidence" is fine)."""
    if isinstance(value, dict):
        return set(value) | {k for v in value.values() for k in _keys(v)}
    if isinstance(value, list):
        return {k for v in value for k in _keys(v)}
    return set()
