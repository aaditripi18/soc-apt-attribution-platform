"""ADR-0028 D1 against a real cluster: polling an index returns every document
once, unchanged, and a live cycle over them equals the recording run.

Opt-in, like ``test_live_elasticsearch.py``: skipped unless
``ATTRIBUTION_LIVE_ELASTICSEARCH=1`` and the cluster variables are set. Writes
one index of its own (``attribution-live-test-comsvcs``), deleted afterwards.
The recording is the tracked OTRF comsvcs LSASS dump (NXLog records); its
``TimeCreated`` is fixed-width, so it is mapped as a keyword and ordered
lexically - the polling code is the same for a date field."""

from __future__ import annotations

import json
import os
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from attribution_platform.api.__main__ import elasticsearch_client_from_env
from attribution_platform.dataplane import SharedMemoryClient
from attribution_platform.investigation.__main__ import investigation_runner, load_workbench
from attribution_platform.live.__main__ import read_model_summary
from attribution_platform.live.capture import CaptureStore
from attribution_platform.live.elastic_source import ElasticsearchSource
from attribution_platform.live.session import ANALYSED, LiveSession
from attribution_platform.replay.recording_check import check_recording
from attribution_platform.replay.recording_pipeline import RecordingSource

REPO = Path(__file__).resolve().parents[1]
RECORDING = REPO / "data" / "telemetry-samples" / "otrf" / "psh_lsass_memory_dump_comsvcs.zip"
INDEX = "attribution-live-test-comsvcs"

pytestmark = pytest.mark.skipif(
    os.environ.get("ATTRIBUTION_LIVE_ELASTICSEARCH") != "1"
    or not os.environ.get("ELASTIC_PASSWORD"),
    reason="live Elasticsearch verification is opt-in (ATTRIBUTION_LIVE_ELASTICSEARCH=1)",
)


def test_polling_a_real_index_feeds_the_same_investigation(tmp_path: Path) -> None:
    client = elasticsearch_client_from_env(dict(os.environ))
    assert client is not None
    with zipfile.ZipFile(RECORDING) as archive:
        (name,) = archive.namelist()
        lines = archive.read(name).decode("utf-8").splitlines()
    # indexed in the order a collector would deliver them: by event time
    records: list[dict[str, Any]] = sorted(
        (json.loads(line) for line in lines), key=lambda r: str(r["TimeCreated"])
    )

    client._request("DELETE", f"/{INDEX}", None)  # noqa: SLF001 - a clean start
    client.ensure_index(INDEX, {"TimeCreated": {"type": "keyword"}})
    try:
        half = len(records) // 2
        for number, record in enumerate(records[:half]):
            client.index_document(INDEX, f"{number:05d}", record)
        client._request("POST", f"/{INDEX}/_refresh", None)  # noqa: SLF001
        source = ElasticsearchSource(client, INDEX, time_field="TimeCreated", page_size=50)
        first = source.read()
        for number, record in enumerate(records[half:], start=half):
            client.index_document(INDEX, f"{number:05d}", record)
        client._request("POST", f"/{INDEX}/_refresh", None)  # noqa: SLF001
        second = source.read()
        assert source.read() == []
        # every document once, unchanged
        polled = sorted(json.dumps(json.loads(line), sort_keys=True) for line in first + second)
        assert polled == sorted(json.dumps(r, sort_keys=True) for r in records)

        # a live cycle over the polled documents is the recording run of them
        workbench = load_workbench()
        live_client = SharedMemoryClient()
        replay = ElasticsearchSource(client, INDEX, time_field="TimeCreated", page_size=50)
        session = LiveSession(
            name="es",
            followers=[replay],
            store=CaptureStore(tmp_path / "live", "es"),
            check=check_recording,
            run=investigation_runner(live_client, workbench),
            summarise=lambda i: read_model_summary(live_client, i),
            clock=lambda: datetime(2026, 10, 19, tzinfo=UTC) + timedelta(seconds=1),
        )
        outcome = session.cycle()
        assert outcome.state == ANALYSED and outcome.summary is not None
        batch = tmp_path / "batch.log"
        batch.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
        report = check_recording(batch)
        reference_client = SharedMemoryClient()
        reference = investigation_runner(reference_client, workbench)(
            RecordingSource("batch", batch, report.sha256, report.declared_sources)
        )
        assert (outcome.evidence, outcome.units) == (reference.evidence, reference.units)
        expected = read_model_summary(reference_client, reference.investigation_id)
        assert outcome.summary["counted_techniques"] == expected["counted_techniques"]
        assert "T1003.001" in outcome.summary["counted_techniques"]
    finally:
        client._request("DELETE", f"/{INDEX}", None)  # noqa: SLF001
