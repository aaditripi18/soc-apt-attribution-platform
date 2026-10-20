"""Live mode (ADR-0028): follow log files and investigate the window every cycle.

    python -m attribution_platform.live --name lab --follow <file> [--follow <file> ...]
        [--elasticsearch-index <pattern> ...] [--time-field event.ingested]
        [--interval 60] [--window-hours 24] [--directory data/cache/live/<name>]
        [--serve] [--port 8000] [--cycles N]

Each followed file must hold records in a shape the recording pipeline reads
(Winlogbeat / Elastic Agent event logs, Wazuh ``alerts.json``, Zeek JSON logs,
raw ``audit.log``). Every cycle appends what arrived to the capture store,
freezes the window into a hashed snapshot and investigates it with the same
intake check and pipeline as the command line and the upload route. With
``--serve`` the read-model API and console serve the results, and
``GET /api/live`` reports the sources and recent cycles. ``--cycles N`` stops
after N cycles (without ``--serve``), for scripted runs.

``--elasticsearch-index`` polls an index pattern (for example
``logs-windows.sysmon_operational-*``) read-only, with the credentials of
``--elasticsearch`` elsewhere (``ELASTIC_PASSWORD`` and the related variables);
documents are read in order of ``--time-field`` (default ``event.ingested``).
"""

from __future__ import annotations

import os
import sys
import threading
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from attribution_platform.api.__main__ import elasticsearch_client_from_env
from attribution_platform.api.read_model import get_assessment, get_profile_match
from attribution_platform.api.server import create_server
from attribution_platform.dataplane import SharedMemoryClient
from attribution_platform.dataplane.client import ElasticClient
from attribution_platform.investigation.__main__ import (
    investigation_runner,
    load_workbench,
    serving_context,
    upload_service,
)
from attribution_platform.live.capture import CaptureStore, FileFollower
from attribution_platform.live.elastic_source import ElasticsearchSource
from attribution_platform.live.session import LiveSession, LiveSource
from attribution_platform.replay.recording_check import check_recording
from attribution_platform.replay.recording_pipeline import DetectionMemo

REPO_ROOT = Path(__file__).resolve().parents[3]
LIVE_ROOT = REPO_ROOT / "data" / "cache" / "live"


def read_model_summary(client: ElasticClient, investigation_id: str) -> Mapping[str, Any]:
    """What a cycle compares with the previous one, read from stored records
    (the cycle adds the unit count from the run itself)."""
    assessment = get_assessment(client, investigation_id)
    match = get_profile_match(client, investigation_id)
    return {
        "counted_techniques": sorted(o["technique_id"] for o in match["observed"]),
        "verdict": assessment["verdict"],
        "named_actors": sorted({lead["actor_name"] for lead in assessment.get("actor_leads", ())}),
    }


def _values(args: list[str], flag: str) -> list[str]:
    return [args[i + 1] for i, a in enumerate(args) if a == flag and i + 1 < len(args)]


def _value(args: list[str], flag: str, default: str) -> str:
    found = _values(args, flag)
    return found[-1] if found else default


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    follows = _values(args, "--follow")
    indices = _values(args, "--elasticsearch-index")
    if not (follows or indices) or "-h" in args or "--help" in args:
        print(__doc__)
        return 2
    sources: list[LiveSource] = [FileFollower(Path(path)) for path in follows]
    if indices:
        elastic = elasticsearch_client_from_env(dict(os.environ))
        if elastic is None:
            print("ELASTIC_PASSWORD must be set to poll Elasticsearch.", file=sys.stderr)
            return 1
        time_field = _value(args, "--time-field", "event.ingested")
        sources += [ElasticsearchSource(elastic, index, time_field=time_field) for index in indices]
    name = _value(args, "--name", "live")
    interval = float(_value(args, "--interval", "60"))
    window_hours = int(_value(args, "--window-hours", "24"))
    directory = Path(_value(args, "--directory", str(LIVE_ROOT / name)))

    client = SharedMemoryClient()
    workbench = load_workbench()
    session = LiveSession(
        name=name,
        followers=sources,
        store=CaptureStore(directory, name),
        check=check_recording,
        run=investigation_runner(client, workbench, detection_memo=DetectionMemo()),
        summarise=lambda investigation_id: read_model_summary(client, investigation_id),
        window_hours=window_hours,
        release=client.release,
    )

    if "--serve" not in args:
        for _ in range(int(_value(args, "--cycles", "1"))):
            outcome = session.cycle()
            print(outcome.to_json())
        return 0

    port = int(_value(args, "--port", "8000"))
    server = create_server(
        client,
        host="127.0.0.1",
        port=port,
        context=serving_context(workbench),
        uploads=upload_service(client, workbench),
        live=session,
    )
    stop = threading.Event()
    threading.Thread(
        target=session.run_forever, args=(interval, stop), name="live-cycle", daemon=True
    ).start()
    print(
        f"Live '{name}': {len(follows)} file(s), {len(indices)} Elasticsearch pattern(s), "
        f"every {interval:g} s, window {window_hours} h"
    )
    print(f"Serving on http://127.0.0.1:{port}/  (status: /api/live; Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
