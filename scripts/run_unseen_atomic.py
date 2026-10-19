#!/usr/bin/env python3
"""Investigate every pre-registered unseen recording once, unchanged, and serve
the results (ADR-0027 protocol step 3).

Each recording goes through the same intake check and investigation as the
command line and the upload route, one at a time in one process. A recording
the intake refuses, or whose investigation fails, is recorded with its reason
in ``data/validation/unseen-otrf-atomic/run.json`` and the others continue.
Then the read-model API is served for ``measure_unseen_atomic.py``.

    python scripts/run_unseen_atomic.py --port 8004
"""

from __future__ import annotations

import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path, PurePath

from attribution_platform.api.server import create_server
from attribution_platform.dataplane import SharedMemoryClient
from attribution_platform.investigation.__main__ import (
    investigation_runner,
    load_workbench,
    serving_context,
)
from attribution_platform.replay.recording_check import check_recording
from attribution_platform.replay.recording_pipeline import RecordingSource

REPO = Path(__file__).resolve().parents[1]
MANIFEST = REPO / "data" / "telemetry-samples" / "otrf-atomic-unseen" / "manifest.json"
OUT = REPO / "data" / "validation" / "unseen-otrf-atomic" / "run.json"


def main(argv: list[str]) -> int:
    port = int(argv[argv.index("--port") + 1]) if "--port" in argv else 8004
    commit = subprocess.run(
        ["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=True, cwd=REPO
    ).stdout.strip()
    dirty = subprocess.run(
        ["git", "status", "--porcelain", "--untracked-files=no"],
        capture_output=True,
        text=True,
        check=True,
        cwd=REPO,
    ).stdout.strip()
    client = SharedMemoryClient()
    workbench = load_workbench()
    run = investigation_runner(client, workbench)
    outcomes = []
    for entry in json.loads(MANIFEST.read_text(encoding="utf-8"))["files"]:
        path = REPO / entry["cache_path"]
        name = PurePath(entry["source_path"]).name
        outcome: dict[str, object] = {"recording": name}
        try:
            report = check_recording(path)
            if not report.accepted:
                outcome.update(state="refused by intake", problems=list(report.problems))
            else:
                result = run(RecordingSource(name, path, report.sha256, report.declared_sources))
                outcome.update(
                    state="investigated",
                    investigation_id=result.investigation_id,
                    evidence=result.evidence,
                    units=result.units,
                )
        except Exception as exc:  # noqa: BLE001 - recorded as the result, the run goes on
            outcome.update(state="failed", problems=[f"{type(exc).__name__}: {exc}"[:500]])
        outcomes.append(outcome)
        print(f"{outcome['state']:<18} {name}", flush=True)
    OUT.write_text(
        json.dumps(
            {
                "version": "unseen-run/1",
                "build_commit": commit,
                "working_tree_clean": not dirty,
                "run_at_utc": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "recordings": outcomes,
            },
            indent=1,
        )
        + "\n",
        encoding="utf-8",
        newline="\n",
    )
    server = create_server(client, host="127.0.0.1", port=port, context=serving_context(workbench))
    print(f"Serving on http://127.0.0.1:{port}/api", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
