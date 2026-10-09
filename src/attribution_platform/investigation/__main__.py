"""Investigate one recording from the command line, optionally serving the
results through the read-model API (ADR-0009).

    python -m attribution_platform.investigation <recording> [--serve] [--port N]
        [--elasticsearch] [--json out.json]

``<recording>`` is either a recording id pinned in
``data/calibration/corpus/v2/recordings.json`` (e.g. ``otrf-apt3-empire``) or a
path to a recording archive (``.zip`` / ``.tar.gz`` of JSON lines, e.g. your own
lab export — ``docs/operations/lab-recording-guide.md``). A path that is not
pinned must first pass the intake check (``replay/recording_check.py``); its
SHA-256 and source declaration come from that check, never from guesses.

Results are kept in memory by default (a throwaway session); ``--elasticsearch``
persists them to the cluster configured by the same environment variables as
``python -m attribution_platform.api``. ``--serve`` then starts the read-model API
on 127.0.0.1 (``--port``, default 8000). Nothing here ranks candidates or
emits a confidence: analyses are uncalibrated until a calibration_version exists.
"""

from __future__ import annotations

import json
import os
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from attribution_platform.api.__main__ import elasticsearch_client_from_env
from attribution_platform.api.server import create_server
from attribution_platform.attack_knowledge.loader import load_attack_knowledge
from attribution_platform.dataplane import ElasticClient, FakeElasticClient
from attribution_platform.detection import DetectionEngine, load_rule_pack
from attribution_platform.detection_content.detectability import load_detectability
from attribution_platform.investigation.records import (
    InvestigationRecord,
    load_attribution_analysis,
)
from attribution_platform.investigation.run import run_investigation
from attribution_platform.replay.recording_check import check_recording
from attribution_platform.replay.recording_pipeline import (
    RecordingSource,
    load_recording_sources,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
RECORDINGS = REPO_ROOT / "data" / "calibration" / "corpus" / "v2" / "recordings.json"
SIGMA_PACK = (
    REPO_ROOT
    / "data"
    / "detection"
    / "sigma"
    / "r2026-07-01"
    / "generated"
    / "sigma-r2026-07-01-sigma_core++.rules.json"
)


COVERAGE_REPORT = SIGMA_PACK.with_name("coverage-report.json")
IMPORT_REPORT = SIGMA_PACK.with_name("sigma-r2026-07-01-sigma_core++.import-report.json")


class CliError(Exception):
    """A refusal the CLI reports and exits non-zero on."""


@dataclass(frozen=True)
class Session:
    record: InvestigationRecord
    client: ElasticClient


def resolve_source(argument: str, *, recordings: Path = RECORDINGS) -> RecordingSource:
    """A pinned recording id, or a checked archive path."""
    pinned = load_recording_sources(recordings, REPO_ROOT) if recordings.is_file() else {}
    if argument in pinned:
        return pinned[argument]
    path = Path(argument)
    if not path.is_file():
        raise CliError(f"{argument!r} is neither a pinned recording id nor an existing file")
    report = check_recording(path)
    if not report.accepted:
        raise CliError("the recording failed its intake check: " + "; ".join(report.problems))
    return RecordingSource(
        recording_id=path.name,
        path=path,
        sha256=report.sha256,
        declared_sources=report.declared_sources,
    )


def investigate(argument: str, *, client: ElasticClient, recordings: Path = RECORDINGS) -> Session:
    """Resolve, run and persist one investigation."""
    source = resolve_source(argument, recordings=recordings)
    knowledge = load_attack_knowledge()
    pack = load_rule_pack(SIGMA_PACK, knowledge=knowledge)
    record = run_investigation(
        source,
        client=client,
        engine=DetectionEngine(rules=pack.rules),
        knowledge=knowledge,
        detection_pack_content_hash=pack.content_hash,
        detectability=load_detectability(
            COVERAGE_REPORT, IMPORT_REPORT, pack_content_hash=pack.content_hash
        ),
    )
    return Session(record=record, client=client)


def summary(session: Session) -> dict[str, object]:
    """Per-unit facts only — no ranking, no confidence."""
    units = []
    for group_id in session.record.units:
        analysis = load_attribution_analysis(session.client, group_id) or {}
        units.append(
            {
                "group_id": group_id,
                "observed_techniques": len(analysis.get("observed_feature_technique_ids", ())),
                "candidates": len(analysis.get("candidates", ())),
                "calibration_status": analysis.get("calibration_status"),
            }
        )
    return {
        "investigation_id": session.record.investigation_id,
        "source_id": session.record.source_id,
        "source_sha256": session.record.source_sha256,
        "attack_kb_version": session.record.attack_kb_version,
        "evidence": session.record.evidence,
        "units": units,
    }


def main(argv: Sequence[str] | None = None, env: dict[str, str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    env = dict(os.environ) if env is None else env
    if not args or args[0] in ("-h", "--help"):
        print(__doc__)
        return 2
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    client: ElasticClient
    if "--elasticsearch" in args:
        configured = elasticsearch_client_from_env(env)
        if configured is None:
            print("ELASTIC_PASSWORD must be set for --elasticsearch.", file=sys.stderr)
            return 1
        client = configured
    else:
        client = FakeElasticClient()

    try:
        session = investigate(args[0], client=client)
    except CliError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 1

    report = summary(session)
    print(f"investigation {report['investigation_id']}")
    print(f"source        {report['source_id']}  sha256 {report['source_sha256']}")
    print(f"evidence      {report['evidence']}  ATT&CK {report['attack_kb_version']}")
    for unit in report["units"]:  # type: ignore[attr-defined]
        print(
            f"  unit {unit['group_id'][:48]}…  techniques {unit['observed_techniques']:>3}  "
            f"candidates {unit['candidates']:>4}  {unit['calibration_status']}"
        )
    if "--json" in args:
        out = Path(args[args.index("--json") + 1])
        out.write_text(json.dumps(report, indent=1) + "\n", encoding="utf-8", newline="\n")

    if "--serve" in args:
        port = int(args[args.index("--port") + 1]) if "--port" in args else 8000
        server = create_server(session.client, host="127.0.0.1", port=port)
        print(f"Serving the read-model API on http://127.0.0.1:{port}  (Ctrl+C to stop)")
        print(f"  http://127.0.0.1:{port}/investigations/{report['investigation_id']}")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
