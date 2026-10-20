"""Investigate recordings from the command line, optionally serving the
results through the read-model API (ADR-0009) and the analyst frontend
(ADR-0016).

    python -m attribution_platform.investigation <recording> [<recording> ...]
        [--serve] [--port N] [--elasticsearch] [--json out.json] [--dossier out.md]
        [--emulation-report caldera-report.json] [--no-upload] [--no-assistant]

Each ``<recording>`` is either a recording id pinned in
``data/calibration/corpus/v2/recordings.json`` (e.g. ``otrf-apt3-empire``) or a
path to a recording archive (``.zip`` / ``.tar.gz`` of JSON lines, e.g. your own
lab export — ``docs/operations/lab-recording-guide.md``). A path that is not
pinned must first pass the intake check (``replay/recording_check.py``); its
SHA-256 and source declaration come from that check, never from guesses.

``--dossier`` writes the attribution dossier (``investigation/dossier.py``):
every unit explained in plain language from the persisted read model.

Results are kept in memory by default (a throwaway session); ``--elasticsearch``
persists them to the cluster configured by the same environment variables as
``python -m attribution_platform.api``. ``--serve`` then starts the read-model API
on 127.0.0.1 (``--port``, default 8000); when the frontend has been built
(``npm run build`` in ``frontend/``) the same address serves it. ``--dossier``
needs exactly one recording. With ``--serve`` the console can also take a recording by
upload (ADR-0020; this machine only, one investigation at a time, files kept in the
git-ignored ``data/cache/uploads``); ``--serve`` alone starts an empty console to upload
into, and ``--no-upload`` turns uploading off. The console's analyst
assistant (ADR-0022) asks a model served by Ollama on this machine (``ATTRIBUTION_ASSISTANT_MODEL``,
default ``llama3.1:8b``); nothing is sent off the machine, and ``--no-assistant`` turns it off.
``--emulation-report`` (one recording) is the
emulation tool's own report of a lab run (a MITRE CALDERA operation report): each step it lists is
compared with what was detected (ADR-0019); its command text is never read. Nothing here
ranks candidates or emits a confidence: analyses are uncalibrated until a
calibration_version exists.
"""

from __future__ import annotations

import json
import os
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from attribution_platform.api.__main__ import elasticsearch_client_from_env
from attribution_platform.api.assistant import service_from_env
from attribution_platform.api.context import ApiContext, build_technique_catalogue, load_api_context
from attribution_platform.api.kibana_export import export_investigation
from attribution_platform.api.server import create_server
from attribution_platform.api.uploads import RunResult, UploadService
from attribution_platform.attack_knowledge.loader import AttackKnowledge, load_attack_knowledge
from attribution_platform.attribution.collection_guidance import Detectability
from attribution_platform.dataplane import ElasticClient, FakeElasticClient, SharedMemoryClient
from attribution_platform.detection import (
    DetectionEngine,
    load_rule_pack,
    pack_set_content_hash,
)
from attribution_platform.detection_content.detectability import load_detectability
from attribution_platform.detection_content.pinned import (
    COVERAGE_REPORT,
    ELASTIC_IMPORT_REPORT,
    ELASTIC_PACK,
    FRONTEND_DIST,
    KNOWN_ANSWER_CHECKS,
    PLATFORM_PACK,
    SIGMA_ACTOR_IMPORT_REPORT,
    SIGMA_ACTOR_PACK,
    SIGMA_PACK,
    TECHNIQUE_GROUND_TRUTH,
    TECHNIQUE_SUPPORT_REVIEW,
    UNSEEN_FIRST_RUN,
    UNSEEN_RESULTS,
)
from attribution_platform.detection_content.pinned import SIGMA_IMPORT_REPORT as IMPORT_REPORT
from attribution_platform.detection_content.technique_support import (
    EMPTY_REVIEW,
    TechniqueSupportReview,
    load_technique_support_review,
)
from attribution_platform.intel.indicators import IndicatorSet, load_indicator_set
from attribution_platform.investigation.dossier import render_dossier
from attribution_platform.investigation.emulation import (
    EmulationReportError,
    load_caldera_report,
)
from attribution_platform.investigation.records import (
    InvestigationRecord,
    load_attribution_analysis,
)
from attribution_platform.investigation.run import run_investigation
from attribution_platform.replay.recording_check import check_recording
from attribution_platform.replay.recording_pipeline import (
    DetectionMemo,
    RecordingSource,
    load_recording_sources,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
RECORDINGS = REPO_ROOT / "data" / "calibration" / "corpus" / "v2" / "recordings.json"
ADVISORIES = REPO_ROOT / "data" / "intel" / "advisories"
ADVISORY_ATTRIBUTIONS = REPO_ROOT / "data" / "intel" / "advisory-attributions.json"


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


@dataclass(frozen=True)
class Workbench:
    """Everything pinned an investigation runs against, loaded once so several
    recordings in one session share it."""

    knowledge: AttackKnowledge
    engine: DetectionEngine
    detection_pack_content_hash: str
    detectability: Mapping[str, Detectability]
    indicators: IndicatorSet
    technique_support: TechniqueSupportReview = EMPTY_REVIEW


def load_workbench() -> Workbench:
    knowledge = load_attack_knowledge()
    packs = [load_rule_pack(path, knowledge=knowledge) for path in (SIGMA_PACK, ELASTIC_PACK)]
    # ADR-0018: actor-specific rules are detection content like the rest, but the
    # coverage report (and so detectability) is about techniques and covers the
    # two technique packs only.
    actor_pack = load_rule_pack(SIGMA_ACTOR_PACK, knowledge=knowledge)
    # ADR-0026: the few rules written here, for measured gaps no published rule covers.
    platform_pack = load_rule_pack(PLATFORM_PACK, knowledge=knowledge)
    engine_packs = [*packs, actor_pack, platform_pack]
    return Workbench(
        knowledge=knowledge,
        engine=DetectionEngine(rules=tuple(r for pack in engine_packs for r in pack.rules)),
        detection_pack_content_hash=pack_set_content_hash(engine_packs),
        detectability=load_detectability(
            COVERAGE_REPORT,
            (IMPORT_REPORT, ELASTIC_IMPORT_REPORT),
            pack_content_hash=[pack.content_hash for pack in packs],
        ),
        indicators=load_indicator_set(ADVISORIES, ADVISORY_ATTRIBUTIONS),
        technique_support=load_technique_support_review(TECHNIQUE_SUPPORT_REVIEW),
    )


def investigate(
    argument: str,
    *,
    client: ElasticClient,
    recordings: Path = RECORDINGS,
    workbench: Workbench | None = None,
    emulation_report: Path | None = None,
) -> Session:
    """Resolve, run and persist one investigation."""
    source = resolve_source(argument, recordings=recordings)
    bench = workbench if workbench is not None else load_workbench()
    record = run_investigation(
        source,
        client=client,
        engine=bench.engine,
        knowledge=bench.knowledge,
        detection_pack_content_hash=bench.detection_pack_content_hash,
        detectability=bench.detectability,
        indicators=bench.indicators,
        technique_support=bench.technique_support,
        emulation=load_caldera_report(emulation_report) if emulation_report else None,
    )
    return Session(record=record, client=client)


UPLOADS = REPO_ROOT / "data" / "cache" / "uploads"


def investigation_runner(
    client: ElasticClient, workbench: Workbench, *, detection_memo: DetectionMemo | None = None
) -> Callable[[RecordingSource], RunResult]:
    """Investigate one recording exactly as the command line does, for a
    serving session (uploads, ADR-0020; live cycles, ADR-0028). With the
    in-memory store, a run is prepared apart and published in one step, so a
    reader never sees half an investigation."""

    def run(source: RecordingSource) -> RunResult:
        shared = client if isinstance(client, SharedMemoryClient) else None
        target: ElasticClient = FakeElasticClient() if shared is not None else client
        record = run_investigation(
            source,
            client=target,
            engine=workbench.engine,
            knowledge=workbench.knowledge,
            detection_pack_content_hash=workbench.detection_pack_content_hash,
            detectability=workbench.detectability,
            indicators=workbench.indicators,
            technique_support=workbench.technique_support,
            detection_memo=detection_memo,
        )
        if shared is not None and isinstance(target, FakeElasticClient):
            shared.absorb(target, owner=record.investigation_id)
        return RunResult(
            investigation_id=record.investigation_id,
            evidence=record.evidence,
            units=len(record.units),
        )

    return run


def serving_context(workbench: Workbench) -> ApiContext:
    """The reference context a serving session hands the API (ADR-0016)."""
    return load_api_context(
        workbench.knowledge,
        coverage_report=COVERAGE_REPORT,
        sigma_import_report=IMPORT_REPORT,
        elastic_import_report=ELASTIC_IMPORT_REPORT,
        static_dir=FRONTEND_DIST,
        known_answer_checks=KNOWN_ANSWER_CHECKS,
        actor_import_report=SIGMA_ACTOR_IMPORT_REPORT,
        advisory_attributions=ADVISORY_ATTRIBUTIONS,
        platform_pack=PLATFORM_PACK,
        technique_support_review=TECHNIQUE_SUPPORT_REVIEW,
        measurements={
            "technique_ground_truth": TECHNIQUE_GROUND_TRUTH,
            "unseen": UNSEEN_RESULTS,
            "unseen_first_run": UNSEEN_FIRST_RUN,
        },
    )


def upload_service(
    client: ElasticClient, workbench: Workbench, *, directory: Path = UPLOADS
) -> UploadService:
    """The upload service of a serving session (ADR-0020): the same intake
    check and the same investigation as the command line."""
    return UploadService(
        directory=directory, check=check_recording, run=investigation_runner(client, workbench)
    )


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
        client = SharedMemoryClient()

    arguments = []
    for argument in args:
        if argument.startswith("--"):
            break
        arguments.append(argument)
    if "--dossier" in args and len(arguments) != 1:
        print("--dossier needs exactly one recording.", file=sys.stderr)
        return 2

    emulation_report: Path | None = None
    if "--emulation-report" in args:
        if len(arguments) != 1:
            print("--emulation-report needs exactly one recording.", file=sys.stderr)
            return 2
        emulation_report = Path(args[args.index("--emulation-report") + 1])
        if not emulation_report.is_file():
            print(f"refused: no emulation report at {emulation_report}", file=sys.stderr)
            return 1

    reports: list[dict[str, object]] = []
    try:
        workbench = load_workbench()
        for argument in arguments:
            session = investigate(
                argument, client=client, workbench=workbench, emulation_report=emulation_report
            )
            report = summary(session)
            reports.append(report)
            print(f"investigation {report['investigation_id']}")
            print(f"source        {report['source_id']}  sha256 {report['source_sha256']}")
            print(f"evidence      {report['evidence']}  ATT&CK {report['attack_kb_version']}")
            for unit in report["units"]:  # type: ignore[attr-defined]
                print(
                    f"  unit {unit['group_id'][:48]}…  techniques "
                    f"{unit['observed_techniques']:>3}  candidates {unit['candidates']:>4}  "
                    f"{unit['calibration_status']}"
                )
    except (CliError, EmulationReportError) as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 1

    if "--elasticsearch" in args:
        # ADR-0024: the same results as flat documents for the Kibana dashboard.
        charts = ApiContext(
            knowledge=workbench.knowledge,
            techniques=build_technique_catalogue(workbench.knowledge),
        )
        for report in reports:
            counts = export_investigation(client, charts, str(report["investigation_id"]))
            print(
                f"kibana        {counts['detections']} detections, "
                f"{counts['group_matches']} group matches exported"
            )

    if "--json" in args:
        out = Path(args[args.index("--json") + 1])
        payload: object = reports[0] if len(reports) == 1 else {"investigations": reports}
        out.write_text(json.dumps(payload, indent=1) + "\n", encoding="utf-8", newline="\n")

    if "--dossier" in args:
        out = Path(args[args.index("--dossier") + 1])
        investigation_id = str(reports[0]["investigation_id"])
        text = render_dossier(client, workbench.knowledge, investigation_id)
        out.write_text(text, encoding="utf-8", newline="\n")
        print(f"dossier       {out}")

    if "--serve" in args:
        port = int(args[args.index("--port") + 1]) if "--port" in args else 8000
        context = serving_context(workbench)
        uploads = None if "--no-upload" in args else upload_service(client, workbench)
        assistant = None if "--no-assistant" in args else service_from_env(env)
        server = create_server(
            client,
            host="127.0.0.1",
            port=port,
            context=context,
            uploads=uploads,
            assistant=assistant,
        )
        print(f"Serving the read-model API on http://127.0.0.1:{port}/api  (Ctrl+C to stop)")
        if context.static_dir is not None:
            print(f"Analyst frontend: http://127.0.0.1:{port}/")
        else:
            print("Frontend not built (run `npm run build` in frontend/, or `npm run dev`).")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
