"""ADR-0016: the reads the analyst frontend adds to the read-model API.

Reference routes (``/attack/techniques``, ``/coverage``) repeat pinned artefacts;
``/units/<id>/evidence`` and ``/investigations/<id>/dossier`` join stored records.
Every route also answers under ``/api``; a built frontend is served as files
only, never outside its directory. Nothing here adds a decision field.
"""

from __future__ import annotations

import hashlib
import json
import threading
import urllib.error
import urllib.request
import zipfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from attribution_platform.api import create_server
from attribution_platform.api.context import ApiContext, load_api_context, rule_key
from attribution_platform.api.server import static_file
from attribution_platform.attack_knowledge.loader import AttackKnowledge, load_attack_knowledge
from attribution_platform.attack_knowledge.traversal import active_groups, groups_using_technique
from attribution_platform.dataplane import FakeElasticClient
from attribution_platform.detection import DetectionEngine, load_rule_pack
from attribution_platform.detection_content.pinned import (
    COVERAGE_REPORT,
    ELASTIC_IMPORT_REPORT,
    SIGMA_IMPORT_REPORT,
    SIGMA_PACK,
)
from attribution_platform.investigation import run_investigation
from attribution_platform.investigation.dossier import DOSSIER_VERSION, render_dossier
from attribution_platform.replay.recording_pipeline import RecordingSource

HOST = "WS01.example.local"
FORBIDDEN_KEYS = ("likelihood", "confidence", "wep", "verdict", "rank", "probability")


def _process_create(record_id: int, guid: str, parent: str, image: str, cmd: str) -> dict[str, Any]:
    return {
        "@timestamp": f"2026-01-01T12:00:{record_id:02d}.000Z",
        "winlog": {
            "channel": "Microsoft-Windows-Sysmon/Operational",
            "event_id": 1,
            "record_id": record_id,
            "computer_name": HOST,
            "event_data": {
                "UtcTime": f"2026-01-01 12:00:{record_id:02d}.000",
                "ProcessGuid": guid,
                "ProcessId": str(1000 + record_id),
                "Image": image,
                "CommandLine": cmd,
                "ParentProcessGuid": parent,
            },
        },
    }


@pytest.fixture(scope="module")
def knowledge() -> AttackKnowledge:
    return load_attack_knowledge()


@pytest.fixture(scope="module")
def static_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    root = tmp_path_factory.mktemp("dist")
    (root / "index.html").write_text("<!doctype html><title>t</title>", encoding="utf-8")
    (root / "assets").mkdir()
    (root / "assets" / "app-abc.js").write_text("export {};", encoding="utf-8")
    (root.parent / "secret.txt").write_text("outside", encoding="utf-8")
    return root


@pytest.fixture(scope="module")
def context(knowledge: AttackKnowledge, static_dir: Path) -> ApiContext:
    return load_api_context(
        knowledge,
        coverage_report=COVERAGE_REPORT,
        sigma_import_report=SIGMA_IMPORT_REPORT,
        elastic_import_report=ELASTIC_IMPORT_REPORT,
        static_dir=static_dir,
    )


@pytest.fixture(scope="module")
def served(
    knowledge: AttackKnowledge,
    context: ApiContext,
    tmp_path_factory: pytest.TempPathFactory,
) -> Iterator[tuple[str, FakeElasticClient, str, tuple[str, ...]]]:
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    whoami = "C:\\Windows\\System32\\whoami.exe"
    records = [
        _process_create(
            1, "{P}", "{ROOT}", powershell, "powershell.exe -nop -w hidden -enc SQBFAFgA"
        ),
        _process_create(2, "{A}", "{P}", whoami, "whoami /all -all"),
    ]
    path = tmp_path_factory.mktemp("rec") / "rec.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("rec.json", "\n".join(json.dumps(r) for r in records) + "\n")
    pack = load_rule_pack(SIGMA_PACK, knowledge=knowledge)
    client = FakeElasticClient()
    record = run_investigation(
        RecordingSource(
            recording_id="rec-frontend-test",
            path=path,
            sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
            declared_sources={HOST: ("sysmon",)},
        ),
        client=client,
        engine=DetectionEngine(rules=pack.rules),
        knowledge=knowledge,
        detection_pack_content_hash=pack.content_hash,
    )
    server = create_server(client, context=context)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address[:2]
    try:
        yield f"http://{host!s}:{port}", client, record.investigation_id, record.units
    finally:
        server.shutdown()
        server.server_close()


def _get(url: str) -> tuple[int, str, Any]:
    try:
        with urllib.request.urlopen(url, timeout=10) as response:  # noqa: S310 - localhost
            body = response.read()
            content_type = str(response.headers.get("Content-Type"))
            status = int(response.status)
    except urllib.error.HTTPError as exc:
        body, content_type, status = exc.read(), str(exc.headers.get("Content-Type")), exc.code
    if content_type.startswith("application/json"):
        return status, content_type, json.loads(body)
    return status, content_type, body.decode("utf-8")


def _keys(value: Any) -> Iterator[str]:
    if isinstance(value, dict):
        for key, inner in value.items():
            yield str(key).lower()
            yield from _keys(inner)
    elif isinstance(value, list):
        for inner in value:
            yield from _keys(inner)


# ===========================================================================
# Reference data
# ===========================================================================


def test_technique_catalogue_repeats_the_knowledge_base(
    context: ApiContext, knowledge: AttackKnowledge
) -> None:
    catalogue = dict(context.techniques or {})
    assert catalogue["attack_kb_version"] == knowledge.attack_kb_version
    assert catalogue["active_groups"] == len(active_groups(knowledge))
    techniques = catalogue["techniques"]
    ids = [t["attack_id"] for t in techniques]
    assert ids == sorted(ids) and len(ids) == len(set(ids))
    coverage = json.loads(COVERAGE_REPORT.read_text(encoding="utf-8"))
    assert len(ids) == coverage["summary"]["active_techniques"]
    shortnames = [t["shortname"] for t in catalogue["tactics"]]
    assert len(shortnames) == len(set(shortnames)) and "credential-access" in shortnames
    lsass = next(t for t in techniques if t["attack_id"] == "T1003.001")
    assert lsass["name"] == "LSASS Memory" and lsass["is_subtechnique"] is True
    assert lsass["tactics"] == ["credential-access"]
    assert lsass["groups_using"] == len(groups_using_technique(knowledge, lsass["stix_id"]))
    for technique in techniques:
        assert set(technique["tactics"]) <= set(shortnames)


def test_coverage_view_is_the_committed_report(context: ApiContext) -> None:
    view = dict(context.coverage or {})
    report = json.loads(COVERAGE_REPORT.read_text(encoding="utf-8"))
    assert view["summary"] == report["summary"]
    assert view["techniques"] == report["techniques"]
    assert view["gap_ranking"] == report["gap_ranking"]
    assert len(view["groups"]) == report["summary"]["active_groups"]
    assert all("uncovered" not in group for group in view["groups"])
    sigma = json.loads(SIGMA_IMPORT_REPORT.read_text(encoding="utf-8"))
    elastic = json.loads(ELASTIC_IMPORT_REPORT.read_text(encoding="utf-8"))
    assert view["content"]["sigma"]["summary"] == sigma["summary"]
    assert view["content"]["elastic"]["summary"] == elastic["summary"]
    # Rule counts per logsource are sums over the import reports' own rows.
    offered = {
        origin: sum(1 for r in rows["rules"] if r["status"] != "rejected")
        for origin, rows in (("sigma", sigma), ("elastic", elastic))
    }
    assert sum(row["sigma_rules"] for row in view["logsources"]) == offered["sigma"]
    assert sum(row["elastic_rules"] for row in view["logsources"]) >= offered["elastic"]
    # "gap_ranking" orders telemetry blockers by reach; nothing ranks an actor.
    keys = set(_keys(view)) - {"gap_ranking"}
    assert not [k for k in keys if any(f in k for f in FORBIDDEN_KEYS)]


def test_rule_key_names_the_upstream_rule() -> None:
    assert rule_key("sigma:0022869c-49f7-4ff2-ba03-85ac42ddac58:000") == (
        "sigma:0022869c-49f7-4ff2-ba03-85ac42ddac58"
    )
    assert rule_key("elastic:000047bb-b27a-47ec-8b62-ef1a5d2c9e19:okta:000") == (
        "elastic:000047bb-b27a-47ec-8b62-ef1a5d2c9e19"
    )


# ===========================================================================
# Routes
# ===========================================================================


def test_every_route_also_answers_under_api(
    served: tuple[str, FakeElasticClient, str, tuple[str, ...]],
) -> None:
    base, _, investigation_id, units = served
    for route in (
        "/health",
        "/investigations",
        f"/investigations/{investigation_id}",
        f"/investigations/{investigation_id}/units",
        f"/units/{units[0]}",
        "/coverage",
        "/attack/techniques",
    ):
        plain, prefixed = _get(base + route), _get(base + "/api" + route)
        assert plain[0] == prefixed[0] == 200, route
        assert plain[2] == prefixed[2], route
    assert _get(base + "/api/nope")[0] == 404
    assert _get(base + "/api/coverage?x=1")[0] == 400


def test_unit_evidence_joins_evidence_observations_and_rules(
    served: tuple[str, FakeElasticClient, str, tuple[str, ...]],
) -> None:
    base, _, _, units = served
    status, _, body = _get(f"{base}/api/units/{units[0]}/evidence")
    assert status == 200 and body["group_id"] == units[0]
    _, _, unit = _get(f"{base}/api/units/{units[0]}")
    assert sorted(e["evidence_id"] for e in body["evidence"]) == sorted(
        unit["group"]["member_evidence_ids"]
    )
    assert sorted(body["observations"]) == sorted(unit["group"]["member_observation_ids"])
    starts = [(e["time_span"] or {}).get("start", "") for e in body["evidence"]]
    assert starts == sorted(starts)
    for evidence in body["evidence"]:
        for observation_id in evidence["provenance"]["source_observation_ids"]:
            assert observation_id in body["observations"]
        rule = body["rules"][rule_key(evidence["provenance"]["method"])]
        assert rule["origin"] == "sigma" and rule["url"].startswith("https://github.com/SigmaHQ/")
        assert rule["title"] and rule["content_tier"] in {"core", "enrich"}
    assert not [k for k in _keys(body) if any(f in k for f in FORBIDDEN_KEYS)]
    assert _get(f"{base}/api/units/no-such-unit/evidence")[0] == 404


def test_dossier_route_returns_the_rendered_dossier(
    served: tuple[str, FakeElasticClient, str, tuple[str, ...]], knowledge: AttackKnowledge
) -> None:
    base, client, investigation_id, _ = served
    status, _, body = _get(f"{base}/api/investigations/{investigation_id}/dossier")
    assert status == 200
    assert body == {
        "investigation_id": investigation_id,
        "dossier_version": DOSSIER_VERSION,
        "markdown": render_dossier(client, knowledge, investigation_id),
    }
    assert _get(f"{base}/api/investigations/absent/dossier")[0] == 404


def test_reference_routes_need_a_context() -> None:
    server = create_server(FakeElasticClient())
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address[:2]
    try:
        base = f"http://{host!s}:{port}"
        for route in ("/coverage", "/attack/techniques", "/api/coverage"):
            status, _, body = _get(base + route)
            assert status == 404 and "not available" in body["error"]
        assert _get(base + "/")[0] == 404  # no frontend without a context
    finally:
        server.shutdown()
        server.server_close()


# ===========================================================================
# The built frontend
# ===========================================================================


def test_built_frontend_is_served_beside_the_api(
    served: tuple[str, FakeElasticClient, str, tuple[str, ...]],
) -> None:
    base = served[0]
    status, content_type, body = _get(base + "/")
    assert status == 200 and content_type.startswith("text/html") and "<title>t</title>" in body
    assert _get(base + "/index.html")[2] == body
    status, content_type, _ = _get(base + "/assets/app-abc.js")
    assert status == 200 and content_type.startswith("text/javascript")
    assert _get(base + "/assets/missing.js")[0] == 404
    # The JSON routes are untouched by the frontend.
    assert _get(base + "/investigations")[1].startswith("application/json")


@pytest.mark.parametrize(
    "path",
    [
        "/assets/../../secret.txt",
        "/assets/%2e%2e/%2e%2e/secret.txt",
        "/assets/..%5c..%5csecret.txt",
        "/secret.txt",
        "/assets/",
    ],
)
def test_static_paths_never_leave_the_directory(static_dir: Path, path: str) -> None:
    assert static_file(static_dir, path) is None


def test_unbuilt_frontend_is_not_served(knowledge: AttackKnowledge, tmp_path: Path) -> None:
    context = load_api_context(
        knowledge,
        coverage_report=COVERAGE_REPORT,
        sigma_import_report=SIGMA_IMPORT_REPORT,
        elastic_import_report=ELASTIC_IMPORT_REPORT,
        static_dir=tmp_path,
    )
    assert context.static_dir is None


# ===========================================================================
# ADR-0009 Amendment D: a unit beyond the exact search's work bound
# ===========================================================================


def test_unit_beyond_the_search_bound_is_recorded_not_fatal(
    knowledge: AttackKnowledge,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The exact combination search stops at its work bound. That must cost one
    unit its per-candidate quantities — said in words — never the investigation,
    and never an approximation in their place."""
    from attribution_platform.attribution import comparative_analysis
    from attribution_platform.investigation import load_attribution_analysis

    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    whoami = "C:\\Windows\\System32\\whoami.exe"
    records = [
        _process_create(
            1, "{P}", "{ROOT}", powershell, "powershell.exe -nop -w hidden -enc SQBFAFgA"
        ),
        _process_create(2, "{A}", "{P}", whoami, "whoami /all -all"),
    ]
    path = tmp_path / "rec.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("rec.json", "\n".join(json.dumps(r) for r in records) + "\n")
    source = RecordingSource(
        recording_id="rec-bound-test",
        path=path,
        sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        declared_sources={HOST: ("sysmon",)},
    )
    pack = load_rule_pack(SIGMA_PACK, knowledge=knowledge)

    def run() -> tuple[FakeElasticClient, Any]:
        client = FakeElasticClient()
        record = run_investigation(
            source,
            client=client,
            engine=DetectionEngine(rules=pack.rules),
            knowledge=knowledge,
            detection_pack_content_hash=pack.content_hash,
        )
        return client, record

    client, record = run()
    computed = [dict(load_attribution_analysis(client, g) or {}) for g in record.units]
    assert all(a["comparison_status"] == "computed" for a in computed)
    assert all(a["comparison_note"] is None for a in computed)
    multi = [a for a in computed if len(a["observed_feature_technique_ids"]) >= 2]
    assert multi, "the fixture needs a unit with two decision features"

    monkeypatch.setattr(comparative_analysis, "_MAX_SEARCH_STEPS", 0)
    client, bounded = run()
    assert bounded.units == record.units  # the investigation still completes
    by_group = {a["group_id"]: a for a in computed}
    stopped = 0
    for group_id in bounded.units:
        analysis = dict(load_attribution_analysis(client, group_id) or {})
        before = by_group[group_id]
        assert analysis["candidates"] == before["candidates"]
        assert analysis["collection_guidance"] == before["collection_guidance"]
        if len(analysis["observed_feature_technique_ids"]) < 2:
            assert analysis["comparison_status"] == "computed"
            continue
        stopped += 1
        assert analysis["comparison_status"] == "not_computed"
        assert "work bound" in analysis["comparison_note"]
        assert analysis["hypotheses"] == []
        assert analysis["unattributed_decision_support"] is None
    assert stopped == len(multi)
    dossier = render_dossier(client, knowledge, bounded.investigation_id)
    assert "was not computed for this unit" in dossier


def test_investigation_says_how_much_evidence_is_in_units(
    served: tuple[str, FakeElasticClient, str, tuple[str, ...]],
) -> None:
    """Low-level Evidence with no structural link to core Evidence is in no unit
    (ADR-0003 Amendment H). The record states both numbers, so a reader is never
    told that all Evidence is "in" the units."""
    base, _, investigation_id, units = served
    _, _, record = _get(f"{base}/api/investigations/{investigation_id}")
    in_units = 0
    for group_id in units:
        _, _, joined = _get(f"{base}/api/units/{group_id}/evidence")
        in_units += len(joined["evidence"])
    assert record["evidence_in_units"] == in_units
    assert record["evidence_in_units"] + record["evidence_outside_units"] == record["evidence"]
    _, _, listed = _get(f"{base}/api/investigations")
    assert listed[0]["evidence_in_units"] == in_units
    _, _, dossier = _get(f"{base}/api/investigations/{investigation_id}/dossier")
    assert (
        f"{record['evidence']} Evidence item(s): {in_units} in {len(units)} unit(s)"
        in (dossier["markdown"])
    )


def test_baseline_beyond_the_bound_keeps_the_per_candidate_comparison(
    knowledge: AttackKnowledge,
    served: tuple[str, FakeElasticClient, str, tuple[str, ...]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The baseline is one search over every observed feature at once — the larger
    problem. When only it stops, the per-candidate quantities are kept."""
    from attribution_platform.attribution.errors import SearchBoundExceededError
    from attribution_platform.dataplane import load_behavioral_sequence, load_correlation_group
    from attribution_platform.investigation import load_attribution_analysis, run

    _, client, investigation_id, units = served

    def stop(*_args: object, **_kwargs: object) -> None:
        raise SearchBoundExceededError("search: more than 0 search steps — exceeds the work bound")

    monkeypatch.setattr(run, "compute_unattributed_decision_support", stop)
    for group_id in units:
        stored = dict(load_attribution_analysis(client, group_id) or {})
        group = load_correlation_group(client, group_id)
        sequence = load_behavioral_sequence(client, stored["sequence_id"])
        assert group is not None and sequence is not None
        record = run.analyze_unit(
            group, sequence, investigation_id=investigation_id, knowledge=knowledge
        )
        assert record.comparison_status.value == "baseline_not_computed"
        assert record.unattributed_decision_support is None
        assert "baseline was not computed" in (record.comparison_note or "")
        # the per-candidate comparison is exactly what a complete run stored
        assert [h.hypothesis_id for h in record.hypotheses] == [
            h["hypothesis_id"] for h in stored["hypotheses"]
        ]
        assert [h.support_value for h in record.hypotheses] == [
            h["support_value"] for h in stored["hypotheses"]
        ]


def test_assessment_route_serves_the_stored_verdict(
    served: tuple[str, FakeElasticClient, str, tuple[str, ...]], knowledge: AttackKnowledge
) -> None:
    """ADR-0017: the run stores the investigation's assessment; the API serves it
    unchanged and the dossier quotes its statement."""
    from attribution_platform.investigation import load_attribution_analysis
    from attribution_platform.investigation.assessment import (
        assess_investigation,
        assessment_to_json,
    )

    base, client, investigation_id, units = served
    status, _, body = _get(f"{base}/api/investigations/{investigation_id}/assessment")
    assert status == 200 and body["investigation_id"] == investigation_id
    assert body["verdict"] in {"no_decision_features", "not_distinguishable", "third_party_lead"}
    analyses = [dict(load_attribution_analysis(client, g) or {}) for g in sorted(units)]
    assert body == json.loads(
        json.dumps(assessment_to_json(assess_investigation(knowledge, investigation_id, analyses)))
    )
    assert body["units_total"] == len(units)
    names = [c["name"].lower() for c in body["candidates"]]
    assert names == sorted(names)
    _, _, dossier = _get(f"{base}/api/investigations/{investigation_id}/dossier")
    assert "## Attribution assessment" in dossier["markdown"]
    assert body["statement"] in dossier["markdown"]
    assert _get(f"{base}/api/investigations/absent/assessment")[0] == 404


def test_known_answer_checks_are_served_and_internally_consistent(
    knowledge: AttackKnowledge,
) -> None:
    """ADR-0017 D5: the tracked known-answer checks are what ``/validation`` serves,
    and their summary is a count of their own cases."""
    from attribution_platform.api.read_model import get_validation
    from attribution_platform.detection_content.pinned import KNOWN_ANSWER_CHECKS

    context = load_api_context(
        knowledge,
        coverage_report=COVERAGE_REPORT,
        sigma_import_report=SIGMA_IMPORT_REPORT,
        elastic_import_report=ELASTIC_IMPORT_REPORT,
        known_answer_checks=KNOWN_ANSWER_CHECKS,
    )
    body = dict(get_validation(context))
    assert body == json.loads(KNOWN_ANSWER_CHECKS.read_text(encoding="utf-8"))
    cases, summary = body["cases"], body["summary"]
    emulations = [c for c in cases if c["kind"] == "emulation"]
    tool_tests = [c for c in cases if c["kind"] == "tool_test"]
    assert (summary["cases"], summary["emulations"], summary["tool_tests"]) == (
        len(cases),
        len(emulations),
        len(tool_tests),
    )
    positions = [
        o["known_actor_position"]
        for c in emulations
        for o in c["orderings"]
        if o["known_actor_position"] is not None
    ]
    assert summary["orderings_measured"] == len(positions)
    assert summary["orderings_naming_the_known_actor_first"] == positions.count(1)
    assert summary["best_position_of_a_known_actor"] == min(positions)
    assert summary["worst_position_of_a_known_actor"] == max(positions)
    for case in cases:
        assert (case["known_actor"] is None) == (case["kind"] == "tool_test")
        named = case["named_actors"]
        if case["verdict"] == "actor_specific_evidence":
            # ADR-0018: a verdict may name a Group, and on a known-answer case
            # the only acceptable name is the known one
            assert case["known_actor"] is not None
            assert named == [case["known_actor"]["attack_id"]]
            assert case["known_actor"]["name"] in case["statement"]
            assert "lead to verify" in case["statement"]
        else:
            assert not named
            assert case["known_actor"] is None or (
                case["known_actor"]["name"] not in case["statement"]
            )
    assert summary["verdicts_naming_a_wrong_actor"] == 0
    assert summary["verdicts_naming_an_actor"] == sum(1 for c in cases if c["named_actors"])
    # no tool test (no actor) is given a name
    assert not [c for c in tool_tests if c["named_actors"]]
    # without the file the route says so
    bare = load_api_context(
        knowledge,
        coverage_report=COVERAGE_REPORT,
        sigma_import_report=SIGMA_IMPORT_REPORT,
        elastic_import_report=ELASTIC_IMPORT_REPORT,
    )
    with pytest.raises(Exception, match="not available"):
        get_validation(bare)


def test_actor_specific_content_is_described_and_labels_its_evidence(
    knowledge: AttackKnowledge,
) -> None:
    """ADR-0018 D5: `/coverage` lists every reviewed actor rule with its decision
    and reason; an actor rule's Evidence is labelled with the reason it counts."""
    from attribution_platform.api.context import rule_key
    from attribution_platform.detection_content.pinned import SIGMA_ACTOR_IMPORT_REPORT

    context = load_api_context(
        knowledge,
        coverage_report=COVERAGE_REPORT,
        sigma_import_report=SIGMA_IMPORT_REPORT,
        elastic_import_report=ELASTIC_IMPORT_REPORT,
        actor_import_report=SIGMA_ACTOR_IMPORT_REPORT,
    )
    report = json.loads(SIGMA_ACTOR_IMPORT_REPORT.read_text(encoding="utf-8"))
    view = dict((context.coverage or {})["actor_specific"])
    assert view["summary"] == report["summary"]
    assert len(view["rules"]) == len(report["rules"])
    assert all(tag["reason"] for rule in view["rules"] for tag in rule["actor_tags"])
    usable = [r for r in report["rules"] if r["status"] != "rejected"]
    assert usable
    for row in usable:
        label = context.rules[rule_key(f"sigma-actor:{row['sigma_id']}:000")]
        assert label["content_tier"] == "actor" and label["url"].startswith("https://github.com/")
        assert label["actor_tags"] and all(t["decision"] == "accept" for t in label["actor_tags"])
    # without the report the section is absent, not invented
    bare = load_api_context(
        knowledge,
        coverage_report=COVERAGE_REPORT,
        sigma_import_report=SIGMA_IMPORT_REPORT,
        elastic_import_report=ELASTIC_IMPORT_REPORT,
    )
    assert (bare.coverage or {})["actor_specific"] is None


def test_rules_carry_their_review_and_measurements_are_served_as_stored(
    knowledge: AttackKnowledge,
) -> None:
    """ADR-0025: a reviewed rule shows what its matches establish and why (or why
    it was left ambiguous); the technique measurements are the stored reports."""
    from attribution_platform.detection_content.pinned import (
        TECHNIQUE_GROUND_TRUTH,
        TECHNIQUE_SUPPORT_REVIEW,
        UNSEEN_RESULTS,
    )

    context = load_api_context(
        knowledge,
        coverage_report=COVERAGE_REPORT,
        sigma_import_report=SIGMA_IMPORT_REPORT,
        elastic_import_report=ELASTIC_IMPORT_REPORT,
        technique_support_review=TECHNIQUE_SUPPORT_REVIEW,
        measurements={"technique_ground_truth": TECHNIQUE_GROUND_TRUTH, "unseen": UNSEEN_RESULTS},
    )
    review = json.loads(TECHNIQUE_SUPPORT_REVIEW.read_text(encoding="utf-8"))
    decided = next(d for d in review["decisions"] if d.get("when"))
    served = context.rules[decided["rule_source"]]["review"]
    assert served["establishes"] == decided["establishes"] and served["reason"] == decided["reason"]
    assert [c["establishes"] for c in served["when"]] == [c["establishes"] for c in decided["when"]]
    ambiguous = review["left_ambiguous_after_reading"][0]
    if ambiguous["rule_source"] in context.rules:
        assert context.rules[ambiguous["rule_source"]]["review"] == {
            "left_ambiguous": ambiguous["why"]
        }
    assert context.measurements is not None
    unseen = json.loads(UNSEEN_RESULTS.read_text(encoding="utf-8"))
    assert context.measurements["unseen"]["summary"] == unseen["summary"]
    assert "cases" not in context.measurements["unseen"]
