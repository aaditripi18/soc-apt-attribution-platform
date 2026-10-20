"""ADR-0024: the flat documents behind the Kibana dashboard are derived from the
served read model, carry no judgement the console does not show, and the tracked
dashboard file is what the builder produces."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from attribution_platform.api.context import ApiContext, build_technique_catalogue
from attribution_platform.api.kibana_export import (
    DETECTIONS_INDEX,
    GROUP_MATCHES_INDEX,
    export_investigation,
)
from attribution_platform.api.read_model import get_investigation_activity, get_profile_match
from attribution_platform.attack_knowledge.loader import load_attack_knowledge

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(REPO / "scripts"))

import build_kibana_dashboard as builder  # noqa: E402

from test_dossier import _investigate  # noqa: E402
from test_wazuh_alerts import _alert  # noqa: E402


def test_the_export_is_the_read_model_flattened(tmp_path: Path) -> None:
    alerts = [_alert(), _alert(id="2.2", mitre={"id": ["T1105"]})]
    text = "".join(json.dumps(a) + "\n" for a in alerts)
    client, investigation_id = _investigate(tmp_path, "alerts.json", text)
    knowledge = load_attack_knowledge()
    context = ApiContext(knowledge=knowledge, techniques=build_technique_catalogue(knowledge))
    counts = export_investigation(client, context, investigation_id)
    events = get_investigation_activity(client, investigation_id)["events"]
    matches = get_profile_match(client, investigation_id)["matches"]
    assert counts == {"detections": len(events), "group_matches": len(matches)}
    assert counts["detections"] == 2 and counts["group_matches"] > 0

    detections = client.search(DETECTIONS_INDEX, {"match_all": {}}, size=100)
    by_technique = {d["threat"]["technique"]["id"]: d for d in detections}
    service = by_technique["T1543.003"]
    assert service["threat"]["technique"]["name"] == "Windows Service"
    assert service["host"] == {"name": "Windows11"}
    assert service["@timestamp"].startswith("2023-10-16T12:12:18")
    assert service["investigation"] == {"id": investigation_id, "source": "alerts.json"}
    assert "persistence" in service["threat"]["tactic"]["name"]

    stored = client.search(GROUP_MATCHES_INDEX, {"match_all": {}}, size=1000)
    served = {m["candidate_id"]: m for m in matches}
    assert {d["threat"]["group"]["id"] for d in stored} == set(served)
    for document in stored:
        match = served[document["threat"]["group"]["id"]]
        assert document["behavioural_overlap_percent"] == round(100 * match["overlap"], 2)
        assert document["matched_techniques"] == match["matched"]
        # the basis of the percentage: matched, of the techniques counted
        assert document["counted_techniques"] == len(
            get_profile_match(client, investigation_id)["observed"]
        )
        assert document["matched_techniques"] <= document["counted_techniques"]
        assert document["identified"] is (match["named_by"] == "actor_specific")
        assert document["advisory_lead"] is (match["named_by"] == "advisory_indicator")
    # a similarity is never exported under another name
    exported = json.dumps([*detections, *stored]).lower()
    assert not [w for w in ("confidence", "probability", "likelihood", "score") if w in exported]
    # exporting again overwrites: no duplicates
    assert export_investigation(client, context, investigation_id) == counts
    assert len(client.search(DETECTIONS_INDEX, {"match_all": {}}, size=100)) == 2


def test_the_tracked_dashboard_is_what_the_builder_writes() -> None:
    assert builder.OUT.read_text(encoding="utf-8") == builder.render()
    objects = [json.loads(line) for line in builder.render().splitlines()]
    by_type: dict[str, list[dict[str, Any]]] = {}
    for obj in objects:
        by_type.setdefault(obj["type"], []).append(obj)
    assert {v["attributes"]["title"] for v in by_type["index-pattern"]} == {
        DETECTIONS_INDEX,
        GROUP_MATCHES_INDEX,
    }
    (dashboard,) = by_type["dashboard"]
    ids = {v["id"] for v in by_type["visualization"]}
    assert {r["id"] for r in dashboard["references"]} == ids and len(ids) == 13
    views = {v["id"] for v in by_type["index-pattern"]}
    for visualization in by_type["visualization"]:
        assert {r["id"] for r in visualization["references"]} <= views
        state = json.loads(visualization["attributes"]["visState"])
        for agg in state["aggs"]:
            field = agg["params"].get("field")
            assert field is None or not field.endswith((".text", "_score"))
    text = builder.render().lower()
    assert "not** the" in text and "confidence" not in text
