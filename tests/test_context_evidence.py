"""ADR-0026 Amendment B: low-level Evidence that belongs to no activity cluster
is listed as context - stored, served and never compared."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from attribution_platform.api.read_model import (
    get_investigation,
    get_investigation_activity,
    get_investigation_context,
)

sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_dossier import _investigate  # noqa: E402
from test_wazuh_alerts import _alert  # noqa: E402


def test_low_level_evidence_outside_clusters_is_listed_as_context(tmp_path: Path) -> None:
    # a low-level alert alone: Evidence that forms no cluster
    text = json.dumps(_alert(level=3, mitre={"id": ["T1078"]})) + "\n"
    client, investigation_id = _investigate(tmp_path, "context.json", text)
    record = get_investigation(client, investigation_id)
    assert record["units"] == [] and record["evidence_outside_units"] == 1
    assert get_investigation_activity(client, investigation_id)["events"] == []

    context = get_investigation_context(client, investigation_id)
    assert context["listed"] == context["evidence_outside_units"] == 1
    (item,) = context["items"]
    assert item["attack_id"] == "T1078" and item["host"] == "Windows11"
    assert item["rule_source"] == "wazuh:110011"
    assert item["time"].startswith("2023-10-16T12:12:18")
    # context is never a command line and never a judgement
    assert not [k for k in item if "command" in k or "score" in k or "verdict" in k]


def test_an_investigation_with_everything_in_clusters_has_no_context(tmp_path: Path) -> None:
    client, investigation_id = _investigate(tmp_path, "core.json", json.dumps(_alert()) + "\n")
    context = get_investigation_context(client, investigation_id)
    assert context["items"] == [] and context["evidence_outside_units"] == 0
