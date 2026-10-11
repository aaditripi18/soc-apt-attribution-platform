"""Derived views of every non-Sysmon data stream against Elastic's own fixtures.

For each stream Elastic rules are translated for (ADR-0015), Elastic's integration
ships pipeline test fixtures: raw input events and the ECS documents its ingest
pipeline must produce. Each view is compared with those documents for every
fixture event this platform's adapter accepts. (Sysmon has its own, older test:
``test_elastic_sysmon_conformance.py``.)
"""

from __future__ import annotations

import json
import re
import sys
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from attribution_platform.detection.derived_cloud import (
    AZURE_AUDIT_VIEWS,
    AZURE_SIGNIN_VIEWS,
    CLOUDTRAIL_VIEWS,
    GITHUB_VIEWS,
    KUBERNETES_VIEWS,
    O365_VIEWS,
    OKTA_VIEWS,
)
from attribution_platform.detection.derived_json import (
    all_leaf_paths,
    java_double,
    java_hashmap_order,
    java_to_string,
)
from attribution_platform.detection.derived_powershell import POWERSHELL_VIEWS
from attribution_platform.detection.derived_registry import VIEW_SETS
from attribution_platform.detection.derived_security import SECURITY_VIEWS, security_argv
from attribution_platform.detection.derived_views import ViewSet
from attribution_platform.detection_content.elastic_field_map import STREAMS
from attribution_platform.domain import Observation
from attribution_platform.sources.cloudtrail import CloudTrailSourceAdapter
from attribution_platform.sources.entra import EntraIdSourceAdapter
from attribution_platform.sources.errors import SourceAdapterError
from attribution_platform.sources.github_audit import GitHubAuditSourceAdapter
from attribution_platform.sources.kubernetes_audit import KubernetesAuditSourceAdapter
from attribution_platform.sources.o365 import O365SourceAdapter
from attribution_platform.sources.okta import OktaSourceAdapter
from attribution_platform.sources.powershell import PowerShellSourceAdapter
from attribution_platform.sources.sysmon_xml import parse_sysmon_event_xml
from attribution_platform.sources.windows_security import WindowsSecuritySourceAdapter

sys.path.insert(0, str(Path(__file__).resolve().parent))
import elastic_conformance as ec  # noqa: E402

REPO = Path(__file__).resolve().parents[1]
_CLOUDTRAIL_REMOVED = frozenset({"", "-", "none"})


def _json_event(event: Any) -> Any:
    """A fixture event as the raw record an adapter reads: a JSON log line, a
    ``message`` / ``event.original`` JSON string, or the event object itself."""
    text: Any = event
    if isinstance(event, dict):
        text = event.get("message") or (event.get("event") or {}).get("original")
        if text is None:
            return event
    if not isinstance(text, str) or not text.strip():
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


_EXECUTION_PID = re.compile(r"<Execution ProcessID='(\d+)'")
_SECURITY_SID = re.compile(r"<Security UserID='([^']+)'")


def _powershell_event(event: Any) -> Any:
    """A PowerShell fixture event as the collector record the adapter reads.
    Elastic's fixtures come in two forms, as the pipeline accepts both: an event
    already decoded by the agent (a ``winlog`` object, which the pipeline then
    uses), or only the XML in ``event.original``."""
    winlog = event.get("winlog")
    if isinstance(winlog, dict) and "event_id" in winlog:
        record: dict[str, Any] = {"winlog": dict(winlog), "@timestamp": event["@timestamp"]}
    else:
        original = str((event.get("event") or {}).get("original", ""))
        first = original.split("</Event>", 1)[0] + "</Event>"
        try:
            record = parse_sysmon_event_xml(first.strip())  # one envelope, any channel
        except SourceAdapterError:
            return None
        record["@timestamp"] = event["@timestamp"]
        pid, sid = _EXECUTION_PID.search(first), _SECURITY_SID.search(first)
        if pid is not None:
            record["winlog"]["process"] = {"pid": int(pid.group(1))}
        if sid is not None:
            record["winlog"]["user"] = {"identifier": sid.group(1)}
    record["winlog"]["event_id"] = int(record["winlog"]["event_id"])
    if record["winlog"]["event_id"] != 4104:
        return None  # the stream's views are for script-block events
    return record


@dataclass(frozen=True)
class Case:
    stream: str
    views: ViewSet
    adapter: Callable[[Any], tuple[Observation, ...]]
    #: The fewest fixture events the adapter must accept (a regression guard).
    min_accepted: int
    decode: Callable[[Any], Any] = _json_event
    dynamic: Mapping[str, Callable[[Observation], Iterable[str]]] | None = None


CASES = [
    Case(
        "aws_cloudtrail",
        CLOUDTRAIL_VIEWS,
        CloudTrailSourceAdapter().to_observations,
        120,
        dynamic={
            "aws.cloudtrail.flattened.request_parameters.": lambda o: all_leaf_paths(
                o.aws_cloudtrail.request_parameters if o.aws_cloudtrail else None,
                _CLOUDTRAIL_REMOVED,
            )
        },
    ),
    Case("o365_audit", O365_VIEWS, O365SourceAdapter().to_observations, 370),
    Case("azure_auditlogs", AZURE_AUDIT_VIEWS, EntraIdSourceAdapter().to_observations, 11),
    Case("azure_signinlogs", AZURE_SIGNIN_VIEWS, EntraIdSourceAdapter().to_observations, 66),
    Case("okta_system", OKTA_VIEWS, OktaSourceAdapter().to_observations, 26),
    Case("github_audit", GITHUB_VIEWS, GitHubAuditSourceAdapter().to_observations, 10),
    Case(
        "kubernetes_audit_logs", KUBERNETES_VIEWS, KubernetesAuditSourceAdapter().to_observations, 3
    ),
    Case(
        "system_security",
        SECURITY_VIEWS,
        WindowsSecuritySourceAdapter().to_observations,
        43,
        decode=lambda event: event,
    ),
    Case(
        "windows_powershell_operational",
        POWERSHELL_VIEWS,
        PowerShellSourceAdapter().to_observations,
        2,
        decode=_powershell_event,
    ),
]


@pytest.mark.parametrize("case", CASES, ids=lambda c: c.stream)
def test_fixtures_match_their_manifest(case: Case) -> None:
    assert ec.verify_manifest(case.stream) > 0


@pytest.mark.parametrize("case", CASES, ids=lambda c: c.stream)
def test_every_view_equals_the_pipeline_output(case: Case) -> None:
    result = ec.compare(case.stream, case.views, case.adapter, case.decode, case.dynamic)
    assert result.accepted >= case.min_accepted
    assert result.divergent == []
    # Every view is exercised by at least one fixture event, or is listed here as
    # one the fixtures do not happen to cover.
    untested = set(case.views.views) - set(result.compared) - set(result.undetermined)
    assert untested <= _NOT_IN_FIXTURES.get(case.stream, set()), sorted(untested)


#: Views no fixture event of the stream has a value for (they stay verified by
#: reading the pipeline; listed so a silently untested view cannot be added).
_NOT_IN_FIXTURES: dict[str, set[str]] = {
    "okta_system": {"okta.outcome.reason"},
    "kubernetes_audit_logs": {"kubernetes.audit.objectRef.subresource"},
    # no fixture script block carries a script path
    "windows_powershell_operational": {
        "file.path",
        "file.name",
        "file.directory",
        "file.extension",
    },
    "system_security": {
        "winlog.event_data.AdditionalInfo",
        "winlog.event_data.OperationType",
        "winlog.event_data.Properties",
        "winlog.event_data.TaskName",
    },
}


def test_every_stream_has_a_registered_view_set_and_a_conformance_case() -> None:
    assert {s.views.namespace for s in STREAMS} == set(VIEW_SETS)
    tested = {case.views.namespace for case in CASES} | {"elastic_sysmon"}
    assert tested == set(VIEW_SETS)


def test_pipeline_tables_are_extracted_from_the_pinned_pipelines() -> None:
    sys.path.insert(0, str(REPO / "scripts"))
    import extract_elastic_pipeline_tables as extract

    for name, build in extract.TABLES.items():
        committed = (extract.OUT / name).read_text(encoding="utf-8")
        assert extract.render(build()) == committed, name


# --- the Java renderings the pipelines rely on ------------------------------------


def test_java_hashmap_order_is_bucket_order_not_insertion_order() -> None:
    # Elastic's fixture: {"functionName":..,"statementId":..,"action":..,"principal":..}
    keys = ["action", "functionName", "principal", "statementId"]
    assert java_hashmap_order(keys) == ["principal", "functionName", "statementId", "action"]
    # More than 12 keys: the table has doubled to 32 buckets.
    many = [f"k{i}" for i in range(13)]
    assert sorted(java_hashmap_order(many)) == sorted(many)
    assert java_hashmap_order(many) != many


def test_java_to_string_prunes_then_renders() -> None:
    text = json.dumps({"userName": "Bob", "tags": [{"key": "a", "v": None}, {}], "x": "", "n": 1.0})
    rendered = java_to_string(text)
    assert rendered is not None
    assert "userName=Bob" in rendered and "tags=[{key=a}]" in rendered and "n=1.0" in rendered
    assert "x=" not in rendered
    assert java_to_string(json.dumps({"a": "-", "b": "none"}), _CLOUDTRAIL_REMOVED) is None
    assert java_to_string(None) is None


@pytest.mark.parametrize(
    ("value", "text"),
    [
        (1.0, "1.0"),
        (0.001, "0.001"),
        (0.0001, "1.0E-4"),
        (1e7, "1.0E7"),
        (123.456, "123.456"),
        (9999999.0, "9999999.0"),
        (-2.5, "-2.5"),
        (1e21, "1.0E21"),
    ],
)
def test_java_double(value: float, text: str) -> None:
    assert java_double(value) == text


def test_security_4688_split_keeps_quotes() -> None:
    assert security_argv('"C:\\Program Files\\a.exe" -x  "b c"') == (
        '"C:\\Program Files\\a.exe"',
        "-x",
        '"b c"',
    )
    assert security_argv("  ") == ()
    assert security_argv("cmd") == ("cmd",)
