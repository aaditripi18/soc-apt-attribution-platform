"""The ``elastic_sysmon.*`` derived views against Elastic's own pipeline fixtures.

Elastic's Windows integration ships, beside its Sysmon ingest pipeline, a test
input (raw Sysmon events) and the ECS documents the pipeline must produce from it.
Every view in :data:`SYSMON_DERIVED_FIELDS` is checked against those documents for
every event our adapter accepts: an Elastic rule condition reads the same value
here as it would in Elasticsearch (ADR-0015 D2).
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
from pathlib import Path
from typing import Any

import pytest

from attribution_platform.detection.derived_fields import (
    ECS_FIELD_TYPES,
    KEYWORD_IGNORE_ABOVE,
    SYSMON_DERIVED_FIELDS,
    windows_argv,
)
from attribution_platform.domain import Observation
from attribution_platform.sources.errors import SourceAdapterError
from attribution_platform.sources.sysmon import SysmonSourceAdapter

FIXTURES = (
    Path(__file__).resolve().parents[1]
    / "data"
    / "detection"
    / "elastic"
    / "conformance"
    / "sysmon_operational"
)

#: The one known divergence: Elastic's fixture has a process-creation event with
#: no Image, ProcessId or ProcessGuid. The adapter records no process for it (it
#: has no identity), while the pipeline still copies the PE / integrity fields.
_KNOWN_DIVERGENCE = {
    "process.pe.company",
    "process.pe.description",
    "process.pe.product",
    "winlog.event_data.IntegrityLevel",
}


def _get(document: dict[str, Any], dotted: str) -> Any:
    current: Any = document
    for part in dotted.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def _pairs() -> list[tuple[dict[str, Any], Observation]]:
    events = json.loads((FIXTURES / "test-events.json").read_text(encoding="utf-8"))["events"]
    expected = json.loads(
        (FIXTURES / "test-events.json-expected.json").read_text(encoding="utf-8")
    )["expected"]
    adapter = SysmonSourceAdapter()
    pairs = []
    for raw, document in zip(events, expected, strict=True):
        try:
            (observation,) = adapter.to_observations(raw)
        except SourceAdapterError:
            continue  # an event id the adapter does not support
        pairs.append((document, observation))
    return pairs


def test_fixtures_match_the_manifest() -> None:
    manifest = json.loads((FIXTURES / "manifest.json").read_text(encoding="utf-8"))
    for entry in manifest["files"]:
        raw = (FIXTURES / entry["path"]).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == entry["sha256"], entry["path"]
        blob = hashlib.sha1(b"blob %d\0" % len(raw) + raw).hexdigest()  # noqa: S324 - git id
        assert blob == entry["blob_id"], entry["path"]


def test_every_derived_view_equals_the_pipeline_output() -> None:
    pairs = _pairs()
    assert len(pairs) >= 200  # the adapter accepts most fixture events
    compared: dict[str, int] = {}
    divergent: list[tuple[str, str, Any, Any]] = []
    for document, observation in pairs:
        for ecs_field, derive in SYSMON_DERIVED_FIELDS.items():
            ours = derive(observation)
            theirs = _get(document, ecs_field)
            if isinstance(theirs, list):
                theirs = tuple(str(v) for v in theirs)
            elif theirs is not None:
                theirs = str(theirs)
            if ECS_FIELD_TYPES.get(ecs_field) == "ip" and theirs is not None:
                # the document keeps the address as written; queries compare addresses
                theirs = str(ipaddress.ip_address(str(theirs)))
            if ours is None and theirs is None:
                continue
            compared[ecs_field] = compared.get(ecs_field, 0) + 1
            if ours != theirs:
                divergent.append((str(_get(document, "event.code")), ecs_field, ours, theirs))
    unexpected = [d for d in divergent if d[1] not in _KNOWN_DIVERGENCE]
    assert unexpected == []
    # The documented divergence is exactly the one image-less creation event.
    assert {d[1] for d in divergent} == _KNOWN_DIVERGENCE
    assert all(d[0] == "1" and d[2] is None for d in divergent)
    # Every view the fixtures exercise was actually compared.
    for field in (
        "process.args",
        "process.name",
        "process.parent.args",
        "file.extension",
        "registry.data.strings",
        "registry.value",
        "dll.name",
        "dns.question.name",
        "winlog.event_data.GrantedAccess",
    ):
        assert compared.get(field, 0) >= 1, field


@pytest.mark.parametrize(
    ("command_line", "argv"),
    [
        ("cmd.exe /c whoami", ("cmd.exe", "/c", "whoami")),
        ('"C:\\Program Files\\a.exe" -x', ("C:\\Program Files\\a.exe", "-x")),
        ('a "b c" d', ("a", "b c", "d")),
        ('a \\"b', ("a", '"b')),  # backslash-escaped quote
        ('a \\\\"b c"', ("a", "\\b c")),  # 2n backslashes + quote: n backslashes, quote toggles
        ("a\\\\b", ("a\\\\b",)),  # backslashes not before a quote are literal
        ('"a""b"', ('a"b',)),  # pre-2008 doubled quote inside quotes
        ("  a\t b  ", ("a", "b")),
    ],
)
def test_windows_argv_follows_the_pipeline(command_line: str, argv: tuple[str, ...]) -> None:
    assert windows_argv(command_line) == argv


def test_keyword_values_over_ignore_above_are_not_queryable() -> None:
    long_name = "a" * KEYWORD_IGNORE_ABOVE + ".exe"
    adapter = SysmonSourceAdapter()
    (observation,) = adapter.to_observations(
        {
            "@timestamp": "2026-01-01T00:00:00Z",
            "winlog": {
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "event_id": 1,
                "record_id": 1,
                "computer_name": "host",
                "event_data": {
                    "Image": "C:\\x\\" + long_name,
                    "CommandLine": long_name + " short",
                    "ProcessId": "1",
                },
            },
        }
    )
    assert SYSMON_DERIVED_FIELDS["process.name"](observation) is None  # keyword, too long
    assert SYSMON_DERIVED_FIELDS["process.args"](observation) == ("short",)
    # process.command_line is a wildcard-typed field: no ignore_above.
    assert SYSMON_DERIVED_FIELDS["process.command_line"](observation) == long_name + " short"
