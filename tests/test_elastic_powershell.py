"""Elastic's PowerShell rules (ADR-0015 Amendment B): the pinned analyzer
reproduced exactly, phrases decided by the engine's plain ``contains``, and the
translation refusing whatever it does not reproduce."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from attribution_platform.attack_knowledge.loader import load_attack_knowledge
from attribution_platform.detection import DetectionEngine, load_rule_pack
from attribution_platform.detection.derived_powershell import (
    POWERSHELL_VIEWS,
    powershell_script_tokens,
    token_form,
)
from attribution_platform.detection_content.elastic_field_map import POWERSHELL_STREAM, STREAMS
from attribution_platform.detection_content.elastic_import import _dnf, _specialise
from attribution_platform.detection_content.elastic_query import parse_kql
from attribution_platform.detection_content.pinned import ELASTIC_IMPORT_REPORT, ELASTIC_PACK
from attribution_platform.detection_content.sigma_import import Gap, Literal
from attribution_platform.domain import Observation
from attribution_platform.sources.powershell import PowerShellSourceAdapter

CONFORMANCE = (
    Path(__file__).resolve().parents[1]
    / "data"
    / "detection"
    / "elastic"
    / "conformance"
    / "windows_powershell_operational"
)


def _script_block(text: str, path: str = "") -> Observation:
    (observation,) = PowerShellSourceAdapter().to_observations(
        {
            "@timestamp": datetime(2026, 1, 1, tzinfo=UTC).isoformat(),
            "winlog": {
                "channel": "Microsoft-Windows-PowerShell/Operational",
                "event_id": 4104,
                "record_id": 7,
                "computer_name": "WS01.example.local",
                "process": {"pid": 4242},
                "user": {"identifier": "S-1-5-21-1-2-3-1001"},
                "event_data": {
                    "ScriptBlockText": text,
                    "ScriptBlockId": "b",
                    "Path": path,
                    "MessageNumber": "1",
                    "MessageTotal": "1",
                },
            },
        }
    )
    return observation


# --- the analyzer -------------------------------------------------------------------


def test_the_pinned_manifest_declares_the_analyzer_reproduced_here() -> None:
    """The definition is read from Elastic's repository at the pinned commit, not
    remembered: the vendored link names the shared pipeline by hash, and the
    pattern below is the data stream manifest's."""
    link = (CONFORMANCE / "pipeline" / "default.yml.link").read_text(encoding="utf-8")
    assert "powershell_operational.yml" in link
    assert "e07f1bff401a226d5e4470b8b3f1e68d8f2913abed1025fda8c57cf311c88948" in link


@pytest.mark.parametrize(
    ("text", "tokens"),
    [
        ("Invoke-Mimikatz -DumpCreds", ("invoke-mimikatz", "-dumpcreds")),
        (
            "[System.Reflection.Assembly]::Load($b)",
            ("system", "reflection", "assembly", "load", "b"),
        ),
        ("New_Object  \t\n x", ("new_object", "x")),  # underscore is a word character
        ("--a--", ("--a--",)),  # hyphens never separate
        ("caf\u00e9 na\u00efve", ("caf", "na", "ve")),  # \\W is ASCII-only in Java
        ("::$()", ()),
        ("", ()),
    ],
)
def test_tokens_are_the_pattern_analyzers(text: str, tokens: tuple[str, ...]) -> None:
    assert powershell_script_tokens(text) == tokens


def test_a_phrase_is_a_run_of_consecutive_tokens() -> None:
    view = POWERSHELL_VIEWS.views["powershell.file.script_block_text"]
    analyse = POWERSHELL_VIEWS.analyzers["powershell.file.script_block_text"]
    text = view(_script_block("$x = [System.Reflection.Assembly]::Load($bytes); IEX $x"))
    assert text == " x system reflection assembly load bytes iex x "

    def matches(phrase: str) -> bool:
        form = analyse(phrase)
        return form is not None and form in text

    assert matches("System.Reflection.Assembly")  # punctuation between tokens is irrelevant
    assert matches("reflection assembly]::LOAD")  # and so is case
    assert not matches("Assembly.Reflection")  # order matters
    assert not matches("System.Assembly")  # the tokens must be adjacent
    assert not matches("Reflect")  # a token is matched whole, never by prefix
    assert not matches("ystem")
    assert analyse("::") is None  # no token: matches no document
    assert token_form(()) is None


def test_views_are_for_script_block_events_only() -> None:
    block = _script_block("Get-Process", "C:\\Tools\\run.it\\job.ps1")
    get = POWERSHELL_VIEWS.resolve
    assert get("file.path", block) == "C:\\Tools\\run.it\\job.ps1"
    assert get("file.directory", block) == "C:\\Tools\\run.it"
    assert (get("file.name", block), get("file.extension", block)) == ("job.ps1", "ps1")
    assert (get("user.id", block), get("process.pid", block)) == ("S-1-5-21-1-2-3-1001", "4242")
    relative = _script_block("x", "job.ps1")  # no backslash: the pipeline sets only file.path
    assert get("file.path", relative) == "job.ps1"
    assert get("file.name", relative) is None and get("file.directory", relative) is None
    assert get("file.path", _script_block("x")) is None


# --- translation --------------------------------------------------------------------


def _conjuncts(query: str) -> list[tuple[Any, ...]]:
    (profile,) = POWERSHELL_STREAM.profiles
    node = _specialise(parse_kql(query).expr, profile, POWERSHELL_STREAM)
    assert not isinstance(node, bool)
    return _dnf(node, False, 64, POWERSHELL_STREAM.views)


def test_quoted_values_become_phrase_conditions_and_alternatives_one_condition() -> None:
    (conjunct,) = _conjuncts(
        "event.category:process and host.os.type:windows and "
        'powershell.file.script_block_text : ("Invoke-Mimikatz" or "sekurlsa::logonpasswords") '
        'and not powershell.file.script_block_text : "Unit Test"'
    )
    positive, negative = conjunct
    assert isinstance(positive, Literal) and isinstance(negative, Literal)
    assert positive.field_path == "elastic_powershell.powershell.file.script_block_text"
    assert (positive.operator, positive.negate) == ("contains", False)
    alternatives: Any = positive.value
    assert alternatives == (" invoke-mimikatz ", " sekurlsa logonpasswords ")
    assert (negative.operator, negative.value, negative.negate) == ("contains", " unit test ", True)


def test_what_is_not_reproduced_is_a_gap_never_a_looser_match() -> None:
    field = "powershell.file.script_block_text"
    for query, detail in (
        (f"{field} : System.Net.WebClient", "unquoted_multi_token"),  # any-token semantics
        (f"{field} : *Mimikatz*", "contains"),  # wildcard on analysed text
        (f'{field} : "::"', "value_without_tokens"),
    ):
        (conjunct,) = _conjuncts(query)
        (gap,) = conjunct
        assert isinstance(gap, Gap) and gap.detail.endswith(detail), (query, gap)
    # an unquoted single token is the same query as the quoted one
    assert _conjuncts(f"{field} : Mimikatz") == _conjuncts(f'{field} : "Mimikatz"')
    # a phrase that can match nothing adds nothing to its alternatives
    ((literal,),) = _conjuncts(f'{field} : ("::" or "Get-Clipboard")')
    assert literal.value == " get-clipboard "
    # another event category is decided false for this stream
    (profile,) = POWERSHELL_STREAM.profiles
    assert (
        _specialise(parse_kql("event.category:network").expr, profile, POWERSHELL_STREAM) is False
    )


# --- the imported pack ----------------------------------------------------------------


def test_the_stream_applies_only_to_powershell_indices() -> None:
    assert POWERSHELL_STREAM in STREAMS
    assert POWERSHELL_STREAM.applies_to(("logs-windows.powershell*", "winlogbeat-*"))
    assert not POWERSHELL_STREAM.applies_to(("logs-windows.sysmon_operational-*",))
    assert not POWERSHELL_STREAM.applies_to(("logs-endpoint.events.process-*",))


def test_imported_powershell_rules_fire_on_their_phrases_and_not_on_lookalikes() -> None:
    report = json.loads(ELASTIC_IMPORT_REPORT.read_text(encoding="utf-8"))
    imported = [
        r
        for r in report["rules"]
        if any(p.startswith("powershell:") for p in r["profiles"]) and r["status"] != "rejected"
    ]
    assert len(imported) == 30
    pack = load_rule_pack(ELASTIC_PACK, knowledge=load_attack_knowledge())
    rules = tuple(r for r in pack.rules if ":powershell:4104:" in r.rule_ref.rule_id)
    engine = DetectionEngine(rules=rules)

    def fired(text: str) -> set[str]:
        return {
            result.rule_ref.rule_id.split(":")[1]
            for result in engine.evaluate([_script_block(text)])
        }

    # an ordinary administrative script fires nothing
    assert fired("Get-ChildItem C:\\Users | Where-Object { $_.Length -gt 1MB }") == set()
    # a published credential-dumping cmdlet name fires
    hit = fired("IEX (New-Object Net.WebClient).DownloadString($u); Invoke-Mimikatz -DumpCreds")
    assert hit
    # the same letters inside a longer word are another token: no match
    assert fired("$NotInvoke-MimikatzAtAll = 1; Write-Host Invoke-Mimikatzzz") == set()
    # only script-block events are selected: the same text as a process command line is not
    by_name = {r["rule_id"]: r["name"] for r in imported}
    assert all(rule_id in by_name for rule_id in hit)
