"""Known-answer checks for every actor-specific rule (ADR-0018 Amendment B).

For each rule of the pinned actor pack, a raw event carrying exactly the
published artefact the rule looks for is built, put through the real source
adapter, and must make that rule fire and name its Group. The same event with
the artefact replaced by neutral values must make no actor rule fire. The
artefact strings are indicator values read from the rule itself.

A rule this file cannot exercise is listed in ``NOT_EXERCISED`` with the
reason; the list is asserted, so nothing is skipped silently.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from attribution_platform.attack_knowledge.loader import load_attack_knowledge
from attribution_platform.detection import DetectionEngine, RulePack, load_rule_pack
from attribution_platform.detection.rules import DetectionRule
from attribution_platform.detection_content.pinned import (
    SIGMA_ACTOR_IMPORT_REPORT,
    SIGMA_ACTOR_PACK,
)
from attribution_platform.domain import Observation
from attribution_platform.replay.recording_pipeline import DEFAULT_CHANNEL_ADAPTERS, channel_of

REPO_ROOT = Path(__file__).resolve().parents[1]
GOLDEN = REPO_ROOT / "data" / "telemetry-samples" / "otrf-compound" / "golden-records.jsonl"

#: rule id -> why no Windows event is synthesised for it here.
NOT_EXERCISED = {
    "sigma-actor:81c0b7f5-81c9-435e-a291-bc32fc2b72cd:000": "Sysmon for Linux (XML input)",
    "sigma-actor:81c0b7f5-81c9-435e-a291-bc32fc2b72cd:001": "Sysmon for Linux (XML input)",
}


def _golden(golden_id: str) -> dict[str, Any]:
    for line in GOLDEN.read_text(encoding="utf-8").splitlines():
        row = json.loads(line)
        if row["golden_id"] == golden_id:
            record: dict[str, Any] = row["record"]
            return record
    raise AssertionError(golden_id)


def _event_data(record: dict[str, Any]) -> dict[str, Any]:
    data: dict[str, Any] = (
        record["event_data"] if "event_data" in record else record["winlog"]["event_data"]
    )
    return data


def _sysmon(event_id: int, fields: dict[str, str]) -> dict[str, Any]:
    """A Sysmon event of ``event_id`` shaped like the recorded registry event."""
    record = copy.deepcopy(_golden("wlb6-sysmon-13"))
    record["event_id"] = event_id
    record.pop("message", None)
    data = _event_data(record)
    keep = {k: data[k] for k in ("UtcTime", "ProcessGuid", "ProcessId", "Image")}
    record["event_data"] = {**keep, **fields}
    return record


#: Observation field -> (kind of event, raw field carrying it).
_FIELDS = {
    "process.command_line": ("process", "CommandLine"),
    "process.executable": ("process", "Image"),
    "process.pe.original_file_name": ("process", "OriginalFileName"),
    "dll.path": ("image_load", "ImageLoaded"),
    "file.path": ("file", "TargetFilename"),
    "registry.path": ("registry", "TargetObject"),
    "registry.data": ("registry", "Details"),
    "scheduled_task.name": ("task", "TaskName"),
    "scheduled_task.content": ("task", "TaskContent"),
    "service.name": ("service", "ServiceName"),
    "service.file_name": ("service", "ImagePath"),
}
_NEUTRAL = {
    "CommandLine": "C:\\Windows\\System32\\notepad.exe C:\\Users\\a\\notes.txt",
    "Image": "C:\\Windows\\System32\\notepad.exe",
    "OriginalFileName": "NOTEPAD.EXE",
    "ImageLoaded": "C:\\Windows\\System32\\kernel32.dll",
    "TargetFilename": "C:\\Users\\a\\Documents\\notes.txt",
    "TargetObject": "HKLM\\SOFTWARE\\Example\\Setting",
    "Details": "DWORD (0x00000000)",
    "TaskName": "\\Example Task",
    "TaskContent": "<Task><Actions><Exec><Command>notepad.exe</Command></Exec></Actions></Task>",
    "ServiceName": "ExampleService",
    "ImagePath": "C:\\Program Files\\Example\\service.exe",
}


def _value(conditions: list[Any]) -> str:
    """One string satisfying every positive condition on one field."""
    exact = [c.value for c in conditions if c.operator == "equals"]
    if exact:
        return str(exact[0])
    head = [str(c.value) for c in conditions if c.operator == "startswith"]
    middle = [str(c.value) for c in conditions if c.operator == "contains"]
    tail = [str(c.value) for c in conditions if c.operator == "endswith"]
    assert len(head) <= 1 and len(tail) <= 1, conditions
    return " ".join([*head, *middle, *tail])


def _record(rule: DetectionRule, *, neutral: bool) -> dict[str, Any]:
    by_raw: dict[str, list[Any]] = {}
    kinds = set()
    for condition in rule.conditions:
        mapped = _FIELDS.get(condition.field_path)
        if mapped is None or condition.negate:
            continue
        kinds.add(mapped[0])
        by_raw.setdefault(mapped[1], []).append(condition)
    kind = next(iter(kinds - {"process"}), "process")
    assert kinds <= {kind, "process"}, (rule.rule_ref.rule_id, kinds)
    fields = {raw: _NEUTRAL[raw] if neutral else _value(found) for raw, found in by_raw.items()}
    if kind == "process":
        record = copy.deepcopy(_golden("wlb6-sysmon-1"))
        _event_data(record).update({"OriginalFileName": "x", **fields})
        return record
    if kind == "image_load":
        return _sysmon(7, {"ImageLoaded": _NEUTRAL["ImageLoaded"], **fields})
    if kind == "file":
        return _sysmon(
            11,
            {
                "TargetFilename": _NEUTRAL["TargetFilename"],
                "CreationUtcTime": "2019-05-14 22:31:26.780",
                **fields,
            },
        )
    if kind == "registry":
        return _sysmon(
            13,
            {
                "EventType": "SetValue",
                "TargetObject": _NEUTRAL["TargetObject"],
                "Details": _NEUTRAL["Details"],
                **fields,
            },
        )
    system_log = any(
        c.field_path == "event.dataset" and c.value == "system.system" for c in rule.conditions
    )
    record = copy.deepcopy(
        _golden("b-4698" if kind == "task" else "sys-7045" if system_log else "b-4697")
    )
    record.pop("message", None)
    _event_data(record).update(fields)
    return record


def _observations(record: dict[str, Any]) -> list[Observation]:
    adapter = DEFAULT_CHANNEL_ADAPTERS[channel_of(record)]
    return list(adapter.to_observations(record))


@pytest.fixture(scope="module")
def pack() -> RulePack:
    return load_rule_pack(SIGMA_ACTOR_PACK, knowledge=load_attack_knowledge())


def _rule_ids() -> list[str]:
    pack_json = json.loads(SIGMA_ACTOR_PACK.read_text(encoding="utf-8"))
    return [str(rule["rule_id"]) for rule in pack_json["rules"]]


def test_the_unexercised_rules_are_exactly_the_listed_ones() -> None:
    assert set(NOT_EXERCISED) <= set(_rule_ids())


@pytest.mark.parametrize("rule_id", [r for r in _rule_ids() if r not in NOT_EXERCISED])
def test_the_published_artefact_fires_the_rule_and_names_its_group(
    pack: RulePack, rule_id: str
) -> None:
    rule = next(r for r in pack.rules if r.rule_ref.rule_id == rule_id)
    observations = _observations(_record(rule, neutral=False))
    assert observations, "the adapter refused the synthesised event"
    fired = [rule.evaluate(o) for o in observations]
    unmet = [
        (c.field_path, c.operator, c.value)
        for c in rule.conditions
        if c.evaluate(observations[0]) is None
    ]
    assert any(f is not None for f in fired), unmet
    (mapping,) = rule.technique_mappings
    assert mapping.attack_ref.object_type == "intrusion-set"

    # the same event without the artefact: no actor rule at all fires
    engine = DetectionEngine(rules=pack.rules)
    assert engine.evaluate(_observations(_record(rule, neutral=True))) == ()


def test_every_group_the_report_calls_usable_is_exercised(pack: RulePack) -> None:
    report = json.loads(SIGMA_ACTOR_IMPORT_REPORT.read_text(encoding="utf-8"))
    exercised = {
        m.attack_ref.external_id
        for rule in pack.rules
        if rule.rule_ref.rule_id not in NOT_EXERCISED
        for m in rule.technique_mappings
    }
    assert exercised | {"G1056"} == set(report["summary"]["groups_with_a_usable_rule"])
