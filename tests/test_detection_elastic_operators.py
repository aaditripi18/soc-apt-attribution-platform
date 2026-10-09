"""Engine operators added for exact Elastic rule translation (ADR-0015)."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from attribution_platform.detection import FieldCondition
from attribution_platform.detection.errors import DetectionError
from attribution_platform.domain import (
    EventMetadata,
    HostRef,
    Observation,
    ProcessRef,
    SourceRef,
)

BS = chr(92)


def _obs(command_line: str | None = None, executable: str | None = None) -> Observation:
    return Observation(
        observation_id="o1",
        timestamp=datetime(2026, 1, 1, tzinfo=UTC),
        raw_reference=SourceRef(source_type="sysmon", source_event_id="1"),
        event=EventMetadata(kind="event", category=("process",), type=("start",)),
        host=HostRef(name="h", ip=(), os_type="windows"),
        process=ProcessRef(pid=1, executable=executable, command_line=command_line),
    )


def _matches(condition: FieldCondition, observation: Observation) -> bool:
    return condition.evaluate(observation) is not None


@pytest.mark.parametrize(
    ("pattern", "case_insensitive", "value", "expected"),
    [
        (
            "C:" + BS * 2 + "Users" + BS * 2 + "*" + BS * 2 + "a.exe",
            False,
            "C:" + BS + "Users" + BS + "bob" + BS + "a.exe",
            True,
        ),
        (
            "C:" + BS * 2 + "Users" + BS * 2 + "*" + BS * 2 + "a.exe",
            False,
            "C:" + BS + "Users" + BS + "bob" + BS + "A.exe",
            False,
        ),
        (
            "C:" + BS * 2 + "Users" + BS * 2 + "*" + BS * 2 + "a.exe",
            True,
            "c:" + BS + "users" + BS + "bob" + BS + "A.EXE",
            True,
        ),
        ("a?c", False, "abc", True),
        ("a?c", False, "ac", False),
        ("a" + BS + "?c", False, "a?c", True),  # an escaped ? is literal
        ("a" + BS + "?c", False, "abc", False),
        ("a" + BS + "*", False, "a*", True),
        ("a" + BS + "*", False, "ab", False),
        ("*", False, "", True),
    ],
)
def test_wildcard(pattern: str, case_insensitive: bool, value: str, expected: bool) -> None:
    condition = FieldCondition(
        "process.executable", "wildcard", pattern, case_insensitive=case_insensitive
    )
    assert _matches(condition, _obs(executable=value)) is expected


def test_wildcard_rejects_a_trailing_lone_backslash() -> None:
    with pytest.raises(DetectionError, match="lone backslash"):
        _matches(FieldCondition("process.executable", "wildcard", "a" + BS), _obs(executable="a"))


def test_any_of_values() -> None:
    contains = FieldCondition("process.command_line", "contains", ("-enc", "iex"))
    assert _matches(contains, _obs(command_line="powershell iex(x)"))
    assert not _matches(contains, _obs(command_line="powershell -nop"))
    negated = FieldCondition("process.command_line", "endswith", ("a", "b"), negate=True)
    assert _matches(negated, _obs(command_line="xyz"))
    assert not _matches(negated, _obs(command_line="xb"))


def test_element_operators_on_derived_arrays() -> None:
    observation = _obs(command_line='cmd.exe /c "net user" /ADD')
    args = "elastic_sysmon.process.args"
    assert _matches(FieldCondition(args, "has_element", "net user"), observation)
    assert _matches(
        FieldCondition(args, "element_in", ("/x", "/add"), case_insensitive=True), observation
    )
    assert not _matches(FieldCondition(args, "element_in", ("/x", "/add")), observation)
    assert _matches(FieldCondition(args, "element_startswith", "net "), observation)
    assert _matches(FieldCondition(args, "element_endswith", ".exe"), observation)
    assert _matches(FieldCondition(args, "element_contains", ("zzz", "et u")), observation)
    assert _matches(FieldCondition(args, "element_wildcard", "n?t*"), observation)
    # Negation: no element matches.
    assert not _matches(FieldCondition(args, "has_element", "/c", negate=True), observation)
    assert _matches(FieldCondition(args, "has_element", "/q", negate=True), observation)


def test_array_and_scalar_operators_do_not_mix() -> None:
    observation = _obs(command_line="a b", executable="C:" + BS + "a.exe")
    with pytest.raises(DetectionError):
        _matches(FieldCondition("elastic_sysmon.process.args", "contains", "a"), observation)
    with pytest.raises(DetectionError):
        _matches(FieldCondition("process.executable", "element_contains", "a"), observation)


def test_exists_on_arrays_means_at_least_one_element() -> None:
    args = FieldCondition("elastic_sysmon.process.args", "exists")
    assert _matches(args, _obs(command_line="a"))
    assert not _matches(args, _obs(command_line="   "))  # blank: no argv at all
    assert not _matches(args, _obs(command_line=None))
    no_ip = FieldCondition("host.ip", "exists")
    assert not _matches(no_ip, _obs())  # an empty tuple is not a value


def test_unknown_derived_field_fails_closed() -> None:
    with pytest.raises(DetectionError, match="unknown derived field_path"):
        _matches(FieldCondition("elastic_sysmon.process.nope", "exists"), _obs())


@pytest.mark.parametrize("bad", [(), ("a", ""), ("   ",)])
def test_tuple_values_are_validated(bad: tuple[str, ...]) -> None:
    for operator in ("wildcard", "element_in", "element_contains"):
        with pytest.raises(DetectionError):
            FieldCondition("process.executable", operator, bad)
