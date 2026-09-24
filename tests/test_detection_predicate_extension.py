"""ADR-0007 D4 predicate-language extension tests.

Covers ``startswith``/``endswith``/``has_element``, the per-condition
``case_insensitive`` and ``negate`` flags (incl. Sigma's absent-field-under-NOT
semantics), array-field fail-closed behaviour, rule-pack loading of the new
keys, Evidence claim wording, and backward compatibility: conditions that do
not use the new flags behave, and are explained, exactly as before.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from attribution_platform.attack_knowledge.loader import AttackKnowledge, load_attack_knowledge
from attribution_platform.detection import (
    DetectionEngine,
    DetectionError,
    DetectionRule,
    FieldCondition,
    MatchedField,
    derive_evidence_from_detection,
    load_rule_pack,
)
from attribution_platform.domain import EventMetadata, Observation, ProcessRef, SourceRef
from attribution_platform.extraction import RuleRef

REPO_ROOT = Path(__file__).resolve().parents[1]
#: The fixture rule packs, Phase-0 scenarios and calibration corpus v1 used here are
#: frozen against this ATT&CK release (doc 11 §0 upgrade record); they load it by name.
FIXTURE_ATTACK_KB = "enterprise-attack-19.0"
CORE_RULES_PATH = REPO_ROOT / "fixtures" / "phase1_core_rules.json"
T0 = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)


@pytest.fixture(scope="module")
def knowledge() -> AttackKnowledge:
    return load_attack_knowledge(FIXTURE_ATTACK_KB)


def _obs(observation_id: str = "o1", **entities: Any) -> Observation:
    return Observation(
        observation_id=observation_id,
        timestamp=T0,
        raw_reference=SourceRef(source_type="synthetic", source_event_id=f"raw-{observation_id}"),
        **entities,
    )


def _proc_obs(executable: str | None = None, command_line: str | None = None) -> Observation:
    return _obs(
        process=ProcessRef(executable=executable, command_line=command_line),
        event=EventMetadata(kind="event", category=("process",), type=("start",)),
    )


# ===========================================================================
# startswith / endswith
# ===========================================================================


@pytest.mark.parametrize(
    ("operator", "value", "matches"),
    [
        ("endswith", "\\cmd.exe", True),
        ("endswith", "\\CMD.EXE", False),  # case-sensitive by default
        ("endswith", "\\powershell.exe", False),
        ("startswith", "C:\\Windows\\", True),
        ("startswith", "c:\\windows\\", False),
        ("startswith", "D:\\", False),
    ],
)
def test_startswith_endswith(operator: str, value: str, matches: bool) -> None:
    condition = FieldCondition("process.executable", operator, value)
    result = condition.evaluate(_proc_obs(executable="C:\\Windows\\System32\\cmd.exe"))
    assert (result is not None) is matches
    if result is not None:
        assert result.operator == operator
        assert result.expected == value
        assert result.observed == "C:\\Windows\\System32\\cmd.exe"


def test_startswith_endswith_absent_field_does_not_match() -> None:
    for operator in ("startswith", "endswith"):
        assert FieldCondition("process.executable", operator, "x").evaluate(_proc_obs()) is None


# ===========================================================================
# case_insensitive
# ===========================================================================


@pytest.mark.parametrize(
    ("operator", "value"),
    [
        ("equals", "c:\\windows\\system32\\CMD.exe"),
        ("contains", "SYSTEM32"),
        ("startswith", "c:\\WINDOWS"),
        ("endswith", "\\CMD.EXE"),
        ("in", ("c:\\other.exe", "C:\\WINDOWS\\SYSTEM32\\CMD.EXE")),
    ],
)
def test_case_insensitive_matches_across_operators(
    operator: str, value: str | tuple[str, ...]
) -> None:
    obs = _proc_obs(executable="C:\\Windows\\System32\\cmd.exe")
    assert FieldCondition("process.executable", operator, value).evaluate(obs) is None
    result = FieldCondition("process.executable", operator, value, case_insensitive=True).evaluate(
        obs
    )
    assert result is not None
    assert result.case_insensitive is True
    assert result.observed == "C:\\Windows\\System32\\cmd.exe"  # recorded verbatim, not folded


def test_case_insensitive_uses_casefold_not_lower() -> None:
    # casefold maps "ß" to "ss"; lower() would not.
    obs = _proc_obs(command_line="STRASSE")
    assert (
        FieldCondition("process.command_line", "equals", "straße", case_insensitive=True).evaluate(
            obs
        )
        is not None
    )


def test_case_insensitive_rejected_for_exists() -> None:
    with pytest.raises(DetectionError, match="meaningless"):
        FieldCondition("process.executable", "exists", case_insensitive=True)


# ===========================================================================
# negate
# ===========================================================================


def test_negate_matches_when_positive_predicate_fails() -> None:
    condition = FieldCondition("process.executable", "endswith", "\\explorer.exe", negate=True)
    result = condition.evaluate(_proc_obs(executable="C:\\Windows\\System32\\cmd.exe"))
    assert result is not None
    assert result.negated is True
    assert result.field_present is True
    assert result.observed == "C:\\Windows\\System32\\cmd.exe"


def test_negate_rejects_when_positive_predicate_matches() -> None:
    condition = FieldCondition("process.executable", "endswith", "\\explorer.exe", negate=True)
    assert condition.evaluate(_proc_obs(executable="C:\\Windows\\explorer.exe")) is None


def test_negate_on_absent_field_matches_sigma_semantics() -> None:
    condition = FieldCondition("process.executable", "endswith", "\\explorer.exe", negate=True)
    result = condition.evaluate(_proc_obs(command_line="whoami"))
    assert result is not None
    assert result.field_present is False
    assert result.observed == ""


def test_negate_absent_entity_group_matches() -> None:
    condition = FieldCondition("process.executable", "equals", "x", negate=True)
    result = condition.evaluate(_obs())  # no process entity at all
    assert result is not None
    assert result.field_present is False


def test_negate_exists() -> None:
    condition = FieldCondition("process.command_line", "exists", negate=True)
    assert condition.evaluate(_proc_obs(executable="a.exe")) is not None
    assert condition.evaluate(_proc_obs(command_line="x")) is None


def test_negate_combines_with_case_insensitive() -> None:
    condition = FieldCondition(
        "process.executable", "endswith", "\\EXPLORER.EXE", case_insensitive=True, negate=True
    )
    assert condition.evaluate(_proc_obs(executable="C:\\Windows\\explorer.exe")) is None
    assert condition.evaluate(_proc_obs(executable="C:\\Windows\\cmd.exe")) is not None


# ===========================================================================
# has_element (array fields)
# ===========================================================================


def test_has_element_matches_array_membership() -> None:
    obs = _proc_obs(executable="a.exe")
    result = FieldCondition("event.category", "has_element", "process").evaluate(obs)
    assert result is not None
    assert result.observed == "process"
    assert FieldCondition("event.category", "has_element", "network").evaluate(obs) is None


def test_has_element_is_exact_not_substring() -> None:
    obs = _proc_obs(executable="a.exe")
    assert FieldCondition("event.category", "has_element", "proc").evaluate(obs) is None


def test_has_element_multi_element_array() -> None:
    obs = _obs(
        event=EventMetadata(kind="event", category=("network",), type=("connection", "start"))
    )
    result = FieldCondition("event.type", "has_element", "start").evaluate(obs)
    assert result is not None
    assert result.observed == "connection,start"


def test_has_element_case_insensitive_and_negate() -> None:
    obs = _proc_obs(executable="a.exe")
    assert (
        FieldCondition("event.category", "has_element", "PROCESS", case_insensitive=True).evaluate(
            obs
        )
        is not None
    )
    assert (
        FieldCondition("event.category", "has_element", "process", negate=True).evaluate(obs)
        is None
    )
    assert (
        FieldCondition("event.category", "has_element", "network", negate=True).evaluate(obs)
        is not None
    )


def test_has_element_on_empty_or_absent_array() -> None:
    no_event = _obs()
    assert FieldCondition("event.category", "has_element", "process").evaluate(no_event) is None
    empty = _obs(event=EventMetadata(kind="event"))
    assert FieldCondition("event.category", "has_element", "process").evaluate(empty) is None


def test_has_element_on_scalar_field_fails_closed() -> None:
    with pytest.raises(DetectionError, match="requires an array-typed field"):
        FieldCondition("process.executable", "has_element", "a.exe").evaluate(
            _proc_obs(executable="a.exe")
        )


@pytest.mark.parametrize("operator", ["equals", "contains", "startswith", "endswith"])
def test_scalar_operators_still_reject_array_fields(operator: str) -> None:
    with pytest.raises(DetectionError, match="only operator 'has_element'"):
        FieldCondition("event.category", operator, "process").evaluate(_proc_obs(executable="a"))


def test_negate_does_not_bypass_array_rejection() -> None:
    with pytest.raises(DetectionError):
        FieldCondition("event.category", "equals", "x", negate=True).evaluate(
            _proc_obs(executable="a")
        )


# ===========================================================================
# Construction validation
# ===========================================================================


@pytest.mark.parametrize("operator", ["startswith", "endswith", "has_element"])
def test_new_operators_require_nonempty_string_value(operator: str) -> None:
    for bad in (None, "", "   ", ("a",)):
        with pytest.raises(DetectionError):
            FieldCondition("process.executable", operator, bad)


@pytest.mark.parametrize("flag", ["case_insensitive", "negate"])
def test_flags_must_be_bool(flag: str) -> None:
    with pytest.raises(DetectionError, match="must be a bool"):
        FieldCondition("process.executable", "equals", "a", **{flag: 1})  # type: ignore[arg-type]


def test_matched_field_absent_requires_negation_and_empty_observed() -> None:
    with pytest.raises(DetectionError, match="only valid for a negated"):
        MatchedField(
            field_path="process.executable", operator="equals", observed="", field_present=False
        )
    with pytest.raises(DetectionError, match="must be ''"):
        MatchedField(
            field_path="process.executable",
            operator="equals",
            observed="x",
            negated=True,
            field_present=False,
        )


def test_matched_field_defaults_preserve_original_shape() -> None:
    mf = MatchedField(field_path="process.name", operator="contains", observed="a", expected="a")
    assert (mf.negated, mf.case_insensitive, mf.field_present) == (False, False, True)


# ===========================================================================
# Rule-pack loading
# ===========================================================================


def _write_pack(tmp_path: Path, conditions: list[dict[str, Any]]) -> Path:
    path = tmp_path / "pack.json"
    path.write_text(
        json.dumps(
            {
                "pack_id": "t",
                "rules": [{"rule_id": "r", "rule_version": "1", "conditions": conditions}],
            }
        ),
        encoding="utf-8",
    )
    return path


def test_pack_loads_new_operators_and_flags(tmp_path: Path, knowledge: AttackKnowledge) -> None:
    path = _write_pack(
        tmp_path,
        [
            {"field_path": "event.category", "operator": "has_element", "value": "process"},
            {
                "field_path": "process.executable",
                "operator": "endswith",
                "value": "\\cmd.exe",
                "case_insensitive": True,
            },
            {
                "field_path": "process.command_line",
                "operator": "contains",
                "value": "/c exit",
                "negate": True,
            },
        ],
    )
    (rule,) = load_rule_pack(path, knowledge=knowledge).rules
    assert rule.conditions[1].case_insensitive is True
    assert rule.conditions[2].negate is True
    assert rule.conditions[0].case_insensitive is False and rule.conditions[0].negate is False


@pytest.mark.parametrize("flag", ["case_insensitive", "negate"])
def test_pack_rejects_non_boolean_flag(
    tmp_path: Path, knowledge: AttackKnowledge, flag: str
) -> None:
    path = _write_pack(
        tmp_path,
        [{"field_path": "process.executable", "operator": "equals", "value": "a", flag: "true"}],
    )
    with pytest.raises(DetectionError, match="JSON boolean"):
        load_rule_pack(path, knowledge=knowledge)


def test_existing_core_pack_conditions_use_default_semantics(knowledge: AttackKnowledge) -> None:
    pack = load_rule_pack(CORE_RULES_PATH, knowledge=knowledge)
    for rule in pack.rules:
        for condition in rule.conditions:
            assert condition.case_insensitive is False
            assert condition.negate is False


# ===========================================================================
# End to end: a Sigma-shaped "selection and not filter" rule
# ===========================================================================


def _sigma_shaped_rule() -> DetectionRule:
    return DetectionRule(
        rule_ref=RuleRef(rule_id="sigma-shaped", rule_version="1"),
        conditions=(
            FieldCondition("event.category", "has_element", "process"),
            FieldCondition("process.executable", "endswith", "\\whoami.exe", case_insensitive=True),
            FieldCondition(
                "process.command_line", "contains", "/all", case_insensitive=True, negate=True
            ),
        ),
    )


def test_selection_and_not_filter_end_to_end(knowledge: AttackKnowledge) -> None:
    rule = _sigma_shaped_rule()
    fires = _proc_obs(executable="C:\\Windows\\System32\\WHOAMI.EXE", command_line="whoami")
    filtered = _proc_obs(executable="C:\\Windows\\System32\\whoami.exe", command_line="whoami /ALL")
    network = _obs(
        process=ProcessRef(executable="C:\\Windows\\System32\\whoami.exe"),
        event=EventMetadata(kind="event", category=("network",)),
    )
    results = DetectionEngine(rules=(rule,)).evaluate([fires, filtered, network])
    assert len(results) == 1
    (evidence,) = derive_evidence_from_detection(results[0], fires, knowledge=knowledge)
    assert "event.category has_element 'process'" in evidence.claim
    assert "process.executable endswith '\\\\whoami.exe' (case-insensitive)" in evidence.claim
    assert "process.command_line not contains '/all' (case-insensitive)" in evidence.claim


def test_absent_field_is_stated_in_claim(knowledge: AttackKnowledge) -> None:
    rule = _sigma_shaped_rule()
    obs = _proc_obs(executable="C:\\Windows\\System32\\whoami.exe")  # no command line
    (result,) = DetectionEngine(rules=(rule,)).evaluate([obs])
    (evidence,) = derive_evidence_from_detection(result, obs, knowledge=knowledge)
    assert "process.command_line not contains '/all' (case-insensitive) (field absent)" in (
        evidence.claim
    )


def test_claim_without_new_flags_keeps_original_wording(knowledge: AttackKnowledge) -> None:
    rule = DetectionRule(
        rule_ref=RuleRef(rule_id="plain", rule_version="1"),
        conditions=(
            FieldCondition("process.executable", "contains", "cmd"),
            FieldCondition("process.command_line", "exists"),
        ),
    )
    obs = _proc_obs(executable="cmd.exe", command_line="/c dir")
    (result,) = DetectionEngine(rules=(rule,)).evaluate([obs])
    (evidence,) = derive_evidence_from_detection(result, obs, knowledge=knowledge)
    assert evidence.claim == (
        "rule plain v1 (platform-rules) matched: "
        "process.executable contains 'cmd'; process.command_line exists"
    )
