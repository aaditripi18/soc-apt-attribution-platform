"""ADR-0025: a rule's ATT&CK tags describe the rule, not the match. A technique
that is one of several alternatives its rule declares is kept and shown, and
never counted when comparing with group profiles — unless a recorded review of
that rule, or an independent rule, establishes it."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest

from attribution_platform.api.read_model import get_investigation_activity
from attribution_platform.attack_knowledge.external_ids import ExternalIdResolver
from attribution_platform.attack_knowledge.loader import AttackKnowledge, load_attack_knowledge
from attribution_platform.detection import load_rule_pack
from attribution_platform.detection.contracts import (
    DetectionResult,
    MatchBasis,
    MatchedField,
    TechniqueMapping,
)
from attribution_platform.detection.evidence import (
    ambiguous_technique_ids,
    derive_evidence_from_detection,
)
from attribution_platform.detection_content.technique_support import (
    EMPTY_REVIEW,
    TechniqueSupportError,
    load_technique_support_review,
)
from attribution_platform.domain import AttackRef
from attribution_platform.extraction import RuleRef

REPO = Path(__file__).resolve().parents[1]
REVIEW = REPO / "data" / "detection" / "technique-support-review.json"
sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_dossier import _investigate  # noqa: E402
from test_indicators import _event_data, _sysmon_1  # noqa: E402

LSASS, SAM, NTDS, DUMPING, MASQUERADING = "T1003.001", "T1003.002", "T1003.003", "T1003", "T1036"


@pytest.fixture(scope="module")
def knowledge() -> AttackKnowledge:
    return load_attack_knowledge()


def _detection(knowledge: AttackKnowledge, *external_ids: str) -> tuple[DetectionResult, Any]:
    (observation,) = (
        __import__("attribution_platform.sources.sysmon", fromlist=["SysmonSourceAdapter"])
        .SysmonSourceAdapter()
        .to_observations(_sysmon_1())
    )
    resolver = ExternalIdResolver(knowledge, ("attack-pattern", "tool"))
    mappings = []
    for external_id in external_ids:
        obj, _ = resolver.resolve(external_id)  # type: ignore[misc]
        mappings.append(
            TechniqueMapping(
                attack_ref=AttackRef(
                    stix_id=str(obj["id"]),
                    object_type=str(obj["type"]),
                    attack_kb_version=knowledge.attack_kb_version,
                    external_id=external_id,
                ),
                mapping_basis="test",
            )
        )
    detection = DetectionResult(
        detection_id=f"rule::{observation.observation_id}",
        rule_ref=RuleRef(rule_id="rule", rule_version="1"),
        detection_source="test:rule",
        supporting_observation_ids=(observation.observation_id,),
        match_basis=MatchBasis((MatchedField("host.name", "exists", "h"),)),
        technique_mappings=tuple(mappings),
    )
    return detection, observation


def _ambiguous(
    knowledge: AttackKnowledge, *ids: str, reviewed: frozenset[str] | None = None
) -> set[str]:
    detection, _ = _detection(knowledge, *ids)
    by_stix = {m.attack_ref.stix_id: m.attack_ref.external_id for m in detection.technique_mappings}
    return {str(by_stix[s]) for s in ambiguous_technique_ids(detection, reviewed)}


def test_what_one_match_establishes(knowledge: AttackKnowledge) -> None:
    # one technique, or a technique with its own sub-technique: one claim
    assert _ambiguous(knowledge, LSASS) == set()
    assert _ambiguous(knowledge, DUMPING, LSASS) == set()
    # several sub-techniques of one parent: the parent holds, each sub is one of several
    assert _ambiguous(knowledge, DUMPING, LSASS, SAM, NTDS) == {LSASS, SAM, NTDS}
    assert _ambiguous(knowledge, LSASS, SAM) == {LSASS, SAM}
    # techniques of different parents: none is established by the match alone
    assert _ambiguous(knowledge, LSASS, MASQUERADING) == {LSASS, MASQUERADING}
    assert _ambiguous(knowledge, DUMPING, LSASS, MASQUERADING) == {DUMPING, LSASS, MASQUERADING}
    # software is not a technique: it neither is ambiguous nor makes one so
    assert _ambiguous(knowledge, LSASS, "S0002") == set()
    # a recorded review establishes exactly what it names
    assert _ambiguous(knowledge, LSASS, MASQUERADING, reviewed=frozenset({LSASS})) == {MASQUERADING}
    # a review is authoritative: an empty one establishes nothing, even for a
    # rule that declares a single technique
    assert _ambiguous(knowledge, LSASS, reviewed=frozenset()) == {LSASS}
    assert _ambiguous(knowledge, DUMPING, LSASS, reviewed=frozenset({DUMPING})) == {LSASS}


def test_declared_techniques_are_kept_and_marked(knowledge: AttackKnowledge) -> None:
    detection, observation = _detection(knowledge, LSASS, MASQUERADING)
    evidence = derive_evidence_from_detection(detection, observation, knowledge=knowledge)
    assert [e.attack_ref.external_id for e in evidence] == [LSASS, MASQUERADING]  # both kept
    assert all(e.technique_ambiguous for e in evidence)
    assert all("one of 2 techniques this rule declares" in e.claim for e in evidence)
    reviewed = derive_evidence_from_detection(
        detection, observation, knowledge=knowledge, reviewed=frozenset({LSASS})
    )
    assert [e.technique_ambiguous for e in reviewed] == [False, True]
    assert "one of" not in reviewed[0].claim
    (single,) = derive_evidence_from_detection(*_detection(knowledge, LSASS), knowledge=knowledge)
    assert single.technique_ambiguous is False


def test_the_tracked_review_is_sound(knowledge: AttackKnowledge) -> None:
    review = load_technique_support_review(REVIEW)
    assert EMPTY_REVIEW.for_source("sigma:x") is None and len(review.sha256) == 64
    declared: dict[str, set[str]] = {}
    for pack in (
        REPO
        / "data/detection/sigma/r2026-07-01/generated/sigma-r2026-07-01-sigma_core++.rules.json",
        REPO / "data/detection/elastic/195f15c0bac8/generated/elastic-195f15c0bac8.rules.json",
    ):
        for rule in load_rule_pack(pack, knowledge=knowledge).rules:
            declared.setdefault(rule.rule_source, set()).update(
                str(m.attack_ref.external_id) for m in rule.technique_mappings
            )
    raw = json.loads(REVIEW.read_text(encoding="utf-8"))["decisions"]
    assert len(raw) == len(review.supported) >= 25
    for entry in raw:
        source = entry["rule_source"]
        # a decision is about a rule that exists, restates what it declares, and
        # establishes only some of that - never a technique the rule does not name
        assert set(entry["declares"]) == declared[source], source
        assert review.for_source(source) <= declared[source], source  # all, some or none


@pytest.mark.parametrize(
    "change",
    [
        {"version": "other"},
        {
            "decisions": [
                {"rule_source": "sigma:a", "rule_name": "n", "reason": "r", "establishes": "T1003"}
            ]
        },
        {
            "decisions": [
                {
                    "rule_source": "sigma:a",
                    "rule_name": "n",
                    "reason": " ",
                    "establishes": ["T1003"],
                }
            ]
        },
        {
            "decisions": [
                {"rule_source": "sigma:a", "rule_name": "n", "reason": "r", "establishes": ["x"]}
            ]
        },
        {
            "decisions": [
                {
                    "rule_source": "sigma:a",
                    "rule_name": "n",
                    "reason": "r",
                    "establishes": ["T1003"],
                },
                {
                    "rule_source": "sigma:a",
                    "rule_name": "n",
                    "reason": "r",
                    "establishes": ["T1003"],
                },
            ]
        },
    ],
)
def test_a_malformed_review_is_refused(tmp_path: Path, change: dict[str, Any]) -> None:
    path = tmp_path / "review.json"
    path.write_text(
        json.dumps({"version": "technique-support-review/1", "decisions": [], **change}),
        encoding="utf-8",
    )
    with pytest.raises(TechniqueSupportError):
        load_technique_support_review(path)


def _run(tmp_path: Path, name: str, command_line: str) -> list[dict[str, Any]]:
    record = _sysmon_1()
    _event_data(record).update(Image="C:\\Program Files\\procdump.exe", CommandLine=command_line)
    client, investigation_id = _investigate(tmp_path, name, json.dumps(record) + "\n")
    return list(get_investigation_activity(client, investigation_id)["events"])


def test_ambiguous_tags_cannot_inflate_the_comparison_and_supported_evidence_is_kept(
    tmp_path: Path,
) -> None:
    # 1. only the tool's name is seen: rules declaring LSASS dumping *and*
    #    masquerading fire, and neither technique is established
    named = _run(tmp_path, "named.jsonl", "procdump.exe -accepteula 4242")
    shown = {e["attack_id"] for e in named}
    assert {LSASS, MASQUERADING} <= shown  # declared, and still shown
    counted = {e["attack_id"] for e in named if e["decision_feature"]}
    assert not counted & {LSASS, MASQUERADING, SAM, NTDS}

    # 2. the dump itself is seen: a reviewed rule establishes LSASS dumping; the
    #    masquerading tag of the same rules still establishes nothing
    dumped = _run(tmp_path, "dumped.jsonl", "procdump.exe -accepteula -ma lsass.exe out.dmp")
    counted = {e["attack_id"] for e in dumped if e["decision_feature"]}
    assert LSASS in counted
    assert MASQUERADING not in counted and MASQUERADING in {e["attack_id"] for e in dumped}
