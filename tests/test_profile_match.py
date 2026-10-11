"""ADR-0021: behavioural profile match and response guidance.

The overlap is one stated formula over ATT&CK's own records; candidates are
ordered by it and those that cannot be told apart form one cluster; mitigations
are ATT&CK's. Nothing here is a likelihood, and no key says it is."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest

from attribution_platform.attack_knowledge.loader import AttackKnowledge, load_attack_knowledge
from attribution_platform.attack_knowledge.traversal import (
    active_groups,
    groups_using_technique,
    techniques_used_by,
)
from attribution_platform.investigation.assessment import assess_investigation, assessment_to_json
from attribution_platform.investigation.profile_match import (
    match_profiles,
    profile_match_to_json,
)

sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_investigation_assessment import _analysis, _technique  # noqa: E402

#: Words that would claim more than a similarity.
FORBIDDEN_KEYS = ("likelihood", "confidence", "wep", "probability", "rank", "score")
OBSERVED = ["T1003.001", "T1059.001", "T1021.002"]


@pytest.fixture(scope="module")
def knowledge() -> AttackKnowledge:
    return load_attack_knowledge()


@pytest.fixture(scope="module")
def match(knowledge: AttackKnowledge) -> dict[str, Any]:
    stix = [_technique(knowledge, t) for t in OBSERVED]
    assessment = assess_investigation(
        knowledge,
        "investigation::x",
        [_analysis(knowledge, "u1", stix[:2]), _analysis(knowledge, "u2", stix[1:])],
    )
    return profile_match_to_json(match_profiles(knowledge, assessment_to_json(assessment)))


def test_weights_are_one_minus_the_share_of_groups_using_the_technique(
    knowledge: AttackKnowledge, match: dict[str, Any]
) -> None:
    total = len(active_groups(knowledge))
    assert match["active_groups"] == total
    assert [t["technique_id"] for t in match["observed"]] == sorted(OBSERVED)
    for technique in match["observed"]:
        users = len(groups_using_technique(knowledge, technique["technique_stix_id"]))
        assert technique["groups_using"] == users
        assert technique["weight"] == pytest.approx(1 - users / total, abs=1e-6)
    assert match["total_weight"] == pytest.approx(sum(t["weight"] for t in match["observed"]))
    # a technique most Groups use weighs less than a rarer one
    by_id = {t["technique_id"]: t for t in match["observed"]}
    assert by_id["T1059.001"]["groups_using"] > by_id["T1021.002"]["groups_using"]
    assert by_id["T1059.001"]["weight"] < by_id["T1021.002"]["weight"]


def test_overlap_is_the_weighted_share_of_observed_behaviour_in_the_profile(
    knowledge: AttackKnowledge, match: dict[str, Any]
) -> None:
    weight = {t["technique_id"]: t["weight"] for t in match["observed"]}
    stix_of = {t["technique_id"]: t["technique_stix_id"] for t in match["observed"]}
    assert match["matches"]
    for row in match["matches"]:
        profile = set(techniques_used_by(knowledge, row["stix_id"]))
        expected = sorted(t for t in OBSERVED if stix_of[t] in profile)
        assert row["matched_technique_ids"] == expected and row["matched"] == len(expected)
        assert row["overlap"] == pytest.approx(
            sum(weight[t] for t in expected) / match["total_weight"], abs=1e-5
        )
        assert 0 < row["overlap"] <= 1
        assert row["profile_techniques"] == len(profile)
        assert row["profile_share"] == pytest.approx(len(expected) / len(profile), abs=1e-5)
        assert row["named_by"] is None
    # a profile holding every observed technique overlaps fully
    assert any(row["overlap"] == 1.0 for row in match["matches"])


def test_candidates_are_ordered_by_overlap_and_ties_form_clusters(match: dict[str, Any]) -> None:
    keys = [
        (-m["overlap"], -m["matched"], m["name"].lower(), m["candidate_id"])
        for m in match["matches"]
    ]
    assert keys == sorted(keys)
    by_cluster: dict[str, list[dict[str, Any]]] = {}
    for row in match["matches"]:
        by_cluster.setdefault(row["cluster_id"], []).append(row)
    assert [c["cluster_id"] for c in match["clusters"]] == list(by_cluster)
    assert match["clusters"][0]["label"] == "Cluster A"
    overlaps = [c["overlap"] for c in match["clusters"]]
    assert overlaps == sorted(overlaps, reverse=True)
    for cluster in match["clusters"]:
        rows = by_cluster[cluster["cluster_id"]]
        # same observed techniques, hence the same overlap: indistinguishable here
        assert {tuple(r["matched_technique_ids"]) for r in rows} == {
            tuple(cluster["matched_technique_ids"])
        }
        assert cluster["member_ids"] == [r["candidate_id"] for r in rows]
        assert cluster["member_names"] == [r["name"] for r in rows]
    assert sum(len(c["member_ids"]) for c in match["clusters"]) == len(match["matches"])
    assert len(match["clusters"]) <= 2 ** len(OBSERVED) - 1
    assert any(len(c["member_ids"]) > 1 for c in match["clusters"])


def test_mitigations_are_attack_s_own_for_the_observed_techniques(
    knowledge: AttackKnowledge, match: dict[str, Any]
) -> None:
    mitigates: dict[str, set[str]] = {}
    parent: dict[str, str] = {}
    for relationship in knowledge.relationships():
        if relationship.get("relationship_type") == "mitigates":
            mitigates.setdefault(str(relationship["target_ref"]), set()).add(
                str(relationship["source_ref"])
            )
        elif relationship.get("relationship_type") == "subtechnique-of":
            parent[str(relationship["source_ref"])] = str(relationship["target_ref"])
    stix_of = {t["technique_id"]: t["technique_stix_id"] for t in match["observed"]}
    assert match["mitigations"]
    for mitigation in match["mitigations"]:
        assert mitigation["mitigation_id"].startswith("M")
        assert mitigation["name"] and mitigation["description"]
        assert "(Citation:" not in mitigation["description"]
        for technique_id in mitigation["technique_ids"]:
            stix_id = stix_of[technique_id]
            sources = mitigates.get(stix_id, set()) | mitigates.get(parent.get(stix_id, ""), set())
            assert mitigation["stix_id"] in sources
    counts = [len(m["technique_ids"]) for m in match["mitigations"]]
    assert counts == sorted(counts, reverse=True)
    covered = {t for m in match["mitigations"] for t in m["technique_ids"]}
    assert covered | set(match["techniques_without_mitigation"]) == set(OBSERVED)


def test_a_group_named_by_specific_evidence_is_marked_and_nothing_claims_likelihood(
    knowledge: AttackKnowledge, match: dict[str, Any]
) -> None:
    def keys(value: Any) -> set[str]:
        if isinstance(value, dict):
            return {str(k).lower() for k in value} | {k for v in value.values() for k in keys(v)}
        if isinstance(value, list):
            return {k for v in value for k in keys(v)}
        return set()

    found = keys(match)
    assert not [k for k in found if any(word in k for word in FORBIDDEN_KEYS)], sorted(found)
    assert json.dumps(match, sort_keys=True) == json.dumps(match, sort_keys=True)

    stix = [_technique(knowledge, t) for t in OBSERVED]
    assessment = assessment_to_json(
        assess_investigation(knowledge, "investigation::y", [_analysis(knowledge, "u1", stix)])
    )
    target = assessment["candidates"][0]
    assessment["actor_leads"] = [{"actor_attack_id": target["candidate_id"]}]
    named = profile_match_to_json(match_profiles(knowledge, assessment))
    marked = [m for m in named["matches"] if m["named_by"] is not None]
    assert [(m["candidate_id"], m["named_by"]) for m in marked] == [
        (target["candidate_id"], "actor_specific")
    ]
    # being named does not move a candidate: the order is the overlap's alone
    assert [m["candidate_id"] for m in named["matches"]] == [
        m["candidate_id"]
        for m in profile_match_to_json(
            match_profiles(knowledge, {**assessment, "actor_leads": []})
        )["matches"]
    ]


def test_nothing_observed_gives_an_empty_match(knowledge: AttackKnowledge) -> None:
    assessment = assessment_to_json(assess_investigation(knowledge, "investigation::z", []))
    empty = profile_match_to_json(match_profiles(knowledge, assessment))
    assert (empty["observed"], empty["matches"], empty["clusters"], empty["mitigations"]) == (
        [],
        [],
        [],
        [],
    )
    assert empty["total_weight"] == 0


def test_a_candidate_linked_only_through_software_has_no_overlap_to_report(
    knowledge: AttackKnowledge,
) -> None:
    """ATT&CK software evidence (a public tool, say) brings in every Group recorded
    using it. Such a candidate shares no observed technique: it is counted, not
    listed with a zero, and the assessment says what links it."""
    stix = [_technique(knowledge, t) for t in OBSERVED]
    analysis = _analysis(knowledge, "u1", stix)
    # a real Group whose profile holds none of the observed techniques
    outsider = next(
        g
        for g in active_groups(knowledge)
        if not set(techniques_used_by(knowledge, str(g["id"]))) & set(stix)
    )
    extra = {
        "stix_id": str(outsider["id"]),
        "name": str(outsider["name"]),
        "kind": "group",
        "attack_external_id": "G9999",
        "candidate_id": "candidate::software-only",
        "generation_basis": ["tool--x"],
    }
    analysis["candidates"] = [*analysis["candidates"], extra]
    assessment = assessment_to_json(assess_investigation(knowledge, "investigation::s", [analysis]))
    listed = {c["candidate_id"]: c for c in assessment["candidates"]}
    assert listed["G9999"]["matched_technique_ids"] == []
    assert any("linked only through software observed here" in r for r in assessment["reasons"])
    with_technique = len(assessment["candidates"]) - 1
    assert assessment["reasons"][0].startswith(f"{with_technique} ATT&CK Groups and Campaigns")

    match = profile_match_to_json(match_profiles(knowledge, assessment))
    assert "G9999" not in {m["candidate_id"] for m in match["matches"]}
    assert match["candidates_without_technique_overlap"] == 1
    assert len(match["matches"]) == with_technique
    assert all(m["matched"] >= 1 and m["overlap"] > 0 for m in match["matches"])
