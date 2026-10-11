"""ADR-0017: the investigation-level attribution assessment.

A verdict with its reasons, built from the stored unit analyses: it can say that
nothing is attributable, that many actors are consistent and none stands out, or
that an advisory indicator names an actor (a lead). It can never name an actor
on technique overlap, and it never orders candidates.
"""

from __future__ import annotations

import dataclasses
import json
from typing import Any

import pytest

from attribution_platform.attack_knowledge.loader import AttackKnowledge, load_attack_knowledge
from attribution_platform.attack_knowledge.traversal import (
    active_campaigns,
    active_groups,
    groups_using_technique,
    techniques_used_by,
)
from attribution_platform.investigation.assessment import (
    InvestigationAssessmentRecord,
    Verdict,
    assess_investigation,
    assessment_to_json,
)

FORBIDDEN_KEYS = ("likelihood", "confidence", "wep", "probability", "rank", "score")


@pytest.fixture(scope="module")
def knowledge() -> AttackKnowledge:
    return load_attack_knowledge()


def _external(obj: Any) -> str:
    return next(
        str(r["external_id"])
        for r in obj["external_references"]
        if r.get("source_name") == "mitre-attack"
    )


def _technique(knowledge: AttackKnowledge, attack_id: str) -> str:
    return next(
        str(o["id"])
        for o in (*knowledge.techniques(), *knowledge.sub_techniques())
        if _external(o) == attack_id
    )


def _analysis(
    knowledge: AttackKnowledge,
    group_id: str,
    techniques: list[str],
    indicator_matches: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """A stored unit analysis as the read model holds it: the candidates are every
    active Group / Campaign whose profile includes an observed technique."""
    observed = set(techniques)
    candidates = []
    for kind, objects in (
        ("group", active_groups(knowledge)),
        ("campaign", active_campaigns(knowledge)),
    ):
        for obj in objects:
            basis = sorted(set(techniques_used_by(knowledge, str(obj["id"]))) & observed)
            if basis:
                candidates.append(
                    {
                        "stix_id": str(obj["id"]),
                        "name": str(obj["name"]),
                        "kind": kind,
                        "attack_external_id": _external(obj),
                        "generation_basis": basis,
                    }
                )
    return {
        "group_id": group_id,
        "observed_feature_technique_ids": sorted(observed),
        "candidates": candidates,
        "indicator_matches": indicator_matches or [],
    }


def _keys(value: Any) -> set[str]:
    if isinstance(value, dict):
        return {str(k).lower() for k in value} | {k for v in value.values() for k in _keys(v)}
    if isinstance(value, list):
        return {k for v in value for k in _keys(v)}
    return set()


def test_nothing_observed_is_not_attributable(knowledge: AttackKnowledge) -> None:
    record = assess_investigation(knowledge, "inv", [_analysis(knowledge, "u1", [])])
    assert record.verdict is Verdict.NO_DECISION_FEATURES
    assert record.candidates == () and record.overlap_counts == () and record.reasons == ()
    assert (record.units_total, record.units_with_decision_features) == (1, 0)
    assert "Nothing here can be attributed" in record.statement


def test_shared_techniques_single_no_actor_out(knowledge: AttackKnowledge) -> None:
    lsass, powershell = _technique(knowledge, "T1003.001"), _technique(knowledge, "T1059.001")
    analyses = [
        _analysis(knowledge, "u1", [lsass]),
        _analysis(knowledge, "u2", [lsass, powershell]),
    ]
    record = assess_investigation(knowledge, "inv", analyses)
    assert record.verdict is Verdict.NOT_DISTINGUISHABLE
    assert "No actor can be singled out" in record.statement
    assert [t.technique_id for t in record.observed_techniques] == ["T1003.001", "T1059.001"]
    by_id = {t.technique_id: t for t in record.observed_techniques}
    assert by_id["T1003.001"].units == 2 and by_id["T1059.001"].units == 1
    assert by_id["T1003.001"].groups_using == len(groups_using_technique(knowledge, lsass))

    # candidates: exactly the actors whose profile includes an observed technique
    expected = {
        str(o["id"])
        for o in (*active_groups(knowledge), *active_campaigns(knowledge))
        if set(techniques_used_by(knowledge, str(o["id"]))) & {lsass, powershell}
    }
    assert {c.stix_id for c in record.candidates} == expected
    assert record.candidate_groups + record.candidate_campaigns == len(expected)
    for candidate in record.candidates:
        profile = set(techniques_used_by(knowledge, candidate.stix_id))
        want = sorted(
            t for t, s in (("T1003.001", lsass), ("T1059.001", powershell)) if s in profile
        )
        assert list(candidate.matched_technique_ids) == want
        assert candidate.profile_techniques == len(profile)

    # name order, never overlap order
    names = [c.name.lower() for c in record.candidates]
    assert names == sorted(names)
    matched = [len(c.matched_technique_ids) for c in record.candidates]
    assert matched != sorted(matched, reverse=True), "the fixture must not be accidentally sorted"

    # the counts are counts of those facts
    counts = {c.min_matched: c.candidates for c in record.overlap_counts}
    assert counts[1] == len(expected)
    assert counts[2] == sum(1 for c in record.candidates if len(c.matched_technique_ids) == 2)
    assert str(len(expected)) in record.reasons[0]


def test_an_advisory_indicator_is_a_lead_not_a_conclusion(knowledge: AttackKnowledge) -> None:
    lsass = _technique(knowledge, "T1003.001")
    match = {
        "named_actor": "Volt Typhoon",
        "named_actor_attack_id": "G1017",
        "indicator_name": "file hash",
        "kind": "sha256",
        "value": "ab" * 32,
        "report_name": "MAR-10448362",
        "within_validity": True,
        "attribution_quote": "…",
    }
    unnamed = {**match, "named_actor": None, "value": "cd" * 32}
    record = assess_investigation(
        knowledge, "inv", [_analysis(knowledge, "u1", [lsass], [match, unnamed])]
    )
    assert record.verdict is Verdict.THIRD_PARTY_LEAD
    assert [lead.actor_name for lead in record.indicator_leads] == ["Volt Typhoon"]
    assert "No actor can be singled out from the observed behaviour" in record.statement
    assert "the publisher's claim" in record.statement and "not a conclusion" in record.statement
    # a lead without any decision feature is still not an attribution of behaviour
    bare = assess_investigation(knowledge, "inv", [_analysis(knowledge, "u1", [], [match])])
    assert bare.verdict is Verdict.NO_DECISION_FEATURES


def test_no_verdict_names_an_actor_and_no_field_orders_them(knowledge: AttackKnowledge) -> None:
    assert {v.value for v in Verdict} == {
        "no_decision_features",
        "not_distinguishable",
        "third_party_lead",
        "actor_specific_evidence",  # ADR-0018: only from evidence specific to the Group
    }
    fields = {f.name for f in dataclasses.fields(InvestigationAssessmentRecord)}
    assert not [f for f in fields if any(word in f for word in FORBIDDEN_KEYS)]
    record = assess_investigation(
        knowledge, "inv", [_analysis(knowledge, "u1", [_technique(knowledge, "T1548")])]
    )
    # T1548 itself is recorded for a single Group; that is not a verdict.
    assert record.observed_techniques[0].groups_using == 1
    assert record.verdict is Verdict.NOT_DISTINGUISHABLE
    only = record.candidates[0].name
    assert only not in record.statement and all(only not in r for r in record.reasons)
    body = assessment_to_json(record)
    assert not [k for k in _keys(body) if any(word in k for word in FORBIDDEN_KEYS)]


def test_assessment_is_deterministic_and_order_independent(knowledge: AttackKnowledge) -> None:
    a = _analysis(knowledge, "u1", [_technique(knowledge, "T1003.001")])
    b = _analysis(knowledge, "u2", [_technique(knowledge, "T1059.001")])
    first = json.dumps(assessment_to_json(assess_investigation(knowledge, "inv", [a, b])))
    second = json.dumps(assessment_to_json(assess_investigation(knowledge, "inv", [b, a])))
    assert first == second
