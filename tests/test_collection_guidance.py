"""Evidence-collection guidance (ADR-0005 Amendment E) on the pinned ATT&CK KB:
facts only (which candidates use a technique, how many the answer would set
apart, MITRE's data components, this platform's detectability), a deterministic
order over questions — never over candidates — and a fail-closed reader of the
pack's own reports."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from attribution_platform.attack_knowledge.loader import AttackKnowledge, load_attack_knowledge
from attribution_platform.attack_knowledge.traversal import (
    resolve_alias,
    techniques_used_by,
)
from attribution_platform.attribution.collection_guidance import (
    Detectability,
    compute_collection_guidance,
)
from attribution_platform.detection_content.detectability import (
    DetectabilityError,
    load_detectability,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
GENERATED = REPO_ROOT / "data" / "detection" / "sigma" / "r2026-07-01" / "generated"
COVERAGE = GENERATED / "coverage-report.json"
IMPORT_REPORT = GENERATED / "sigma-r2026-07-01-sigma_core++.import-report.json"
ELASTIC_IMPORT_REPORT = (
    REPO_ROOT
    / "data"
    / "detection"
    / "elastic"
    / "195f15c0bac8"
    / "generated"
    / "elastic-195f15c0bac8.import-report.json"
)


@pytest.fixture(scope="module")
def knowledge() -> AttackKnowledge:
    return load_attack_knowledge()


def _group(knowledge: AttackKnowledge, name: str) -> str:
    stix_id = resolve_alias(knowledge, name)
    assert stix_id is not None, name
    return stix_id


@pytest.fixture(scope="module")
def three_groups(knowledge: AttackKnowledge) -> list[tuple[str, str]]:
    return [(f"cand-{n}", _group(knowledge, n)) for n in ("APT29", "APT28", "Turla")]


def test_split_counts_are_exact_attack_facts(
    knowledge: AttackKnowledge, three_groups: list[tuple[str, str]]
) -> None:
    guidance = compute_collection_guidance(
        knowledge, candidates=three_groups, observed_technique_stix_ids=(), max_questions=500
    )
    profiles = {cid: set(techniques_used_by(knowledge, sid)) for cid, sid in three_groups}
    assert guidance.candidates_total == 3
    for q in guidance.questions:
        users = {cid for cid, techniques in profiles.items() if q.technique_stix_id in techniques}
        assert set(q.candidates_using) == users
        assert q.split == min(len(users), 3 - len(users)) >= 1
    # every technique used by some but not all candidates is a question
    some = set().union(*profiles.values())
    every = set.intersection(*profiles.values())
    assert guidance.questions_considered == len(some - every)


def test_order_is_split_then_detectability_then_id(
    knowledge: AttackKnowledge, three_groups: list[tuple[str, str]]
) -> None:
    guidance = compute_collection_guidance(
        knowledge, candidates=three_groups, observed_technique_stix_ids=(), max_questions=500
    )
    keys = [
        (
            -q.split,
            not (q.detectability is not None and q.detectability.detectable),
            q.technique_id,
        )
        for q in guidance.questions
    ]
    assert keys == sorted(keys)


def test_observed_techniques_are_not_asked_again(
    knowledge: AttackKnowledge, three_groups: list[tuple[str, str]]
) -> None:
    first = compute_collection_guidance(
        knowledge, candidates=three_groups, observed_technique_stix_ids=()
    ).questions[0]
    again = compute_collection_guidance(
        knowledge,
        candidates=three_groups,
        observed_technique_stix_ids=(first.technique_stix_id,),
        max_questions=500,
    )
    assert first.technique_stix_id not in {q.technique_stix_id for q in again.questions}


def test_a_single_candidate_has_nothing_to_separate(knowledge: AttackKnowledge) -> None:
    guidance = compute_collection_guidance(
        knowledge,
        candidates=[("only", _group(knowledge, "APT29"))],
        observed_technique_stix_ids=(),
    )
    assert guidance.questions == () and guidance.questions_considered == 0


def test_questions_carry_attack_data_components_and_a_plain_rationale(
    knowledge: AttackKnowledge, three_groups: list[tuple[str, str]]
) -> None:
    detect = {"T1003.001": Detectability(status="covered", logsources=("windows/process_access",))}
    guidance = compute_collection_guidance(
        knowledge, candidates=three_groups, observed_technique_stix_ids=(), detectability=detect
    )
    assert guidance.questions
    assert any(q.data_components for q in guidance.questions)  # MITRE's detection model
    q = guidance.questions[0]
    assert f"{len(q.candidates_using)} of 3 candidates use {q.technique_id}" in q.rationale


def test_deterministic_and_bounded(
    knowledge: AttackKnowledge, three_groups: list[tuple[str, str]]
) -> None:
    a = compute_collection_guidance(
        knowledge, candidates=three_groups, observed_technique_stix_ids=(), max_questions=3
    )
    b = compute_collection_guidance(
        knowledge, candidates=list(reversed(three_groups)), observed_technique_stix_ids=()
    )
    assert len(a.questions) == 3
    assert a.questions == b.questions[:3]
    with pytest.raises(ValueError, match="max_questions"):
        compute_collection_guidance(
            knowledge, candidates=three_groups, observed_technique_stix_ids=(), max_questions=0
        )


# ===========================================================================
# Detectability from the pack's own reports
# ===========================================================================


def test_detectability_reads_the_pack_reports() -> None:
    coverage = json.loads(COVERAGE.read_text(encoding="utf-8"))
    pack_hashes = [p["content_hash"] for p in coverage["provenance"]["rule_packs"]]
    detect = load_detectability(
        COVERAGE, (IMPORT_REPORT, ELASTIC_IMPORT_REPORT), pack_content_hash=pack_hashes
    )
    assert detect["T1003.001"].detectable
    # Covered only by Elastic content (ADR-0015): its Sysmon event profiles' logsources.
    assert detect["T1127.001"].detectable  # MSBuild
    assert detect["T1127.001"].logsources
    assert "windows/process_access" in detect["T1003.001"].logsources
    assert detect["T1059.002"].logsources == ("macos/process_creation",)  # AppleScript
    pre = detect["T1583.001"]  # Acquire Infrastructure: Domains (PRE)
    assert not pre.detectable and pre.logsources == ()


def test_detectability_refuses_a_report_built_for_another_pack() -> None:
    with pytest.raises(DetectabilityError, match="regenerate"):
        load_detectability(COVERAGE, IMPORT_REPORT, pack_content_hash="0" * 64)


def test_detectability_refuses_a_partial_pack_set() -> None:
    coverage = json.loads(COVERAGE.read_text(encoding="utf-8"))
    sigma_only = coverage["provenance"]["rule_packs"][0]["content_hash"]
    with pytest.raises(DetectabilityError, match="regenerate"):
        load_detectability(COVERAGE, IMPORT_REPORT, pack_content_hash=sigma_only)
