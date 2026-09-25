"""Tests for gate G2.3: golden corpus + replay + correlation persistence.

Covers: the checked-in fixture (fixtures/phase2_correlation_scenarios.json)
loads and every scenario genuinely fires against the real, unmodified
fixtures/phase1_core_rules.json rule pack; every structural dimension
(SHARED_OBSERVATION, SAME_PROCESS_ENTITY, PROCESS_LINEAGE) and every
contextual dimension (SAME_HOST_ID, SAME_HOST_NAME, SAME_USER_ID,
SAME_USER_NAME, SAME_DESTINATION_IP) is exercised by at least one golden
scenario, computed by the real G2.1/G2.2 engines (never hand-authored);
CR-1 (contextual links never merge or create groups, even across many
dimensions or a shared host); host-scoped SAME_PROCESS_ENTITY remains
unconditionally structural regardless of timestamp (no temporal-expiry
logic introduced); deterministic replay across independent runs;
persistence round-trip and idempotent replay for CorrelationLink/
CorrelationGroup; the full raw fixture -> Observation -> Evidence ->
CorrelationLink -> CorrelationGroup provenance chain; changing a source
Observation changes the correlation result; and architecture guards proving
this module never fabricates a CorrelationLink/CorrelationGroup and never
feeds ATT&CK knowledge into correlation.

This is a validation/integration gate, not the attribution engine: no
likelihood, confidence, scoring, candidate-generation, or ATT&CK-attribution
logic exists anywhere in this file or the modules it exercises.

Does NOT touch fixtures/phase1_core_rules.json, fixtures/phase1_detection_replay.json,
or any G2.0/G2.1/G2.2 module. Offline, deterministic.
"""

from __future__ import annotations

import ast
import json
from collections.abc import Mapping
from pathlib import Path

import pytest

from attribution_platform.attack_knowledge.loader import AttackKnowledge, load_attack_knowledge
from attribution_platform.correlation import CorrelationGroup, CorrelationLink, LinkClass
from attribution_platform.dataplane import (
    CORRELATION_GROUPS_INDEX,
    CORRELATION_LINKS_INDEX,
    FakeElasticClient,
    load_correlation_group,
    load_correlation_link,
)
from attribution_platform.detection import DetectionEngine, RulePack, load_rule_pack
from attribution_platform.domain import Evidence, to_canonical_json
from attribution_platform.replay import (
    CorrelationReplayResult,
    DetectionReplayResult,
    load_detection_replay_fixture_file,
    replay_fixture_through_correlation,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
#: The fixture rule packs, Phase-0 scenarios and calibration corpus v1 used here are
#: frozen against this ATT&CK release (doc 11 §0 upgrade record); they load it by name.
FIXTURE_ATTACK_KB = "enterprise-attack-19.0"
FIXTURE_PATH = REPO_ROOT / "fixtures" / "phase2_correlation_scenarios.json"
RULE_PACK_PATH = REPO_ROOT / "fixtures" / "phase1_core_rules.json"
CORRELATION_PIPELINE_FILE = (
    REPO_ROOT / "src" / "attribution_platform" / "replay" / "correlation_pipeline.py"
)


@pytest.fixture(scope="module")
def knowledge() -> AttackKnowledge:
    return load_attack_knowledge(FIXTURE_ATTACK_KB)


@pytest.fixture()
def rule_pack(knowledge: AttackKnowledge) -> RulePack:
    return load_rule_pack(RULE_PACK_PATH, knowledge=knowledge)


@pytest.fixture()
def engine(rule_pack: RulePack) -> DetectionEngine:
    return DetectionEngine(rules=rule_pack.rules)


def _replay(engine: DetectionEngine, knowledge: AttackKnowledge) -> CorrelationReplayResult:
    fixture = load_detection_replay_fixture_file(FIXTURE_PATH)
    return replay_fixture_through_correlation(
        fixture, client=FakeElasticClient(), engine=engine, knowledge=knowledge
    )


def _by_scenario(
    results: tuple[DetectionReplayResult, ...],
) -> dict[str, DetectionReplayResult]:
    return {r.scenario_id: r for r in results}


def _single_evidence(result: DetectionReplayResult) -> Evidence:
    assert len(result.evidences) == 1
    return result.evidences[0]


def _evidence_with_attack_ref(result: DetectionReplayResult, *, present: bool) -> Evidence:
    matches = [e for e in result.evidences if (e.attack_ref is not None) == present]
    assert len(matches) == 1
    return matches[0]


def _group_containing(groups: tuple[CorrelationGroup, ...], evidence_id: str) -> CorrelationGroup:
    matches = [g for g in groups if evidence_id in g.member_evidence_ids]
    assert len(matches) == 1, f"expected exactly one group containing {evidence_id!r}"
    return matches[0]


def _no_group_contains(groups: tuple[CorrelationGroup, ...], evidence_id: str) -> None:
    assert not any(evidence_id in g.member_evidence_ids for g in groups)


def _links_between(
    links: tuple[CorrelationLink, ...], id_a: str, id_b: str, link_class: LinkClass
) -> tuple[CorrelationLink, ...]:
    return tuple(
        link
        for link in links
        if link.link_class == link_class and {link.anchor_a, link.anchor_b} == {id_a, id_b}
    )


# ===========================================================================
# 1. Fixture validation
# ===========================================================================


def test_the_checked_in_fixture_loads_and_is_well_formed() -> None:
    fixture = load_detection_replay_fixture_file(FIXTURE_PATH)
    assert fixture.fixture_id == "phase2-correlation-scenarios"
    assert len(fixture.content_hash) == 64
    assert len(fixture.scenarios) == 28


def test_every_golden_scenario_fires_against_the_real_rule_pack(
    engine: DetectionEngine, knowledge: AttackKnowledge
) -> None:
    """Sanity check on the corpus design itself: every scenario is
    constructed to match at least one real rule (two scenarios match two),
    for a total of 30 Evidence items across 28 raw telemetry records."""
    result = _replay(engine, knowledge)
    detection_results = result.detection_results
    assert len(detection_results) == 28
    assert all(r.detections for r in detection_results)
    total_evidence = sum(len(r.evidences) for r in detection_results)
    assert total_evidence == 30


# ===========================================================================
# 2. All three structural dimensions are exercised by the real G2.1 engine
# ===========================================================================


def test_g1_office_to_cmd_to_child_process_lineage(
    engine: DetectionEngine, knowledge: AttackKnowledge
) -> None:
    result = _replay(engine, knowledge)
    scenarios = _by_scenario(result.detection_results)
    cmd_evidence = _single_evidence(scenarios["g1-cmd"])
    certutil_evidence = _single_evidence(scenarios["g1-certutil"])

    group = _group_containing(result.contextual_result.groups, cmd_evidence.evidence_id)
    assert group is _group_containing(
        result.contextual_result.groups, certutil_evidence.evidence_id
    )
    assert set(group.member_evidence_ids) == {
        cmd_evidence.evidence_id,
        certutil_evidence.evidence_id,
    }

    lineage_links = _links_between(
        result.structural_result.links,
        cmd_evidence.evidence_id,
        certutil_evidence.evidence_id,
        LinkClass.PROCESS_LINEAGE,
    )
    assert len(lineage_links) == 1
    assert group.structural_link_ids == (lineage_links[0].link_id,)
    # Directional: the basis names the parent's Observation first.
    assert (
        lineage_links[0].basis.observation_id_a == cmd_evidence.provenance.source_observation_ids[0]
    )
    assert (
        lineage_links[0].basis.observation_id_b
        == (certutil_evidence.provenance.source_observation_ids[0])
    )

    host_links = _links_between(
        result.contextual_result.contextual_links,
        cmd_evidence.evidence_id,
        certutil_evidence.evidence_id,
        LinkClass.SAME_HOST_ID,
    )
    assert len(host_links) == 1
    assert group.contextual_link_ids == (host_links[0].link_id,)


def test_g2_two_evidence_from_one_observation_shared_observation(
    engine: DetectionEngine, knowledge: AttackKnowledge
) -> None:
    result = _replay(engine, knowledge)
    scenarios = _by_scenario(result.detection_results)
    g2 = scenarios["g2-shared"]
    assert len(g2.evidences) == 2
    procdump_evidence = _evidence_with_attack_ref(g2, present=True)
    logon_evidence = _evidence_with_attack_ref(g2, present=False)
    # Both Evidence really do trace back to the exact same Observation.
    assert procdump_evidence.provenance.source_observation_ids == (g2.observation.observation_id,)
    assert logon_evidence.provenance.source_observation_ids == (g2.observation.observation_id,)

    group = _group_containing(result.structural_result.groups, procdump_evidence.evidence_id)
    assert set(group.member_evidence_ids) == {
        procdump_evidence.evidence_id,
        logon_evidence.evidence_id,
    }
    shared_links = _links_between(
        result.structural_result.links,
        procdump_evidence.evidence_id,
        logon_evidence.evidence_id,
        LinkClass.SHARED_OBSERVATION,
    )
    assert len(shared_links) == 1
    assert group.structural_link_ids == (shared_links[0].link_id,)
    assert shared_links[0].basis.observation_id_a == shared_links[0].basis.observation_id_b


def test_g3_one_process_described_twice_same_process_entity(
    engine: DetectionEngine, knowledge: AttackKnowledge
) -> None:
    """Also proves the long-lived-process point: G2.1's unconditional
    SAME_PROCESS_ENTITY decision is unchanged at G2.3 -- two Observations of
    the same process instance a full minute apart still correlate, with no
    temporal-expiry logic anywhere in this pipeline."""
    result = _replay(engine, knowledge)
    scenarios = _by_scenario(result.detection_results)
    evidence_a = _single_evidence(scenarios["g3-rundll-a"])
    evidence_b = _single_evidence(scenarios["g3-rundll-b"])
    assert (
        scenarios["g3-rundll-a"].observation.timestamp
        != scenarios["g3-rundll-b"].observation.timestamp
    )

    group = _group_containing(result.structural_result.groups, evidence_a.evidence_id)
    assert set(group.member_evidence_ids) == {evidence_a.evidence_id, evidence_b.evidence_id}
    entity_links = _links_between(
        result.structural_result.links,
        evidence_a.evidence_id,
        evidence_b.evidence_id,
        LinkClass.SAME_PROCESS_ENTITY,
    )
    assert len(entity_links) == 1
    assert group.structural_link_ids == (entity_links[0].link_id,)


def test_g11_branching_process_tree_one_parent_two_children_one_group(
    engine: DetectionEngine, knowledge: AttackKnowledge
) -> None:
    result = _replay(engine, knowledge)
    scenarios = _by_scenario(result.detection_results)
    cmd = _single_evidence(scenarios["g11-cmd"])
    certutil = _single_evidence(scenarios["g11-certutil"])
    procdump = _single_evidence(scenarios["g11-procdump"])

    group = _group_containing(result.contextual_result.groups, cmd.evidence_id)
    assert group is _group_containing(result.contextual_result.groups, certutil.evidence_id)
    assert group is _group_containing(result.contextual_result.groups, procdump.evidence_id)
    assert set(group.member_evidence_ids) == {
        cmd.evidence_id,
        certutil.evidence_id,
        procdump.evidence_id,
    }
    assert len(group.structural_link_ids) == 2

    # The two children are linked to the shared parent, never to each other.
    assert (
        _links_between(
            result.structural_result.links,
            certutil.evidence_id,
            procdump.evidence_id,
            LinkClass.PROCESS_LINEAGE,
        )
        == ()
    )
    assert (
        len(
            _links_between(
                result.structural_result.links,
                cmd.evidence_id,
                certutil.evidence_id,
                LinkClass.PROCESS_LINEAGE,
            )
        )
        == 1
    )
    assert (
        len(
            _links_between(
                result.structural_result.links,
                cmd.evidence_id,
                procdump.evidence_id,
                LinkClass.PROCESS_LINEAGE,
            )
        )
        == 1
    )

    # host-g11 is shared by all three -> three pairwise SAME_HOST_ID links,
    # all attached to this one group (CR-1: contextual links, however many,
    # never add to the structural reason the group exists).
    assert len(group.contextual_link_ids) == 3
    assert len(group.structural_link_ids) == 2


def test_g12_two_separate_lineage_chains_on_one_host_two_groups_no_merge(
    engine: DetectionEngine, knowledge: AttackKnowledge
) -> None:
    result = _replay(engine, knowledge)
    scenarios = _by_scenario(result.detection_results)
    cmd_a = _single_evidence(scenarios["g12a-cmd"])
    certutil_a = _single_evidence(scenarios["g12a-certutil"])
    cmd_b = _single_evidence(scenarios["g12b-cmd"])
    procdump_b = _single_evidence(scenarios["g12b-procdump"])

    group_a = _group_containing(result.contextual_result.groups, cmd_a.evidence_id)
    group_b = _group_containing(result.contextual_result.groups, cmd_b.evidence_id)
    assert group_a.group_id != group_b.group_id
    assert set(group_a.member_evidence_ids) == {cmd_a.evidence_id, certutil_a.evidence_id}
    assert set(group_b.member_evidence_ids) == {cmd_b.evidence_id, procdump_b.evidence_id}
    assert set(group_a.member_evidence_ids).isdisjoint(group_b.member_evidence_ids)

    # host-g12 is shared across both chains: a cross-group SAME_HOST_ID link
    # exists and attaches to *both* groups, but never merges them (CR-1).
    cross_links = _links_between(
        result.contextual_result.contextual_links,
        cmd_a.evidence_id,
        cmd_b.evidence_id,
        LinkClass.SAME_HOST_ID,
    )
    assert len(cross_links) == 1
    assert cross_links[0].link_id in group_a.contextual_link_ids
    assert cross_links[0].link_id in group_b.contextual_link_ids
    assert group_a.group_id != group_b.group_id  # still not merged


# ===========================================================================
# 3. All five contextual dimensions attach without ever forming a group
# ===========================================================================


def test_g4_busy_host_unrelated_processes_no_structural_merge(
    engine: DetectionEngine, knowledge: AttackKnowledge
) -> None:
    result = _replay(engine, knowledge)
    scenarios = _by_scenario(result.detection_results)
    ps = _single_evidence(scenarios["g4-ps"])
    procdump = _single_evidence(scenarios["g4-procdump"])
    certutil = _single_evidence(scenarios["g4-certutil"])

    for evidence_id in (ps.evidence_id, procdump.evidence_id, certutil.evidence_id):
        _no_group_contains(result.structural_result.groups, evidence_id)

    # Same host for all three -> three pairwise SAME_HOST_ID contextual
    # links exist, even though none of them forms or touches any group.
    for a, b in ((ps, procdump), (ps, certutil), (procdump, certutil)):
        links = _links_between(
            result.contextual_result.contextual_links,
            a.evidence_id,
            b.evidence_id,
            LinkClass.SAME_HOST_ID,
        )
        assert len(links) == 1


def test_g5_shared_admin_user_context_no_structural_merge(
    engine: DetectionEngine, knowledge: AttackKnowledge
) -> None:
    result = _replay(engine, knowledge)
    scenarios = _by_scenario(result.detection_results)
    rundll = _single_evidence(scenarios["g5-rundll"])
    ps = _single_evidence(scenarios["g5-ps"])

    _no_group_contains(result.structural_result.groups, rundll.evidence_id)
    _no_group_contains(result.structural_result.groups, ps.evidence_id)

    user_links = _links_between(
        result.contextual_result.contextual_links,
        rundll.evidence_id,
        ps.evidence_id,
        LinkClass.SAME_USER_ID,
    )
    assert len(user_links) == 1
    assert user_links[0].basis.field_path == "user.id"
    # Different hosts -> no SAME_HOST_ID/SAME_HOST_NAME link for this pair.
    assert (
        _links_between(
            result.contextual_result.contextual_links,
            rundll.evidence_id,
            ps.evidence_id,
            LinkClass.SAME_HOST_ID,
        )
        == ()
    )


def test_g6_same_destination_ip_no_structural_merge(
    engine: DetectionEngine, knowledge: AttackKnowledge
) -> None:
    result = _replay(engine, knowledge)
    scenarios = _by_scenario(result.detection_results)
    certutil = _single_evidence(scenarios["g6-certutil"])
    ps = _single_evidence(scenarios["g6-ps"])

    _no_group_contains(result.structural_result.groups, certutil.evidence_id)
    _no_group_contains(result.structural_result.groups, ps.evidence_id)

    ip_links = _links_between(
        result.contextual_result.contextual_links,
        certutil.evidence_id,
        ps.evidence_id,
        LinkClass.SAME_DESTINATION_IP,
    )
    assert len(ip_links) == 1
    assert ip_links[0].basis.observed_value == "203.0.113.9"
    assert ip_links[0].basis.uncertainty_note is not None


def test_g7_same_host_name_different_host_id_yields_name_dimension_only(
    engine: DetectionEngine, knowledge: AttackKnowledge
) -> None:
    result = _replay(engine, knowledge)
    scenarios = _by_scenario(result.detection_results)
    rundll = _single_evidence(scenarios["g7-rundll"])
    ps = _single_evidence(scenarios["g7-ps"])

    _no_group_contains(result.structural_result.groups, rundll.evidence_id)
    _no_group_contains(result.structural_result.groups, ps.evidence_id)

    name_links = _links_between(
        result.contextual_result.contextual_links,
        rundll.evidence_id,
        ps.evidence_id,
        LinkClass.SAME_HOST_NAME,
    )
    assert len(name_links) == 1
    # host.id genuinely differs -> no SAME_HOST_ID link for this pair.
    assert (
        _links_between(
            result.contextual_result.contextual_links,
            rundll.evidence_id,
            ps.evidence_id,
            LinkClass.SAME_HOST_ID,
        )
        == ()
    )


def test_g8_same_user_name_different_user_id_yields_name_dimension_only(
    engine: DetectionEngine, knowledge: AttackKnowledge
) -> None:
    result = _replay(engine, knowledge)
    scenarios = _by_scenario(result.detection_results)
    certutil = _single_evidence(scenarios["g8-certutil"])
    ps = _single_evidence(scenarios["g8-ps"])

    _no_group_contains(result.structural_result.groups, certutil.evidence_id)
    _no_group_contains(result.structural_result.groups, ps.evidence_id)

    name_links = _links_between(
        result.contextual_result.contextual_links,
        certutil.evidence_id,
        ps.evidence_id,
        LinkClass.SAME_USER_NAME,
    )
    assert len(name_links) == 1
    assert (
        _links_between(
            result.contextual_result.contextual_links,
            certutil.evidence_id,
            ps.evidence_id,
            LinkClass.SAME_USER_ID,
        )
        == ()
    )


def test_g9_multiple_contextual_dimensions_attach_distinct_links_to_both_groups(
    engine: DetectionEngine, knowledge: AttackKnowledge
) -> None:
    result = _replay(engine, knowledge)
    scenarios = _by_scenario(result.detection_results)
    cmd_a = _single_evidence(scenarios["g9a-cmd"])
    procdump_b = _evidence_with_attack_ref(scenarios["g9b-shared"], present=True)

    group_a = _group_containing(result.contextual_result.groups, cmd_a.evidence_id)
    group_b = _group_containing(result.contextual_result.groups, procdump_b.evidence_id)
    assert group_a.group_id != group_b.group_id
    assert set(group_a.member_evidence_ids).isdisjoint(group_b.member_evidence_ids)

    host_cross = _links_between(
        result.contextual_result.contextual_links,
        cmd_a.evidence_id,
        procdump_b.evidence_id,
        LinkClass.SAME_HOST_ID,
    )
    user_cross = _links_between(
        result.contextual_result.contextual_links,
        cmd_a.evidence_id,
        procdump_b.evidence_id,
        LinkClass.SAME_USER_ID,
    )
    assert len(host_cross) == 1
    assert len(user_cross) == 1
    assert host_cross[0].link_id != user_cross[0].link_id  # two distinct links, not one

    for link in (host_cross[0], user_cross[0]):
        assert link.link_id in group_a.contextual_link_ids
        assert link.link_id in group_b.contextual_link_ids

    # Still two, unmerged groups despite two shared contextual dimensions.
    assert group_a.group_id != group_b.group_id


def test_g10_context_only_no_structure_produces_no_group(
    engine: DetectionEngine, knowledge: AttackKnowledge
) -> None:
    result = _replay(engine, knowledge)
    scenarios = _by_scenario(result.detection_results)
    ps = _single_evidence(scenarios["g10-ps"])
    certutil = _single_evidence(scenarios["g10-certutil"])

    _no_group_contains(result.structural_result.groups, ps.evidence_id)
    _no_group_contains(result.structural_result.groups, certutil.evidence_id)
    _no_group_contains(result.contextual_result.groups, ps.evidence_id)
    _no_group_contains(result.contextual_result.groups, certutil.evidence_id)

    assert (
        len(
            _links_between(
                result.contextual_result.contextual_links,
                ps.evidence_id,
                certutil.evidence_id,
                LinkClass.SAME_HOST_ID,
            )
        )
        == 1
    )
    assert (
        len(
            _links_between(
                result.contextual_result.contextual_links,
                ps.evidence_id,
                certutil.evidence_id,
                LinkClass.SAME_USER_ID,
            )
        )
        == 1
    )


# ===========================================================================
# 4. Corpus-wide structural/contextual summary (strong regression pin)
# ===========================================================================


def test_corpus_wide_structural_group_and_link_counts(
    engine: DetectionEngine, knowledge: AttackKnowledge
) -> None:
    """Pins the exact structural shape of the whole corpus: 8 groups
    (g1, g2, g3, g9a, g9b, g11, g12a, g12b), 9 structural links (one each
    for g1/g2/g3/g9a/g9b/g12a/g12b, two for g11's branch)."""
    result = _replay(engine, knowledge)
    assert len(result.structural_result.groups) == 8
    assert len(result.structural_result.links) == 9
    for group in result.structural_result.groups:
        assert len(group.member_evidence_ids) >= 2
        assert len(group.structural_link_ids) >= 1


def test_corpus_wide_contextual_group_count_matches_structural(
    engine: DetectionEngine, knowledge: AttackKnowledge
) -> None:
    """contextualize() must preserve the exact structural group set -- same
    8 groups, never fewer (a group silently dropped) and never more (a
    group spuriously created from contextual links alone, which g10 and
    g4-g8 already prove cannot happen for any single pair, but this pins it
    corpus-wide rather than relying only on contextualize()'s current
    implementation, which happens to iterate structural_result.groups 1:1)."""
    result = _replay(engine, knowledge)
    assert len(result.contextual_result.groups) == len(result.structural_result.groups)
    assert len(result.contextual_result.groups) == 8
    assert {g.group_id for g in result.contextual_result.groups} == {
        g.group_id for g in result.structural_result.groups
    }


# ===========================================================================
# 5. Deterministic replay across independent runs
# ===========================================================================


def test_replay_is_deterministic_across_independent_runs(
    engine: DetectionEngine, knowledge: AttackKnowledge
) -> None:
    result_a = _replay(engine, knowledge)
    result_b = _replay(engine, knowledge)

    assert [to_canonical_json(link) for link in result_a.structural_result.links] == [
        to_canonical_json(link) for link in result_b.structural_result.links
    ]
    assert [to_canonical_json(group) for group in result_a.structural_result.groups] == [
        to_canonical_json(group) for group in result_b.structural_result.groups
    ]
    assert [to_canonical_json(link) for link in result_a.contextual_result.contextual_links] == [
        to_canonical_json(link) for link in result_b.contextual_result.contextual_links
    ]
    assert [to_canonical_json(group) for group in result_a.contextual_result.groups] == [
        to_canonical_json(group) for group in result_b.contextual_result.groups
    ]


# ===========================================================================
# 6. Persistence round trip
# ===========================================================================


def test_persisted_correlation_links_and_groups_round_trip(
    engine: DetectionEngine, knowledge: AttackKnowledge
) -> None:
    fixture = load_detection_replay_fixture_file(FIXTURE_PATH)
    client = FakeElasticClient()
    result = replay_fixture_through_correlation(
        fixture, client=client, engine=engine, knowledge=knowledge
    )

    for link in (*result.structural_result.links, *result.contextual_result.contextual_links):
        assert load_correlation_link(client, link.link_id) == link
    for group in result.contextual_result.groups:
        assert load_correlation_group(client, group.group_id) == group


def test_load_correlation_link_and_group_return_none_when_absent() -> None:
    client = FakeElasticClient()
    assert load_correlation_link(client, "corr::does-not-exist") is None
    assert load_correlation_group(client, "corr-group::does-not-exist") is None


# ===========================================================================
# 7. Idempotent replay
# ===========================================================================


def test_replaying_the_same_fixture_twice_into_one_client_is_idempotent(
    engine: DetectionEngine, knowledge: AttackKnowledge
) -> None:
    fixture = load_detection_replay_fixture_file(FIXTURE_PATH)
    client = FakeElasticClient()

    replay_fixture_through_correlation(fixture, client=client, engine=engine, knowledge=knowledge)
    second = replay_fixture_through_correlation(
        fixture, client=client, engine=engine, knowledge=knowledge
    )

    expected_link_docs = len(
        {
            *(link.link_id for link in second.structural_result.links),
            *(link.link_id for link in second.contextual_result.contextual_links),
        }
    )
    expected_group_docs = len({g.group_id for g in second.contextual_result.groups})
    assert client.document_count(CORRELATION_LINKS_INDEX) == expected_link_docs
    assert client.document_count(CORRELATION_GROUPS_INDEX) == expected_group_docs


def test_replaying_twice_produces_identical_link_and_group_ids(
    engine: DetectionEngine, knowledge: AttackKnowledge
) -> None:
    fixture = load_detection_replay_fixture_file(FIXTURE_PATH)
    client = FakeElasticClient()

    result_1 = replay_fixture_through_correlation(
        fixture, client=client, engine=engine, knowledge=knowledge
    )
    result_2 = replay_fixture_through_correlation(
        fixture, client=client, engine=engine, knowledge=knowledge
    )

    ids_1 = sorted(g.group_id for g in result_1.contextual_result.groups)
    ids_2 = sorted(g.group_id for g in result_2.contextual_result.groups)
    assert ids_1 == ids_2
    assert len(ids_1) == len(set(ids_1))


# ===========================================================================
# 8. Full provenance chain: raw fixture -> Observation -> Evidence ->
#    CorrelationLink -> CorrelationGroup
# ===========================================================================


def test_full_provenance_chain_is_navigable_end_to_end(
    engine: DetectionEngine, knowledge: AttackKnowledge, rule_pack: RulePack
) -> None:
    result = _replay(engine, knowledge)
    scenarios = _by_scenario(result.detection_results)
    cmd_scenario = scenarios["g1-cmd"]
    certutil_scenario = scenarios["g1-certutil"]
    cmd_evidence = _single_evidence(cmd_scenario)
    certutil_evidence = _single_evidence(certutil_scenario)

    # raw fixture -> Observation
    assert cmd_scenario.observation.raw_reference.source_event_id == "evt-g1-cmd"
    assert cmd_scenario.observation.observation_id == "obs-g1-cmd"

    # Observation -> Evidence (G1.0, unchanged; method_content_hash traces
    # back to the real, unmodified rule pack)
    assert cmd_evidence.provenance.source_observation_ids == (
        cmd_scenario.observation.observation_id,
    )
    assert cmd_evidence.provenance.method_content_hash == rule_pack.content_hash

    # Evidence -> CorrelationLink (G2.1)
    link = _links_between(
        result.structural_result.links,
        cmd_evidence.evidence_id,
        certutil_evidence.evidence_id,
        LinkClass.PROCESS_LINEAGE,
    )[0]
    assert set(link.provenance.source_evidence_ids) == {
        cmd_evidence.evidence_id,
        certutil_evidence.evidence_id,
    }
    assert set(link.provenance.source_observation_ids) == {
        cmd_scenario.observation.observation_id,
        certutil_scenario.observation.observation_id,
    }

    # CorrelationLink -> CorrelationGroup (G2.1)
    group = _group_containing(result.structural_result.groups, cmd_evidence.evidence_id)
    assert link.link_id in group.structural_link_ids
    assert set(group.provenance.source_evidence_ids) == set(group.member_evidence_ids)
    assert set(group.provenance.source_observation_ids) == set(group.member_observation_ids)


# ===========================================================================
# 9. Changing a source Observation changes the correlation result
# ===========================================================================


def test_changing_a_source_observation_changes_the_correlation_result(
    tmp_path: Path, engine: DetectionEngine, knowledge: AttackKnowledge
) -> None:
    """Breaking the g1 lineage relationship in the fixture (different
    parent_entity_id) must remove the PROCESS_LINEAGE link/group that
    otherwise forms -- proving the result is genuinely derived from the
    replayed Observations, not hand-authored or fixed."""
    data = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    for scenario in data["scenarios"]:
        if scenario["scenario_id"] == "g1-certutil":
            scenario["process"]["parent_entity_id"] = "proc-does-not-exist"
    tampered_path = tmp_path / "tampered_fixture.json"
    tampered_path.write_text(json.dumps(data), encoding="utf-8")

    fixture = load_detection_replay_fixture_file(tampered_path)
    result = replay_fixture_through_correlation(
        fixture, client=FakeElasticClient(), engine=engine, knowledge=knowledge
    )
    scenarios = _by_scenario(result.detection_results)
    cmd_evidence = _single_evidence(scenarios["g1-cmd"])
    certutil_evidence = _single_evidence(scenarios["g1-certutil"])

    assert (
        _links_between(
            result.structural_result.links,
            cmd_evidence.evidence_id,
            certutil_evidence.evidence_id,
            LinkClass.PROCESS_LINEAGE,
        )
        == ()
    )
    _no_group_contains(result.structural_result.groups, cmd_evidence.evidence_id)
    _no_group_contains(result.structural_result.groups, certutil_evidence.evidence_id)


# ===========================================================================
# 10. Architecture guards
# ===========================================================================


def test_correlation_pipeline_never_constructs_link_or_group_directly() -> None:
    """Static AST check: correlation_pipeline.py must never call
    CorrelationLink(...) or CorrelationGroup(...) directly -- every one must
    come from the real correlate_structurally()/contextualize() engines."""
    tree = ast.parse(CORRELATION_PIPELINE_FILE.read_text(encoding="utf-8"))
    forbidden_calls = {"CorrelationLink", "CorrelationGroup", "DetectionResult", "Evidence"}
    offending = [
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in forbidden_calls
    ]
    assert not offending, (
        f"correlation_pipeline.py must not construct {offending} directly; every one must come "
        "from the real detection-replay/correlate_structurally/contextualize calls"
    )


def test_correlation_pipeline_actually_uses_the_real_engines() -> None:
    source = CORRELATION_PIPELINE_FILE.read_text(encoding="utf-8")
    assert "replay_fixture_through_detection_engine(" in source
    assert "correlate_structurally(items, context_observations=context_observations)" in source
    assert "structural_result, items, context_observations=context_observations" in source


def test_correlation_pipeline_never_passes_attack_knowledge_into_correlation() -> None:
    """AST-level proof that AttackKnowledge, though required for the G1.2
    detection-replay hop, is never threaded into correlate_structurally/
    contextualize -- correlation stays ATT&CK-free at G2.3, exactly as
    G2.1/G2.2 already guarantee for their own source."""
    tree = ast.parse(CORRELATION_PIPELINE_FILE.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in ("correlate_structurally", "contextualize")
        ):
            kwarg_names = {kw.arg for kw in node.keywords}
            assert "knowledge" not in kwarg_names


_FORBIDDEN_MAPPING_FIELD_TERMS = (
    "likelihood",
    "confidence",
    "score",
    "weight",
    "candidate",
    "actor",
    "campaign",
    "attribution",
)


def _collect_mapping_field_names(mapping: Mapping[str, object]) -> set[str]:
    """Recursively collect every field name in an Elasticsearch-mapping-
    shaped dict, descending into any nested dict value -- in particular the
    nested ``"properties"`` blocks ``basis``/``provenance`` actually use --
    so a forbidden term hidden inside a sub-object is not missed by a
    top-level-only scan."""
    names: set[str] = set()
    for key, value in mapping.items():
        names.add(key)
        if isinstance(value, Mapping):
            names |= _collect_mapping_field_names(value)
    return names


def _assert_no_forbidden_mapping_fields(mapping: Mapping[str, object]) -> None:
    for field_name in _collect_mapping_field_names(mapping):
        lowered = field_name.lower()
        for term in _FORBIDDEN_MAPPING_FIELD_TERMS:
            assert term not in lowered, f"forbidden term {term!r} found in field {field_name!r}"


def test_correlation_mappings_contain_no_attribution_or_scoring_fields() -> None:
    """The persisted-field guard from the task spec: neither correlation
    index mapping may ever gain a likelihood/confidence/score/candidate/
    actor/campaign field -- correlation and attribution stay separate
    layers (ADR-0003 D3/D10). Recurses into nested "properties" blocks
    (basis/provenance) rather than checking only top-level keys, so a
    forbidden field hidden inside a sub-object would be caught too -- see
    test_forbidden_mapping_field_guard_actually_catches_a_nested_field for a
    regression proof the recursion genuinely works, not just the top level."""
    from attribution_platform.dataplane import CORRELATION_GROUPS_MAPPING, CORRELATION_LINKS_MAPPING

    _assert_no_forbidden_mapping_fields(CORRELATION_LINKS_MAPPING)
    _assert_no_forbidden_mapping_fields(CORRELATION_GROUPS_MAPPING)


def test_forbidden_mapping_field_guard_actually_catches_a_nested_field() -> None:
    """Regression proof for the guard above: a forbidden field buried two
    levels deep inside a nested "properties" block -- mirroring exactly how
    basis/provenance are actually shaped in the real mappings -- must be
    caught, not silently pass because only top-level keys were scanned."""
    tainted_mapping: dict[str, object] = {
        "link_id": {"type": "keyword"},
        "basis": {
            "properties": {
                "field_path": {"type": "keyword"},
                "likelihood": {"type": "float"},
            }
        },
    }
    with pytest.raises(AssertionError, match="likelihood"):
        _assert_no_forbidden_mapping_fields(tainted_mapping)
