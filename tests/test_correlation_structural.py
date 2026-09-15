"""Tests for gate G2.1: the structural correlation engine.

Covers exactly the three structural dimensions ADR-0003 approved
(SHARED_OBSERVATION, SAME_PROCESS_ENTITY, PROCESS_LINEAGE), host-scoped
process-entity identity (host.id preferred, host.name fallback, fail-closed
when neither is available), directional PROCESS_LINEAGE preservation,
connected-component CorrelationGroup formation via a small deterministic
union-find, provenance, determinism/idempotency, and an extensive negative
suite proving host/user/destination sameness, matching process names,
temporal proximity, and shared ATT&CK techniques never create or merge a
structural link or group -- the exact correction the Phase 2 architecture
review made to ADR-0003 before it was accepted.

Uses the existing, unmodified `attribution_platform.extraction.derive_evidence`
and domain contracts to build its golden corpus in pure Python (the same
pattern `test_detection.py` already uses for the G1.0 engine) rather than a
JSON fixture + replay pipeline -- ADR-0003 explicitly reserves
fixture/replay-based golden-corpus testing for gate G2.3, not G2.1.

Does NOT touch any G0.x/G1.x source, test, or fixture, and does not modify
Phase 1 detection behavior. Offline, deterministic, no Elastic/Docker/
Windows/network required (loads only the vendored ATT&CK KB, for the one
test proving shared-technique alone does not correlate).
"""

from __future__ import annotations

import ast
from datetime import UTC, datetime
from pathlib import Path

import pytest

from attribution_platform.attack_knowledge.loader import AttackKnowledge, load_attack_knowledge
from attribution_platform.correlation import (
    CorrelationError,
    LinkClass,
    StructuralCorrelationResult,
    correlate_structurally,
)
from attribution_platform.domain import (
    AttackRef,
    Evidence,
    EvidenceType,
    HostRef,
    NetworkEndpoint,
    NetworkInfo,
    Observation,
    ProcessRef,
    SourceRef,
    UserRef,
)
from attribution_platform.extraction import RuleRef, derive_evidence

REPO_ROOT = Path(__file__).resolve().parents[1]
CORRELATION_DIR = REPO_ROOT / "src" / "attribution_platform" / "correlation"

T0 = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)


@pytest.fixture(scope="module")
def knowledge() -> AttackKnowledge:
    return load_attack_knowledge()


def _obs(
    observation_id: str,
    *,
    timestamp: datetime = T0,
    host: HostRef | None = None,
    process: ProcessRef | None = None,
    user: UserRef | None = None,
    network: NetworkInfo | None = None,
) -> Observation:
    return Observation(
        observation_id=observation_id,
        timestamp=timestamp,
        raw_reference=SourceRef(source_type="synthetic", source_event_id=f"raw-{observation_id}"),
        host=host,
        process=process,
        user=user,
        network=network,
    )


def _evidence(
    evidence_id: str,
    observation: Observation,
    *,
    rule_id: str = "golden-rule",
    rule_version: str = "1.0",
    evidence_type: EvidenceType = EvidenceType.BEHAVIORAL,
    claim: str = "synthetic structural-correlation golden-corpus evidence",
    attack_ref: AttackRef | None = None,
    knowledge: AttackKnowledge | None = None,
) -> Evidence:
    return derive_evidence(
        evidence_id=evidence_id,
        evidence_type=evidence_type,
        claim=claim,
        observations=(observation,),
        rule_ref=RuleRef(rule_id=rule_id, rule_version=rule_version),
        attack_ref=attack_ref,
        knowledge=knowledge,
    )


def _pair(
    evidence_id: str, observation: Observation, **kwargs: object
) -> tuple[Evidence, Observation]:
    ev = _evidence(evidence_id, observation, **kwargs)  # type: ignore[arg-type]
    return (ev, observation)


def _link_classes(result: StructuralCorrelationResult) -> set[LinkClass]:
    return {link.link_class for link in result.links}


# ===========================================================================
# 1. SHARED_OBSERVATION
# ===========================================================================


def test_shared_observation_produces_one_structural_link() -> None:
    obs = _obs("obs-1", process=ProcessRef(name="powershell.exe"))
    items = [_pair("ev-1", obs), _pair("ev-2", obs)]

    result = correlate_structurally(items)

    assert len(result.links) == 1
    link = result.links[0]
    assert link.link_class == LinkClass.SHARED_OBSERVATION
    assert {link.anchor_a, link.anchor_b} == {"ev-1", "ev-2"}
    assert link.basis.field_path == "observation_id"
    assert link.basis.observed_value == "obs-1"
    assert link.basis.observation_id_a == link.basis.observation_id_b == "obs-1"
    assert len(result.groups) == 1
    assert result.groups[0].member_evidence_ids == ("ev-1", "ev-2")


def test_shared_observation_does_not_use_timestamp_host_user_or_event_fields() -> None:
    """SHARED_OBSERVATION must derive only from observation_id identity --
    not from two DIFFERENT observations merely sharing a timestamp, host,
    user, or event field."""
    obs_a = _obs("obs-a", timestamp=T0, host=HostRef(id="H1"), user=UserRef(id="U1"))
    obs_b = _obs("obs-b", timestamp=T0, host=HostRef(id="H1"), user=UserRef(id="U1"))
    items = [_pair("ev-1", obs_a), _pair("ev-2", obs_b)]

    result = correlate_structurally(items)

    assert result.links == ()
    assert result.groups == ()


# ===========================================================================
# 2. SAME_PROCESS_ENTITY
# ===========================================================================


def test_same_process_entity_correlates_within_one_host() -> None:
    host = HostRef(id="HOST-01")
    obs_a = _obs("obs-a", host=host, process=ProcessRef(entity_id="{GUID-1}", name="a.exe"))
    obs_b = _obs("obs-b", host=host, process=ProcessRef(entity_id="{GUID-1}", name="b.exe"))
    items = [_pair("ev-1", obs_a), _pair("ev-2", obs_b)]

    result = correlate_structurally(items)

    assert len(result.links) == 1
    link = result.links[0]
    assert link.link_class == LinkClass.SAME_PROCESS_ENTITY
    assert link.basis.field_path == "process.entity_id"
    assert link.basis.observed_value == "{GUID-1}"
    assert len(result.groups) == 1
    assert set(result.groups[0].member_evidence_ids) == {"ev-1", "ev-2"}


# ===========================================================================
# 3 & 4. PROCESS_LINEAGE + direction
# ===========================================================================


def test_process_lineage_produces_directional_link() -> None:
    host = HostRef(id="HOST-01")
    parent_obs = _obs(
        "obs-parent", host=host, process=ProcessRef(entity_id="{PARENT}", name="winword.exe")
    )
    child_obs = _obs(
        "obs-child",
        host=host,
        process=ProcessRef(entity_id="{CHILD}", parent_entity_id="{PARENT}", name="cmd.exe"),
    )
    items = [_pair("ev-parent", parent_obs), _pair("ev-child", child_obs)]

    result = correlate_structurally(items)

    lineage_links = [
        entry for entry in result.links if entry.link_class == LinkClass.PROCESS_LINEAGE
    ]
    assert len(lineage_links) == 1
    link = lineage_links[0]
    assert link.basis.field_path == "process.parent_entity_id"
    assert link.basis.observed_value == "{PARENT}"
    assert link.basis.observation_id_a == "obs-parent"
    assert link.basis.observation_id_b == "obs-child"
    assert len(result.groups) == 1
    assert set(result.groups[0].member_evidence_ids) == {"ev-parent", "ev-child"}


def test_process_lineage_direction_is_independent_of_input_order() -> None:
    """Swapping the order items are passed in must not reverse parent/child
    -- direction comes from which Observation's parent_entity_id points at
    the other's entity_id, never from list position."""
    host = HostRef(id="HOST-01")
    parent_obs = _obs("obs-parent", host=host, process=ProcessRef(entity_id="{PARENT}"))
    child_obs = _obs(
        "obs-child", host=host, process=ProcessRef(entity_id="{CHILD}", parent_entity_id="{PARENT}")
    )

    result_forward = correlate_structurally(
        [_pair("ev-parent", parent_obs), _pair("ev-child", child_obs)]
    )
    result_reversed = correlate_structurally(
        [_pair("ev-child", child_obs), _pair("ev-parent", parent_obs)]
    )

    for result in (result_forward, result_reversed):
        (link,) = [entry for entry in result.links if entry.link_class == LinkClass.PROCESS_LINEAGE]
        assert link.basis.observation_id_a == "obs-parent"
        assert link.basis.observation_id_b == "obs-child"


# ===========================================================================
# 5, 6, 7. Host-scoped process identity
# ===========================================================================


def test_same_entity_id_on_different_hosts_does_not_correlate() -> None:
    """The exact collision ADR-0003 requires guarding against: identical
    raw entity_id values, but on two different hosts."""
    obs_a = _obs("obs-a", host=HostRef(id="HOST-01"), process=ProcessRef(entity_id="{GUID-1}"))
    obs_b = _obs("obs-b", host=HostRef(id="HOST-02"), process=ProcessRef(entity_id="{GUID-1}"))
    items = [_pair("ev-1", obs_a), _pair("ev-2", obs_b)]

    result = correlate_structurally(items)

    assert result.links == ()
    assert result.groups == ()


def test_host_id_is_preferred_over_host_name() -> None:
    """Same host.id but different host.name -> still correlates (host.id
    wins)."""
    obs_a = _obs(
        "obs-a",
        host=HostRef(id="HOST-01", name="workstation-a"),
        process=ProcessRef(entity_id="{GUID-1}"),
    )
    obs_b = _obs(
        "obs-b",
        host=HostRef(id="HOST-01", name="workstation-b"),
        process=ProcessRef(entity_id="{GUID-1}"),
    )
    result = correlate_structurally([_pair("ev-1", obs_a), _pair("ev-2", obs_b)])
    assert len(result.links) == 1

    # Same host.name but different host.id -> must NOT correlate (host.id,
    # when present, always wins over host.name, even on mismatch).
    obs_c = _obs(
        "obs-c",
        host=HostRef(id="HOST-01", name="shared-name"),
        process=ProcessRef(entity_id="{GUID-2}"),
    )
    obs_d = _obs(
        "obs-d",
        host=HostRef(id="HOST-02", name="shared-name"),
        process=ProcessRef(entity_id="{GUID-2}"),
    )
    result2 = correlate_structurally([_pair("ev-3", obs_c), _pair("ev-4", obs_d)])
    assert result2.links == ()


def test_host_name_fallback_when_host_id_absent() -> None:
    obs_a = _obs(
        "obs-a", host=HostRef(name="workstation-x"), process=ProcessRef(entity_id="{GUID-1}")
    )
    obs_b = _obs(
        "obs-b", host=HostRef(name="workstation-x"), process=ProcessRef(entity_id="{GUID-1}")
    )
    result = correlate_structurally([_pair("ev-1", obs_a), _pair("ev-2", obs_b)])
    assert len(result.links) == 1
    assert result.links[0].link_class == LinkClass.SAME_PROCESS_ENTITY

    # Different host.name, still no host.id -> must not correlate.
    obs_c = _obs(
        "obs-c", host=HostRef(name="workstation-x"), process=ProcessRef(entity_id="{GUID-2}")
    )
    obs_d = _obs(
        "obs-d", host=HostRef(name="workstation-y"), process=ProcessRef(entity_id="{GUID-2}")
    )
    result2 = correlate_structurally([_pair("ev-3", obs_c), _pair("ev-4", obs_d)])
    assert result2.links == ()


def test_no_host_at_all_fails_closed_never_correlates() -> None:
    """No host.id and no host.name at all -- host scope cannot be
    established, so the process-entity dimensions must fail closed (skip),
    never treat the bare entity_id as globally unique."""
    obs_a = _obs("obs-a", process=ProcessRef(entity_id="{GUID-1}"))
    obs_b = _obs("obs-b", process=ProcessRef(entity_id="{GUID-1}"))
    result = correlate_structurally([_pair("ev-1", obs_a), _pair("ev-2", obs_b)])
    assert result.links == ()
    assert result.groups == ()


# ===========================================================================
# 8, 9. Missing entity/parent-entity -> fail closed
# ===========================================================================


def test_missing_process_entity_id_fails_closed() -> None:
    host = HostRef(id="HOST-01")
    obs_a = _obs("obs-a", host=host, process=ProcessRef(name="a.exe"))  # no entity_id
    obs_b = _obs("obs-b", host=host, process=ProcessRef(name="a.exe"))
    result = correlate_structurally([_pair("ev-1", obs_a), _pair("ev-2", obs_b)])
    assert result.links == ()


def test_missing_process_entirely_fails_closed() -> None:
    host = HostRef(id="HOST-01")
    obs_a = _obs("obs-a", host=host)  # no process at all
    obs_b = _obs("obs-b", host=host, process=ProcessRef(entity_id="{GUID-1}"))
    result = correlate_structurally([_pair("ev-1", obs_a), _pair("ev-2", obs_b)])
    assert result.links == ()


def test_missing_parent_entity_id_fails_closed_no_lineage() -> None:
    host = HostRef(id="HOST-01")
    parent_obs = _obs("obs-parent", host=host, process=ProcessRef(entity_id="{PARENT}"))
    child_obs = _obs(
        "obs-child", host=host, process=ProcessRef(entity_id="{CHILD}")
    )  # no parent_entity_id
    result = correlate_structurally([_pair("ev-parent", parent_obs), _pair("ev-child", child_obs)])
    assert not any(entry.link_class == LinkClass.PROCESS_LINEAGE for entry in result.links)


# ===========================================================================
# 10, 11, 12. SAME_HOST / SAME_USER / SAME_DESTINATION negatives
# ===========================================================================


def test_same_host_alone_produces_no_structural_link() -> None:
    """A busy host: many unrelated processes, no shared entity/lineage."""
    host = HostRef(id="HOST-01")
    items = [
        _pair(
            "ev-1", _obs("obs-1", host=host, process=ProcessRef(entity_id="{A}", name="chrome.exe"))
        ),
        _pair(
            "ev-2",
            _obs("obs-2", host=host, process=ProcessRef(entity_id="{B}", name="powershell.exe")),
        ),
        _pair(
            "ev-3",
            _obs("obs-3", host=host, process=ProcessRef(entity_id="{C}", name="outlook.exe")),
        ),
    ]
    result = correlate_structurally(items)
    assert result.links == ()
    assert result.groups == ()


def test_same_user_alone_produces_no_structural_link() -> None:
    """A shared administrator/service account performing unrelated actions."""
    user = UserRef(id="svc-admin")
    items = [
        _pair(
            "ev-1",
            _obs(
                "obs-1",
                host=HostRef(id="H1"),
                user=user,
                process=ProcessRef(entity_id="{A}"),
            ),
        ),
        _pair(
            "ev-2",
            _obs(
                "obs-2",
                host=HostRef(id="H2"),
                user=user,
                process=ProcessRef(entity_id="{B}"),
            ),
        ),
    ]
    result = correlate_structurally(items)
    assert result.links == ()


def test_same_destination_ip_alone_produces_no_structural_link() -> None:
    endpoint = NetworkInfo(destination=NetworkEndpoint(ip="203.0.113.10", port=443))
    items = [
        _pair("ev-1", _obs("obs-1", host=HostRef(id="H1"), network=endpoint)),
        _pair("ev-2", _obs("obs-2", host=HostRef(id="H2"), network=endpoint)),
    ]
    result = correlate_structurally(items)
    assert result.links == ()


# ===========================================================================
# 13, 14, 15. process-name / timestamp / ATT&CK negatives
# ===========================================================================


def test_same_process_name_different_entity_does_not_correlate() -> None:
    host = HostRef(id="HOST-01")
    obs_a = _obs("obs-a", host=host, process=ProcessRef(entity_id="{A}", name="powershell.exe"))
    obs_b = _obs("obs-b", host=host, process=ProcessRef(entity_id="{B}", name="powershell.exe"))
    result = correlate_structurally([_pair("ev-1", obs_a), _pair("ev-2", obs_b)])
    assert result.links == ()


def test_temporal_proximity_alone_does_not_correlate() -> None:
    host = HostRef(id="HOST-01")
    obs_a = _obs("obs-a", timestamp=T0, host=host, process=ProcessRef(entity_id="{A}"))
    obs_b = _obs(
        "obs-b",
        timestamp=datetime(2026, 1, 1, 12, 0, 1, tzinfo=UTC),  # one second later
        host=host,
        process=ProcessRef(entity_id="{B}"),
    )
    result = correlate_structurally([_pair("ev-1", obs_a), _pair("ev-2", obs_b)])
    assert result.links == ()


def test_shared_attack_technique_alone_does_not_correlate(knowledge: AttackKnowledge) -> None:
    technique = knowledge.techniques()[0]
    ref = AttackRef(
        stix_id=technique["id"],
        object_type=technique["type"],
        attack_kb_version=knowledge.attack_kb_version,
    )
    host = HostRef(id="HOST-01")
    obs_a = _obs("obs-a", host=host, process=ProcessRef(entity_id="{A}"))
    obs_b = _obs("obs-b", host=host, process=ProcessRef(entity_id="{B}"))
    items = [
        _pair("ev-1", obs_a, attack_ref=ref, knowledge=knowledge),
        _pair("ev-2", obs_b, attack_ref=ref, knowledge=knowledge),
    ]
    result = correlate_structurally(items)
    assert result.links == ()


# ===========================================================================
# 16, 17, 18. Trees, branching, group connectivity
# ===========================================================================


def test_two_unrelated_process_trees_on_one_host_remain_separate_groups() -> None:
    host = HostRef(id="HOST-01")
    tree_a_parent = _obs("obs-a1", host=host, process=ProcessRef(entity_id="{A1}"))
    tree_a_child = _obs(
        "obs-a2", host=host, process=ProcessRef(entity_id="{A2}", parent_entity_id="{A1}")
    )
    tree_b_parent = _obs("obs-b1", host=host, process=ProcessRef(entity_id="{B1}"))
    tree_b_child = _obs(
        "obs-b2", host=host, process=ProcessRef(entity_id="{B2}", parent_entity_id="{B1}")
    )
    items = [
        _pair("ev-a1", tree_a_parent),
        _pair("ev-a2", tree_a_child),
        _pair("ev-b1", tree_b_parent),
        _pair("ev-b2", tree_b_child),
    ]

    result = correlate_structurally(items)

    assert len(result.groups) == 2
    member_sets = {frozenset(g.member_evidence_ids) for g in result.groups}
    assert member_sets == {frozenset({"ev-a1", "ev-a2"}), frozenset({"ev-b1", "ev-b2"})}


def test_branching_lineage_forms_one_group_with_parent_and_both_children() -> None:
    host = HostRef(id="HOST-01")
    parent_obs = _obs("obs-parent", host=host, process=ProcessRef(entity_id="{PARENT}"))
    child1_obs = _obs(
        "obs-child1",
        host=host,
        process=ProcessRef(entity_id="{CHILD1}", parent_entity_id="{PARENT}"),
    )
    child2_obs = _obs(
        "obs-child2",
        host=host,
        process=ProcessRef(entity_id="{CHILD2}", parent_entity_id="{PARENT}"),
    )
    items = [
        _pair("ev-parent", parent_obs),
        _pair("ev-child1", child1_obs),
        _pair("ev-child2", child2_obs),
    ]

    result = correlate_structurally(items)

    assert len(result.groups) == 1
    group = result.groups[0]
    assert set(group.member_evidence_ids) == {"ev-parent", "ev-child1", "ev-child2"}
    lineage_links = [
        entry for entry in result.links if entry.link_class == LinkClass.PROCESS_LINEAGE
    ]
    assert len(lineage_links) == 2


def test_group_contains_exactly_the_structurally_connected_evidence() -> None:
    host = HostRef(id="HOST-01")
    parent_obs = _obs("obs-parent", host=host, process=ProcessRef(entity_id="{PARENT}"))
    child_obs = _obs(
        "obs-child", host=host, process=ProcessRef(entity_id="{CHILD}", parent_entity_id="{PARENT}")
    )
    unrelated_obs = _obs("obs-unrelated", host=host, process=ProcessRef(entity_id="{OTHER}"))
    items = [
        _pair("ev-parent", parent_obs),
        _pair("ev-child", child_obs),
        _pair("ev-unrelated", unrelated_obs),
    ]

    result = correlate_structurally(items)

    assert len(result.groups) == 1
    group = result.groups[0]
    assert set(group.member_evidence_ids) == {"ev-parent", "ev-child"}
    assert "ev-unrelated" not in group.member_evidence_ids
    assert set(group.structural_link_ids) == {entry.link_id for entry in result.links}


# ===========================================================================
# 19. No contextual merge
# ===========================================================================


def test_shared_host_user_and_destination_do_not_merge_separate_groups() -> None:
    host = HostRef(id="HOST-01")
    user = UserRef(id="svc-admin")
    dest = NetworkInfo(destination=NetworkEndpoint(ip="203.0.113.10"))

    tree_a_parent = _obs(
        "obs-a1", host=host, user=user, network=dest, process=ProcessRef(entity_id="{A1}")
    )
    tree_a_child = _obs(
        "obs-a2",
        host=host,
        user=user,
        network=dest,
        process=ProcessRef(entity_id="{A2}", parent_entity_id="{A1}"),
    )
    tree_b_parent = _obs(
        "obs-b1", host=host, user=user, network=dest, process=ProcessRef(entity_id="{B1}")
    )
    tree_b_child = _obs(
        "obs-b2",
        host=host,
        user=user,
        network=dest,
        process=ProcessRef(entity_id="{B2}", parent_entity_id="{B1}"),
    )
    items = [
        _pair("ev-a1", tree_a_parent),
        _pair("ev-a2", tree_a_child),
        _pair("ev-b1", tree_b_parent),
        _pair("ev-b2", tree_b_child),
    ]

    result = correlate_structurally(items)

    assert len(result.groups) == 2  # still separate despite identical host/user/destination
    assert _link_classes(result) == {LinkClass.PROCESS_LINEAGE}  # never a contextual class


# ===========================================================================
# 20. Determinism
# ===========================================================================


def test_repeated_execution_on_identical_input_is_deterministic() -> None:
    host = HostRef(id="HOST-01")
    parent_obs = _obs("obs-parent", host=host, process=ProcessRef(entity_id="{PARENT}"))
    child_obs = _obs(
        "obs-child", host=host, process=ProcessRef(entity_id="{CHILD}", parent_entity_id="{PARENT}")
    )
    items = [_pair("ev-parent", parent_obs), _pair("ev-child", child_obs)]

    result_1 = correlate_structurally(items)
    result_2 = correlate_structurally(items)

    assert result_1.links == result_2.links
    assert result_1.groups == result_2.groups


# ===========================================================================
# 21, 22. Link/group deduplication and input-order independence
# ===========================================================================


def test_no_duplicate_links_for_the_same_structural_relationship() -> None:
    obs = _obs("obs-1", process=ProcessRef(name="powershell.exe"))
    items = [_pair("ev-1", obs), _pair("ev-2", obs)]
    result = correlate_structurally(items)
    link_ids = [entry.link_id for entry in result.links]
    assert len(link_ids) == len(set(link_ids))


def test_group_id_identical_regardless_of_input_ordering() -> None:
    host = HostRef(id="HOST-01")
    parent_obs = _obs("obs-parent", host=host, process=ProcessRef(entity_id="{PARENT}"))
    child_obs = _obs(
        "obs-child", host=host, process=ProcessRef(entity_id="{CHILD}", parent_entity_id="{PARENT}")
    )
    forward = [_pair("ev-parent", parent_obs), _pair("ev-child", child_obs)]
    reversed_ = list(reversed(forward))

    result_forward = correlate_structurally(forward)
    result_reversed = correlate_structurally(reversed_)

    assert result_forward.groups[0].group_id == result_reversed.groups[0].group_id
    assert result_forward.links[0].link_id == result_reversed.links[0].link_id


# ===========================================================================
# 23. Provenance
# ===========================================================================


def test_link_and_group_provenance_retain_expected_ids() -> None:
    host = HostRef(id="HOST-01")
    parent_obs = _obs("obs-parent", host=host, process=ProcessRef(entity_id="{PARENT}"))
    child_obs = _obs(
        "obs-child", host=host, process=ProcessRef(entity_id="{CHILD}", parent_entity_id="{PARENT}")
    )
    result = correlate_structurally([_pair("ev-parent", parent_obs), _pair("ev-child", child_obs)])

    link = result.links[0]
    assert set(link.provenance.source_evidence_ids) == {"ev-parent", "ev-child"}
    assert set(link.provenance.source_observation_ids) == {"obs-parent", "obs-child"}

    group = result.groups[0]
    assert set(group.provenance.source_evidence_ids) == {"ev-parent", "ev-child"}
    assert set(group.provenance.source_observation_ids) == {"obs-parent", "obs-child"}


def test_provenance_method_defaults_are_stamped_and_overridable() -> None:
    from attribution_platform.correlation import (
        STRUCTURAL_CORRELATION_METHOD,
        STRUCTURAL_CORRELATION_METHOD_VERSION,
    )

    obs = _obs("obs-1", process=ProcessRef(name="x"))
    (link,) = correlate_structurally([_pair("ev-1", obs), _pair("ev-2", obs)]).links
    assert link.provenance.method == STRUCTURAL_CORRELATION_METHOD
    assert link.provenance.method_version == STRUCTURAL_CORRELATION_METHOD_VERSION

    (link_custom,) = correlate_structurally(
        [_pair("ev-1", obs), _pair("ev-2", obs)], method="custom", method_version="9.9"
    ).links
    assert link_custom.provenance.method == "custom"
    assert link_custom.provenance.method_version == "9.9"


# ===========================================================================
# 24. CR-1 structural semantics
# ===========================================================================


def test_multiple_evidence_from_one_execution_thread_are_grouped_not_independent() -> None:
    """CR-1: Evidence items arising from one connected execution/lineage
    thread must be represented as one group -- so a later attribution layer
    can count them once -- not as independent, unrelated behavioral
    instances."""
    host = HostRef(id="HOST-01")
    parent_obs = _obs(
        "obs-office", host=host, process=ProcessRef(entity_id="{OFFICE}", name="winword.exe")
    )
    shell_obs = _obs(
        "obs-shell",
        host=host,
        process=ProcessRef(entity_id="{SHELL}", parent_entity_id="{OFFICE}", name="cmd.exe"),
    )
    payload_obs = _obs(
        "obs-payload",
        host=host,
        process=ProcessRef(entity_id="{PAYLOAD}", parent_entity_id="{SHELL}", name="payload.exe"),
    )
    items = [
        _pair("ev-office", parent_obs),
        _pair("ev-shell", shell_obs),
        _pair("ev-payload", payload_obs),
    ]

    result = correlate_structurally(items)

    assert len(result.groups) == 1
    assert set(result.groups[0].member_evidence_ids) == {"ev-office", "ev-shell", "ev-payload"}


# ===========================================================================
# Additional: input validation, empty input, error handling
# ===========================================================================


def test_empty_input_returns_empty_result() -> None:
    result = correlate_structurally([])
    assert result.links == ()
    assert result.groups == ()


def test_mismatched_evidence_observation_pairing_fails_closed() -> None:
    obs_a = _obs("obs-a")
    obs_b = _obs("obs-b")
    evidence_a = _evidence("ev-1", obs_a)
    with pytest.raises(CorrelationError, match="does not have exactly the supplied observation"):
        correlate_structurally([(evidence_a, obs_b)])


def test_multi_observation_evidence_cannot_be_paired_with_only_one_observation() -> None:
    """G2.1 audit finding: Evidence is a legitimate shape at the G0.6
    contract level even with multiple source Observations, but G2.1 is
    intentionally scoped to single-Observation Evidence (matching Phase 1's
    only current producer). Pairing such an Evidence with just one of its
    several source Observations must fail closed rather than silently
    correlate against a partial view of its provenance."""
    obs_a = _obs("obs-a")
    obs_b = _obs("obs-b")
    multi_observation_evidence = derive_evidence(
        evidence_id="ev-multi",
        evidence_type=EvidenceType.BEHAVIORAL,
        claim="evidence derived from two observations",
        observations=(obs_a, obs_b),
        rule_ref=RuleRef(rule_id="golden-rule", rule_version="1.0"),
    )
    assert multi_observation_evidence.provenance.source_observation_ids == ("obs-a", "obs-b")

    with pytest.raises(CorrelationError, match="does not have exactly the supplied observation"):
        correlate_structurally([(multi_observation_evidence, obs_a)])


def test_single_observation_evidence_still_correlates_normally() -> None:
    """The valid, currently-supported single-Observation path must remain
    fully functional after the tightened validation."""
    obs = _obs("obs-1", process=ProcessRef(name="powershell.exe"))
    items = [_pair("ev-1", obs), _pair("ev-2", obs)]

    result = correlate_structurally(items)

    assert len(result.links) == 1
    assert result.links[0].link_class == LinkClass.SHARED_OBSERVATION


def test_duplicate_evidence_id_in_input_fails_closed() -> None:
    obs = _obs("obs-1")
    evidence = _evidence("ev-1", obs)
    with pytest.raises(CorrelationError, match="duplicate evidence_id"):
        correlate_structurally([(evidence, obs), (evidence, obs)])


# ===========================================================================
# Guards: G2.1 stays structural-only, source-agnostic, ATT&CK-free
# ===========================================================================


def test_structural_module_never_imports_attack_knowledge_sources_or_dataplane() -> None:
    """G2.1 must not read ATT&CK knowledge, and must stay as source-agnostic
    as G2.0 already established for the package."""
    forbidden = ("attack_knowledge", "sources", "dataplane", "replay", "api")
    path = CORRELATION_DIR / "structural.py"
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    offending: list[str] = []
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.ImportFrom)
            and node.module
            and any(f"attribution_platform.{layer}" in node.module for layer in forbidden)
        ):
            offending.append(f"from {node.module} import ...")
    assert not offending, f"structural.py must not import {forbidden}: {offending}"


def test_structural_module_contains_no_contextual_dimension_computation() -> None:
    """G2.1 must not compute any of the five contextual dimensions -- they
    are G2.2's job. This is a source-level guard, not just a runtime
    behavior test: none of the contextual LinkClass members may appear as
    an assigned link_class anywhere in structural.py's source."""
    path = CORRELATION_DIR / "structural.py"
    text = path.read_text(encoding="utf-8")
    forbidden_contextual = (
        "LinkClass.SAME_HOST_ID",
        "LinkClass.SAME_HOST_NAME",
        "LinkClass.SAME_USER_ID",
        "LinkClass.SAME_USER_NAME",
        "LinkClass.SAME_DESTINATION_IP",
    )
    for term in forbidden_contextual:
        assert term not in text, f"contextual dimension {term!r} referenced in structural.py"


def test_structural_module_introduces_no_temporal_or_sequence_vocabulary() -> None:
    path = CORRELATION_DIR / "structural.py"
    text = path.read_text(encoding="utf-8")
    forbidden_terms = (
        "TEMPORAL_PROXIMITY",
        "BehavioralSequence",
        "time_window",
        "sequence_order",
    )
    for term in forbidden_terms:
        assert term not in text, f"forbidden term {term!r} found in structural.py"
