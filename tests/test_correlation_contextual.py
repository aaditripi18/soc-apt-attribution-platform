"""Tests for gate G2.2: the contextual correlation engine.

Covers exactly the five contextual dimensions ADR-0003 approved
(SAME_HOST_ID, SAME_HOST_NAME, SAME_USER_ID, SAME_USER_NAME,
SAME_DESTINATION_IP), their independence from each other (no dimension
substitutes for another), fail-closed handling of missing/blank fields, and
-- the central G2.2 invariant -- that contextual links can NEVER create,
merge, or be required to form a CorrelationGroup: they only ever attach to
groups G2.1's structural engine already produced. Also covers provenance,
determinism, multi-Observation-Evidence rejection (reusing G2.1's exact
boundary), and an explicit regression suite proving contextual correlation
cannot alter structural link generation or group formation/membership.

Uses the same pure-Python golden-corpus pattern `test_correlation_structural.py`
already established (domain contracts + `derive_evidence`), not a JSON
fixture/replay pipeline -- ADR-0003 reserves that for G2.3.

Does NOT touch any G0.x/G1.x source, test, or fixture, and does not modify
G2.0/G2.1 behavior. Offline, deterministic, no Elastic/Docker/Windows/network
required (loads only the vendored ATT&CK KB, for the one test proving
shared-technique alone does not create a contextual link).
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
    contextualize,
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

_CONTEXTUAL_CLASSES = (
    LinkClass.SAME_HOST_ID,
    LinkClass.SAME_HOST_NAME,
    LinkClass.SAME_USER_ID,
    LinkClass.SAME_USER_NAME,
    LinkClass.SAME_DESTINATION_IP,
)


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
    claim: str = "synthetic contextual-correlation golden-corpus evidence",
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


def _empty_structural_result() -> StructuralCorrelationResult:
    return StructuralCorrelationResult(links=(), groups=())


# ===========================================================================
# 1-5. Positive: one link per dimension
# ===========================================================================


def test_same_host_id_positive() -> None:
    obs_a = _obs("obs-a", host=HostRef(id="HOST-01"))
    obs_b = _obs("obs-b", host=HostRef(id="HOST-01"))
    items = [_pair("ev-1", obs_a), _pair("ev-2", obs_b)]

    result = contextualize(_empty_structural_result(), items)

    assert len(result.contextual_links) == 1
    link = result.contextual_links[0]
    assert link.link_class == LinkClass.SAME_HOST_ID
    assert link.basis.field_path == "host.id"
    assert link.basis.observed_value == "HOST-01"
    assert {link.anchor_a, link.anchor_b} == {"ev-1", "ev-2"}


def test_same_host_name_positive() -> None:
    obs_a = _obs("obs-a", host=HostRef(name="workstation-a"))
    obs_b = _obs("obs-b", host=HostRef(name="workstation-a"))
    result = contextualize(_empty_structural_result(), [_pair("ev-1", obs_a), _pair("ev-2", obs_b)])
    assert len(result.contextual_links) == 1
    link = result.contextual_links[0]
    assert link.link_class == LinkClass.SAME_HOST_NAME
    assert link.basis.field_path == "host.name"
    assert link.basis.observed_value == "workstation-a"


def test_same_user_id_positive() -> None:
    obs_a = _obs("obs-a", user=UserRef(id="U-001"))
    obs_b = _obs("obs-b", user=UserRef(id="U-001"))
    result = contextualize(_empty_structural_result(), [_pair("ev-1", obs_a), _pair("ev-2", obs_b)])
    assert len(result.contextual_links) == 1
    link = result.contextual_links[0]
    assert link.link_class == LinkClass.SAME_USER_ID
    assert link.basis.field_path == "user.id"
    assert link.basis.observed_value == "U-001"


def test_same_user_name_positive() -> None:
    obs_a = _obs("obs-a", user=UserRef(name="svc-admin"))
    obs_b = _obs("obs-b", user=UserRef(name="svc-admin"))
    result = contextualize(_empty_structural_result(), [_pair("ev-1", obs_a), _pair("ev-2", obs_b)])
    assert len(result.contextual_links) == 1
    link = result.contextual_links[0]
    assert link.link_class == LinkClass.SAME_USER_NAME
    assert link.basis.field_path == "user.name"
    assert link.basis.observed_value == "svc-admin"


def test_same_destination_ip_positive() -> None:
    dest = NetworkInfo(destination=NetworkEndpoint(ip="203.0.113.10"))
    obs_a = _obs("obs-a", network=dest)
    obs_b = _obs("obs-b", network=dest)
    result = contextualize(_empty_structural_result(), [_pair("ev-1", obs_a), _pair("ev-2", obs_b)])
    assert len(result.contextual_links) == 1
    link = result.contextual_links[0]
    assert link.link_class == LinkClass.SAME_DESTINATION_IP
    assert link.basis.field_path == "network.destination.ip"
    assert link.basis.observed_value == "203.0.113.10"


# ===========================================================================
# 6-10. Missing field -> no link (fail closed)
# ===========================================================================


def test_missing_host_id_produces_no_same_host_id_link() -> None:
    obs_a = _obs("obs-a", host=HostRef(name="x"))  # no id
    obs_b = _obs("obs-b", host=HostRef(name="x"))
    result = contextualize(_empty_structural_result(), [_pair("ev-1", obs_a), _pair("ev-2", obs_b)])
    assert all(entry.link_class != LinkClass.SAME_HOST_ID for entry in result.contextual_links)


def test_missing_host_name_produces_no_same_host_name_link() -> None:
    obs_a = _obs("obs-a", host=HostRef(id="H1"))  # no name
    obs_b = _obs("obs-b", host=HostRef(id="H1"))
    result = contextualize(_empty_structural_result(), [_pair("ev-1", obs_a), _pair("ev-2", obs_b)])
    assert all(entry.link_class != LinkClass.SAME_HOST_NAME for entry in result.contextual_links)


def test_missing_user_id_produces_no_same_user_id_link() -> None:
    obs_a = _obs("obs-a", user=UserRef(name="alice"))  # no id
    obs_b = _obs("obs-b", user=UserRef(name="alice"))
    result = contextualize(_empty_structural_result(), [_pair("ev-1", obs_a), _pair("ev-2", obs_b)])
    assert all(entry.link_class != LinkClass.SAME_USER_ID for entry in result.contextual_links)


def test_missing_user_name_produces_no_same_user_name_link() -> None:
    obs_a = _obs("obs-a", user=UserRef(id="U1"))  # no name
    obs_b = _obs("obs-b", user=UserRef(id="U1"))
    result = contextualize(_empty_structural_result(), [_pair("ev-1", obs_a), _pair("ev-2", obs_b)])
    assert all(entry.link_class != LinkClass.SAME_USER_NAME for entry in result.contextual_links)


def test_missing_destination_ip_produces_no_link() -> None:
    obs_a = _obs("obs-a", network=NetworkInfo(destination=NetworkEndpoint(port=443)))  # no ip
    obs_b = _obs("obs-b", network=NetworkInfo(destination=NetworkEndpoint(port=443)))
    result = contextualize(_empty_structural_result(), [_pair("ev-1", obs_a), _pair("ev-2", obs_b)])
    assert result.contextual_links == ()


def test_no_network_at_all_produces_no_destination_ip_link() -> None:
    obs_a = _obs("obs-a")
    obs_b = _obs("obs-b")
    result = contextualize(_empty_structural_result(), [_pair("ev-1", obs_a), _pair("ev-2", obs_b)])
    assert result.contextual_links == ()


# ===========================================================================
# 11. Blank values fail closed
# ===========================================================================


def test_blank_host_id_fails_closed() -> None:
    obs_a = _obs("obs-a", host=HostRef(id="   "))
    obs_b = _obs("obs-b", host=HostRef(id="   "))
    result = contextualize(_empty_structural_result(), [_pair("ev-1", obs_a), _pair("ev-2", obs_b)])
    assert all(entry.link_class != LinkClass.SAME_HOST_ID for entry in result.contextual_links)


def test_blank_user_name_fails_closed() -> None:
    obs_a = _obs("obs-a", user=UserRef(name=""))
    obs_b = _obs("obs-b", user=UserRef(name=""))
    result = contextualize(_empty_structural_result(), [_pair("ev-1", obs_a), _pair("ev-2", obs_b)])
    assert all(entry.link_class != LinkClass.SAME_USER_NAME for entry in result.contextual_links)


def test_blank_destination_ip_fails_closed() -> None:
    obs_a = _obs("obs-a", network=NetworkInfo(destination=NetworkEndpoint(ip="  ")))
    obs_b = _obs("obs-b", network=NetworkInfo(destination=NetworkEndpoint(ip="  ")))
    result = contextualize(_empty_structural_result(), [_pair("ev-1", obs_a), _pair("ev-2", obs_b)])
    assert result.contextual_links == ()


# ===========================================================================
# 12-15, 33-36. No dimension substitutes for another
# ===========================================================================


def test_same_host_id_does_not_imply_same_host_name() -> None:
    """12/33: same host.id, different host.name -> SAME_HOST_ID yes,
    SAME_HOST_NAME no."""
    obs_a = _obs("obs-a", host=HostRef(id="HOST-01", name="alpha"))
    obs_b = _obs("obs-b", host=HostRef(id="HOST-01", name="beta"))
    result = contextualize(_empty_structural_result(), [_pair("ev-1", obs_a), _pair("ev-2", obs_b)])
    classes = {entry.link_class for entry in result.contextual_links}
    assert classes == {LinkClass.SAME_HOST_ID}


def test_same_host_name_does_not_imply_same_host_id() -> None:
    """13/34: same host.name, different host.id -> SAME_HOST_NAME yes,
    SAME_HOST_ID no."""
    obs_a = _obs("obs-a", host=HostRef(id="HOST-01", name="shared-name"))
    obs_b = _obs("obs-b", host=HostRef(id="HOST-02", name="shared-name"))
    result = contextualize(_empty_structural_result(), [_pair("ev-1", obs_a), _pair("ev-2", obs_b)])
    classes = {entry.link_class for entry in result.contextual_links}
    assert classes == {LinkClass.SAME_HOST_NAME}


def test_same_user_id_does_not_imply_same_user_name() -> None:
    """14/35: same user.id, different user.name -> SAME_USER_ID yes,
    SAME_USER_NAME no."""
    obs_a = _obs("obs-a", user=UserRef(id="U-001", name="alice"))
    obs_b = _obs("obs-b", user=UserRef(id="U-001", name="bob"))
    result = contextualize(_empty_structural_result(), [_pair("ev-1", obs_a), _pair("ev-2", obs_b)])
    classes = {entry.link_class for entry in result.contextual_links}
    assert classes == {LinkClass.SAME_USER_ID}


def test_same_user_name_does_not_imply_same_user_id() -> None:
    """15/36: same user.name, different user.id -> SAME_USER_NAME yes,
    SAME_USER_ID no."""
    obs_a = _obs("obs-a", user=UserRef(id="U-001", name="svc-admin"))
    obs_b = _obs("obs-b", user=UserRef(id="U-002", name="svc-admin"))
    result = contextualize(_empty_structural_result(), [_pair("ev-1", obs_a), _pair("ev-2", obs_b)])
    classes = {entry.link_class for entry in result.contextual_links}
    assert classes == {LinkClass.SAME_USER_NAME}


# ===========================================================================
# 16-18. Same host/user/destination alone never structural
# ===========================================================================


def test_same_host_alone_never_creates_a_structural_link_or_group() -> None:
    host = HostRef(id="HOST-01")
    items = [
        _pair("ev-1", _obs("obs-1", host=host, process=ProcessRef(entity_id="{A}"))),
        _pair("ev-2", _obs("obs-2", host=host, process=ProcessRef(entity_id="{B}"))),
    ]
    structural = correlate_structurally(items)
    assert structural.links == ()
    assert structural.groups == ()

    contextual = contextualize(structural, items)
    assert len(contextual.contextual_links) == 1
    assert contextual.contextual_links[0].link_class == LinkClass.SAME_HOST_ID
    assert contextual.groups == ()  # still no group -- contextual alone never creates one


def test_same_user_alone_never_creates_a_structural_link_or_group() -> None:
    user = UserRef(id="svc-admin")
    items = [
        _pair("ev-1", _obs("obs-1", user=user, process=ProcessRef(entity_id="{A}"))),
        _pair("ev-2", _obs("obs-2", user=user, process=ProcessRef(entity_id="{B}"))),
    ]
    structural = correlate_structurally(items)
    assert structural.groups == ()
    contextual = contextualize(structural, items)
    assert contextual.groups == ()


def test_same_destination_ip_alone_never_creates_a_structural_link_or_group() -> None:
    dest = NetworkInfo(destination=NetworkEndpoint(ip="203.0.113.10"))
    items = [
        _pair("ev-1", _obs("obs-1", network=dest)),
        _pair("ev-2", _obs("obs-2", network=dest)),
    ]
    structural = correlate_structurally(items)
    assert structural.groups == ()
    contextual = contextualize(structural, items)
    assert contextual.groups == ()


# ===========================================================================
# 19-21. Two separate structural groups sharing context remain separate
# ===========================================================================


def _two_lineage_trees_on_shared_context(
    host: HostRef, user: UserRef | None = None, network: NetworkInfo | None = None
) -> list[tuple[Evidence, Observation]]:
    tree_a_parent = _obs(
        "obs-a1", host=host, user=user, network=network, process=ProcessRef(entity_id="{A1}")
    )
    tree_a_child = _obs(
        "obs-a2",
        host=host,
        user=user,
        network=network,
        process=ProcessRef(entity_id="{A2}", parent_entity_id="{A1}"),
    )
    tree_b_parent = _obs(
        "obs-b1", host=host, user=user, network=network, process=ProcessRef(entity_id="{B1}")
    )
    tree_b_child = _obs(
        "obs-b2",
        host=host,
        user=user,
        network=network,
        process=ProcessRef(entity_id="{B2}", parent_entity_id="{B1}"),
    )
    return [
        _pair("ev-a1", tree_a_parent),
        _pair("ev-a2", tree_a_child),
        _pair("ev-b1", tree_b_parent),
        _pair("ev-b2", tree_b_child),
    ]


def test_shared_host_does_not_merge_two_structural_groups() -> None:
    items = _two_lineage_trees_on_shared_context(host=HostRef(id="HOST-01"))
    structural = correlate_structurally(items)
    assert len(structural.groups) == 2

    contextual = contextualize(structural, items)
    assert len(contextual.groups) == 2
    member_sets = {frozenset(g.member_evidence_ids) for g in contextual.groups}
    assert member_sets == {frozenset({"ev-a1", "ev-a2"}), frozenset({"ev-b1", "ev-b2"})}


def test_shared_user_does_not_merge_two_structural_groups() -> None:
    items = _two_lineage_trees_on_shared_context(
        host=HostRef(id="HOST-01"), user=UserRef(id="svc-admin")
    )
    structural = correlate_structurally(items)
    contextual = contextualize(structural, items)
    assert len(contextual.groups) == 2


def test_shared_destination_ip_does_not_merge_two_structural_groups() -> None:
    items = _two_lineage_trees_on_shared_context(
        host=HostRef(id="HOST-01"),
        network=NetworkInfo(destination=NetworkEndpoint(ip="203.0.113.10")),
    )
    structural = correlate_structurally(items)
    contextual = contextualize(structural, items)
    assert len(contextual.groups) == 2


def test_cross_group_contextual_link_attaches_to_both_groups_without_merging() -> None:
    """The contextual link between a member of group A and a member of
    group B is attached to BOTH groups independently -- proving the ADR's
    'never interpreted as relating the groups to each other' rule."""
    items = _two_lineage_trees_on_shared_context(host=HostRef(id="HOST-01"))
    structural = correlate_structurally(items)
    contextual = contextualize(structural, items)

    assert len(contextual.groups) == 2
    for group in contextual.groups:
        assert len(group.contextual_link_ids) > 0
    # The same underlying SAME_HOST_ID link ids may be shared across both
    # groups' contextual_link_ids -- that is expected, not a merge.
    ids_a, ids_b = (set(g.contextual_link_ids) for g in contextual.groups)
    assert ids_a & ids_b  # they do share at least one contextual link id
    member_sets = {frozenset(g.member_evidence_ids) for g in contextual.groups}
    assert len(member_sets) == 2  # but membership is still fully separate


# ===========================================================================
# 22-23. Contextual links only ever appear in contextual_link_ids
# ===========================================================================


def test_contextual_links_never_appear_in_structural_link_ids() -> None:
    host = HostRef(id="HOST-01")
    parent_obs = _obs("obs-parent", host=host, process=ProcessRef(entity_id="{PARENT}"))
    child_obs = _obs(
        "obs-child", host=host, process=ProcessRef(entity_id="{CHILD}", parent_entity_id="{PARENT}")
    )
    items = [_pair("ev-parent", parent_obs), _pair("ev-child", child_obs)]
    structural = correlate_structurally(items)
    contextual = contextualize(structural, items)

    group = contextual.groups[0]
    contextual_ids = {entry.link_id for entry in contextual.contextual_links}
    assert not (set(group.structural_link_ids) & contextual_ids)
    assert set(group.contextual_link_ids) <= contextual_ids


# ===========================================================================
# 24. No structural group -> contextual correlation creates none
# ===========================================================================


def test_contextual_correlation_creates_no_group_when_none_is_structural() -> None:
    obs_a = _obs("obs-a", host=HostRef(id="HOST-01"))
    obs_b = _obs("obs-b", host=HostRef(id="HOST-01"))
    items = [_pair("ev-1", obs_a), _pair("ev-2", obs_b)]

    empty_structural = StructuralCorrelationResult(links=(), groups=())
    result = contextualize(empty_structural, items)

    assert len(result.contextual_links) == 1  # the fact is still recorded
    assert result.groups == ()  # but no group is ever created from it


# ===========================================================================
# 25. Structural group membership unchanged after contextual attachment
# ===========================================================================


def test_structural_group_membership_unchanged_after_contextual_attachment() -> None:
    host = HostRef(id="HOST-01")
    parent_obs = _obs("obs-parent", host=host, process=ProcessRef(entity_id="{PARENT}"))
    child_obs = _obs(
        "obs-child", host=host, process=ProcessRef(entity_id="{CHILD}", parent_entity_id="{PARENT}")
    )
    items = [_pair("ev-parent", parent_obs), _pair("ev-child", child_obs)]
    structural = correlate_structurally(items)
    contextual = contextualize(structural, items)

    original = structural.groups[0]
    updated = contextual.groups[0]
    assert updated.group_id == original.group_id
    assert updated.member_evidence_ids == original.member_evidence_ids
    assert updated.member_observation_ids == original.member_observation_ids
    assert updated.structural_link_ids == original.structural_link_ids
    assert updated.provenance == original.provenance


# ===========================================================================
# 26. Multiple contextual dimensions produce separate links
# ===========================================================================


def test_multiple_shared_contextual_properties_produce_separate_links() -> None:
    host = HostRef(id="HOST-01", name="workstation-a")
    user = UserRef(id="U-001", name="svc-admin")
    dest = NetworkInfo(destination=NetworkEndpoint(ip="203.0.113.10"))
    obs_a = _obs("obs-a", host=host, user=user, network=dest)
    obs_b = _obs("obs-b", host=host, user=user, network=dest)

    result = contextualize(_empty_structural_result(), [_pair("ev-1", obs_a), _pair("ev-2", obs_b)])

    classes = {entry.link_class for entry in result.contextual_links}
    assert classes == {
        LinkClass.SAME_HOST_ID,
        LinkClass.SAME_HOST_NAME,
        LinkClass.SAME_USER_ID,
        LinkClass.SAME_USER_NAME,
        LinkClass.SAME_DESTINATION_IP,
    }
    assert len(result.contextual_links) == 5
    link_ids = [entry.link_id for entry in result.contextual_links]
    assert len(link_ids) == len(set(link_ids))  # all distinct


# ===========================================================================
# 27-28. Deduplication and input-order independence
# ===========================================================================


def test_duplicate_contextual_relationships_are_deduplicated() -> None:
    obs_a = _obs("obs-a", host=HostRef(id="HOST-01"))
    obs_b = _obs("obs-b", host=HostRef(id="HOST-01"))
    obs_c = _obs("obs-c", host=HostRef(id="HOST-01"))
    items = [_pair("ev-1", obs_a), _pair("ev-2", obs_b), _pair("ev-3", obs_c)]

    result = contextualize(_empty_structural_result(), items)

    link_ids = [entry.link_id for entry in result.contextual_links]
    assert len(link_ids) == len(set(link_ids))
    assert len(result.contextual_links) == 3  # 3 choose 2 pairs, each unique


def test_input_ordering_does_not_change_contextual_link_ids() -> None:
    obs_a = _obs("obs-a", host=HostRef(id="HOST-01"))
    obs_b = _obs("obs-b", host=HostRef(id="HOST-01"))
    forward = [_pair("ev-1", obs_a), _pair("ev-2", obs_b)]
    reversed_ = list(reversed(forward))

    result_forward = contextualize(_empty_structural_result(), forward)
    result_reversed = contextualize(_empty_structural_result(), reversed_)

    assert result_forward.contextual_links[0].link_id == result_reversed.contextual_links[0].link_id


def test_input_ordering_does_not_change_group_attachment() -> None:
    host = HostRef(id="HOST-01")
    parent_obs = _obs("obs-parent", host=host, process=ProcessRef(entity_id="{PARENT}"))
    child_obs = _obs(
        "obs-child", host=host, process=ProcessRef(entity_id="{CHILD}", parent_entity_id="{PARENT}")
    )
    forward = [_pair("ev-parent", parent_obs), _pair("ev-child", child_obs)]
    reversed_ = list(reversed(forward))

    structural = correlate_structurally(forward)
    contextual_forward = contextualize(structural, forward)
    contextual_reversed = contextualize(structural, reversed_)

    assert (
        contextual_forward.groups[0].contextual_link_ids
        == contextual_reversed.groups[0].contextual_link_ids
    )


# ===========================================================================
# 29. Provenance completeness
# ===========================================================================


def test_contextual_link_and_group_provenance_complete() -> None:
    host = HostRef(id="HOST-01")
    parent_obs = _obs("obs-parent", host=host, process=ProcessRef(entity_id="{PARENT}"))
    child_obs = _obs(
        "obs-child", host=host, process=ProcessRef(entity_id="{CHILD}", parent_entity_id="{PARENT}")
    )
    items = [_pair("ev-parent", parent_obs), _pair("ev-child", child_obs)]
    structural = correlate_structurally(items)
    contextual = contextualize(structural, items)

    link = contextual.contextual_links[0]
    assert set(link.provenance.source_evidence_ids) == {"ev-parent", "ev-child"}
    assert set(link.provenance.source_observation_ids) == {"obs-parent", "obs-child"}

    group = contextual.groups[0]
    assert set(group.provenance.source_evidence_ids) == {"ev-parent", "ev-child"}
    assert set(group.provenance.source_observation_ids) == {"obs-parent", "obs-child"}


# ===========================================================================
# 30. CorrelationBasis.field_path correct per dimension (table-driven)
# ===========================================================================


@pytest.mark.parametrize(
    ("link_class", "field_path"),
    [
        (LinkClass.SAME_HOST_ID, "host.id"),
        (LinkClass.SAME_HOST_NAME, "host.name"),
        (LinkClass.SAME_USER_ID, "user.id"),
        (LinkClass.SAME_USER_NAME, "user.name"),
        (LinkClass.SAME_DESTINATION_IP, "network.destination.ip"),
    ],
)
def test_field_path_correct_per_dimension(link_class: LinkClass, field_path: str) -> None:
    kwargs: dict[str, object] = {}
    if link_class == LinkClass.SAME_HOST_ID:
        kwargs = {"host": HostRef(id="V")}
    elif link_class == LinkClass.SAME_HOST_NAME:
        kwargs = {"host": HostRef(name="V")}
    elif link_class == LinkClass.SAME_USER_ID:
        kwargs = {"user": UserRef(id="V")}
    elif link_class == LinkClass.SAME_USER_NAME:
        kwargs = {"user": UserRef(name="V")}
    elif link_class == LinkClass.SAME_DESTINATION_IP:
        kwargs = {"network": NetworkInfo(destination=NetworkEndpoint(ip="V"))}

    obs_a = _obs("obs-a", **kwargs)  # type: ignore[arg-type]
    obs_b = _obs("obs-b", **kwargs)  # type: ignore[arg-type]
    result = contextualize(_empty_structural_result(), [_pair("ev-1", obs_a), _pair("ev-2", obs_b)])

    (link,) = result.contextual_links
    assert link.link_class == link_class
    assert link.basis.field_path == field_path


# ===========================================================================
# 31. uncertainty_note handling
# ===========================================================================


@pytest.mark.parametrize("link_class", _CONTEXTUAL_CLASSES)
def test_every_contextual_link_carries_an_uncertainty_note(link_class: LinkClass) -> None:
    kwargs: dict[str, object] = {}
    if link_class == LinkClass.SAME_HOST_ID:
        kwargs = {"host": HostRef(id="V")}
    elif link_class == LinkClass.SAME_HOST_NAME:
        kwargs = {"host": HostRef(name="V")}
    elif link_class == LinkClass.SAME_USER_ID:
        kwargs = {"user": UserRef(id="V")}
    elif link_class == LinkClass.SAME_USER_NAME:
        kwargs = {"user": UserRef(name="V")}
    elif link_class == LinkClass.SAME_DESTINATION_IP:
        kwargs = {"network": NetworkInfo(destination=NetworkEndpoint(ip="V"))}

    obs_a = _obs("obs-a", **kwargs)  # type: ignore[arg-type]
    obs_b = _obs("obs-b", **kwargs)  # type: ignore[arg-type]
    (link,) = contextualize(
        _empty_structural_result(), [_pair("ev-1", obs_a), _pair("ev-2", obs_b)]
    ).contextual_links

    assert link.basis.uncertainty_note is not None
    assert len(link.basis.uncertainty_note) > 0
    # never numeric/probabilistic language
    assert not any(char.isdigit() for char in link.basis.uncertainty_note)


# ===========================================================================
# 32. Multi-Observation Evidence rejected
# ===========================================================================


def test_multi_observation_evidence_rejected_by_contextualize() -> None:
    obs_a = _obs("obs-a", host=HostRef(id="H1"))
    obs_b = _obs("obs-b", host=HostRef(id="H1"))
    multi_observation_evidence = derive_evidence(
        evidence_id="ev-multi",
        evidence_type=EvidenceType.BEHAVIORAL,
        claim="evidence derived from two observations",
        observations=(obs_a, obs_b),
        rule_ref=RuleRef(rule_id="golden-rule", rule_version="1.0"),
    )
    with pytest.raises(CorrelationError, match="does not have exactly the supplied observation"):
        contextualize(_empty_structural_result(), [(multi_observation_evidence, obs_a)])


# ===========================================================================
# 37. Destination IP across unrelated process trees stays contextual only
# ===========================================================================


def test_shared_destination_across_unrelated_process_trees_stays_contextual_only() -> None:
    dest = NetworkInfo(destination=NetworkEndpoint(ip="203.0.113.10"))
    items = _two_lineage_trees_on_shared_context(host=HostRef(id="HOST-01"), network=dest)
    structural = correlate_structurally(items)
    contextual = contextualize(structural, items)

    assert len(contextual.groups) == 2
    assert all(
        entry.link_class in (LinkClass.SAME_HOST_ID, LinkClass.SAME_DESTINATION_IP)
        for entry in contextual.contextual_links
    )


# ===========================================================================
# 38-40. Non-field negatives: ATT&CK, timestamp, process name
# ===========================================================================


def test_shared_attack_technique_alone_creates_no_contextual_link(
    knowledge: AttackKnowledge,
) -> None:
    technique = knowledge.techniques()[0]
    ref = AttackRef(
        stix_id=technique["id"],
        object_type=technique["type"],
        attack_kb_version=knowledge.attack_kb_version,
    )
    obs_a = _obs("obs-a")
    obs_b = _obs("obs-b")
    items = [
        _pair("ev-1", obs_a, attack_ref=ref, knowledge=knowledge),
        _pair("ev-2", obs_b, attack_ref=ref, knowledge=knowledge),
    ]
    result = contextualize(_empty_structural_result(), items)
    assert result.contextual_links == ()


def test_temporal_proximity_alone_creates_no_contextual_link() -> None:
    obs_a = _obs("obs-a", timestamp=T0)
    obs_b = _obs("obs-b", timestamp=datetime(2026, 1, 1, 12, 0, 1, tzinfo=UTC))
    result = contextualize(_empty_structural_result(), [_pair("ev-1", obs_a), _pair("ev-2", obs_b)])
    assert result.contextual_links == ()


def test_process_name_equality_alone_creates_no_contextual_link() -> None:
    obs_a = _obs("obs-a", process=ProcessRef(name="powershell.exe"))
    obs_b = _obs("obs-b", process=ProcessRef(name="powershell.exe"))
    result = contextualize(_empty_structural_result(), [_pair("ev-1", obs_a), _pair("ev-2", obs_b)])
    assert result.contextual_links == ()


# ===========================================================================
# G2.1 regression protection: contextual correlation cannot alter
# structural link generation, group formation, or membership.
# ===========================================================================


def test_contextualize_does_not_alter_structural_result_object() -> None:
    """calling contextualize must not mutate the StructuralCorrelationResult
    it was given (frozen dataclasses guarantee this structurally, but this
    test proves it behaviorally too: re-deriving structural correlation
    from the same items afterward gives an identical result)."""
    host = HostRef(id="HOST-01")
    parent_obs = _obs("obs-parent", host=host, process=ProcessRef(entity_id="{PARENT}"))
    child_obs = _obs(
        "obs-child", host=host, process=ProcessRef(entity_id="{CHILD}", parent_entity_id="{PARENT}")
    )
    items = [_pair("ev-parent", parent_obs), _pair("ev-child", child_obs)]

    structural_before = correlate_structurally(items)
    contextualize(structural_before, items)
    structural_after = correlate_structurally(items)

    assert structural_before.links == structural_after.links
    assert structural_before.groups == structural_after.groups


def test_contextualize_never_changes_structural_group_count() -> None:
    host = HostRef(id="HOST-01")
    items = _two_lineage_trees_on_shared_context(host=host, user=UserRef(id="shared"))
    structural = correlate_structurally(items)
    contextual = contextualize(structural, items)
    assert len(contextual.groups) == len(structural.groups)


def test_contextualize_never_introduces_a_structural_link_class() -> None:
    host = HostRef(id="HOST-01")
    user = UserRef(id="U1")
    dest = NetworkInfo(destination=NetworkEndpoint(ip="203.0.113.10"))
    obs_a = _obs("obs-a", host=host, user=user, network=dest)
    obs_b = _obs("obs-b", host=host, user=user, network=dest)
    result = contextualize(_empty_structural_result(), [_pair("ev-1", obs_a), _pair("ev-2", obs_b)])
    structural_classes = {
        LinkClass.SHARED_OBSERVATION,
        LinkClass.SAME_PROCESS_ENTITY,
        LinkClass.PROCESS_LINEAGE,
    }
    assert not any(entry.link_class in structural_classes for entry in result.contextual_links)


# ===========================================================================
# Guards: G2.2 stays contextual-only, source-agnostic, ATT&CK-free
# ===========================================================================


def test_contextual_module_never_imports_attack_knowledge_sources_or_dataplane() -> None:
    forbidden = ("attack_knowledge", "sources", "dataplane", "replay", "api")
    path = CORRELATION_DIR / "contextual.py"
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    offending: list[str] = []
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.ImportFrom)
            and node.module
            and any(f"attribution_platform.{layer}" in node.module for layer in forbidden)
        ):
            offending.append(f"from {node.module} import ...")
    assert not offending, f"contextual.py must not import {forbidden}: {offending}"


def test_contextual_module_does_not_reimplement_or_import_structural_internals() -> None:
    """G2.2 may import structural.py's PUBLIC result type, but must never
    touch its private connected-component internals (_connected_components,
    _Node, _validate_nodes) -- proving it cannot accidentally feed
    contextual edges into the union-find."""
    path = CORRELATION_DIR / "contextual.py"
    text = path.read_text(encoding="utf-8")
    forbidden_names = ("_connected_components", "structural._Node", "structural._validate_nodes")
    for name in forbidden_names:
        assert name not in text, f"contextual.py must not reference {name!r}"


def test_contextual_module_introduces_no_temporal_or_sequence_vocabulary() -> None:
    """``TEMPORAL_PROXIMITY``/``BehavioralSequence`` are deliberately excluded
    from this scan: the module docstring legitimately names them, in prose,
    as scope explicitly deferred to G2.4 -- exactly like G2.0's own guard
    excluding "intrusion-set" for the same reason. The code-shaped terms
    below (a config variable, an ordering-function name) would still catch
    a genuine regression; they do not appear anywhere in prose."""
    path = CORRELATION_DIR / "contextual.py"
    text = path.read_text(encoding="utf-8")
    forbidden_terms = ("time_window", "sequence_order")
    for term in forbidden_terms:
        assert term not in text, f"forbidden term {term!r} found in contextual.py"


def test_contextual_module_introduces_no_scoring_or_attribution_vocabulary() -> None:
    path = CORRELATION_DIR / "contextual.py"
    text = path.read_text(encoding="utf-8")
    forbidden_terms = (
        "Candidate",
        "Hypothesis",
        "AttackChain",
        "Likelihood",
        "Confidence",
        "AttributionResult",
        "attribution_score",
        "attribution_confidence",
        "IntrusionSet",
        "ThreatActor",
        "campaign_ref",
        "actor_ref",
    )
    for term in forbidden_terms:
        assert term not in text, f"forbidden term {term!r} found in contextual.py"
