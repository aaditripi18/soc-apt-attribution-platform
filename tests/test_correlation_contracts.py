"""Tests for gate G2.0: correlation domain contracts (ADR-0003), updated at
G2.4.3 (ADR-0004 D20) for the ninth ``LinkClass`` member.

Covers: the closed nine-value ``LinkClass`` vocabulary (exactly three
structural, exactly six contextual, no overlap/omission);
``CorrelationBasis`` field preservation and its structural-basis-has-no-
uncertainty-note invariant; ``CorrelationProvenance``'s non-empty,
canonicalized id-set pattern (parallel to G0.3's ``DerivationProvenance``);
``CorrelationLink``'s distinct-and-symmetric anchors, class/basis agreement,
and deterministic identity; ``CorrelationGroup``'s minimum-two-members and
structural/contextual disjointness invariants, and ``build_correlation_group``
as the one construction path that can actually enforce "every structural
link really is structural"; deterministic id-composition helpers
(stability under identical inputs, sensitivity to a changed identity
input); canonical-JSON serialization round-tripping via the existing,
unmodified ``domain.to_canonical_json``; the explicit negative proof that
``SAME_HOST_ID``/``SAME_USER_ID`` can never form a group; a documentation
test for the process-entity host-scoping note; and guards preserving
ADR-0003's boundaries (no attribution/scoring/actor/ATT&CK-actor vocabulary,
no hard-coded technique ids, no import of sources/dataplane/replay/api).

Does NOT touch any G0.x/G1.x source, test, or fixture. Offline,
deterministic, no Elastic/Docker/Windows/network required.
"""

from __future__ import annotations

import ast
import dataclasses
import json
import re
from pathlib import Path

import pytest

from attribution_platform.correlation import (
    CONTEXTUAL_LINK_CLASSES,
    CorrelationBasis,
    CorrelationError,
    CorrelationGroup,
    CorrelationLink,
    CorrelationProvenance,
    LinkClass,
    build_correlation_group,
    compute_group_id,
    compute_link_id,
)
from attribution_platform.domain import to_canonical_json

REPO_ROOT = Path(__file__).resolve().parents[1]
CORRELATION_DIR = REPO_ROOT / "src" / "attribution_platform" / "correlation"

_STRUCTURAL = (
    LinkClass.SHARED_OBSERVATION,
    LinkClass.SAME_PROCESS_ENTITY,
    LinkClass.PROCESS_LINEAGE,
    LinkClass.PROCESS_INTERACTION,
)
_CONTEXTUAL = (
    LinkClass.SAME_HOST_ID,
    LinkClass.SAME_HOST_NAME,
    LinkClass.SAME_USER_ID,
    LinkClass.SAME_USER_NAME,
    LinkClass.SAME_DESTINATION_IP,
    LinkClass.TEMPORAL_PROXIMITY,
    LinkClass.PROCESS_ACCESS_TARGET,
)


def _provenance(**overrides: object) -> CorrelationProvenance:
    kwargs: dict[str, object] = {
        "method": "structural-correlation",
        "method_version": "1.0",
        "source_evidence_ids": ("ev-1", "ev-2"),
        "source_observation_ids": ("obs-1", "obs-2"),
    }
    kwargs.update(overrides)
    return CorrelationProvenance(**kwargs)  # type: ignore[arg-type]


def _basis(
    link_class: LinkClass = LinkClass.SAME_PROCESS_ENTITY, **overrides: object
) -> CorrelationBasis:
    kwargs: dict[str, object] = {
        "link_class": link_class,
        "field_path": "process.entity_id",
        "observed_value": "{GUID-1234}",
        "observation_id_a": "obs-1",
        "observation_id_b": "obs-2",
    }
    kwargs.update(overrides)
    return CorrelationBasis(**kwargs)  # type: ignore[arg-type]


def _link(
    link_class: LinkClass = LinkClass.SAME_PROCESS_ENTITY, **overrides: object
) -> CorrelationLink:
    kwargs: dict[str, object] = {
        "link_id": compute_link_id(
            link_class=link_class, observed_value="{GUID-1234}", anchor_a="ev-1", anchor_b="ev-2"
        ),
        "anchor_a": "ev-1",
        "anchor_b": "ev-2",
        "link_class": link_class,
        "basis": _basis(link_class),
        "provenance": _provenance(),
    }
    kwargs.update(overrides)
    return CorrelationLink(**kwargs)  # type: ignore[arg-type]


# ===========================================================================
# 1. LinkClass: the closed eleven-value vocabulary (ADR-0003 Amendment A5)
# ===========================================================================


def test_all_eleven_link_classes_exist() -> None:
    expected = {
        "SHARED_OBSERVATION",
        "SAME_PROCESS_ENTITY",
        "PROCESS_LINEAGE",
        "SAME_HOST_ID",
        "SAME_HOST_NAME",
        "SAME_USER_ID",
        "SAME_USER_NAME",
        "SAME_DESTINATION_IP",
        "TEMPORAL_PROXIMITY",
        "PROCESS_INTERACTION",
        "PROCESS_ACCESS_TARGET",
    }
    assert {member.name for member in LinkClass} == expected
    assert len(LinkClass) == 11


def test_exactly_four_structural_and_seven_contextual() -> None:
    structural = {member for member in LinkClass if member.is_structural}
    contextual = {member for member in LinkClass if not member.is_structural}
    assert structural == set(_STRUCTURAL)
    assert len(structural) == 4
    assert contextual == set(_CONTEXTUAL)
    assert len(contextual) == 7
    assert LinkClass.TEMPORAL_PROXIMITY in contextual
    # Amendment A4: handle access is common benign behaviour -> never group-forming
    assert LinkClass.PROCESS_ACCESS_TARGET in contextual
    assert contextual == CONTEXTUAL_LINK_CLASSES


def test_structural_and_contextual_partition_with_no_overlap_or_omission() -> None:
    structural = {member for member in LinkClass if member.is_structural}
    contextual = {member for member in LinkClass if not member.is_structural}
    assert structural | contextual == set(LinkClass)
    assert structural & contextual == set()


@pytest.mark.parametrize("member", _STRUCTURAL)
def test_each_structural_member_reports_is_structural_true(member: LinkClass) -> None:
    assert member.is_structural is True


@pytest.mark.parametrize("member", _CONTEXTUAL)
def test_each_contextual_member_reports_is_structural_false(member: LinkClass) -> None:
    assert member.is_structural is False


def test_unknown_link_class_value_rejected() -> None:
    with pytest.raises(ValueError):
        LinkClass("not_a_real_link_class")


# ===========================================================================
# 2. Negative proof: SAME_HOST_ID / SAME_USER_ID never form a group
# ===========================================================================


def test_same_host_id_and_same_user_id_are_not_structural() -> None:
    """Direct proof of the ADR-0003 correction this gate implements: sharing
    a host or user identity alone must never be group-forming."""
    assert LinkClass.SAME_HOST_ID.is_structural is False
    assert LinkClass.SAME_USER_ID.is_structural is False


def test_same_host_id_link_rejected_by_build_correlation_group_as_structural() -> None:
    host_link = _link(
        LinkClass.SAME_HOST_ID,
        link_id=compute_link_id(
            link_class=LinkClass.SAME_HOST_ID,
            observed_value="HOST-01",
            anchor_a="ev-1",
            anchor_b="ev-2",
        ),
        basis=_basis(
            LinkClass.SAME_HOST_ID,
            field_path="host.id",
            observed_value="HOST-01",
            uncertainty_note="shared host co-residence does not imply a causal relationship",
        ),
    )
    with pytest.raises(CorrelationError, match="cannot form a CorrelationGroup"):
        build_correlation_group(
            group_id=compute_group_id(["ev-1", "ev-2"]),
            member_evidence_ids=("ev-1", "ev-2"),
            member_observation_ids=("obs-1", "obs-2"),
            structural_links=(host_link,),
            provenance=_provenance(),
        )


def test_same_user_id_link_rejected_by_build_correlation_group_as_structural() -> None:
    user_link = _link(
        LinkClass.SAME_USER_ID,
        link_id=compute_link_id(
            link_class=LinkClass.SAME_USER_ID,
            observed_value="svc-admin",
            anchor_a="ev-1",
            anchor_b="ev-2",
        ),
        basis=_basis(
            LinkClass.SAME_USER_ID,
            field_path="user.id",
            observed_value="svc-admin",
            uncertainty_note=(
                "shared/service accounts are common and do not imply a causal relationship"
            ),
        ),
    )
    with pytest.raises(CorrelationError, match="cannot form a CorrelationGroup"):
        build_correlation_group(
            group_id=compute_group_id(["ev-1", "ev-2"]),
            member_evidence_ids=("ev-1", "ev-2"),
            member_observation_ids=("obs-1", "obs-2"),
            structural_links=(user_link,),
            provenance=_provenance(),
        )


# ===========================================================================
# 3. CorrelationBasis
# ===========================================================================


def test_basis_preserves_its_explanatory_fields() -> None:
    basis = _basis(
        LinkClass.PROCESS_LINEAGE,
        field_path="process.parent_entity_id",
        observed_value="{PARENT-GUID}",
        observation_id_a="obs-parent",
        observation_id_b="obs-child",
    )
    assert basis.link_class == LinkClass.PROCESS_LINEAGE
    assert basis.field_path == "process.parent_entity_id"
    assert basis.observed_value == "{PARENT-GUID}"
    assert basis.observation_id_a == "obs-parent"
    assert basis.observation_id_b == "obs-child"
    assert basis.uncertainty_note is None


def test_shared_observation_basis_allows_equal_observation_ids() -> None:
    """SHARED_OBSERVATION legitimately means the same Observation twice."""
    basis = _basis(
        LinkClass.SHARED_OBSERVATION,
        field_path="detection.technique_mappings",
        observed_value="two-technique-fanout",
        observation_id_a="obs-1",
        observation_id_b="obs-1",
    )
    assert basis.observation_id_a == basis.observation_id_b == "obs-1"


def test_contextual_basis_may_carry_an_uncertainty_note() -> None:
    basis = _basis(
        LinkClass.SAME_DESTINATION_IP,
        field_path="network.destination.ip",
        observed_value="203.0.113.10",
        uncertainty_note="shared infrastructure/CDN routinely produces identical destinations",
    )
    assert basis.uncertainty_note is not None


def test_structural_basis_rejects_an_uncertainty_note() -> None:
    with pytest.raises(CorrelationError, match="must be absent for structural"):
        _basis(LinkClass.PROCESS_LINEAGE, uncertainty_note="should not be allowed")


@pytest.mark.parametrize(
    "missing_field",
    ["field_path", "observed_value", "observation_id_a", "observation_id_b"],
)
def test_basis_rejects_empty_required_fields(missing_field: str) -> None:
    with pytest.raises(CorrelationError):
        _basis(**{missing_field: ""})  # type: ignore[arg-type]


def test_basis_rejects_non_link_class() -> None:
    with pytest.raises(CorrelationError, match="must be a LinkClass"):
        _basis(link_class="same_process_entity")  # type: ignore[arg-type]


# ===========================================================================
# 4. CorrelationProvenance (parallel to DerivationProvenance)
# ===========================================================================


def test_provenance_requires_nonempty_evidence_ids() -> None:
    with pytest.raises(CorrelationError, match="source_evidence_ids must be non-empty"):
        _provenance(source_evidence_ids=())


def test_provenance_requires_nonempty_observation_ids() -> None:
    with pytest.raises(CorrelationError, match="source_observation_ids must be non-empty"):
        _provenance(source_observation_ids=())


def test_provenance_canonicalizes_ids_to_sorted_unique() -> None:
    prov = _provenance(
        source_evidence_ids=("ev-2", "ev-1", "ev-1"),
        source_observation_ids=("obs-2", "obs-1", "obs-1"),
    )
    assert prov.source_evidence_ids == ("ev-1", "ev-2")
    assert prov.source_observation_ids == ("obs-1", "obs-2")


def test_provenance_content_hash_optional_and_never_fabricated() -> None:
    prov = _provenance()
    assert prov.method_content_hash is None
    prov_with_hash = _provenance(method_content_hash="a" * 64)
    assert prov_with_hash.method_content_hash == "a" * 64


def test_provenance_cannot_be_silently_dropped_from_link() -> None:
    with pytest.raises(CorrelationError, match="must be a CorrelationProvenance"):
        _link(provenance="not-a-provenance")


def test_provenance_cannot_be_silently_dropped_from_group() -> None:
    with pytest.raises(CorrelationError, match="must be a CorrelationProvenance"):
        build_correlation_group(
            group_id=compute_group_id(["ev-1", "ev-2"]),
            member_evidence_ids=("ev-1", "ev-2"),
            member_observation_ids=("obs-1", "obs-2"),
            structural_links=(_link(),),
            provenance="not-a-provenance",  # type: ignore[arg-type]
        )


# ===========================================================================
# 5. CorrelationLink
# ===========================================================================


def test_link_preserves_anchors_class_basis_and_provenance() -> None:
    link = _link()
    assert {link.anchor_a, link.anchor_b} == {"ev-1", "ev-2"}
    assert link.link_class == LinkClass.SAME_PROCESS_ENTITY
    assert isinstance(link.basis, CorrelationBasis)
    assert isinstance(link.provenance, CorrelationProvenance)


def test_link_rejects_identical_anchors() -> None:
    with pytest.raises(CorrelationError, match="must be distinct Evidence ids"):
        _link(anchor_a="ev-1", anchor_b="ev-1")


def test_link_anchors_are_canonicalized_symmetrically() -> None:
    link_ab = _link(anchor_a="ev-1", anchor_b="ev-2")
    link_ba = _link(anchor_a="ev-2", anchor_b="ev-1")
    assert link_ab.anchor_a == link_ba.anchor_a
    assert link_ab.anchor_b == link_ba.anchor_b
    assert link_ab == link_ba


def test_link_class_must_agree_with_basis_link_class() -> None:
    with pytest.raises(CorrelationError, match="does not match basis.link_class"):
        _link(link_class=LinkClass.PROCESS_LINEAGE, basis=_basis(LinkClass.SAME_PROCESS_ENTITY))


def test_link_rejects_non_link_class() -> None:
    with pytest.raises(CorrelationError, match="must be a LinkClass"):
        _link(link_class="same_process_entity")  # type: ignore[arg-type]


def test_link_schema_version_present() -> None:
    from attribution_platform.correlation import CORRELATION_LINK_SCHEMA_VERSION

    assert _link().schema_version == CORRELATION_LINK_SCHEMA_VERSION


# ===========================================================================
# 6. Deterministic identity helpers
# ===========================================================================


def test_compute_link_id_stable_for_identical_inputs() -> None:
    id1 = compute_link_id(
        link_class=LinkClass.PROCESS_LINEAGE,
        observed_value="{GUID}",
        anchor_a="ev-1",
        anchor_b="ev-2",
    )
    id2 = compute_link_id(
        link_class=LinkClass.PROCESS_LINEAGE,
        observed_value="{GUID}",
        anchor_a="ev-1",
        anchor_b="ev-2",
    )
    assert id1 == id2


def test_compute_link_id_order_independent_over_anchors() -> None:
    id_ab = compute_link_id(
        link_class=LinkClass.PROCESS_LINEAGE,
        observed_value="{GUID}",
        anchor_a="ev-1",
        anchor_b="ev-2",
    )
    id_ba = compute_link_id(
        link_class=LinkClass.PROCESS_LINEAGE,
        observed_value="{GUID}",
        anchor_a="ev-2",
        anchor_b="ev-1",
    )
    assert id_ab == id_ba


@pytest.mark.parametrize(
    "changed_kwargs",
    [
        {"link_class": LinkClass.SAME_PROCESS_ENTITY},
        {"observed_value": "{DIFFERENT-GUID}"},
        {"anchor_a": "ev-3"},
        {"method_content_hash": "b" * 64},
    ],
)
def test_compute_link_id_changes_when_a_meaningful_input_changes(
    changed_kwargs: dict[str, object],
) -> None:
    base: dict[str, object] = {
        "link_class": LinkClass.PROCESS_LINEAGE,
        "observed_value": "{GUID}",
        "anchor_a": "ev-1",
        "anchor_b": "ev-2",
    }
    baseline_id = compute_link_id(**base)  # type: ignore[arg-type]
    modified = {**base, **changed_kwargs}
    assert compute_link_id(**modified) != baseline_id  # type: ignore[arg-type]


def test_compute_group_id_stable_for_identical_inputs() -> None:
    id1 = compute_group_id(["ev-1", "ev-2", "ev-3"])
    id2 = compute_group_id(["ev-3", "ev-2", "ev-1"])  # order-independent
    assert id1 == id2


def test_compute_group_id_changes_when_membership_changes() -> None:
    id1 = compute_group_id(["ev-1", "ev-2"])
    id2 = compute_group_id(["ev-1", "ev-2", "ev-3"])
    assert id1 != id2


def test_compute_group_id_changes_when_content_hash_changes() -> None:
    id1 = compute_group_id(["ev-1", "ev-2"], method_content_hash="a" * 64)
    id2 = compute_group_id(["ev-1", "ev-2"], method_content_hash="b" * 64)
    assert id1 != id2


def test_compute_group_id_requires_at_least_two_members() -> None:
    with pytest.raises(CorrelationError, match="at least two distinct"):
        compute_group_id(["ev-1"])


def test_compute_link_id_rejects_identical_anchors() -> None:
    with pytest.raises(CorrelationError, match="must be distinct"):
        compute_link_id(
            link_class=LinkClass.SAME_PROCESS_ENTITY,
            observed_value="{GUID}",
            anchor_a="ev-1",
            anchor_b="ev-1",
        )


# ===========================================================================
# 6b. Regression: "::"-delimiter collision fix (G2.0 audit, Critical finding)
#
# Real evidence_id/detection_id strings in this project already contain
# "::" (e.g. detection.evidence's evidence_id = f"{detection_id}::{ext_id}"),
# so joining caller-supplied free-text components with "::" without hashing
# them first let two semantically different inputs produce the same id.
# These tests prove that shape of collision is now impossible.
# ===========================================================================

_HEX64 = re.compile(r"^[0-9a-f]{64}$")


def test_compute_link_id_no_longer_collides_on_the_audit_example() -> None:
    """The exact collision the audit identified:
    compute_link_id(observed_value="A::B", anchor_a="ev-1", anchor_b="ev-2")
    vs.
    compute_link_id(observed_value="A", anchor_a="B", anchor_b="ev-1::ev-2")
    previously produced the identical joined string."""
    id1 = compute_link_id(
        link_class=LinkClass.SAME_PROCESS_ENTITY,
        observed_value="A::B",
        anchor_a="ev-1",
        anchor_b="ev-2",
    )
    id2 = compute_link_id(
        link_class=LinkClass.SAME_PROCESS_ENTITY,
        observed_value="A",
        anchor_a="B",
        anchor_b="ev-1::ev-2",
    )
    assert id1 != id2


def test_compute_group_id_no_longer_collides_on_the_analogous_shape() -> None:
    """The same collision shape, one layer up: two different member sets
    that previously produced the identical joined "corr-group::..." string
    once "::" appeared inside a member id."""
    id1 = compute_group_id(["A::B", "ev-2"])
    id2 = compute_group_id(["A", "B::ev-2"])
    assert id1 != id2


def test_member_set_ids_have_a_fixed_length_whatever_the_member_count() -> None:
    """ADR-0003 Amendment D: one hash per member once made a real unit's
    group id 596,980 characters long — past Elasticsearch's 512-byte _id limit.
    Group, step, sequence and parallel-group ids are now member-count-free."""
    from attribution_platform.correlation.sequence import (
        compute_sequence_id,
        compute_sequence_parallel_group_id,
        compute_step_id,
    )

    few = [f"ev-{i}::x" for i in range(2)]
    many = [f"ev-{i}::x" for i in range(5000)]
    assert len(compute_group_id(few)) == len(compute_group_id(many)) == 76
    assert compute_group_id(many) != compute_group_id(many[:-1])
    assert compute_group_id(list(reversed(many))) == compute_group_id(many)
    assert len(compute_step_id("g", few)) == len(compute_step_id("g", many))
    assert len(compute_sequence_id("g", few)) == len(compute_sequence_id("g", many))
    assert len(compute_sequence_parallel_group_id("s", [["a"], ["b"]])) == len(
        compute_sequence_parallel_group_id("s", [[f"s{i}"] for i in range(500)])
    )
    with_hash = compute_group_id(many, method_content_hash="f" * 64)
    assert len(with_hash.encode()) <= 512


def test_compute_link_id_still_deterministic_for_identical_semantic_inputs() -> None:
    """Fix must not weaken determinism: the same inputs, called twice,
    still produce the same id."""
    kwargs = {
        "link_class": LinkClass.PROCESS_LINEAGE,
        "observed_value": "value::with::colons",
        "anchor_a": "ev-1::a",
        "anchor_b": "ev-2::b",
    }
    assert compute_link_id(**kwargs) == compute_link_id(**kwargs)  # type: ignore[arg-type]


def test_compute_group_id_still_deterministic_for_identical_semantic_inputs() -> None:
    members = ["ev-1::a", "ev-2::b", "ev-3::c"]
    assert compute_group_id(members) == compute_group_id(members)


def test_compute_link_id_anchor_symmetry_preserved_with_colon_bearing_anchors() -> None:
    """Canonical (sorted-before-hash) anchor ordering must still make the id
    order-independent even when the anchors themselves contain "::"."""
    id_ab = compute_link_id(
        link_class=LinkClass.SAME_PROCESS_ENTITY,
        observed_value="{GUID}",
        anchor_a="ev-1::a",
        anchor_b="ev-2::b",
    )
    id_ba = compute_link_id(
        link_class=LinkClass.SAME_PROCESS_ENTITY,
        observed_value="{GUID}",
        anchor_a="ev-2::b",
        anchor_b="ev-1::a",
    )
    assert id_ab == id_ba


def test_compute_group_id_member_ordering_still_canonical_with_colon_bearing_ids() -> None:
    id1 = compute_group_id(["ev-1::a", "ev-2::b", "ev-3::c"])
    id2 = compute_group_id(["ev-3::c", "ev-1::a", "ev-2::b"])
    assert id1 == id2


def test_compute_link_id_free_text_segments_are_fixed_length_hex_digests() -> None:
    """The mechanism that actually closes the collision: each caller-
    supplied free-text component becomes a 64-character hex digest, which
    cannot itself contain the "::" delimiter -- proving no residual
    delimiter ambiguity remains, not just that two chosen examples differ."""
    link_id = compute_link_id(
        link_class=LinkClass.SAME_PROCESS_ENTITY,
        observed_value="anything::goes::here",
        anchor_a="ev-1",
        anchor_b="ev-2",
    )
    prefix, class_token, *free_text_segments = link_id.split("::")
    assert prefix == "corr"
    assert class_token == LinkClass.SAME_PROCESS_ENTITY.value
    assert len(free_text_segments) == 3  # observed_value, lo, hi
    for segment in free_text_segments:
        assert _HEX64.match(segment), f"expected a 64-char hex digest, got {segment!r}"


def test_compute_group_id_free_text_segments_are_fixed_length_hex_digests() -> None:
    group_id = compute_group_id(["ev-1::a", "ev-2::b"])
    prefix, *free_text_segments = group_id.split("::")
    assert prefix == "corr-group"
    assert len(free_text_segments) == 1  # one member-set digest (ADR-0003 Amendment D)
    for segment in free_text_segments:
        assert _HEX64.match(segment), f"expected a 64-char hex digest, got {segment!r}"


def test_compute_link_id_method_content_hash_still_appended_unhashed() -> None:
    """method_content_hash is preserved exactly as before -- it is already a
    fixed-length SHA-256 hex digest by this project's own convention, so it
    stays collision-safe without being re-hashed."""
    content_hash = "a" * 64
    link_id = compute_link_id(
        link_class=LinkClass.SAME_PROCESS_ENTITY,
        observed_value="{GUID}",
        anchor_a="ev-1",
        anchor_b="ev-2",
        method_content_hash=content_hash,
    )
    assert link_id.endswith(f"::{content_hash}")


def test_compute_group_id_method_content_hash_still_appended_unhashed() -> None:
    content_hash = "b" * 64
    group_id = compute_group_id(["ev-1", "ev-2"], method_content_hash=content_hash)
    assert group_id.endswith(f"::{content_hash}")


# ===========================================================================
# 7. CorrelationGroup direct construction invariants
# ===========================================================================


def test_group_requires_at_least_two_members() -> None:
    with pytest.raises(CorrelationError, match="at least two distinct"):
        CorrelationGroup(
            group_id="g1",
            member_evidence_ids=("ev-1",),
            member_observation_ids=("obs-1",),
            structural_link_ids=("corr::same_process_entity::x::ev-1::ev-2",),
            provenance=_provenance(),
        )


def test_group_requires_nonempty_structural_link_ids() -> None:
    with pytest.raises(CorrelationError, match="structural_link_ids must be non-empty"):
        CorrelationGroup(
            group_id="g1",
            member_evidence_ids=("ev-1", "ev-2"),
            member_observation_ids=("obs-1", "obs-2"),
            structural_link_ids=(),
            provenance=_provenance(),
        )


def test_group_canonicalizes_member_ids_to_sorted_unique() -> None:
    group = CorrelationGroup(
        group_id="g1",
        member_evidence_ids=("ev-2", "ev-1", "ev-1"),
        member_observation_ids=("obs-2", "obs-1"),
        structural_link_ids=("corr::same_process_entity::x::ev-1::ev-2",),
        provenance=_provenance(),
    )
    assert group.member_evidence_ids == ("ev-1", "ev-2")


def test_group_rejects_a_link_id_present_in_both_structural_and_contextual() -> None:
    shared_id = "corr::same_process_entity::x::ev-1::ev-2"
    with pytest.raises(CorrelationError, match="appear in both"):
        CorrelationGroup(
            group_id="g1",
            member_evidence_ids=("ev-1", "ev-2"),
            member_observation_ids=("obs-1", "obs-2"),
            structural_link_ids=(shared_id,),
            contextual_link_ids=(shared_id,),
            provenance=_provenance(),
        )


def test_group_contract_has_no_group_to_group_relationship_field() -> None:
    """Architectural regression protection (G2.2 audit finding): a
    contextual link may attach to a CorrelationGroup, but two groups
    sharing a contextual_link_id must never be interpreted as related
    (ADR-0003 §"CorrelationGroup semantics" — "a contextual link touching
    two different groups must never be interpreted as relating those
    groups"). The only structural safeguard available at the contract
    level is that no field on CorrelationGroup itself can express a
    group-to-group relationship in the first place -- discovering that two
    groups share a contextual link requires an external join
    (`set(a.contextual_link_ids) & set(b.contextual_link_ids)`), never a
    stored reference. This test pins the exact field set so a future
    change cannot silently add one (e.g. ``related_group_ids``,
    ``contextual_group_ids``, ``correlated_group_ids``, ``parent_group_id``,
    ``child_group_ids``, or any equivalent) without this test failing and
    forcing a deliberate architectural decision, not an accidental one."""
    field_names = {f.name for f in dataclasses.fields(CorrelationGroup)}
    assert field_names == {
        "group_id",
        "member_evidence_ids",
        "member_observation_ids",
        "structural_link_ids",
        "contextual_link_ids",
        "provenance",
        "schema_version",
    }

    forbidden_group_relationship_fields = {
        "related_group_ids",
        "related_groups",
        "contextual_group_ids",
        "correlated_group_ids",
        "correlated_groups",
        "parent_group_id",
        "child_group_ids",
        "linked_group_ids",
        "group_links",
    }
    assert field_names.isdisjoint(forbidden_group_relationship_fields)


# ===========================================================================
# 8. build_correlation_group: the class-membership-enforcing constructor
# ===========================================================================


def test_build_correlation_group_happy_path() -> None:
    structural = _link(LinkClass.PROCESS_LINEAGE, anchor_a="ev-1", anchor_b="ev-2")
    contextual = _link(
        LinkClass.SAME_HOST_ID,
        anchor_a="ev-1",
        anchor_b="ev-2",
        link_id=compute_link_id(
            link_class=LinkClass.SAME_HOST_ID,
            observed_value="HOST-01",
            anchor_a="ev-1",
            anchor_b="ev-2",
        ),
        basis=_basis(
            LinkClass.SAME_HOST_ID,
            field_path="host.id",
            observed_value="HOST-01",
            uncertainty_note="co-residence does not imply a causal relationship",
        ),
    )
    group = build_correlation_group(
        group_id=compute_group_id(["ev-1", "ev-2"]),
        member_evidence_ids=("ev-1", "ev-2"),
        member_observation_ids=("obs-1", "obs-2"),
        structural_links=(structural,),
        contextual_links=(contextual,),
        provenance=_provenance(),
    )
    assert group.structural_link_ids == (structural.link_id,)
    assert group.contextual_link_ids == (contextual.link_id,)


def test_build_correlation_group_rejects_contextual_link_as_structural() -> None:
    """CorrelationGroup rejects contextual links in its structural-link collection."""
    contextual = _link(
        LinkClass.SAME_USER_ID,
        basis=_basis(
            LinkClass.SAME_USER_ID, field_path="user.id", uncertainty_note="shared identity"
        ),
    )
    with pytest.raises(CorrelationError, match="contextual link_class"):
        build_correlation_group(
            group_id=compute_group_id(["ev-1", "ev-2"]),
            member_evidence_ids=("ev-1", "ev-2"),
            member_observation_ids=("obs-1", "obs-2"),
            structural_links=(contextual,),
            provenance=_provenance(),
        )


def test_build_correlation_group_rejects_structural_link_as_contextual() -> None:
    """CorrelationGroup rejects structural links in its contextual-link collection."""
    structural = _link(LinkClass.SHARED_OBSERVATION, basis=_basis(LinkClass.SHARED_OBSERVATION))
    with pytest.raises(CorrelationError, match="structural link_class"):
        build_correlation_group(
            group_id=compute_group_id(["ev-1", "ev-2"]),
            member_evidence_ids=("ev-1", "ev-2"),
            member_observation_ids=("obs-1", "obs-2"),
            structural_links=(),
            contextual_links=(structural,),
            provenance=_provenance(),
        )


# ===========================================================================
# 9. Process-entity host-scoping (documentation-level, no matching algorithm)
# ===========================================================================


def test_process_entity_dimensions_need_no_host_field() -> None:
    """ADR-0003: host participates in SAME_PROCESS_ENTITY/PROCESS_LINEAGE
    join-key computation only as a future G2.1-engine collision safeguard --
    it is never the *reported* dimension/field for these two classes. This
    test proves the contract itself requires nothing host-related to
    represent a valid match for either class; it implements no join logic."""
    entity_basis = _basis(
        LinkClass.SAME_PROCESS_ENTITY, field_path="process.entity_id", observed_value="{GUID-1}"
    )
    lineage_basis = _basis(
        LinkClass.PROCESS_LINEAGE,
        field_path="process.parent_entity_id",
        observed_value="{GUID-1}",
        observation_id_a="obs-parent",
        observation_id_b="obs-child",
    )
    assert "host" not in entity_basis.field_path
    assert "host" not in lineage_basis.field_path


# ===========================================================================
# 10. Serialization (reuses the existing, unmodified domain serializer)
# ===========================================================================


def test_link_serializes_deterministically_via_to_canonical_json() -> None:
    link = _link()
    assert to_canonical_json(link) == to_canonical_json(_link())


def test_group_serializes_deterministically_via_to_canonical_json() -> None:
    group = build_correlation_group(
        group_id=compute_group_id(["ev-1", "ev-2"]),
        member_evidence_ids=("ev-1", "ev-2"),
        member_observation_ids=("obs-1", "obs-2"),
        structural_links=(_link(LinkClass.PROCESS_LINEAGE),),
        provenance=_provenance(),
    )
    body = json.loads(to_canonical_json(group))
    assert body["group_id"] == group.group_id
    assert set(body["member_evidence_ids"]) == {"ev-1", "ev-2"}
    assert body["structural_link_ids"] == list(group.structural_link_ids)


def test_link_serialization_omits_no_attribution_fields() -> None:
    body = json.loads(to_canonical_json(_link()))
    forbidden_keys = {"score", "weight", "confidence", "likelihood", "actor", "candidate"}
    assert forbidden_keys.isdisjoint(body.keys())
    assert forbidden_keys.isdisjoint(body["basis"].keys())


# ===========================================================================
# 11. Guards: preserve ADR-0003 invariants against this package's own source
# ===========================================================================


def test_correlation_package_never_imports_from_sources() -> None:
    """Static AST check: no module in correlation/ imports
    attribution_platform.sources -- the correlation core must stay
    source-agnostic, exactly like detection/'s own equivalent guard."""
    correlation_files = sorted(CORRELATION_DIR.glob("*.py"))
    assert correlation_files, "expected to find correlation/*.py files"

    offending: list[str] = []
    for path in correlation_files:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module and "sources" in node.module:
                offending.append(f"{path.name}: from {node.module} import ...")
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if "sources" in alias.name:
                        offending.append(f"{path.name}: import {alias.name}")

    assert not offending, f"correlation/ must not import from sources/: {offending}"


def test_correlation_package_never_imports_forbidden_layers() -> None:
    """correlation/ must also never depend on dataplane/, replay/, or api/
    -- it is a pure, Elastic-free logic layer, mirroring detection/'s own
    dependency-direction guard. (attack_knowledge is intentionally NOT
    forbidden here: ADR-0003 permits a later gate to use it for tactic
    *annotation* only -- but G2.0 itself uses nothing beyond the stdlib.)"""
    forbidden = ("dataplane", "replay", "api")
    correlation_files = sorted(CORRELATION_DIR.glob("*.py"))

    offending: list[str] = []
    for path in correlation_files:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.ImportFrom)
                and node.module
                and any(f"attribution_platform.{layer}" in node.module for layer in forbidden)
            ):
                offending.append(f"{path.name}: from {node.module} import ...")

    assert not offending, f"correlation/ must not import dataplane/replay/api: {offending}"


def test_correlation_g20_uses_no_external_project_dependency() -> None:
    """G2.0's own files need nothing beyond the stdlib -- confirms
    contracts.py/errors.py do not (yet) depend on domain/attack_knowledge/
    detection either, which is stronger than ADR-0003 strictly requires but
    reflects the genuinely minimal G2.0 scope. Deliberately scoped to just
    the two G2.0 files (not every *.py in the package): G2.1's
    structural.py legitimately imports ``domain`` (ADR-0003 D8 permits the
    engine to depend on it) -- that dependency is covered by its own guard
    in ``tests/test_correlation_structural.py``, not by this G2.0-specific
    invariant."""
    correlation_files = [CORRELATION_DIR / "contracts.py", CORRELATION_DIR / "errors.py"]
    offending: list[str] = []
    for path in correlation_files:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.ImportFrom)
                and node.module
                and node.module.startswith("attribution_platform")
                and not node.module.startswith("attribution_platform.correlation")
            ):
                offending.append(f"{path.name}: from {node.module} import ...")
    assert not offending, f"correlation/ (G2.0) unexpectedly depends on: {offending}"


_TECHNIQUE_ID = re.compile(r"\bT\d{4}(\.\d{3})?\b")
_TACTIC_ID = re.compile(r"\bTA\d{4}\b")
_KNOWN_ACTOR_STRINGS = (
    "APT1",
    "APT28",
    "APT29",
    "Fancy Bear",
    "Cozy Bear",
    "Lazarus",
    "Sandworm",
    "Sofacy",
    "Turla",
    "Equation Group",
)


def test_no_hard_coded_attack_ids_in_correlation_source() -> None:
    for path in CORRELATION_DIR.glob("*.py"):
        text = path.read_text(encoding="utf-8")
        assert not _TECHNIQUE_ID.search(text), f"hard-coded technique id in {path.name}"
        assert not _TACTIC_ID.search(text), f"hard-coded tactic id in {path.name}"


def test_no_hard_coded_actor_names_in_correlation_source() -> None:
    for path in CORRELATION_DIR.glob("*.py"):
        text = path.read_text(encoding="utf-8")
        for actor in _KNOWN_ACTOR_STRINGS:
            assert actor not in text, f"hard-coded actor name {actor!r} in {path.name}"


def test_no_attribution_scoring_or_attack_chain_vocabulary_in_correlation_source() -> None:
    """No candidate-generation/scoring/attack-chain/ATT&CK-actor vocabulary
    anywhere in this gate's source -- correlation must stay a pure,
    fact-based join layer, never hidden attribution (ADR-0003 D1/D10)."""
    forbidden_terms = (
        "Candidate",
        "Hypothesis",
        "AttackChain",
        "Likelihood",
        "Confidence",
        "correlate_actor",
        "AttributionResult",
        "AttributionAssessment",
        "attribution_score",
        "attribution_confidence",
        "IntrusionSet",
        "ThreatActor",
        "campaign_ref",
        "actor_ref",
    )
    for path in CORRELATION_DIR.glob("*.py"):
        text = path.read_text(encoding="utf-8")
        for term in forbidden_terms:
            assert term not in text, f"forbidden term {term!r} found in {path.name}"
