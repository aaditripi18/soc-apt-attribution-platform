"""The contextual correlation engine (gate G2.2).

Implements exactly the six contextual, attach-only dimensions ADR-0003
approved — ``SAME_HOST_ID``, ``SAME_HOST_NAME``, ``SAME_USER_ID``,
``SAME_USER_NAME``, ``SAME_DESTINATION_IP``, and (Amendment A4)
``PROCESS_ACCESS_TARGET`` — and nothing else. This
module is deliberately separate from, and structurally unable to affect,
:mod:`attribution_platform.correlation.structural` (G2.1): it never calls,
imports, or reimplements that module's connected-component algorithm, and
its public entry point takes an *already-computed*
:class:`~attribution_platform.correlation.structural.StructuralCorrelationResult`
as input rather than raw Evidence/Observations — making it structurally
impossible for a caller to accidentally treat a contextual link as
group-forming, since :func:`contextualize` has no code path that builds a
``CorrelationGroup`` from scratch at all.

**What "contextual" means, operationally, here:** two Observations share an
identical value in exactly one field — ``host.id``, ``host.name``,
``user.id``, ``user.name``, or ``network.destination.ip`` — with no other
inference. This is a fact about shared *environment, identity, or
infrastructure*, never about shared *behavior*. Per ADR-0003's own
correction (the reason G2.1 exists in its current, corrected form): a host
is a container for unrelated activity, a user (especially an administrator
or service account) performs an unbounded set of unrelated actions, and
shared network infrastructure routinely produces identical destination
endpoints for causally unrelated traffic. None of the five dimensions here
may ever create or merge a ``CorrelationGroup`` — see "Attachment, never
group formation" below.

**Field semantics (exact-equality only, no inference):**

- ``SAME_HOST_ID``: ``host.id`` equal, both present and non-blank.
- ``SAME_HOST_NAME``: ``host.name`` equal, both present and non-blank.
  Independent of ``SAME_HOST_ID`` — sharing one does not imply or require
  sharing the other, and both may legitimately coexist as two distinct
  links for the same pair.
- ``SAME_USER_ID``: ``user.id`` equal, both present and non-blank.
- ``SAME_USER_NAME``: ``user.name`` equal, both present and non-blank.
  Independent of ``SAME_USER_ID``, for the same reason as host.
- ``SAME_DESTINATION_IP``: ``network.destination.ip`` equal, both present
  and non-blank.
- ``PROCESS_ACCESS_TARGET`` (ADR-0003 Amendment A4): a process-access
  Observation (``Observation.process_access`` present) attests that process
  instance S opened a handle to instance T on the same host (both
  ``entity_id`` values required). Evidence on S is related to Evidence on T
  not confidently before the access — the same causality bound and the
  same witness rule (the access Observation may be Evidence or one of
  ``context_observations``) as structural ``PROCESS_INTERACTION``. Handle
  access is extremely common benign behaviour, so this is explanation only
  and never forms or merges a group.

No dimension here ever substitutes for another (``host.name`` is never used
when ``host.id`` is absent, and vice versa — unlike G2.1's internal
host-*scoping* key, which deliberately does fall back, this module reports
the two facts separately, because a contextual link's whole purpose is to
preserve exactly which field actually matched). Comparison is exact-string
equality after an existence-and-non-blank check — no case-folding, no alias
resolution, no IP-format validation: this project's domain layer imposes
none of those on ``HostRef``/``UserRef``/``NetworkEndpoint`` (they have no
``__post_init__`` validation at all — see
:mod:`attribution_platform.domain.entities`), so inventing a normalization
layer here would be exactly the kind of business heuristic ADR-0003 warns
against. This mirrors the one normalization convention that *does* already
exist in this codebase — G2.1's own ``_host_scope_key``, which also does
nothing beyond an existence-and-blank check before exact comparison.

**Attachment, never group formation.** :func:`contextualize` never builds a
``CorrelationGroup`` from nothing: it only ever takes the groups already
present on the ``StructuralCorrelationResult`` it is given and, for each
one, attaches whichever contextual links touch at least one of that group's
existing members (ADR-0003's own rule: "attached to a group for every group
that has at least one member touched by that contextual link — the same
contextual link id may legitimately appear on multiple groups'
``contextual_link_ids``, which is expected, not a defect"). A contextual
link between two Evidence items that are in *different* structural groups
is attached to *both* groups independently — it is never interpreted as
relating those groups to each other, and it never merges them. A contextual
link between two Evidence items where *neither* belongs to any structural
group is still computed and returned in ``contextual_links``, but attaches
to no group at all — contextual correlation alone cannot create one.

**Group identity is untouched.** ``CorrelationGroup.group_id`` is computed
(G2.0's ``compute_group_id``) from the sorted set of member Evidence ids
alone — it takes no link information as input at all, structural or
contextual. Every group this module returns keeps the *exact* ``group_id``
it already had; this module never recomputes it. ``member_evidence_ids``,
``member_observation_ids``, ``structural_link_ids``, and ``provenance`` are
likewise carried through completely unchanged — only ``contextual_link_ids``
is ever populated, via G2.0's own :func:`build_correlation_group`, which
independently re-verifies every structural link is still structural and
every contextual link is genuinely contextual (defense in depth, unchanged
from G2.1's own usage of it).

**Uncertainty is explicit, not numeric.** Every contextual link's
``CorrelationBasis.uncertainty_note`` names, in plain language, why the
match does not imply behavioral relatedness — see :data:`_UNCERTAINTY_NOTES`
below, phrased directly from ADR-0003's own §"Contextual dimensions" and
§"Explainability". No probability, confidence, weight, or numeric score is
ever attached to a contextual link (G2.0's own ``CorrelationBasis`` already
makes this structurally impossible — ``uncertainty_note`` is free text).

**CR-1: contextual links are not corroborating evidence.** Nothing in this
module counts, scores, or weights contextual links, and nothing here reads
or writes any likelihood/confidence/attribution field — there are none on
any correlation contract. Multiple contextual dimensions holding for the
same pair (e.g. same host *and* same user *and* same destination) produce
multiple, independent ``CorrelationLink`` objects, each recording its own
single fact — never collapsed into one link, and never treated as three
times the "strength" of one.

**Multi-Observation Evidence.** Uses the exact same fail-closed
single-Observation pairing boundary G2.1 established (an Evidence must have
*exactly* the paired Observation as its sole ``source_observation_ids``
entry) — reimplemented locally here (this module does not import G2.1's
private ``_validate_nodes``/``_Node``, matching this project's established
convention of each layer owning its own local validation rather than
reaching into another module's private helpers — e.g.
:mod:`attribution_platform.detection.contracts`'s own local
``_require_nonempty_str`` instead of importing ``domain``'s), never relaxed.

**Deterministic identity.** Every id here comes from G2.0's own
``compute_link_id`` (unchanged, collision-safe) — no second id scheme. The
``link_class`` (part of the id) makes ``SAME_HOST_ID`` and ``SAME_HOST_NAME``
links for the same pair/value always produce different ids, so they can
never collapse into one relationship. Group ``group_id`` values are reused
verbatim from the input, never recomputed.

**Source-agnostic, ATT&CK-free.** Imports only
:mod:`attribution_platform.correlation` (its own package) and
:mod:`attribution_platform.domain` — never ``sources``, ``dataplane``,
``replay``, ``api``, or ``attack_knowledge`` (enforced by a guard test,
mirroring ``structural.py``'s own).

**Deliberately NOT here (forbidden this gate):** G2.1's structural matching
or connected-component logic (untouched, unmodified, unimported for its
private internals); ``TEMPORAL_PROXIMITY``; ``BehavioralSequence``; ATT&CK
of any kind; Elastic/EQL; scoring, weighting, likelihood, confidence, or
attribution of any kind.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass

from attribution_platform.correlation.contracts import (
    CorrelationBasis,
    CorrelationGroup,
    CorrelationLink,
    CorrelationProvenance,
    LinkClass,
    build_correlation_group,
    compute_link_id,
)
from attribution_platform.correlation.errors import CorrelationError
from attribution_platform.correlation.structural import StructuralCorrelationResult
from attribution_platform.correlation.timing import is_confidently_before
from attribution_platform.domain import Evidence, Observation

#: Default ``CorrelationProvenance.method``/``method_version`` this engine
#: stamps onto every contextual link it produces, unless the caller
#: overrides them. Mirrors ``structural.py``'s own
#: ``STRUCTURAL_CORRELATION_METHOD`` convention.
CONTEXTUAL_CORRELATION_METHOD = "contextual-correlation"
#: 1.1: + PROCESS_ACCESS_TARGET; 1.2: chain materialization (ADR-0003 Amendment C).
CONTEXTUAL_CORRELATION_METHOD_VERSION = "1.2"

#: The exact, ADR-0003-derived uncertainty note for each contextual
#: dimension -- plain language, never a numeric value. Distinct per
#: dimension because the ADR itself treats them differently (user identity
#: is explicitly called out as a *stronger* risk than host co-residence).
_UNCERTAINTY_NOTES: dict[LinkClass, str] = {
    LinkClass.SAME_HOST_ID: (
        "same host.id indicates co-residence only; a host commonly runs many concurrent, "
        "unrelated processes, so this does not imply the two observations are part of the "
        "same behavior"
    ),
    LinkClass.SAME_HOST_NAME: (
        "same host.name indicates co-residence only (a less stable identifier than host.id); "
        "a host commonly runs many concurrent, unrelated processes, so this does not imply "
        "the two observations are part of the same behavior"
    ),
    LinkClass.SAME_USER_ID: (
        "same user.id indicates shared account identity only; shared/service and "
        "administrator accounts routinely perform large, heterogeneous sets of unrelated "
        "actions, so this does not imply a causal relationship"
    ),
    LinkClass.SAME_USER_NAME: (
        "same user.name indicates shared account identity only (a less stable identifier "
        "than user.id); shared/service and administrator accounts routinely perform large, "
        "heterogeneous sets of unrelated actions, so this does not imply a causal relationship"
    ),
    LinkClass.SAME_DESTINATION_IP: (
        "same network.destination.ip indicates shared network infrastructure only; CDNs, "
        "NAT, and common egress points routinely produce identical destination endpoints "
        "for causally unrelated traffic"
    ),
    LinkClass.PROCESS_ACCESS_TARGET: (
        "one process opened a handle to the other; handle access between processes is "
        "extremely common benign behaviour (security agents, service hosts, system "
        "processes), so this does not imply the two observations are part of the same "
        "behavior"
    ),
}

#: field_path recorded on every contextual dimension's CorrelationBasis.
_FIELD_PATHS: dict[LinkClass, str] = {
    LinkClass.SAME_HOST_ID: "host.id",
    LinkClass.SAME_HOST_NAME: "host.name",
    LinkClass.SAME_USER_ID: "user.id",
    LinkClass.SAME_USER_NAME: "user.name",
    LinkClass.SAME_DESTINATION_IP: "network.destination.ip",
    LinkClass.PROCESS_ACCESS_TARGET: "target_process.entity_id",
}


@dataclass(frozen=True)
class ContextualCorrelationResult:
    """What :func:`contextualize` produced: every contextual link found
    (including any that touch no structural group at all), and the *same*
    groups the input ``StructuralCorrelationResult`` had, now carrying
    ``contextual_link_ids`` where applicable. Group identity, membership,
    structural links, and provenance are otherwise byte-for-byte unchanged
    from the input."""

    contextual_links: tuple[CorrelationLink, ...]
    groups: tuple[CorrelationGroup, ...]


@dataclass(frozen=True)
class _Node:
    """One (Evidence, its supporting Observation) pair, validated at input.
    Deliberately a local, private re-declaration of the identical shape
    ``structural.py`` uses internally -- see the module docstring for why
    this is duplicated rather than imported."""

    evidence: Evidence
    observation: Observation


def _validate_nodes(items: Sequence[tuple[Evidence, Observation]]) -> tuple[_Node, ...]:
    """The exact same fail-closed Evidence/Observation pairing boundary
    G2.1 established: the Observation must be the Evidence's *sole* source
    Observation (never a partial view of multi-Observation provenance), and
    evidence ids must be unique across ``items``."""
    seen_evidence_ids: set[str] = set()
    nodes: list[_Node] = []
    for i, (evidence, observation) in enumerate(items):
        if not isinstance(evidence, Evidence):
            raise CorrelationError(
                f"contextualize: items[{i}][0] must be a domain Evidence, "
                f"got {type(evidence).__name__}"
            )
        if not isinstance(observation, Observation):
            raise CorrelationError(
                f"contextualize: items[{i}][1] must be a domain Observation, "
                f"got {type(observation).__name__}"
            )
        if evidence.provenance.source_observation_ids != (observation.observation_id,):
            raise CorrelationError(
                f"contextualize: items[{i}]: evidence {evidence.evidence_id!r} does not have "
                f"exactly the supplied observation {observation.observation_id!r} as its sole "
                f"source (source_observation_ids={evidence.provenance.source_observation_ids!r}"
                f"). G2.2 requires single-Observation Evidence, matching G2.1's own scope; "
                f"multi-Observation Evidence is not supported yet, and partial correlation "
                f"against only one of several source Observations is rejected rather than "
                f"silently dropping the rest of its provenance"
            )
        if evidence.evidence_id in seen_evidence_ids:
            raise CorrelationError(
                f"contextualize: duplicate evidence_id {evidence.evidence_id!r} in items"
            )
        seen_evidence_ids.add(evidence.evidence_id)
        nodes.append(_Node(evidence=evidence, observation=observation))
    return tuple(nodes)


def _host_id(observation: Observation) -> str | None:
    host = observation.host
    if host is None or host.id is None or not host.id.strip():
        return None
    return host.id


def _host_name(observation: Observation) -> str | None:
    host = observation.host
    if host is None or host.name is None or not host.name.strip():
        return None
    return host.name


def _user_id(observation: Observation) -> str | None:
    user = observation.user
    if user is None or user.id is None or not user.id.strip():
        return None
    return user.id


def _user_name(observation: Observation) -> str | None:
    user = observation.user
    if user is None or user.name is None or not user.name.strip():
        return None
    return user.name


def _destination_ip(observation: Observation) -> str | None:
    network = observation.network
    if network is None or network.destination is None:
        return None
    ip = network.destination.ip
    if ip is None or not ip.strip():
        return None
    return ip


#: Which field-extractor feeds each contextual LinkClass. A single,
#: explicit table -- adding a dimension means adding one entry here, never
#: duplicating the matching loop.
_DIMENSION_EXTRACTORS: dict[LinkClass, Callable[[Observation], str | None]] = {
    LinkClass.SAME_HOST_ID: _host_id,
    LinkClass.SAME_HOST_NAME: _host_name,
    LinkClass.SAME_USER_ID: _user_id,
    LinkClass.SAME_USER_NAME: _user_name,
    LinkClass.SAME_DESTINATION_IP: _destination_ip,
}


def _host_scope(observation: Observation) -> tuple[str, str] | None:
    """The same host-scoping rule structural process identity uses: prefer
    ``host.id``, fall back to ``host.name``; ``None`` when neither exists."""
    host_id = _host_id(observation)
    if host_id is not None:
        return ("id", host_id)
    host_name = _host_name(observation)
    return ("name", host_name) if host_name is not None else None


def _entity_key(observation: Observation) -> tuple[tuple[str, str], str] | None:
    scope = _host_scope(observation)
    process = observation.process
    if scope is None or process is None or not (process.entity_id or "").strip():
        return None
    assert process.entity_id is not None
    return (scope, process.entity_id)


def _process_access_links(
    nodes: Sequence[_Node],
    context_observations: Sequence[Observation],
    *,
    method: str,
    method_version: str,
    method_content_hash: str | None,
) -> dict[str, CorrelationLink]:
    by_entity: dict[tuple[tuple[str, str], str], list[_Node]] = {}
    for node in nodes:
        key = _entity_key(node.observation)
        if key is not None:
            by_entity.setdefault(key, []).append(node)
    for members in by_entity.values():
        members.sort(
            key=lambda n: (
                n.observation.timestamp,
                n.observation.observation_id,
                n.evidence.evidence_id,
            )
        )

    witnesses: dict[str, Observation] = {}
    for observation in (*(n.observation for n in nodes), *context_observations):
        witnesses.setdefault(observation.observation_id, observation)
    ordered_witnesses = sorted(witnesses.values(), key=lambda o: (o.timestamp, o.observation_id))

    links: dict[str, CorrelationLink] = {}
    for witness in ordered_witnesses:
        source_key = _entity_key(witness)
        target = witness.target_process
        if (
            witness.process_access is None
            or source_key is None
            or target is None
            or not (target.entity_id or "").strip()
            or target.entity_id == source_key[1]
        ):
            continue
        assert target.entity_id is not None
        # One link per attested access (Amendment C1): the accessing instance's
        # first member to the accessed instance's first member not confidently
        # before the access.
        sources = by_entity.get(source_key, ())
        target_node = next(
            (
                n
                for n in by_entity.get((source_key[0], target.entity_id), ())
                if not is_confidently_before(n.observation, witness)
            ),
            None,
        )
        if not sources or target_node is None:
            continue
        link = _make_contextual_link(
            sources[0],
            target_node,
            link_class=LinkClass.PROCESS_ACCESS_TARGET,
            observed_value=target.entity_id,
            method=method,
            method_version=method_version,
            method_content_hash=method_content_hash,
            witness_observation_id=witness.observation_id,
        )
        links.setdefault(link.link_id, link)
    return links


def _make_contextual_link(
    node_a: _Node,
    node_b: _Node,
    *,
    link_class: LinkClass,
    observed_value: str,
    method: str,
    method_version: str,
    method_content_hash: str | None,
    witness_observation_id: str | None = None,
) -> CorrelationLink:
    link_id = compute_link_id(
        link_class=link_class,
        observed_value=observed_value,
        anchor_a=node_a.evidence.evidence_id,
        anchor_b=node_b.evidence.evidence_id,
        method_content_hash=method_content_hash,
    )
    basis = CorrelationBasis(
        link_class=link_class,
        field_path=_FIELD_PATHS[link_class],
        observed_value=observed_value,
        observation_id_a=node_a.observation.observation_id,
        observation_id_b=node_b.observation.observation_id,
        uncertainty_note=_UNCERTAINTY_NOTES[link_class],
    )
    source_observation_ids = tuple(
        {node_a.observation.observation_id, node_b.observation.observation_id}
        | ({witness_observation_id} if witness_observation_id is not None else set())
    )
    provenance = CorrelationProvenance(
        method=method,
        method_version=method_version,
        source_evidence_ids=(node_a.evidence.evidence_id, node_b.evidence.evidence_id),
        source_observation_ids=source_observation_ids,
        method_content_hash=method_content_hash,
    )
    return CorrelationLink(
        link_id=link_id,
        anchor_a=node_a.evidence.evidence_id,
        anchor_b=node_b.evidence.evidence_id,
        link_class=link_class,
        basis=basis,
        provenance=provenance,
    )


def _links_for_dimension(
    nodes: Sequence[_Node],
    *,
    link_class: LinkClass,
    method: str,
    method_version: str,
    method_content_hash: str | None,
) -> dict[str, CorrelationLink]:
    extractor = _DIMENSION_EXTRACTORS[link_class]
    by_value: dict[str, list[_Node]] = {}
    for node in nodes:
        value = extractor(node.observation)
        if value is None:
            continue
        by_value.setdefault(value, []).append(node)

    links: dict[str, CorrelationLink] = {}
    for value, group in by_value.items():
        if len(group) < 2:
            continue
        # ADR-0003 Amendment C1/C4: an equivalence class is linked as a chain in
        # (timestamp, observation_id, evidence_id) order -- n - 1 true pairwise
        # facts instead of every pair.
        ordered = sorted(
            group,
            key=lambda n: (
                n.observation.timestamp,
                n.observation.observation_id,
                n.evidence.evidence_id,
            ),
        )
        for node_a, node_b in zip(ordered, ordered[1:], strict=False):
            link = _make_contextual_link(
                node_a,
                node_b,
                link_class=link_class,
                observed_value=value,
                method=method,
                method_version=method_version,
                method_content_hash=method_content_hash,
            )
            links[link.link_id] = link
    return links


def contextualize(
    structural_result: StructuralCorrelationResult,
    items: Sequence[tuple[Evidence, Observation]],
    *,
    method: str = CONTEXTUAL_CORRELATION_METHOD,
    method_version: str = CONTEXTUAL_CORRELATION_METHOD_VERSION,
    method_content_hash: str | None = None,
    context_observations: Sequence[Observation] = (),
) -> ContextualCorrelationResult:
    """Compute every ``SAME_HOST_ID``/``SAME_HOST_NAME``/``SAME_USER_ID``/
    ``SAME_USER_NAME``/``SAME_DESTINATION_IP``/``PROCESS_ACCESS_TARGET``
    link across ``items``, and
    attach each one to every *existing* structural group (from
    ``structural_result``) that has at least one member the link touches.

    This function never forms, merges, or creates a ``CorrelationGroup``.
    It takes ``structural_result.groups`` as fixed input and returns the
    same groups, unchanged except that some may now carry
    ``contextual_link_ids`` -- ``group_id``, ``member_evidence_ids``,
    ``member_observation_ids``, ``structural_link_ids``, and ``provenance``
    are always identical to the input. A contextual link between two
    Evidence items in two *different* structural groups is attached to
    *both* independently -- it never relates the groups to each other, and
    two groups sharing a contextual link are never merged. A contextual
    link where neither anchor belongs to any structural group is still
    returned in ``contextual_links``, but attaches to no group.

    ``items`` uses the exact same ``(Evidence, Observation)`` pairing shape
    and fail-closed single-Observation validation G2.1's
    ``correlate_structurally`` uses (see :func:`_validate_nodes`). It need
    not be the same set of pairs that produced ``structural_result`` --
    passing additional Evidence not part of any structural group is valid
    and simply yields contextual links that attach to no group.

    ``method``/``method_version``/``method_content_hash`` behave exactly as
    they do in ``correlate_structurally``: defaults to this module's own
    identity; the content hash is never fabricated.

    ``context_observations`` (optional) are Evidence-free telemetry read only
    as witnesses of ``PROCESS_ACCESS_TARGET`` (a process-access event), as in
    ``correlate_structurally``; they never touch any other dimension.

    Pure and deterministic: no I/O, no ATT&CK knowledge, no randomness, no
    wall-clock.
    """
    if not isinstance(structural_result, StructuralCorrelationResult):
        raise CorrelationError(
            f"contextualize: structural_result must be a StructuralCorrelationResult, "
            f"got {type(structural_result).__name__}"
        )

    nodes = _validate_nodes(items)
    for i, observation in enumerate(context_observations):
        if not isinstance(observation, Observation):
            raise CorrelationError(
                f"contextualize: context_observations[{i}] must be a domain Observation, "
                f"got {type(observation).__name__}"
            )

    all_contextual_links: dict[str, CorrelationLink] = {}
    for link_class in _DIMENSION_EXTRACTORS:
        all_contextual_links.update(
            _links_for_dimension(
                nodes,
                link_class=link_class,
                method=method,
                method_version=method_version,
                method_content_hash=method_content_hash,
            )
        )
    all_contextual_links.update(
        _process_access_links(
            nodes,
            context_observations,
            method=method,
            method_version=method_version,
            method_content_hash=method_content_hash,
        )
    )
    sorted_contextual_links = tuple(
        sorted(all_contextual_links.values(), key=lambda link_: link_.link_id)
    )

    structural_links_by_id = {link.link_id: link for link in structural_result.links}

    links_by_anchor: dict[str, list[CorrelationLink]] = {}
    for link in sorted_contextual_links:
        links_by_anchor.setdefault(link.anchor_a, []).append(link)
        links_by_anchor.setdefault(link.anchor_b, []).append(link)

    updated_groups: list[CorrelationGroup] = []
    for group in structural_result.groups:
        touching_by_id = {
            link.link_id: link
            for member in group.member_evidence_ids
            for link in links_by_anchor.get(member, ())
        }
        touching = tuple(touching_by_id[link_id] for link_id in sorted(touching_by_id))
        if not touching:
            updated_groups.append(group)
            continue

        original_structural_links = tuple(
            structural_links_by_id[link_id] for link_id in group.structural_link_ids
        )
        updated_groups.append(
            build_correlation_group(
                group_id=group.group_id,
                member_evidence_ids=group.member_evidence_ids,
                member_observation_ids=group.member_observation_ids,
                structural_links=original_structural_links,
                provenance=group.provenance,
                contextual_links=touching,
            )
        )

    sorted_groups = tuple(sorted(updated_groups, key=lambda group_: group_.group_id))
    return ContextualCorrelationResult(
        contextual_links=sorted_contextual_links, groups=sorted_groups
    )
