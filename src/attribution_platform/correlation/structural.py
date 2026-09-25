"""The structural correlation engine (gate G2.1).

Implements exactly the four structural, group-forming dimensions ADR-0003
approved — ``SHARED_OBSERVATION``, ``SAME_PROCESS_ENTITY``,
``PROCESS_LINEAGE``, and (Amendment A) ``PROCESS_INTERACTION`` — and nothing
else. This is the first module in
:mod:`attribution_platform.correlation` that actually *computes* anything;
G2.0's ``contracts`` module defines the shapes, this module fills them in.

**What "structural" means, operationally, here:**

- ``SHARED_OBSERVATION``: two distinct Evidence items whose supporting
  Observation is the *literal same Observation* (``observation_id`` equal).
- ``SAME_PROCESS_ENTITY``: two Observations whose ``process.entity_id`` is
  equal *within the same host scope* (see "Host-scoped process identity"
  below) — the same running process instance, described twice.
- ``PROCESS_LINEAGE``: one Observation's ``process.parent_entity_id``
  equals another's ``process.entity_id``, again within the same host scope
  — a direct, collector-asserted parent → child creation relationship.
  Directional: the basis always records the parent's Observation id first.
- ``PROCESS_INTERACTION`` (ADR-0003 Amendment A): a remote-thread-creation
  Observation (``Observation.remote_thread`` present) attests that process
  instance S began executing code inside instance T (``process.entity_id``
  = S, ``target_process.entity_id`` = T, same host scope; both required —
  A3). Evidence on S is then linked to Evidence on T whose Observation is
  **not confidently before** the injection (A2's causality bound; equal and
  precision-tied timestamps are linked, compared like ADR-0004 D6).
  The attesting injection Observation need not itself be Evidence
  (Amendment A7): it may be one of the Evidence Observations or one of the
  caller's ``context_observations`` — telemetry read only as a witness of
  the S→T relationship, never a group member. Its id is recorded in the
  link's provenance. Directional: the basis records the injecting side's
  Observation first. One hop only — never transitive through other
  processes.

**What is deliberately NOT a structural signal here, per ADR-0003's own
correction:** ``host.id``/``host.name`` sameness, ``user.id``/``user.name``
sameness, ``network.destination`` sameness, matching ``process.name``,
matching ``ATT&CK`` technique, or temporal proximity. None of these appear
anywhere in this module's matching logic — a busy host with many unrelated
processes, or a shared/service account performing unrelated actions,
produces no structural link and therefore no merged group.

**Host-scoped process identity.** ``process.entity_id`` values are only
meaningful within the host that generated them (ADR-0003's explicit
collision safeguard). Every process-entity comparison in this module is
therefore keyed by ``(host_scope, entity_id)``, never ``entity_id`` alone.
``host_scope`` prefers the stable ``host.id`` and falls back to
``host.name`` only when no ``host.id`` is present — the same
"prefer-a-stable-id, fall back to name" convention already used elsewhere
in this project (e.g. :mod:`attribution_platform.sources.sysmon`'s
``observation_id`` fallback). When neither is available, host scope cannot
be established and the Observation's process-entity dimensions are silently
skipped (fail closed) — never guessed, never treated as globally unique.
Host participates *only* as this internal scoping key: it is never the
``dimension``/``link_class`` of a link, never appears in
``CorrelationBasis.field_path``, and no ``SAME_HOST_ID``/``SAME_HOST_NAME``
link is ever constructed by this module.

**Fail-closed, not best-effort.** An Observation with no ``process``, no
``process.entity_id``, or no ``process.parent_entity_id`` simply does not
participate in the corresponding dimension — this is normal (most
Observations legitimately have no process data at all, e.g. a
network-connection-only event) and is never an error. Nothing here infers
process identity from ``process.name``, ``parent_name``, ``user``,
``host.name`` alone, ``command_line``, or timestamp proximity — the ADR is
explicit that none of these establish "same execution instance."

**A small, deterministic connected-component implementation, not a graph
framework.** :func:`correlate_structurally` builds every structural link
first, then unions Evidence ids that share a link via a minimal union-find
(disjoint-set) — the standard, smallest correct algorithm for this problem,
not a generic graph library. Singleton components (no structural link at
all) never become a ``CorrelationGroup``, matching G2.0's own
``structural_link_ids``-non-empty invariant.

**Determinism.** Every id here comes from G2.0's own
:func:`~attribution_platform.correlation.contracts.compute_link_id`/
:func:`~attribution_platform.correlation.contracts.compute_group_id` —
no second id scheme is introduced. All returned collections are explicitly
sorted by id before being returned, so output order is stable across
processes regardless of Python's per-process string-hash randomization
affecting ``dict``/``set`` iteration order internally.

**No scoring, no weighting, no ATT&CK, no attribution.** This module reads
only the ``process``/``host`` entity groups off ``Observation`` and the
``observation_id`` off ``Evidence.provenance``; it never reads
``Evidence.attack_ref`` and never imports
:mod:`attribution_platform.attack_knowledge`. Two Evidence items that
happen to map to the same ATT&CK technique are not correlated by that fact
alone — only a genuine telemetry-derived structural relationship links them.

**Source-agnostic.** This module imports only
:mod:`attribution_platform.correlation` (its own package) and
:mod:`attribution_platform.domain` — never ``sources``, ``dataplane``,
``replay``, or ``api`` (enforced by a guard test, mirroring
``detection/``'s own).
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from itertools import combinations

from attribution_platform.correlation.contracts import (
    CorrelationBasis,
    CorrelationGroup,
    CorrelationLink,
    CorrelationProvenance,
    LinkClass,
    build_correlation_group,
    compute_group_id,
    compute_link_id,
)
from attribution_platform.correlation.errors import CorrelationError
from attribution_platform.domain import Evidence, Observation, TimePrecision

#: Default ``CorrelationProvenance.method``/``method_version`` this engine
#: stamps onto every link/group it produces, unless the caller overrides
#: them. Mirrors how G1.0's ``DetectionRule.rule_source`` defaults to
#: ``"platform-rules"`` — a module-level identity constant, not a config the
#: engine has to be told on every call.
STRUCTURAL_CORRELATION_METHOD = "structural-correlation"
STRUCTURAL_CORRELATION_METHOD_VERSION = "1.1"  # 1.1: + PROCESS_INTERACTION

#: The (host-scope, entity-id) key process-entity dimensions are compared
#: on. ``host_scope`` is itself ``(kind, value)`` where ``kind`` is
#: ``"id"``/``"name"`` -- a tuple, not a joined string, so this internal
#: bookkeeping key can never suffer the delimiter-collision class of bug
#: G2.0's ``compute_link_id``/``compute_group_id`` had to be hardened
#: against (this key is never serialized into any contract field).
_HostScope = tuple[str, str]
_ProcessEntityKey = tuple[_HostScope, str]


@dataclass(frozen=True)
class StructuralCorrelationResult:
    """What :func:`correlate_structurally` produced: the structural links it
    found, and the ``CorrelationGroup``s they formed. Both are sorted by
    their own id for deterministic, stable output ordering."""

    links: tuple[CorrelationLink, ...]
    groups: tuple[CorrelationGroup, ...]


@dataclass(frozen=True)
class _Node:
    """One (Evidence, its supporting Observation) pair, validated at input."""

    evidence: Evidence
    observation: Observation


def _host_scope_key(observation: Observation) -> _HostScope | None:
    """The host-scoping half of a process-entity identity key. Prefers the
    stable ``host.id``; falls back to ``host.name`` only when no ``host.id``
    is present. Returns ``None`` when neither is available -- callers must
    then treat this Observation's process-entity dimensions as
    unestablished and skip it (fail closed), never risk a cross-host
    ``entity_id`` collision by comparing unscoped."""
    host = observation.host
    if host is None:
        return None
    if host.id is not None and host.id.strip():
        return ("id", host.id)
    if host.name is not None and host.name.strip():
        return ("name", host.name)
    return None


def _process_entity_key(observation: Observation) -> _ProcessEntityKey | None:
    """``(host_scope, process.entity_id)`` for ``SAME_PROCESS_ENTITY``
    matching, or ``None`` if host scope or a real ``entity_id`` is absent."""
    host_scope = _host_scope_key(observation)
    if host_scope is None:
        return None
    process = observation.process
    if process is None or process.entity_id is None or not process.entity_id.strip():
        return None
    return (host_scope, process.entity_id)


def _process_parent_key(observation: Observation) -> _ProcessEntityKey | None:
    """``(host_scope, process.parent_entity_id)`` for ``PROCESS_LINEAGE``
    matching, or ``None`` if host scope or a real ``parent_entity_id`` is
    absent. Uses the *same* host-scoping rule as :func:`_process_entity_key`
    on the child's own Observation -- a parent process is, by definition,
    on the same host as its child, so requiring the two keys' host-scope
    components to match (via plain tuple equality) is correct without a
    separate, explicit "same host" check."""
    host_scope = _host_scope_key(observation)
    if host_scope is None:
        return None
    process = observation.process
    if process is None or process.parent_entity_id is None or not process.parent_entity_id.strip():
        return None
    return (host_scope, process.parent_entity_id)


@dataclass(frozen=True)
class _InjectionFact:
    """One telemetry-attested remote-thread injection S -> T (Amendment A)."""

    host_scope: _HostScope
    source_entity_id: str
    target_entity_id: str
    observation: Observation


def _injection_fact(observation: Observation) -> _InjectionFact | None:
    """The injection a remote-thread Observation attests, or ``None`` when it
    is not one or either process identifier is missing (A3: fail closed; a
    pid-only event forms no link)."""
    if observation.remote_thread is None:
        return None
    source_key = _process_entity_key(observation)
    target = observation.target_process
    if source_key is None or target is None or not (target.entity_id or "").strip():
        return None
    assert target.entity_id is not None
    host_scope, source_entity_id = source_key
    if target.entity_id == source_entity_id:
        return None  # a thread in itself is not an interaction between instances
    return _InjectionFact(
        host_scope=host_scope,
        source_entity_id=source_entity_id,
        target_entity_id=target.entity_id,
        observation=observation,
    )


#: Truncation granularity per declared precision (ADR-0004 D6's table; a
#: local copy — this module does not import ``sequence_engine`` internals).
_PRECISION_GRANULARITY: dict[TimePrecision, timedelta] = {
    TimePrecision.SECOND: timedelta(seconds=1),
    TimePrecision.MILLISECOND: timedelta(milliseconds=1),
    TimePrecision.MICROSECOND: timedelta(microseconds=1),
    TimePrecision.NANOSECOND: timedelta(microseconds=1),
}
_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


def is_confidently_before(candidate: Observation, reference: Observation) -> bool:
    """``True`` only when ``candidate`` certainly happened before
    ``reference``: compared at the two timestamps' common (coarser) declared
    precision; with an undeclared/unknown precision the raw values are
    compared. A tie at the common precision is *not* "before" (A2 links equal
    timestamps — the sensor cannot order them)."""
    ts_a, ts_b = candidate.timestamp, reference.timestamp
    prec_a, prec_b = candidate.timestamp_precision, reference.timestamp_precision
    if prec_a is not None and prec_b is not None:
        gran_a, gran_b = _PRECISION_GRANULARITY.get(prec_a), _PRECISION_GRANULARITY.get(prec_b)
        if gran_a is not None and gran_b is not None:
            granularity = max(gran_a, gran_b)
            ts_a = _EPOCH + ((ts_a - _EPOCH) // granularity) * granularity
            ts_b = _EPOCH + ((ts_b - _EPOCH) // granularity) * granularity
    return ts_a < ts_b


def _validate_context_observations(
    context_observations: Sequence[Observation],
) -> tuple[Observation, ...]:
    for i, observation in enumerate(context_observations):
        if not isinstance(observation, Observation):
            raise CorrelationError(
                f"correlate_structurally: context_observations[{i}] must be a domain "
                f"Observation, got {type(observation).__name__}"
            )
    return tuple(context_observations)


def _validate_nodes(items: Sequence[tuple[Evidence, Observation]]) -> tuple[_Node, ...]:
    seen_evidence_ids: set[str] = set()
    nodes: list[_Node] = []
    for i, (evidence, observation) in enumerate(items):
        if not isinstance(evidence, Evidence):
            raise CorrelationError(
                f"correlate_structurally: items[{i}][0] must be a domain Evidence, "
                f"got {type(evidence).__name__}"
            )
        if not isinstance(observation, Observation):
            raise CorrelationError(
                f"correlate_structurally: items[{i}][1] must be a domain Observation, "
                f"got {type(observation).__name__}"
            )
        if evidence.provenance.source_observation_ids != (observation.observation_id,):
            raise CorrelationError(
                f"correlate_structurally: items[{i}]: evidence {evidence.evidence_id!r} does "
                f"not have exactly the supplied observation {observation.observation_id!r} as "
                f"its sole source (source_observation_ids="
                f"{evidence.provenance.source_observation_ids!r}). G2.1 requires "
                f"single-Observation Evidence; multi-Observation Evidence is not supported yet, "
                f"and partial correlation against only one of several source Observations is "
                f"rejected rather than silently dropping the rest of its provenance"
            )
        if evidence.evidence_id in seen_evidence_ids:
            raise CorrelationError(
                f"correlate_structurally: duplicate evidence_id "
                f"{evidence.evidence_id!r} in items"
            )
        seen_evidence_ids.add(evidence.evidence_id)
        nodes.append(_Node(evidence=evidence, observation=observation))
    return tuple(nodes)


def _make_link(
    node_a: _Node,
    node_b: _Node,
    *,
    link_class: LinkClass,
    field_path: str,
    observed_value: str,
    observation_id_a: str,
    observation_id_b: str,
    uncertainty_note: str | None,
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
        field_path=field_path,
        observed_value=observed_value,
        observation_id_a=observation_id_a,
        observation_id_b=observation_id_b,
        uncertainty_note=uncertainty_note,
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


def _shared_observation_links(
    nodes: Sequence[_Node], *, method: str, method_version: str, method_content_hash: str | None
) -> dict[str, CorrelationLink]:
    by_observation: dict[str, list[_Node]] = {}
    for node in nodes:
        by_observation.setdefault(node.observation.observation_id, []).append(node)

    links: dict[str, CorrelationLink] = {}
    for observation_id, group in by_observation.items():
        if len(group) < 2:
            continue
        ordered = sorted(group, key=lambda n: n.evidence.evidence_id)
        for node_a, node_b in combinations(ordered, 2):
            link = _make_link(
                node_a,
                node_b,
                link_class=LinkClass.SHARED_OBSERVATION,
                field_path="observation_id",
                observed_value=observation_id,
                observation_id_a=observation_id,
                observation_id_b=observation_id,
                uncertainty_note=None,
                method=method,
                method_version=method_version,
                method_content_hash=method_content_hash,
            )
            links[link.link_id] = link
    return links


def _same_process_entity_links(
    nodes: Sequence[_Node], *, method: str, method_version: str, method_content_hash: str | None
) -> dict[str, CorrelationLink]:
    by_entity: dict[_ProcessEntityKey, list[_Node]] = {}
    for node in nodes:
        key = _process_entity_key(node.observation)
        if key is None:
            continue
        by_entity.setdefault(key, []).append(node)

    links: dict[str, CorrelationLink] = {}
    for (_host_scope, entity_id), group in by_entity.items():
        if len(group) < 2:
            continue
        ordered = sorted(group, key=lambda n: n.evidence.evidence_id)
        for node_a, node_b in combinations(ordered, 2):
            link = _make_link(
                node_a,
                node_b,
                link_class=LinkClass.SAME_PROCESS_ENTITY,
                field_path="process.entity_id",
                observed_value=entity_id,
                observation_id_a=node_a.observation.observation_id,
                observation_id_b=node_b.observation.observation_id,
                uncertainty_note=None,
                method=method,
                method_version=method_version,
                method_content_hash=method_content_hash,
            )
            links[link.link_id] = link
    return links


def _process_lineage_links(
    nodes: Sequence[_Node], *, method: str, method_version: str, method_content_hash: str | None
) -> dict[str, CorrelationLink]:
    by_entity: dict[_ProcessEntityKey, list[_Node]] = {}
    for node in nodes:
        key = _process_entity_key(node.observation)
        if key is None:
            continue
        by_entity.setdefault(key, []).append(node)

    links: dict[str, CorrelationLink] = {}
    for child in sorted(nodes, key=lambda n: n.evidence.evidence_id):
        parent_key = _process_parent_key(child.observation)
        if parent_key is None:
            continue
        parents = by_entity.get(parent_key, ())
        for parent in sorted(parents, key=lambda n: n.evidence.evidence_id):
            if parent.evidence.evidence_id == child.evidence.evidence_id:
                continue  # a process cannot be its own parent; skip a data anomaly
            entity_id = parent_key[1]
            link = _make_link(
                parent,
                child,
                link_class=LinkClass.PROCESS_LINEAGE,
                field_path="process.parent_entity_id",
                observed_value=entity_id,
                observation_id_a=parent.observation.observation_id,
                observation_id_b=child.observation.observation_id,
                uncertainty_note=None,
                method=method,
                method_version=method_version,
                method_content_hash=method_content_hash,
            )
            links[link.link_id] = link
    return links


def _process_interaction_links(
    nodes: Sequence[_Node],
    context_observations: Sequence[Observation],
    *,
    method: str,
    method_version: str,
    method_content_hash: str | None,
) -> dict[str, CorrelationLink]:
    by_entity: dict[_ProcessEntityKey, list[_Node]] = {}
    for node in nodes:
        key = _process_entity_key(node.observation)
        if key is not None:
            by_entity.setdefault(key, []).append(node)

    witnesses: dict[str, Observation] = {}
    for observation in (*(n.observation for n in nodes), *context_observations):
        witnesses.setdefault(observation.observation_id, observation)
    facts = sorted(
        (f for f in map(_injection_fact, witnesses.values()) if f is not None),
        key=lambda f: (f.observation.timestamp, f.observation.observation_id),
    )

    links: dict[str, CorrelationLink] = {}
    for fact in facts:  # earliest attestation first: it is the one recorded
        sources = sorted(
            by_entity.get((fact.host_scope, fact.source_entity_id), ()),
            key=lambda n: n.evidence.evidence_id,
        )
        targets = sorted(
            (
                n
                for n in by_entity.get((fact.host_scope, fact.target_entity_id), ())
                if not is_confidently_before(n.observation, fact.observation)
            ),
            key=lambda n: n.evidence.evidence_id,
        )
        for source in sources:
            for target in targets:
                link = _make_link(
                    source,
                    target,
                    link_class=LinkClass.PROCESS_INTERACTION,
                    field_path="target_process.entity_id",
                    observed_value=fact.target_entity_id,
                    observation_id_a=source.observation.observation_id,
                    observation_id_b=target.observation.observation_id,
                    uncertainty_note=None,
                    method=method,
                    method_version=method_version,
                    method_content_hash=method_content_hash,
                    witness_observation_id=fact.observation.observation_id,
                )
                links.setdefault(link.link_id, link)
    return links


def _connected_components(
    nodes: Sequence[_Node],
    links: Sequence[CorrelationLink],
) -> list[frozenset[str]]:
    """A small, deterministic union-find over Evidence ids connected by the
    given structural links -- the minimum correct algorithm for this
    problem, not a general graph framework."""
    parent: dict[str, str] = {
        node.evidence.evidence_id: node.evidence.evidence_id for node in nodes
    }

    def find(x: str) -> str:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a: str, b: str) -> None:
        root_a, root_b = find(a), find(b)
        if root_a == root_b:
            return
        # Deterministic tie-break: attach the lexicographically-larger root
        # under the smaller one, independent of link/processing order.
        if root_a < root_b:
            parent[root_b] = root_a
        else:
            parent[root_a] = root_b

    for link in sorted(links, key=lambda link_: link_.link_id):
        union(link.anchor_a, link.anchor_b)

    members: dict[str, set[str]] = {}
    for evidence_id in parent:
        members.setdefault(find(evidence_id), set()).add(evidence_id)

    return [frozenset(group) for group in members.values() if len(group) >= 2]


def correlate_structurally(
    items: Sequence[tuple[Evidence, Observation]],
    *,
    method: str = STRUCTURAL_CORRELATION_METHOD,
    method_version: str = STRUCTURAL_CORRELATION_METHOD_VERSION,
    method_content_hash: str | None = None,
    context_observations: Sequence[Observation] = (),
) -> StructuralCorrelationResult:
    """Compute every ``SHARED_OBSERVATION``/``SAME_PROCESS_ENTITY``/
    ``PROCESS_LINEAGE``/``PROCESS_INTERACTION`` link across ``items``, and
    the ``CorrelationGroup``s those structural links form (connected
    components; singletons produce no group).

    ``context_observations`` (optional) are telemetry Observations that
    carry no Evidence. They are read **only** as witnesses of
    ``PROCESS_INTERACTION`` (a remote-thread event linking two process
    instances, ADR-0003 Amendment A7); they never become group members and
    no other dimension reads them.

    ``items`` is a sequence of ``(Evidence, Observation)`` pairs -- the same
    shape the existing pipeline already produces at the point a caller would
    invoke this (e.g. one entry per ``(detection, observation)`` pair from
    G1.2's replay, or per stored Evidence/Observation loaded from G0.8).
    Each ``Observation`` must be the one named in its paired ``Evidence``'s
    ``provenance.source_observation_ids`` (checked, not assumed) -- this
    mirrors the same consistency check
    :func:`attribution_platform.detection.derive_evidence_from_detection`
    already performs one layer down. Evidence ids must be unique across
    ``items``.

    ``method``/``method_version`` become every produced link's and group's
    ``CorrelationProvenance.method``/``method_version`` (defaulting to this
    module's own identity). ``method_content_hash`` is optional and never
    fabricated -- pass it only when the caller has a real content hash for
    the correlation configuration used (there is no such configuration yet
    at G2.1, since the three structural dimensions are not individually
    toggleable; left ``None`` by default).

    Pure and deterministic: no I/O, no ATT&CK knowledge, no randomness, no
    wall-clock. Returns an empty result for empty ``items``.
    """
    nodes = _validate_nodes(items)
    context = _validate_context_observations(context_observations)
    if not nodes:
        return StructuralCorrelationResult(links=(), groups=())

    all_links: dict[str, CorrelationLink] = {}
    all_links.update(
        _shared_observation_links(
            nodes,
            method=method,
            method_version=method_version,
            method_content_hash=method_content_hash,
        )
    )
    all_links.update(
        _same_process_entity_links(
            nodes,
            method=method,
            method_version=method_version,
            method_content_hash=method_content_hash,
        )
    )
    all_links.update(
        _process_lineage_links(
            nodes,
            method=method,
            method_version=method_version,
            method_content_hash=method_content_hash,
        )
    )

    all_links.update(
        _process_interaction_links(
            nodes,
            context,
            method=method,
            method_version=method_version,
            method_content_hash=method_content_hash,
        )
    )

    sorted_links = tuple(sorted(all_links.values(), key=lambda link_: link_.link_id))

    nodes_by_evidence_id = {node.evidence.evidence_id: node for node in nodes}
    groups: list[CorrelationGroup] = []
    for member_ids in _connected_components(nodes, sorted_links):
        component_links = tuple(
            link
            for link in sorted_links
            if link.anchor_a in member_ids and link.anchor_b in member_ids
        )
        member_observation_ids = tuple(
            sorted({nodes_by_evidence_id[eid].observation.observation_id for eid in member_ids})
        )
        provenance = CorrelationProvenance(
            method=method,
            method_version=method_version,
            source_evidence_ids=tuple(member_ids),
            source_observation_ids=member_observation_ids,
            method_content_hash=method_content_hash,
        )
        group = build_correlation_group(
            group_id=compute_group_id(member_ids, method_content_hash=method_content_hash),
            member_evidence_ids=tuple(member_ids),
            member_observation_ids=member_observation_ids,
            structural_links=component_links,
            provenance=provenance,
        )
        groups.append(group)

    sorted_groups = tuple(sorted(groups, key=lambda group_: group_.group_id))
    return StructuralCorrelationResult(links=sorted_links, groups=sorted_groups)
