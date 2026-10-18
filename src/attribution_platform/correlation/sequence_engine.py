"""Behavioral-sequence construction engine (gate G2.4.1, ADR-0004).

Pure, deterministic reconstruction of one :class:`BehavioralSequence` from
an already-computed :class:`CorrelationGroup` (G2.1/G2.2, unchanged) and the
real ``(Evidence, Observation)`` pairs / structural / contextual
``CorrelationLink``\\ s that ground it. This module performs **no**
correlation of its own — it consumes G2.1's/G2.2's already-accepted output
exactly as given, the same boundary
:mod:`attribution_platform.correlation.contextual` already draws against
:mod:`attribution_platform.correlation.structural`.

**Pure function, no I/O.** No Elasticsearch, no persistence, no replay, no
network, no filesystem access, no ATT&CK knowledge-base loading. The single
public entry point, :func:`construct_behavioral_sequence`, takes fully
in-memory, already-loaded objects and returns a fully in-memory
:class:`~attribution_platform.correlation.sequence.BehavioralSequence` —
nothing else.

**Fail-closed input scope.** The supplied ``items``/``structural_links``/
``contextual_links`` must correspond *exactly* to ``group``'s own
membership (``group.member_evidence_ids``, ``group.structural_link_ids``,
``group.contextual_link_ids``) — extra or missing entries are rejected,
never silently filtered, mirroring G2.1's own ``_validate_nodes`` strictness
and G2.0's ``build_correlation_group``/G2.4.0's ``build_behavioral_step``/
``build_behavioral_sequence`` re-verification discipline.

**Algorithm, in five phases, all pure and deterministic:**

1. **Step construction** — partition ``group``'s member Evidence into steps
   via a ``SHARED_OBSERVATION``-only union-find (ADR-0004 D4), deliberately
   scoped to that one link class, mirroring
   :mod:`attribution_platform.correlation.structural`'s own "one small,
   purpose-built union-find, not a graph framework" precedent. Each step's
   ``technique_stix_ids`` is mechanically read off its own Evidence's real
   ``attack_ref`` values — this module is now that producer (G2.4.0's
   ``build_behavioral_step`` deliberately does not accept it; see that
   function's own docstring for why). Each step's ``contextual_annotations``
   is the subset of ``contextual_links`` touching its evidence.
2. **``PROCESS_LINEAGE`` ordering** (ADR-0004 D5/D7) — one directed
   ``SequenceEdge`` per structural ``PROCESS_LINEAGE`` link, using the
   link's own directional ``basis.observation_id_a``/``_b`` (never
   timestamps) for direction; a real timestamp disagreement is *recorded*
   (``timestamp_agreement=False``), never used to reverse or drop the edge.
3. **``TEMPORAL_SAME_ENTITY`` ordering** (ADR-0004 D5/D6/D8) — steps
   connected by structural ``SAME_PROCESS_ENTITY`` links are ordered by
   strict, precision-aware ``Observation.timestamp`` comparison only;
   genuinely tied pairs become a ``SequenceGap``, never an invented order;
   strictly-ordered *chains* are Hasse-reduced to their minimal consecutive
   edges (never the full transitive closure).
4. **``SequenceParallelGroup`` construction** (ADR-0004 D9) — for every step
   with two or more direct ``PROCESS_LINEAGE`` children, the accepted
   branch-partition object, with the convergence-safety exclusion applied.
5. **Final assembly** via G2.4.0's own sanctioned
   :func:`~attribution_platform.correlation.sequence.build_behavioral_sequence`
   — re-verifying every edge's/gap's grounding against ``group`` and every
   contract-level invariant G2.4.0 already enforces. This module invents no
   second validation path.

**A genuine architectural ambiguity was found and is handled fail-closed,
not silently resolved — see the module-level note above
:func:`construct_behavioral_sequence` and the final G2.4.1 report.** Neither
ADR-0004 nor the G2.4.0 contracts specify a tie-break for the case where
``SHARED_OBSERVATION`` collapse causes *more than one* same-class structural
``CorrelationLink`` to resolve to the *same* directed (or undirected) step-
level pair. Rather than invent a weighting/precedence rule, this engine
raises :class:`~attribution_platform.correlation.errors.CorrelationError`
when this is detected.

**Deliberately NOT here:** ``TEMPORAL_PROXIMITY`` (G2.4.3 — no window
calculation, no contextual-to-edge/gap conversion of any kind); attribution,
candidate generation, likelihood, confidence, scoring, weighting, ACH,
calibration (none of that vocabulary, and no numeric uncertainty of any
kind, exists anywhere in this module); persistence, replay, or an
Elasticsearch dependency of any kind (G2.4.2); ATT&CK knowledge-base access
of any kind — ``Evidence.attack_ref`` is read as an already-validated,
already-resolved fact, never re-validated or looked up against a knowledge
base here.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from attribution_platform.correlation.contracts import (
    CorrelationGroup,
    CorrelationLink,
    CorrelationProvenance,
    LinkClass,
)
from attribution_platform.correlation.errors import CorrelationError
from attribution_platform.correlation.sequence import (
    BehavioralSequence,
    BehavioralStep,
    GapReason,
    OrderingBasis,
    OrderingBasisKind,
    SequenceEdge,
    SequenceGap,
    SequenceParallelGroup,
    build_behavioral_sequence,
    compute_sequence_edge_id,
    compute_sequence_gap_id,
    compute_sequence_id,
    compute_sequence_parallel_group_id,
    compute_step_id,
)
from attribution_platform.correlation.timing import MAX_GRANULARITY
from attribution_platform.domain import Evidence, EvidenceQuality, Observation, TimePrecision

#: Default ``CorrelationProvenance.method``/``method_version`` this engine
#: stamps onto the ``BehavioralSequence`` it produces, mirroring G2.1's
#: ``STRUCTURAL_CORRELATION_METHOD``/G2.2's ``CONTEXTUAL_CORRELATION_METHOD``
#: convention exactly.
SEQUENCE_ENGINE_METHOD = "behavioral-sequence-construction"
SEQUENCE_ENGINE_METHOD_VERSION = "1.1"  # 1.1: enrich Evidence adds no step technique (Amendment H)

#: The wall-clock granularity each declared ``TimePrecision`` represents,
#: used only to *truncate* two real timestamps to their common (coarser)
#: granularity for comparison (ADR-0004 D6) — never to alter a stored
#: value. ``NANOSECOND`` is mapped to the same granularity as
#: ``MICROSECOND`` because Python's ``datetime`` has no finer resolution;
#: this is a stdlib limitation, not a new semantic invented here.
_PRECISION_GRANULARITY: dict[TimePrecision, timedelta] = {
    TimePrecision.SECOND: timedelta(seconds=1),
    TimePrecision.MILLISECOND: timedelta(milliseconds=1),
    TimePrecision.MICROSECOND: timedelta(microseconds=1),
    TimePrecision.NANOSECOND: timedelta(microseconds=1),
}

_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


def _truncate(value: datetime, granularity: timedelta) -> datetime:
    delta = value - _EPOCH
    truncated = (delta // granularity) * granularity
    return _EPOCH + truncated


@dataclass(frozen=True)
class _TimestampComparison:
    """The pure result of comparing two Observations' timestamps per
    ADR-0004 D6 -- categorical only, never numeric."""

    kind: str  # "a_before_b" | "b_before_a" | "equal" | "coarse_tie"
    precision_uncertain: bool


def _compare_timestamps(obs_a: Observation, obs_b: Observation) -> _TimestampComparison:
    """ADR-0004 D6, implemented literally: exact equality is a tie; if
    either side's precision is absent/unknown, a real inequality is still
    honored but flagged ``precision_uncertain``; otherwise both timestamps
    are truncated to their common (coarser) granularity before comparing --
    a difference that survives truncation is a confident order, one that
    does not is a coarse-precision tie. Never breaks a tie arbitrarily."""
    ts_a, ts_b = obs_a.timestamp, obs_b.timestamp
    if ts_a == ts_b:
        return _TimestampComparison(kind="equal", precision_uncertain=False)

    prec_a, prec_b = obs_a.timestamp_precision, obs_b.timestamp_precision
    if (
        prec_a is None
        or prec_b is None
        or prec_a is TimePrecision.UNKNOWN
        or prec_b is TimePrecision.UNKNOWN
    ):
        kind = "a_before_b" if ts_a < ts_b else "b_before_a"
        return _TimestampComparison(kind=kind, precision_uncertain=True)

    granularity = max(_PRECISION_GRANULARITY[prec_a], _PRECISION_GRANULARITY[prec_b])
    truncated_a = _truncate(ts_a, granularity)
    truncated_b = _truncate(ts_b, granularity)
    if truncated_a == truncated_b:
        return _TimestampComparison(kind="coarse_tie", precision_uncertain=False)
    kind = "a_before_b" if truncated_a < truncated_b else "b_before_a"
    return _TimestampComparison(kind=kind, precision_uncertain=False)


def _sorted_pair(pair: frozenset[str]) -> tuple[str, str]:
    """Deterministically order a 2-element ``frozenset[str]`` into a
    ``tuple[str, str]`` for :func:`_union_find_components`'s ``pairs`` arg."""
    first, second = sorted(pair)
    return (first, second)


def _union_find_components(
    all_ids: Sequence[str], pairs: Sequence[tuple[str, str]]
) -> list[frozenset[str]]:
    """Small, deterministic union-find (mirrors
    :mod:`attribution_platform.correlation.structural`'s own private
    helper, scoped to this module's own purpose) over ``all_ids``, unioned
    pairwise by ``pairs``. Unlike G2.1's own component finder, singleton
    components ARE returned here (every step -- including one with no
    ``SHARED_OBSERVATION`` partner -- must still appear in exactly one
    partition)."""
    parent: dict[str, str] = {item: item for item in all_ids}

    def find(x: str) -> str:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a: str, b: str) -> None:
        root_a, root_b = find(a), find(b)
        if root_a == root_b:
            return
        if root_a < root_b:
            parent[root_b] = root_a
        else:
            parent[root_a] = root_b

    for a, b in pairs:
        union(a, b)

    members: dict[str, set[str]] = {}
    for item in all_ids:
        members.setdefault(find(item), set()).add(item)
    return [frozenset(component) for component in members.values()]


def _reachable_from(start: str, adjacency: Mapping[str, Sequence[str]]) -> set[str]:
    """Plain BFS forward-reachability (including ``start`` itself) over the
    full, already-built edge adjacency -- stdlib-only, not a graph library,
    used only to compute each branch's exclusive-descendant set (ADR-0004
    D9), never to derive an edge itself."""
    visited: set[str] = set()
    queue: deque[str] = deque([start])
    while queue:
        node = queue.popleft()
        if node in visited:
            continue
        visited.add(node)
        for neighbor in adjacency.get(node, ()):
            if neighbor not in visited:
                queue.append(neighbor)
    return visited


def _validate_items(
    group: CorrelationGroup, items: Sequence[tuple[Evidence, Observation]]
) -> tuple[dict[str, Evidence], dict[str, Observation]]:
    evidence_by_id: dict[str, Evidence] = {}
    observation_by_id: dict[str, Observation] = {}
    for index, (evidence, observation) in enumerate(items):
        if not isinstance(evidence, Evidence):
            raise CorrelationError(
                f"construct_behavioral_sequence: items[{index}][0] must be a domain "
                f"Evidence, got {type(evidence).__name__}"
            )
        if not isinstance(observation, Observation):
            raise CorrelationError(
                f"construct_behavioral_sequence: items[{index}][1] must be a domain "
                f"Observation, got {type(observation).__name__}"
            )
        if evidence.provenance.source_observation_ids != (observation.observation_id,):
            raise CorrelationError(
                f"construct_behavioral_sequence: items[{index}]: evidence "
                f"{evidence.evidence_id!r} does not have exactly the supplied observation "
                f"{observation.observation_id!r} as its sole source "
                f"(source_observation_ids={evidence.provenance.source_observation_ids!r}) -- "
                "reusing G2.1's own fail-closed single-Observation requirement"
            )
        if evidence.evidence_id in evidence_by_id:
            raise CorrelationError(
                f"construct_behavioral_sequence: duplicate evidence_id "
                f"{evidence.evidence_id!r} in items"
            )
        evidence_by_id[evidence.evidence_id] = evidence
        observation_by_id[observation.observation_id] = observation

    given_ids = set(evidence_by_id)
    expected_ids = set(group.member_evidence_ids)
    if given_ids != expected_ids:
        missing = expected_ids - given_ids
        extra = given_ids - expected_ids
        raise CorrelationError(
            "construct_behavioral_sequence: items must correspond exactly to "
            f"group.member_evidence_ids for group {group.group_id!r} "
            f"(missing={sorted(missing)!r}, extra={sorted(extra)!r})"
        )
    return evidence_by_id, observation_by_id


def _validate_links(
    group: CorrelationGroup,
    structural_links: Sequence[CorrelationLink],
    contextual_links: Sequence[CorrelationLink],
) -> tuple[dict[str, CorrelationLink], dict[str, CorrelationLink]]:
    structural_by_id: dict[str, CorrelationLink] = {}
    for link in structural_links:
        if not isinstance(link, CorrelationLink):
            raise CorrelationError(
                f"construct_behavioral_sequence: structural_links must contain "
                f"CorrelationLink objects, got {type(link).__name__}"
            )
        if not link.link_class.is_structural:
            raise CorrelationError(
                f"construct_behavioral_sequence: structural_links contains a non-structural "
                f"link {link.link_id!r} (link_class={link.link_class.value!r})"
            )
        structural_by_id[link.link_id] = link
    if set(structural_by_id) != set(group.structural_link_ids):
        raise CorrelationError(
            "construct_behavioral_sequence: structural_links must correspond exactly to "
            f"group.structural_link_ids for group {group.group_id!r}"
        )

    contextual_by_id: dict[str, CorrelationLink] = {}
    for link in contextual_links:
        if not isinstance(link, CorrelationLink):
            raise CorrelationError(
                f"construct_behavioral_sequence: contextual_links must contain "
                f"CorrelationLink objects, got {type(link).__name__}"
            )
        if link.link_class.is_structural:
            raise CorrelationError(
                f"construct_behavioral_sequence: contextual_links contains a structural "
                f"link {link.link_id!r} (link_class={link.link_class.value!r})"
            )
        contextual_by_id[link.link_id] = link
    if set(contextual_by_id) != set(group.contextual_link_ids):
        raise CorrelationError(
            "construct_behavioral_sequence: contextual_links must correspond exactly to "
            f"group.contextual_link_ids for group {group.group_id!r}"
        )

    return structural_by_id, contextual_by_id


@dataclass(frozen=True)
class _Step:
    step: BehavioralStep
    observation: Observation


def _build_steps(
    group: CorrelationGroup,
    evidence_by_id: Mapping[str, Evidence],
    observation_by_id: Mapping[str, Observation],
    structural_by_id: Mapping[str, CorrelationLink],
    contextual_by_id: Mapping[str, CorrelationLink],
) -> tuple[dict[str, _Step], dict[str, str], dict[str, str]]:
    """Phase 1: SHARED_OBSERVATION collapse (ADR-0004 D4) + mechanical
    technique_stix_ids/contextual_annotations derivation. Returns
    (step_by_step_id, evidence_id_to_step_id, observation_id_to_step_id)."""
    shared_observation_pairs = [
        (link.anchor_a, link.anchor_b)
        for link in structural_by_id.values()
        if link.link_class is LinkClass.SHARED_OBSERVATION
    ]
    components = _union_find_components(sorted(evidence_by_id), shared_observation_pairs)

    steps: dict[str, _Step] = {}
    evidence_id_to_step_id: dict[str, str] = {}
    observation_id_to_step_id: dict[str, str] = {}
    for component in components:
        evidence_ids = tuple(sorted(component))
        observation_ids = {
            evidence_by_id[eid].provenance.source_observation_ids[0] for eid in evidence_ids
        }
        if len(observation_ids) != 1:
            raise CorrelationError(
                "construct_behavioral_sequence: internal inconsistency -- a "
                "SHARED_OBSERVATION-collapsed component does not share exactly one "
                f"Observation id (evidence_ids={evidence_ids!r}, "
                f"observation_ids={sorted(observation_ids)!r})"
            )
        (observation_id,) = observation_ids

        step_evidences = [evidence_by_id[eid] for eid in evidence_ids]
        # ADR-0003 Amendment H: enrich-tier Evidence (quality LOW) stays on the
        # step as context (``evidence_ids``) but contributes no technique to the
        # step's attribution features — support(h) rests on core evidence.
        technique_stix_ids = tuple(
            sorted(
                {
                    evidence.attack_ref.stix_id
                    for evidence in step_evidences
                    if evidence.attack_ref is not None
                    # Amendment H: low-level Evidence adds no technique - unless its
                    # rule's review says it counts once linked into the unit
                    and (
                        evidence.quality is not EvidenceQuality.LOW or evidence.counted_when_linked
                    )
                    # ADR-0025: a technique its rule declares but the match does
                    # not establish is shown, not compared
                    and not evidence.technique_ambiguous
                }
            )
        )
        # B4 carry-forward: the distinct EvidenceType values of this step's own
        # member Evidence, read directly off Evidence.evidence_type (the closed
        # vocabulary) — never inferred or re-derived (ADR-0004 Post-acceptance
        # Clarification 3, 2026-09-21; ADR-0005 Amendment D).
        evidence_types = tuple(
            sorted({evidence.evidence_type.value for evidence in step_evidences})
        )
        contextual_annotations = tuple(
            sorted(
                link.link_id
                for link in contextual_by_id.values()
                if link.anchor_a in evidence_ids or link.anchor_b in evidence_ids
            )
        )

        if observation_id in observation_id_to_step_id:
            # Every Evidence on one Observation is one step (ADR-0004 D4); two steps
            # on one Observation would be ordered by nothing -- fail closed.
            raise CorrelationError(
                "construct_behavioral_sequence: Observation "
                f"{observation_id!r} would form two steps -- its Evidence are not all "
                "joined by SHARED_OBSERVATION links"
            )
        step_id = compute_step_id(group.group_id, evidence_ids)
        step = BehavioralStep(
            step_id=step_id,
            group_id=group.group_id,
            evidence_ids=evidence_ids,
            observation_id=observation_id,
            technique_stix_ids=technique_stix_ids,
            evidence_types=evidence_types,
            contextual_annotations=contextual_annotations,
        )
        steps[step_id] = _Step(step=step, observation=observation_by_id[observation_id])
        for eid in evidence_ids:
            evidence_id_to_step_id[eid] = step_id
        observation_id_to_step_id[observation_id] = step_id

    return steps, evidence_id_to_step_id, observation_id_to_step_id


def _build_process_lineage_edges(
    structural_by_id: Mapping[str, CorrelationLink],
    steps: Mapping[str, _Step],
    observation_id_to_step_id: Mapping[str, str],
) -> tuple[SequenceEdge, ...]:
    """Phase 2: ADR-0004 D5/D7. One directed edge per PROCESS_LINEAGE link,
    using the link's own directional basis (never timestamps) for
    direction. Detects -- and fails closed on, never silently resolves --
    the case where more than one PROCESS_LINEAGE link collapses to the
    same directed step-level pair after SHARED_OBSERVATION collapse (see
    module docstring)."""
    link_options: dict[tuple[str, str], list[CorrelationLink]] = {}
    for link in sorted(structural_by_id.values(), key=lambda link_: link_.link_id):
        if link.link_class is not LinkClass.PROCESS_LINEAGE:
            continue
        parent_step_id = observation_id_to_step_id[link.basis.observation_id_a]
        child_step_id = observation_id_to_step_id[link.basis.observation_id_b]
        if parent_step_id == child_step_id:
            # Both ends collapsed into the same SHARED_OBSERVATION step --
            # no inter-step ordering fact remains to represent (ADR-0004 D4).
            continue
        link_options.setdefault((parent_step_id, child_step_id), []).append(link)

    edges: list[SequenceEdge] = []
    for (parent_step_id, child_step_id), links in sorted(link_options.items()):
        if len(links) > 1:
            raise CorrelationError(
                "construct_behavioral_sequence: ambiguous PROCESS_LINEAGE grounding -- "
                f"{len(links)} distinct structural CorrelationLinks "
                f"({sorted(link.link_id for link in links)!r}) all resolve to the same "
                f"step-level edge {parent_step_id!r} -> {child_step_id!r} after "
                "SHARED_OBSERVATION collapse. ADR-0004 does not specify a tie-break rule "
                "for this case; this engine does not invent one."
            )
        (link,) = links
        parent_obs = steps[parent_step_id].observation
        child_obs = steps[child_step_id].observation
        timestamp_agreement = parent_obs.timestamp <= child_obs.timestamp
        basis = OrderingBasis(
            basis_kind=OrderingBasisKind.PROCESS_LINEAGE,
            grounding_link_id=link.link_id,
            timestamp_agreement=timestamp_agreement,
        )
        edge_id = compute_sequence_edge_id(
            from_step_id=parent_step_id,
            to_step_id=child_step_id,
            basis_kind=OrderingBasisKind.PROCESS_LINEAGE,
            grounding_link_id=link.link_id,
        )
        edges.append(
            SequenceEdge(
                edge_id=edge_id,
                from_step_id=parent_step_id,
                to_step_id=child_step_id,
                basis=basis,
            )
        )
    return tuple(sorted(edges, key=lambda edge: edge.edge_id))


def _build_temporal_same_entity_relations(
    structural_by_id: Mapping[str, CorrelationLink],
    steps: Mapping[str, _Step],
    evidence_id_to_step_id: Mapping[str, str],
) -> tuple[tuple[SequenceEdge, ...], tuple[SequenceGap, ...]]:
    """Phases 3: ADR-0004 D5/D6/D8. Resolves SAME_PROCESS_ENTITY links into
    step-level pairs (skipping any that collapsed to one step), detects
    ambiguous multi-link collapses (same fail-closed rule as lineage,
    above), groups genuinely-tied steps into buckets, and emits only the
    Hasse-reduced consecutive-bucket edges plus one gap per tied pair --
    never the transitive closure of edges, and never an invented order for
    a tie."""
    pair_link_options: dict[frozenset[str], list[CorrelationLink]] = {}
    for link in sorted(structural_by_id.values(), key=lambda link_: link_.link_id):
        if link.link_class is not LinkClass.SAME_PROCESS_ENTITY:
            continue
        step_a = evidence_id_to_step_id[link.anchor_a]
        step_b = evidence_id_to_step_id[link.anchor_b]
        if step_a == step_b:
            continue
        pair_link_options.setdefault(frozenset((step_a, step_b)), []).append(link)

    pair_grounding: dict[frozenset[str], CorrelationLink] = {}
    for pair, links in sorted(pair_link_options.items(), key=lambda item: sorted(item[0])):
        if len(links) > 1:
            raise CorrelationError(
                "construct_behavioral_sequence: ambiguous SAME_PROCESS_ENTITY grounding -- "
                f"{len(links)} distinct structural CorrelationLinks "
                f"({sorted(link.link_id for link in links)!r}) all resolve to the same "
                f"step-level pair {sorted(pair)!r} after SHARED_OBSERVATION collapse. "
                "ADR-0004 does not specify a tie-break rule for this case; this engine "
                "does not invent one."
            )
        (pair_grounding[pair],) = links

    if not pair_grounding:
        return (), ()

    cluster_members = sorted({member for pair in pair_grounding for member in pair})
    clusters = _union_find_components(
        cluster_members, [_sorted_pair(pair) for pair in pair_grounding]
    )

    edges: list[SequenceEdge] = []
    gaps: list[SequenceGap] = []
    for cluster in clusters:
        if len(cluster) < 2:
            continue
        # ADR-0003 Amendment C / ADR-0004 C3: G2.1 links one process entity's
        # steps as a chain in (timestamp, observation_id) order. Every
        # consecutive pair of that order must be directly grounded; a missing
        # link means the links do not describe one coherent entity -- fail
        # closed. (Additional links, e.g. a legacy pairwise closure, are
        # permitted and simply not needed.)
        order = sorted(
            cluster,
            key=lambda m: (steps[m].observation.timestamp, steps[m].observation.observation_id),
        )
        position = {member: i for i, member in enumerate(order)}
        for member_a, member_b in zip(order, order[1:], strict=False):
            if frozenset((member_a, member_b)) not in pair_grounding:
                raise CorrelationError(
                    "construct_behavioral_sequence: SAME_PROCESS_ENTITY cluster "
                    f"{sorted(cluster)!r} has no direct structural link between consecutive "
                    f"steps {member_a!r} and {member_b!r} -- the links do not form the chain "
                    "G2.1 produces for one process entity"
                )

        # Ties (ADR-0004 D6) are only possible between timestamps less than the
        # coarsest declared granularity apart, so comparing within that window
        # finds every tie exactly; pairs further apart are strictly ordered in
        # sorted order.
        comparisons: dict[frozenset[str], _TimestampComparison] = {}
        tie_pairs: list[tuple[str, str]] = []
        for i, member_a in enumerate(order):
            obs_a = steps[member_a].observation
            for member_b in order[i + 1 :]:
                obs_b = steps[member_b].observation
                if obs_b.timestamp - obs_a.timestamp >= MAX_GRANULARITY:
                    break
                comparison = _compare_timestamps(obs_a, obs_b)
                comparisons[frozenset((member_a, member_b))] = comparison
                if comparison.kind in ("equal", "coarse_tie"):
                    tie_pairs.append(_sorted_pair(frozenset((member_a, member_b))))
                elif comparison.kind != "a_before_b":
                    raise CorrelationError(
                        "construct_behavioral_sequence: internal inconsistency -- steps "
                        f"{member_a!r}/{member_b!r} compare against their timestamp order"
                    )
        buckets = _union_find_components(order, tie_pairs)

        # A bucket must be a contiguous run of the order and pairwise tied;
        # otherwise the tie relation is non-transitive -- fail closed, never
        # linearize (ADR-0004 D6).
        for bucket in buckets:
            indices = sorted(position[m] for m in bucket)
            if indices != list(range(indices[0], indices[-1] + 1)):
                raise CorrelationError(
                    "construct_behavioral_sequence: non-transitive timestamp order "
                    f"detected across SAME_PROCESS_ENTITY cluster {sorted(cluster)!r} buckets"
                )
            for member_a in bucket:
                for member_b in bucket:
                    if member_a >= member_b:
                        continue
                    tie = comparisons.get(frozenset((member_a, member_b)))
                    if tie is None or tie.kind not in ("equal", "coarse_tie"):
                        raise CorrelationError(
                            "construct_behavioral_sequence: non-transitive timestamp tie "
                            f"detected within SAME_PROCESS_ENTITY cluster {sorted(cluster)!r} "
                            f"-- {member_a!r} and {member_b!r} are not pairwise tied despite "
                            "both being tied with a common other member"
                        )

        bucket_order = sorted(buckets, key=lambda bucket: min(position[m] for m in bucket))
        ordered_buckets = [sorted(bucket, key=position.__getitem__) for bucket in bucket_order]

        def chain_link(
            later: str, order: list[str] = order, position: dict[str, int] = position
        ) -> CorrelationLink:
            """The chain link joining ``later`` to its predecessor."""
            previous = order[position[later] - 1]
            return pair_grounding[frozenset((previous, later))]

        for run in ordered_buckets:
            for member_a in run:
                for member_b in run:
                    if member_a >= member_b:
                        continue
                    later = max(member_a, member_b, key=position.__getitem__)
                    link = chain_link(later)
                    comparison = comparisons[frozenset((member_a, member_b))]
                    reason = (
                        GapReason.EQUAL_TIMESTAMPS
                        if comparison.kind == "equal"
                        else GapReason.COARSE_PRECISION_TIE
                    )
                    gaps.append(
                        SequenceGap(
                            gap_id=compute_sequence_gap_id(
                                step_id_a=member_a,
                                step_id_b=member_b,
                                reason=reason,
                                grounding_link_id=link.link_id,
                            ),
                            step_id_a=member_a,
                            step_id_b=member_b,
                            grounding_link_id=link.link_id,
                            reason=reason,
                        )
                    )

        for earlier, later_bucket in zip(ordered_buckets, ordered_buckets[1:], strict=False):
            # Every consecutive-bucket edge is grounded by the chain link that
            # crosses the bucket boundary -- the direct link between the two
            # steps when both buckets are single steps (the usual case).
            link = chain_link(later_bucket[0])
            for member_from in earlier:
                for member_to in later_bucket:
                    edge_comparison = comparisons.get(
                        frozenset((member_from, member_to))
                    ) or _compare_timestamps(
                        steps[member_from].observation, steps[member_to].observation
                    )
                    basis = OrderingBasis(
                        basis_kind=OrderingBasisKind.TEMPORAL_SAME_ENTITY,
                        grounding_link_id=link.link_id,
                        precision_uncertain=edge_comparison.precision_uncertain,
                    )
                    edges.append(
                        SequenceEdge(
                            edge_id=compute_sequence_edge_id(
                                from_step_id=member_from,
                                to_step_id=member_to,
                                basis_kind=OrderingBasisKind.TEMPORAL_SAME_ENTITY,
                                grounding_link_id=link.link_id,
                            ),
                            from_step_id=member_from,
                            to_step_id=member_to,
                            basis=basis,
                        )
                    )

    return tuple(sorted(edges, key=lambda edge: edge.edge_id)), tuple(
        sorted(gaps, key=lambda gap: gap.gap_id)
    )


def _build_parallel_groups(
    edges: Sequence[SequenceEdge],
) -> tuple[SequenceParallelGroup, ...]:
    """Phase 4: ADR-0004 D9, the accepted branch-partition design. A branch
    point is any step with two or more direct PROCESS_LINEAGE children.
    Each branch's exclusive-descendant set is computed over the FULL edge
    graph (both ordering bases -- a branch may continue through a
    TEMPORAL_SAME_ENTITY edge); a step reachable from more than one child
    is excluded from every branch (convergence safety). If exclusion would
    leave a branch's own root without a valid root, that branch is dropped
    entirely (documented design decision -- see module report); if fewer
    than two branches remain, no SequenceParallelGroup is built for that
    branch point at all."""
    adjacency: dict[str, list[str]] = {}
    lineage_children: dict[str, list[str]] = {}
    for edge in edges:
        adjacency.setdefault(edge.from_step_id, []).append(edge.to_step_id)
        if edge.basis.basis_kind is OrderingBasisKind.PROCESS_LINEAGE:
            lineage_children.setdefault(edge.from_step_id, []).append(edge.to_step_id)

    parallel_groups: list[SequenceParallelGroup] = []
    for source_step_id in sorted(lineage_children):
        children = sorted(set(lineage_children[source_step_id]))
        if len(children) < 2:
            continue

        reachable_by_child = {child: _reachable_from(child, adjacency) for child in children}
        membership_count: dict[str, int] = {}
        for reachable in reachable_by_child.values():
            for step_id in reachable:
                membership_count[step_id] = membership_count.get(step_id, 0) + 1

        branches: list[tuple[str, ...]] = []
        for child in children:
            exclusive = {
                step_id for step_id in reachable_by_child[child] if membership_count[step_id] == 1
            }
            if child not in exclusive:
                continue  # the root itself is convergent -- drop this branch
            remainder = sorted(exclusive - {child})
            branches.append((child, *remainder))

        if len(branches) < 2:
            continue

        branches_tuple = tuple(branches)
        parallel_groups.append(
            SequenceParallelGroup(
                parallel_group_id=compute_sequence_parallel_group_id(
                    source_step_id, branches_tuple
                ),
                source_step_id=source_step_id,
                branches=branches_tuple,
            )
        )
    return tuple(sorted(parallel_groups, key=lambda group: group.parallel_group_id))


def construct_behavioral_sequence(
    group: CorrelationGroup,
    items: Sequence[tuple[Evidence, Observation]],
    structural_links: Sequence[CorrelationLink],
    contextual_links: Sequence[CorrelationLink] = (),
    *,
    method: str = SEQUENCE_ENGINE_METHOD,
    method_version: str = SEQUENCE_ENGINE_METHOD_VERSION,
    method_content_hash: str | None = None,
) -> BehavioralSequence:
    """Reconstruct the one ``BehavioralSequence`` for ``group`` (ADR-0004
    D1) from already-computed correlation output.

    ``items`` must be exactly the ``(Evidence, Observation)`` pairs for
    ``group.member_evidence_ids`` (the same shape G2.1's
    ``correlate_structurally``/G2.2's ``contextualize`` already consume).
    ``structural_links`` must be exactly the real ``CorrelationLink``
    objects named by ``group.structural_link_ids``; ``contextual_links``
    exactly those named by ``group.contextual_link_ids`` (may be empty).
    Every one of these correspondences is verified, not assumed --
    mismatched input is rejected, never silently filtered.

    Pure and deterministic: no I/O, no ATT&CK knowledge, no randomness, no
    wall-clock, and input list order never affects the result (every
    intermediate collection is processed/emitted in sorted-by-id order).

    Raises ``CorrelationError`` if ``items``/``structural_links``/
    ``contextual_links`` do not correspond exactly to ``group``, or if a
    genuine architectural ambiguity is detected (multiple same-class
    structural links collapsing to one step-level relationship after
    ``SHARED_OBSERVATION`` collapse -- see module docstring; ADR-0004 does
    not specify a tie-break, so this is never silently resolved).
    """
    if not isinstance(group, CorrelationGroup):
        raise CorrelationError(
            f"construct_behavioral_sequence: group must be a CorrelationGroup, "
            f"got {type(group).__name__}"
        )

    evidence_by_id, observation_by_id = _validate_items(group, items)
    structural_by_id, contextual_by_id = _validate_links(group, structural_links, contextual_links)

    steps, evidence_id_to_step_id, observation_id_to_step_id = _build_steps(
        group, evidence_by_id, observation_by_id, structural_by_id, contextual_by_id
    )

    lineage_edges = _build_process_lineage_edges(structural_by_id, steps, observation_id_to_step_id)
    temporal_edges, gaps = _build_temporal_same_entity_relations(
        structural_by_id, steps, evidence_id_to_step_id
    )
    all_edges = tuple(sorted((*lineage_edges, *temporal_edges), key=lambda edge: edge.edge_id))
    parallel_groups = _build_parallel_groups(all_edges)

    provenance = CorrelationProvenance(
        method=method,
        method_version=method_version,
        source_evidence_ids=group.member_evidence_ids,
        source_observation_ids=group.member_observation_ids,
        method_content_hash=method_content_hash,
    )
    sequence_id = compute_sequence_id(
        group.group_id,
        [step.step.step_id for step in steps.values()],
        method_content_hash=method_content_hash,
    )

    return build_behavioral_sequence(
        sequence_id=sequence_id,
        group=group,
        steps=tuple(entry.step for entry in steps.values()),
        provenance=provenance,
        edges=all_edges,
        gaps=gaps,
        parallel_groups=parallel_groups,
    )
