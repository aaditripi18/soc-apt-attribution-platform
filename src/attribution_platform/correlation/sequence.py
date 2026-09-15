"""Behavioral-sequence domain contracts (gate G2.4.0, ADR-0004).

**Contracts only — no sequence is constructed here.** This module defines
what a `BehavioralStep`/`BehavioralSequence` and the relations between steps
*are*; it contains no ordering algorithm (no timestamp comparison, no
`SHARED_OBSERVATION`-collapse union-find), no branch/convergence discovery,
no replay, and no persistence. Those are later, separately-gated pieces of
G2.4 (G2.4.1 the construction engine, G2.4.2 golden corpus + replay +
persistence, G2.4.3 `TEMPORAL_PROXIMITY`) built *against* these contracts,
never inside them — mirroring exactly how G2.0's ``contracts`` module
preceded G2.1's ``structural`` engine.

Five new contracts, per ADR-0004 §Domain model:

- :class:`BehavioralStep` — a reference-only object (never a copy of
  ``Evidence``/``Observation``/``DetectionResult``) naming the Evidence ids
  and single Observation id one behavioral moment is grounded in, plus two
  purely-derived convenience fields (``technique_stix_ids``,
  ``contextual_annotations``) that assert nothing beyond what those
  referenced objects themselves already carry.
- :class:`SequenceEdge` — a directed, resolved-order relation between two
  steps, grounded in a real structural ``CorrelationLink``.
- :class:`SequenceGap` — an undirected relation asserting *"these two steps
  have a direct structural relationship, but its order cannot be honestly
  resolved"* — never used for unrelated steps or contextual facts.
- :class:`SequenceParallelGroup` — the explicit, compact, branch-partition
  representation of cross-branch parallelism ADR-0004 D9 requires (not a
  per-pair marker): every step exclusively reachable from one branch of a
  divergence is named in that branch's tuple; any two steps drawn from
  *different* branches of one group are explicitly parallel/unordered.
- :class:`BehavioralSequence` — the DAG container, strictly 1:1 with one
  ``CorrelationGroup`` (ADR-0004 D1).

**Two-tier construction, mirroring G2.0's own precedent exactly.** Every
contract's plain constructor validates everything checkable from its own
given fields alone (non-empty/canonicalized ids, self-consistency,
acyclicity, branch-partition well-formedness, edge/gap disjointness — see
each class's own ``__post_init__``). Enforcing the *cross-layer* claims
ADR-0004 also requires — a step's ids really are members of its claimed
``CorrelationGroup``, an edge's/gap's ``grounding_link_id`` really is one of
that group's own ``structural_link_ids`` — needs the real, already-validated
:class:`~attribution_platform.correlation.contracts.CorrelationGroup`
object, which a step or edge alone does not carry. Two sanctioned builders
provide this, exactly as
:func:`~attribution_platform.correlation.contracts.build_correlation_group`
already does for ``CorrelationGroup`` itself:
:func:`build_behavioral_step` (verifies group membership) and
:func:`build_behavioral_sequence` (verifies every step's group identity and
every edge's/gap's grounding link against the real group). Neither performs
any graph algorithm — no ordering, no reachability, no branch discovery —
only re-verification of already-fully-specified structure, the same
division of responsibility ``build_correlation_group`` already establishes.

**Deliberately does not reach into ``domain.Evidence``/``domain.Observation``
at all.** The deeper fail-closed grounding check ADR-0004 D2 describes
(*"the real ``Evidence.provenance.source_observation_ids == (observation_id,)``"*)
is, by the same layering ADR-0004 explicitly cites, the **engine's**
responsibility (G2.4.1) — exactly as G2.1's own equivalent check
(``_validate_nodes``) lives in ``structural.py``, never in G2.0's
``contracts.py``. This module is therefore strictly source-agnostic in the
same, stronger sense G2.0's ``contracts.py`` is (not merely G2.1/G2.2's
weaker "imports only domain" sense): it imports nothing beyond its own
package (``correlation.contracts``, ``correlation.errors``) and the
standard library.

**Deterministic identity**, reusing G2.0's own SHA-256/collision-safe
convention unchanged (never a naive delimiter join — real ``step_id``/
``evidence_id`` values already contain ``"::"`` by this project's own
convention, so every free-text component is individually hashed before any
``"::"``-join, exactly like ``compute_link_id``/``compute_group_id``):
:func:`compute_step_id`, :func:`compute_sequence_id`,
:func:`compute_sequence_edge_id`, :func:`compute_sequence_gap_id`,
:func:`compute_sequence_parallel_group_id`.

**No attribution, no ATT&CK actor knowledge, no scoring, no
``TEMPORAL_PROXIMITY``.** :data:`OrderingBasisKind` is a closed, two-value
enum (``PROCESS_LINEAGE``, ``TEMPORAL_SAME_ENTITY``) — the exact two
ordering bases ADR-0004 D5 sanctions, no third "inferred" tier.
``TEMPORAL_PROXIMITY`` is explicitly a later, separate G2.4.3 concern
(ADR-0004 D20) and appears nowhere in this module. No field on any contract
here is a likelihood, confidence, weight, score, candidate, actor, or
campaign — ADR-0004 D15/D17 forbid all of that in this layer, enforced by a
guard test mirroring the same discipline already applied to
``correlation/contracts.py`` itself.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from enum import Enum

from attribution_platform.correlation.contracts import CorrelationGroup, CorrelationProvenance
from attribution_platform.correlation.errors import CorrelationError

#: Version of each new G2.4.0 contract's own schema, mirroring G2.0's
#: ``"<slug>/<version>"`` convention exactly.
BEHAVIORAL_STEP_SCHEMA_VERSION = "behavioral-step/1"
SEQUENCE_EDGE_SCHEMA_VERSION = "sequence-edge/1"
SEQUENCE_GAP_SCHEMA_VERSION = "sequence-gap/1"
SEQUENCE_PARALLEL_GROUP_SCHEMA_VERSION = "sequence-parallel-group/1"
BEHAVIORAL_SEQUENCE_SCHEMA_VERSION = "behavioral-sequence/1"


def _require_nonempty_str(value: object, field_name: str) -> str:
    """Local copy of the correlation-layer non-empty-string check (raises
    ``CorrelationError``) — deliberately duplicated rather than imported
    from ``contracts.py``'s private helper, matching this project's own
    established convention of each layer owning its own local validation
    (e.g. ``structural.py``/``contextual.py``'s duplicated ``_validate_nodes``)."""
    if not isinstance(value, str) or not value.strip():
        raise CorrelationError(
            f"{field_name} must be a non-empty, non-whitespace string, got {value!r}"
        )
    return value


def _sha256_hex(value: str) -> str:
    """SHA-256 hex digest of one caller-supplied, free-text identity
    component — local copy of G2.0's own helper (see
    ``contracts._sha256_hex``'s docstring for the exact delimiter-collision
    rationale this exists to avoid; unchanged here)."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class OrderingBasisKind(Enum):
    """The closed, two-value set of ordering bases ADR-0004 D5 sanctions —
    exactly ``PROCESS_LINEAGE`` and ``TEMPORAL_SAME_ENTITY``, no third
    "inferred" tier. ``TEMPORAL_PROXIMITY`` is never a member of this enum:
    it is a contextual dimension (G2.4.3, ADR-0004 D20) that can never
    ground a :class:`SequenceEdge`."""

    PROCESS_LINEAGE = "process_lineage"
    TEMPORAL_SAME_ENTITY = "temporal_same_entity"


class GapReason(Enum):
    """The closed, three-value set of reasons a :class:`SequenceGap` may
    cite (ADR-0004 D6/D11). ``MISSING_TIMESTAMP`` is defined for
    forward-compatibility only — ``Observation.timestamp`` is a required
    field in the current domain contract, so this value is unreachable by
    any real fixture today; it is kept, not removed, exactly as ADR-0004 D6
    itself documents."""

    EQUAL_TIMESTAMPS = "equal_timestamps"
    COARSE_PRECISION_TIE = "coarse_precision_tie"
    MISSING_TIMESTAMP = "missing_timestamp"


@dataclass(frozen=True)
class OrderingBasis:
    """The machine-readable explanation for one :class:`SequenceEdge`
    (ADR-0004's Domain Model section) — a value object with no independent
    identity, mirroring :class:`~attribution_platform.correlation.contracts.CorrelationBasis`'s
    role for ``CorrelationLink``.

    - ``basis_kind``: which of the two ADR-0004 D5 ordering bases this is.
    - ``grounding_link_id``: the real, structural ``CorrelationLink`` id
      this edge's order claim is grounded in — never absent.
    - ``timestamp_agreement``: for a ``PROCESS_LINEAGE`` edge, whether the
      two steps' observed timestamps agree with the lineage-asserted
      direction (ADR-0004 D7) — ``None`` only where no comparison applies.
      A disagreement is recorded, never used to reverse or drop the edge.
    - ``precision_uncertain``: ``True`` when a real timestamp inequality was
      used to order two steps but one side's precision was unknown
      (ADR-0004 D6) — surfaced as a caveat, never silently dropped.
    """

    basis_kind: OrderingBasisKind
    grounding_link_id: str
    timestamp_agreement: bool | None = None
    precision_uncertain: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.basis_kind, OrderingBasisKind):
            raise CorrelationError(
                f"OrderingBasis.basis_kind must be an OrderingBasisKind, "
                f"got {type(self.basis_kind).__name__}"
            )
        _require_nonempty_str(self.grounding_link_id, "OrderingBasis.grounding_link_id")


@dataclass(frozen=True)
class BehavioralStep:
    """One behavioral moment within a :class:`BehavioralSequence` — a new,
    reference-only derived object. **Not** an
    :class:`~attribution_platform.domain.observation.Observation`, **not**
    an :class:`~attribution_platform.domain.evidence.Evidence`, **not** a
    ``DetectionResult``, and copies no raw telemetry (ADR-0004 D2).

    - ``step_id``: deterministic, composed via :func:`compute_step_id`.
    - ``group_id``: the one originating
      :class:`~attribution_platform.correlation.contracts.CorrelationGroup`
      this step belongs to (ADR-0004 D1) — verified against the real group
      only by :func:`build_behavioral_step`, not by this constructor alone.
    - ``evidence_ids``: non-empty, canonicalized sorted-unique — exactly one
      entry for most steps, more than one only for a ``SHARED_OBSERVATION``-
      collapsed step (ADR-0004 D4; the collapse itself is G2.4.1's job).
    - ``observation_id``: the single Observation id every entry in
      ``evidence_ids`` is claimed to be grounded in.
    - ``technique_stix_ids``: optional, canonicalized sorted-unique —
      **mechanically-derived convenience data only**, never an independent
      source of truth. This contract does not itself derive these ids from
      any real ``Evidence.attack_ref`` (that derivation is G2.4.1's job,
      exactly as this module never imports ``domain`` at all); it only
      validates the *shape* of whatever the caller supplies. ``Evidence``
      remains the sole authority for any technique mapping.
    - ``contextual_annotations``: optional, canonicalized sorted-unique —
      the subset of the originating group's own ``contextual_link_ids``
      that touch this step (ADR-0004 D10). Purely informational: nothing in
      this module, and nothing in any future G2.4 engine, may read this
      field as an ordering input.
    """

    step_id: str
    group_id: str
    evidence_ids: tuple[str, ...]
    observation_id: str
    technique_stix_ids: tuple[str, ...] = ()
    contextual_annotations: tuple[str, ...] = ()
    schema_version: str = field(default=BEHAVIORAL_STEP_SCHEMA_VERSION)

    def __post_init__(self) -> None:
        _require_nonempty_str(self.step_id, "BehavioralStep.step_id")
        _require_nonempty_str(self.group_id, "BehavioralStep.group_id")

        if not self.evidence_ids:
            raise CorrelationError("BehavioralStep.evidence_ids must be non-empty")
        for eid in self.evidence_ids:
            _require_nonempty_str(eid, "BehavioralStep.evidence_ids[]")
        object.__setattr__(self, "evidence_ids", tuple(sorted(set(self.evidence_ids))))

        _require_nonempty_str(self.observation_id, "BehavioralStep.observation_id")

        for stix_id in self.technique_stix_ids:
            _require_nonempty_str(stix_id, "BehavioralStep.technique_stix_ids[]")
        object.__setattr__(self, "technique_stix_ids", tuple(sorted(set(self.technique_stix_ids))))

        for annotation_id in self.contextual_annotations:
            _require_nonempty_str(annotation_id, "BehavioralStep.contextual_annotations[]")
        object.__setattr__(
            self, "contextual_annotations", tuple(sorted(set(self.contextual_annotations)))
        )

        _require_nonempty_str(self.schema_version, "BehavioralStep.schema_version")


def build_behavioral_step(
    *,
    step_id: str,
    group: CorrelationGroup,
    evidence_ids: Iterable[str],
    observation_id: str,
    contextual_annotations: Iterable[str] = (),
    schema_version: str = BEHAVIORAL_STEP_SCHEMA_VERSION,
) -> BehavioralStep:
    """The one sanctioned way to construct a :class:`BehavioralStep` that
    can actually *enforce* "this step truly belongs to ``group``" — the
    same division of responsibility
    :func:`~attribution_platform.correlation.contracts.build_correlation_group`
    already establishes for ``CorrelationGroup`` itself.

    Validates, against the real ``group``: every id in ``evidence_ids`` is a
    member of ``group.member_evidence_ids``, and ``observation_id`` is a
    member of ``group.member_observation_ids``. Performs no graph
    algorithm and reaches into no raw ``Evidence``/``Observation`` object —
    the deeper grounding check (each evidence's real
    ``provenance.source_observation_ids == (observation_id,)``) is G2.4.1's
    responsibility, not this contract layer's (see this module's own
    docstring for why).

    **Deliberately accepts no ``technique_stix_ids`` parameter.** Unlike
    ``evidence_ids``/``observation_id``, this function has no way to verify
    a caller-supplied technique id actually traces back to this step's own
    Evidence (that requires the real ``Evidence.attack_ref`` values, which
    this contract layer never reaches into — see the module docstring). A
    sanctioned builder that silently accepted and passed through an
    unenforced value here would misrepresent the strength of its own
    guarantee: every other parameter this function accepts is genuinely
    checked against ``group``; ``technique_stix_ids`` could not be. G2.4.1
    (the engine, once it has real Evidence objects) is expected to derive
    ``technique_stix_ids`` mechanically and construct the step directly via
    the plain :class:`BehavioralStep` constructor, which still validates
    its *shape* (non-empty, canonicalized) but — exactly as honestly
    documented there — asserts no derivation guarantee of its own either;
    the engine, not this contract layer, is what actually earns that
    guarantee, by deriving the value correctly in the first place.
    """
    if not isinstance(group, CorrelationGroup):
        raise CorrelationError(
            f"build_behavioral_step: group must be a CorrelationGroup, "
            f"got {type(group).__name__}"
        )
    canonical_evidence_ids = tuple(sorted(set(evidence_ids)))
    if not canonical_evidence_ids:
        raise CorrelationError("build_behavioral_step: evidence_ids must be non-empty")
    for eid in canonical_evidence_ids:
        if eid not in group.member_evidence_ids:
            raise CorrelationError(
                f"build_behavioral_step: evidence {eid!r} is not a member of "
                f"CorrelationGroup {group.group_id!r}"
            )
    if observation_id not in group.member_observation_ids:
        raise CorrelationError(
            f"build_behavioral_step: observation {observation_id!r} is not a member of "
            f"CorrelationGroup {group.group_id!r}"
        )
    return BehavioralStep(
        step_id=step_id,
        group_id=group.group_id,
        evidence_ids=canonical_evidence_ids,
        observation_id=observation_id,
        contextual_annotations=tuple(contextual_annotations),
        schema_version=schema_version,
    )


@dataclass(frozen=True)
class SequenceEdge:
    """A directed, **resolved-order** relation between two
    :class:`BehavioralStep`\\ s (ADR-0004 D5–D9). ``from_step_id``/
    ``to_step_id`` are **not** canonicalized — unlike
    :class:`~attribution_platform.correlation.contracts.CorrelationLink`'s
    symmetric anchors, direction *is* the fact this object asserts
    (ADR-0004 D13).

    - ``edge_id``: deterministic, composed via :func:`compute_sequence_edge_id`.
    - ``basis``: the :class:`OrderingBasis` — which of the two sanctioned
      ordering bases this edge rests on, and its grounding link.
    """

    edge_id: str
    from_step_id: str
    to_step_id: str
    basis: OrderingBasis
    schema_version: str = field(default=SEQUENCE_EDGE_SCHEMA_VERSION)

    def __post_init__(self) -> None:
        _require_nonempty_str(self.edge_id, "SequenceEdge.edge_id")
        _require_nonempty_str(self.from_step_id, "SequenceEdge.from_step_id")
        _require_nonempty_str(self.to_step_id, "SequenceEdge.to_step_id")
        if self.from_step_id == self.to_step_id:
            raise CorrelationError(
                f"SequenceEdge.from_step_id and to_step_id must be distinct, "
                f"both were {self.from_step_id!r}"
            )
        if not isinstance(self.basis, OrderingBasis):
            raise CorrelationError(
                f"SequenceEdge.basis must be an OrderingBasis, got {type(self.basis).__name__}"
            )
        _require_nonempty_str(self.schema_version, "SequenceEdge.schema_version")


@dataclass(frozen=True)
class SequenceGap:
    """An undirected relation meaning exactly: **a direct structural
    relationship exists between these two steps, but its relative order
    cannot be honestly resolved** (ADR-0004 D11). Never used for unrelated
    steps, contextual relationships, or inferred-without-grounding gaps —
    ``grounding_link_id`` is always required and always a real structural
    link (verified against the real group only by
    :func:`build_behavioral_sequence`, not by this constructor alone).

    ``step_id_a``/``step_id_b`` **are** canonicalized to sorted order
    (unlike :class:`SequenceEdge`) — a gap asserts no direction, mirroring
    :class:`~attribution_platform.correlation.contracts.CorrelationLink`'s
    own symmetric ``anchor_a``/``anchor_b``.
    """

    gap_id: str
    step_id_a: str
    step_id_b: str
    grounding_link_id: str
    reason: GapReason
    schema_version: str = field(default=SEQUENCE_GAP_SCHEMA_VERSION)

    def __post_init__(self) -> None:
        _require_nonempty_str(self.gap_id, "SequenceGap.gap_id")
        _require_nonempty_str(self.step_id_a, "SequenceGap.step_id_a")
        _require_nonempty_str(self.step_id_b, "SequenceGap.step_id_b")
        if self.step_id_a == self.step_id_b:
            raise CorrelationError(
                f"SequenceGap.step_id_a and step_id_b must be distinct, "
                f"both were {self.step_id_a!r}"
            )
        canonical_a, canonical_b = sorted((self.step_id_a, self.step_id_b))
        object.__setattr__(self, "step_id_a", canonical_a)
        object.__setattr__(self, "step_id_b", canonical_b)

        _require_nonempty_str(self.grounding_link_id, "SequenceGap.grounding_link_id")
        if not isinstance(self.reason, GapReason):
            raise CorrelationError(
                f"SequenceGap.reason must be a GapReason, got {type(self.reason).__name__}"
            )
        _require_nonempty_str(self.schema_version, "SequenceGap.schema_version")


@dataclass(frozen=True)
class SequenceParallelGroup:
    """The explicit, compact **branch-partition** representation of
    cross-branch parallelism ADR-0004 D9 requires — the final, accepted
    design (never the earlier immediate-children-only draft; see ADR-0004's
    own Alternatives-considered section for why that was rejected).

    - ``source_step_id``: the shared ``PROCESS_LINEAGE`` branch point.
    - ``branches``: at least two branches; each inner tuple is one branch's
      *exclusive* descendant step ids, **root-first** — ``branches[i][0]``
      is that branch's root, the direct ``PROCESS_LINEAGE`` child of
      ``source_step_id``. This *is* enforced, at the ``BehavioralSequence``
      level (not by this class alone, which has no access to the sibling
      ``edges`` collection): a real ``SequenceEdge`` with
      ``from_step_id == source_step_id`` and ``to_step_id == branches[i][0]``
      must exist for every branch, or construction fails. Deeper members
      (``branches[i][1:]``) are **not** required to have their own direct
      edge from ``source_step_id`` — they remain grounded transitively
      through their own chain of ``SequenceEdge``\\ s, which
      ``BehavioralSequence`` already separately validates. Any two steps
      drawn from *different* branch tuples of one group are explicitly
      parallel/unordered; two steps in the *same* branch retain whatever
      real ``SequenceEdge``/``SequenceGap`` already connects them
      elsewhere.

    **Semantics, not a per-pair marker.** This object asserts no order, no
    causal relationship, and no group membership of its own — it exists
    purely to make "no established order" an explicit, addressable,
    persisted fact (ADR-0004's own audited requirement) rather than a
    silent absence, without materializing every mutually-unreachable step
    pair (`O(n²)`, explicitly rejected).

    **Convergence safety.** A step reachable from more than one of
    ``source_step_id``'s children (a data-quality anomaly G2.1 does not
    forbid) must never appear in more than one branch tuple of the *same*
    group — enforced below — so it is never falsely claimed parallel to
    either branch's members. This is a safety exclusion, not a convergence
    *feature*: this object still asserts nothing about how such a step
    relates to the branches that feed it.
    """

    parallel_group_id: str
    source_step_id: str
    branches: tuple[tuple[str, ...], ...]
    schema_version: str = field(default=SEQUENCE_PARALLEL_GROUP_SCHEMA_VERSION)

    def __post_init__(self) -> None:
        _require_nonempty_str(self.parallel_group_id, "SequenceParallelGroup.parallel_group_id")
        _require_nonempty_str(self.source_step_id, "SequenceParallelGroup.source_step_id")

        if len(self.branches) < 2:
            raise CorrelationError(
                "SequenceParallelGroup.branches must contain at least two branches"
            )

        seen: set[str] = set()
        for index, branch in enumerate(self.branches):
            if not branch:
                raise CorrelationError(f"SequenceParallelGroup.branches[{index}] must be non-empty")
            for step_id in branch:
                _require_nonempty_str(step_id, f"SequenceParallelGroup.branches[{index}][]")
            if len(set(branch)) != len(branch):
                raise CorrelationError(
                    f"SequenceParallelGroup.branches[{index}] contains a duplicate step id"
                )
            overlap = seen & set(branch)
            if overlap:
                raise CorrelationError(
                    f"SequenceParallelGroup: step id(s) {sorted(overlap)!r} appear in more than "
                    "one branch -- a step may belong to at most one branch of a given group "
                    "(convergence-safety exclusion, ADR-0004 D9)"
                )
            seen |= set(branch)

        _require_nonempty_str(self.schema_version, "SequenceParallelGroup.schema_version")


@dataclass(frozen=True)
class BehavioralSequence:
    """An ordered DAG view over one
    :class:`~attribution_platform.correlation.contracts.CorrelationGroup`'s
    members — strictly 1:1 with that group (ADR-0004 D1). The authoritative
    structure is the explicit-edge-list DAG ADR-0004 D3 requires:
    ``steps`` + ``edges`` (directed, resolved order) + ``gaps`` (undirected,
    unresolved-but-linked) + ``parallel_groups`` (explicit cross-branch
    parallelism) — never a flat list, never a nested tree.

    Field order here deliberately differs from ADR-0004's own prose listing
    (which places ``provenance`` after ``parallel_groups``): Python dataclass
    field ordering requires every non-default field before any defaulted
    one, so ``provenance`` (required, no default) is declared before
    ``edges``/``gaps``/``parallel_groups`` (each optional, default ``()``)
    — the exact same reordering
    :class:`~attribution_platform.correlation.contracts.CorrelationGroup`
    already applies to its own ``provenance``/``contextual_link_ids`` pair.
    """

    sequence_id: str
    group_id: str
    steps: tuple[BehavioralStep, ...]
    provenance: CorrelationProvenance
    edges: tuple[SequenceEdge, ...] = ()
    gaps: tuple[SequenceGap, ...] = ()
    parallel_groups: tuple[SequenceParallelGroup, ...] = ()
    schema_version: str = field(default=BEHAVIORAL_SEQUENCE_SCHEMA_VERSION)

    def __post_init__(self) -> None:
        _require_nonempty_str(self.sequence_id, "BehavioralSequence.sequence_id")
        _require_nonempty_str(self.group_id, "BehavioralSequence.group_id")

        if not self.steps:
            raise CorrelationError("BehavioralSequence.steps must be non-empty")
        step_ids = [step.step_id for step in self.steps]
        if len(set(step_ids)) != len(step_ids):
            raise CorrelationError("BehavioralSequence.steps contains a duplicate step_id")
        step_id_set = set(step_ids)
        for step in self.steps:
            if not isinstance(step, BehavioralStep):
                raise CorrelationError(
                    f"BehavioralSequence.steps must contain BehavioralStep objects, "
                    f"got {type(step).__name__}"
                )
            if step.group_id != self.group_id:
                raise CorrelationError(
                    f"BehavioralSequence: step {step.step_id!r} belongs to group "
                    f"{step.group_id!r}, not this sequence's group {self.group_id!r}"
                )
        object.__setattr__(self, "steps", tuple(sorted(self.steps, key=lambda s: s.step_id)))

        edge_ids = [edge.edge_id for edge in self.edges]
        if len(set(edge_ids)) != len(edge_ids):
            raise CorrelationError("BehavioralSequence.edges contains a duplicate edge_id")
        edge_pairs: set[frozenset[str]] = set()
        directed_edges: set[tuple[str, str]] = set()
        for edge in self.edges:
            if not isinstance(edge, SequenceEdge):
                raise CorrelationError(
                    f"BehavioralSequence.edges must contain SequenceEdge objects, "
                    f"got {type(edge).__name__}"
                )
            if edge.from_step_id not in step_id_set:
                raise CorrelationError(
                    f"BehavioralSequence: SequenceEdge {edge.edge_id!r}.from_step_id "
                    f"{edge.from_step_id!r} is not a step in this sequence"
                )
            if edge.to_step_id not in step_id_set:
                raise CorrelationError(
                    f"BehavioralSequence: SequenceEdge {edge.edge_id!r}.to_step_id "
                    f"{edge.to_step_id!r} is not a step in this sequence"
                )
            edge_pairs.add(frozenset((edge.from_step_id, edge.to_step_id)))
            directed_edges.add((edge.from_step_id, edge.to_step_id))
        object.__setattr__(self, "edges", tuple(sorted(self.edges, key=lambda e: e.edge_id)))

        gap_ids = [gap.gap_id for gap in self.gaps]
        if len(set(gap_ids)) != len(gap_ids):
            raise CorrelationError("BehavioralSequence.gaps contains a duplicate gap_id")
        gap_pairs: set[frozenset[str]] = set()
        for gap in self.gaps:
            if not isinstance(gap, SequenceGap):
                raise CorrelationError(
                    f"BehavioralSequence.gaps must contain SequenceGap objects, "
                    f"got {type(gap).__name__}"
                )
            if gap.step_id_a not in step_id_set:
                raise CorrelationError(
                    f"BehavioralSequence: SequenceGap {gap.gap_id!r}.step_id_a "
                    f"{gap.step_id_a!r} is not a step in this sequence"
                )
            if gap.step_id_b not in step_id_set:
                raise CorrelationError(
                    f"BehavioralSequence: SequenceGap {gap.gap_id!r}.step_id_b "
                    f"{gap.step_id_b!r} is not a step in this sequence"
                )
            pair = frozenset((gap.step_id_a, gap.step_id_b))
            if pair in edge_pairs:
                raise CorrelationError(
                    f"BehavioralSequence: steps {sorted(pair)!r} have both a SequenceEdge and "
                    "a SequenceGap between them -- a step pair cannot be both ordered and "
                    "unresolved"
                )
            gap_pairs.add(pair)
        object.__setattr__(self, "gaps", tuple(sorted(self.gaps, key=lambda g: g.gap_id)))

        pg_ids = [pg.parallel_group_id for pg in self.parallel_groups]
        if len(set(pg_ids)) != len(pg_ids):
            raise CorrelationError(
                "BehavioralSequence.parallel_groups contains a duplicate parallel_group_id"
            )
        for parallel_group in self.parallel_groups:
            if not isinstance(parallel_group, SequenceParallelGroup):
                raise CorrelationError(
                    "BehavioralSequence.parallel_groups must contain SequenceParallelGroup "
                    f"objects, got {type(parallel_group).__name__}"
                )
            if parallel_group.source_step_id not in step_id_set:
                raise CorrelationError(
                    f"BehavioralSequence: SequenceParallelGroup "
                    f"{parallel_group.parallel_group_id!r}.source_step_id "
                    f"{parallel_group.source_step_id!r} is not a step in this sequence"
                )
            for branch in parallel_group.branches:
                for member in branch:
                    if member not in step_id_set:
                        raise CorrelationError(
                            f"BehavioralSequence: SequenceParallelGroup "
                            f"{parallel_group.parallel_group_id!r} names step {member!r}, "
                            "which is not a step in this sequence"
                        )
            # Grounding (ADR-0004 D9/D12): each branch's root (branches[i][0], by
            # convention) must be directly connected from source_step_id by a real
            # SequenceEdge -- otherwise "these branches are parallel" is an invented
            # relationship, not one inherited through the edge chain as ADR-0004
            # justifies omitting a separate grounding field on this object. Deeper
            # branch members are intentionally NOT required to have their own direct
            # edge from source_step_id -- they remain grounded transitively through
            # their own chain of SequenceEdges (already validated above), exactly as
            # ADR-0004 describes; this is not branch discovery, it is a single,
            # already-known-position lookup against the already-given edge set. Run
            # as its own pass, after every branch's members are confirmed to exist,
            # so a dangling-member error is never masked by a grounding error.
            for branch in parallel_group.branches:
                root = branch[0]
                if (parallel_group.source_step_id, root) not in directed_edges:
                    raise CorrelationError(
                        f"BehavioralSequence: SequenceParallelGroup "
                        f"{parallel_group.parallel_group_id!r} branch root {root!r} has no "
                        f"SequenceEdge from source_step_id {parallel_group.source_step_id!r} "
                        "-- a parallel-group branch must be grounded by a real edge, never "
                        "asserted without one"
                    )
            for i, branch_i in enumerate(parallel_group.branches):
                for branch_j in parallel_group.branches[i + 1 :]:
                    for member_i in branch_i:
                        for member_j in branch_j:
                            cross_pair = frozenset((member_i, member_j))
                            if cross_pair in edge_pairs or cross_pair in gap_pairs:
                                raise CorrelationError(
                                    "BehavioralSequence: SequenceParallelGroup "
                                    f"{parallel_group.parallel_group_id!r} claims steps "
                                    f"{sorted(cross_pair)!r} (in different branches) are "
                                    "parallel, but they are directly connected by an edge "
                                    "or gap"
                                )
        object.__setattr__(
            self,
            "parallel_groups",
            tuple(sorted(self.parallel_groups, key=lambda p: p.parallel_group_id)),
        )

        _require_acyclic(self.edges)

        if not isinstance(self.provenance, CorrelationProvenance):
            raise CorrelationError(
                f"BehavioralSequence.provenance must be a CorrelationProvenance, "
                f"got {type(self.provenance).__name__}"
            )
        _require_nonempty_str(self.schema_version, "BehavioralSequence.schema_version")


def _require_acyclic(edges: Sequence[SequenceEdge]) -> None:
    """Validate that ``edges`` forms an acyclic graph (ADR-0004 D14) — a
    small, standard cycle-detection pass over an *already fully specified*
    edge set, for validation only. This is not the ordering algorithm and
    derives nothing: it neither computes nor infers any edge, it only
    rejects a caller-supplied edge set that is internally inconsistent,
    exactly as the acyclicity check ADR-0004 D14 requires be enforced "at
    contract-validation level.\" """
    adjacency: dict[str, list[str]] = {}
    for edge in edges:
        adjacency.setdefault(edge.from_step_id, []).append(edge.to_step_id)

    WHITE, GRAY, BLACK = 0, 1, 2
    color: dict[str, int] = {}

    def visit(node: str) -> None:
        color[node] = GRAY
        for neighbor in adjacency.get(node, ()):
            state = color.get(neighbor, WHITE)
            if state == GRAY:
                raise CorrelationError(
                    "BehavioralSequence.edges forms a cycle -- the edge graph must be acyclic "
                    f"(ADR-0004 D14), a back-edge was found reaching {neighbor!r} again"
                )
            if state == WHITE:
                visit(neighbor)
        color[node] = BLACK

    for start_node in adjacency:
        if color.get(start_node, WHITE) == WHITE:
            visit(start_node)


def build_behavioral_sequence(
    *,
    sequence_id: str,
    group: CorrelationGroup,
    steps: Sequence[BehavioralStep],
    provenance: CorrelationProvenance,
    edges: Sequence[SequenceEdge] = (),
    gaps: Sequence[SequenceGap] = (),
    parallel_groups: Sequence[SequenceParallelGroup] = (),
    schema_version: str = BEHAVIORAL_SEQUENCE_SCHEMA_VERSION,
) -> BehavioralSequence:
    """The one sanctioned way to construct a :class:`BehavioralSequence`
    that can actually *enforce* "this sequence, and every edge/gap in it,
    is truly grounded in ``group``" — mirroring
    :func:`~attribution_platform.correlation.contracts.build_correlation_group`'s
    own re-verification role exactly.

    Beyond everything :class:`BehavioralSequence`'s own constructor already
    validates (internal consistency — see its ``__post_init__``), this
    additionally verifies: every step's ``group_id`` equals ``group.group_id``
    (redundant with the plain constructor's own check, restated here for a
    single entry point), and every edge's/gap's ``grounding_link_id`` is
    present in ``group.structural_link_ids`` — the exact ADR-0004 D12
    requirement that "no edge or gap is ever free-floating." Performs no
    graph algorithm of its own.
    """
    if not isinstance(group, CorrelationGroup):
        raise CorrelationError(
            f"build_behavioral_sequence: group must be a CorrelationGroup, "
            f"got {type(group).__name__}"
        )
    for edge in edges:
        if edge.basis.grounding_link_id not in group.structural_link_ids:
            raise CorrelationError(
                f"build_behavioral_sequence: SequenceEdge {edge.edge_id!r} "
                f"grounding_link_id {edge.basis.grounding_link_id!r} is not a structural "
                f"link of CorrelationGroup {group.group_id!r}"
            )
    for gap in gaps:
        if gap.grounding_link_id not in group.structural_link_ids:
            raise CorrelationError(
                f"build_behavioral_sequence: SequenceGap {gap.gap_id!r} grounding_link_id "
                f"{gap.grounding_link_id!r} is not a structural link of CorrelationGroup "
                f"{group.group_id!r}"
            )
    return BehavioralSequence(
        sequence_id=sequence_id,
        group_id=group.group_id,
        steps=tuple(steps),
        provenance=provenance,
        edges=tuple(edges),
        gaps=tuple(gaps),
        parallel_groups=tuple(parallel_groups),
        schema_version=schema_version,
    )


# ===========================================================================
# Deterministic identity helpers (pure string composition -- NOT sequence
# construction logic: no ordering, reachability, or branch-discovery
# happens here, only assembly of an id string from already-known values,
# exactly mirroring G2.0's own compute_link_id/compute_group_id).
# ===========================================================================


def compute_step_id(group_id: str, evidence_ids: Iterable[str]) -> str:
    """Deterministically compose a ``BehavioralStep.step_id`` from the
    owning group's id and the sorted, de-duplicated set of member evidence
    ids (ADR-0004 D13) — never a randomly generated id."""
    _require_nonempty_str(group_id, "compute_step_id(group_id=...)")
    canonical = sorted(set(evidence_ids))
    if not canonical:
        raise CorrelationError("compute_step_id: requires at least one evidence id")
    for eid in canonical:
        _require_nonempty_str(eid, "compute_step_id(evidence_ids=...)[]")
    parts = ["behavioral-step", _sha256_hex(group_id), *(_sha256_hex(eid) for eid in canonical)]
    return "::".join(parts)


def compute_sequence_id(
    group_id: str,
    step_ids: Iterable[str],
    *,
    method_content_hash: str | None = None,
) -> str:
    """Deterministically compose a ``BehavioralSequence.sequence_id`` from
    the owning group's id and the sorted, de-duplicated set of member step
    ids (ADR-0004 D13)."""
    _require_nonempty_str(group_id, "compute_sequence_id(group_id=...)")
    canonical = sorted(set(step_ids))
    if not canonical:
        raise CorrelationError("compute_sequence_id: requires at least one step id")
    for sid in canonical:
        _require_nonempty_str(sid, "compute_sequence_id(step_ids=...)[]")
    parts = [
        "behavioral-sequence",
        _sha256_hex(group_id),
        *(_sha256_hex(sid) for sid in canonical),
    ]
    if method_content_hash is not None:
        _require_nonempty_str(method_content_hash, "compute_sequence_id(method_content_hash=...)")
        parts.append(method_content_hash)
    return "::".join(parts)


def compute_sequence_edge_id(
    *,
    from_step_id: str,
    to_step_id: str,
    basis_kind: OrderingBasisKind,
    grounding_link_id: str,
) -> str:
    """Deterministically compose a ``SequenceEdge.edge_id``. **Not**
    canonicalized/sorted by endpoint — direction is the fact being
    identified (ADR-0004 D13): a hypothetical ``A->B`` and ``B->A`` must
    never collide, unlike ``CorrelationLink.anchor_a``/``anchor_b``'s
    deliberate symmetry."""
    _require_nonempty_str(from_step_id, "compute_sequence_edge_id(from_step_id=...)")
    _require_nonempty_str(to_step_id, "compute_sequence_edge_id(to_step_id=...)")
    if from_step_id == to_step_id:
        raise CorrelationError(
            "compute_sequence_edge_id: from_step_id and to_step_id must be distinct, "
            f"both were {from_step_id!r}"
        )
    if not isinstance(basis_kind, OrderingBasisKind):
        raise CorrelationError(
            f"compute_sequence_edge_id: basis_kind must be an OrderingBasisKind, "
            f"got {type(basis_kind).__name__}"
        )
    _require_nonempty_str(grounding_link_id, "compute_sequence_edge_id(grounding_link_id=...)")
    parts = [
        "sequence-edge",
        basis_kind.value,
        _sha256_hex(from_step_id),
        _sha256_hex(to_step_id),
        _sha256_hex(grounding_link_id),
    ]
    return "::".join(parts)


def compute_sequence_gap_id(
    *,
    step_id_a: str,
    step_id_b: str,
    reason: GapReason,
    grounding_link_id: str,
) -> str:
    """Deterministically compose a ``SequenceGap.gap_id``. Canonicalized
    (sorted) over the two endpoints — a gap is undirected (ADR-0004 D13),
    mirroring ``CorrelationLink.anchor_a``/``anchor_b`` exactly."""
    _require_nonempty_str(step_id_a, "compute_sequence_gap_id(step_id_a=...)")
    _require_nonempty_str(step_id_b, "compute_sequence_gap_id(step_id_b=...)")
    if step_id_a == step_id_b:
        raise CorrelationError(
            f"compute_sequence_gap_id: step_id_a and step_id_b must be distinct, "
            f"both were {step_id_a!r}"
        )
    if not isinstance(reason, GapReason):
        raise CorrelationError(
            f"compute_sequence_gap_id: reason must be a GapReason, got {type(reason).__name__}"
        )
    _require_nonempty_str(grounding_link_id, "compute_sequence_gap_id(grounding_link_id=...)")
    lo, hi = sorted((step_id_a, step_id_b))
    parts = [
        "sequence-gap",
        reason.value,
        _sha256_hex(lo),
        _sha256_hex(hi),
        _sha256_hex(grounding_link_id),
    ]
    return "::".join(parts)


def compute_sequence_parallel_group_id(
    source_step_id: str, branches: Iterable[Iterable[str]]
) -> str:
    """Deterministically compose a
    ``SequenceParallelGroup.parallel_group_id`` from the branch point's id
    and the sorted set of branch-membership sets (ADR-0004 D13). Every free-
    text component (``source_step_id``, every member step id) is
    individually SHA-256-hashed, and each branch's own joined-hash string is
    re-hashed into one fixed-length token before the final ``"::"`` join --
    never a raw delimiter-joined string of step ids. This matters
    concretely here, not just in principle: a real ``step_id`` (see
    :func:`compute_step_id`) already contains ``"::"`` itself, so joining
    raw step ids with any delimiter would risk exactly the collision class
    G2.0's own ``compute_link_id``/``compute_group_id`` already had to be
    hardened against. Branch order (which branch is listed first) and
    within-branch order do not affect the id -- only branch *membership*
    does, since swapping which branch is "first" carries no semantic
    meaning."""
    _require_nonempty_str(source_step_id, "compute_sequence_parallel_group_id(source_step_id=...)")

    canonical_branches: list[tuple[str, ...]] = []
    for branch in branches:
        branch_members = tuple(branch)
        if not branch_members:
            raise CorrelationError(
                "compute_sequence_parallel_group_id: every branch must be non-empty"
            )
        for step_id in branch_members:
            _require_nonempty_str(step_id, "compute_sequence_parallel_group_id(branches=...)[][]")
        canonical_branches.append(tuple(sorted(set(branch_members))))

    if len(canonical_branches) < 2:
        raise CorrelationError("compute_sequence_parallel_group_id: requires at least two branches")

    branch_tokens = sorted(
        _sha256_hex("::".join(_sha256_hex(member) for member in branch))
        for branch in canonical_branches
    )
    parts = ["sequence-parallel-group", _sha256_hex(source_step_id), *branch_tokens]
    return "::".join(parts)
