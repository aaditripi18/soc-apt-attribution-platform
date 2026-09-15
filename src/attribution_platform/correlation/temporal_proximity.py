"""The TEMPORAL_PROXIMITY contextual correlation dimension (gate G2.4.3,
ADR-0004 D20).

Implements exactly the one dimension ADR-0004 D20 reserved for this gate —
``TEMPORAL_PROXIMITY``: two Observations whose timestamps fall within a
versioned, content-hashed window of each other — and nothing else. This
module is a **sibling** of :mod:`attribution_platform.correlation.contextual`
(G2.2), never an extension of it: it imports nothing from that module and
``contextual.py`` is not modified by this gate. Its public entry point
takes an *already-computed*
:class:`~attribution_platform.correlation.structural.StructuralCorrelationResult`
and
:class:`~attribution_platform.correlation.contextual.ContextualCorrelationResult`
as input rather than raw Evidence/Observations — the same "structurally
impossible to accidentally treat a contextual link as group-forming" shape
``contextual.py`` already established for itself relative to ``structural.py``,
applied one layer further.

**What "temporal proximity" means, operationally, here:** two Observations'
``timestamp`` values, each truncated to the coarser of the two
``TimePrecision`` granularities (the identical convention ADR-0004 D6/
:mod:`attribution_platform.correlation.sequence_engine` already established
for ordering comparisons — reused for *tolerance*, not order, here), differ
by no more than a versioned, content-hashed ``window``. This is a fact about
*coincidence in time*, never about *instance identity* or *causation* — it
never substitutes for, and always may coexist with,
``LinkClass.SAME_PROCESS_ENTITY`` (which remains the only fact establishing
"same running process instance," unconditionally, regardless of any time
gap — ADR-0004 D19, unchanged).

**Symmetric by construction, not by choice.** Unlike ``PROCESS_LINEAGE``,
proximity in time has no direction: ``|t_a - t_b| <= window`` is symmetric
regardless of which Observation is ``a`` and which is ``b``. The
deterministic ``observation_id_a``/``observation_id_b`` ordering this module
assigns (lower-sorted node first, for id-composition determinism only) is
**never** an ordering claim — the identical caveat ADR-0004 D5 already
attaches to ``SAME_PROCESS_ENTITY``'s own basis-field order ("a sort
artifact, not chronology") applies here, word for word.

**Attachment, never group formation.** :func:`compute_temporal_proximity`
never builds a ``CorrelationGroup`` from nothing: it only ever takes the
groups already present on the given ``ContextualCorrelationResult`` and, for
each one, re-verifies it (via G2.0's own
:func:`~attribution_platform.correlation.contracts.build_correlation_group`)
with the **union** of its already-existing ``contextual_link_ids`` and
whichever new ``TEMPORAL_PROXIMITY`` links touch it — never a replacement.
A ``TEMPORAL_PROXIMITY`` link between two Evidence items in *different*
structural groups attaches to *both* groups independently, exactly
mirroring G2.2's own documented rule for the other five dimensions; it is
never interpreted as relating those groups, and it never merges them.
``group_id``/``member_evidence_ids``/``member_observation_ids``/
``structural_link_ids``/``provenance`` are always identical to the input —
only ``contextual_link_ids`` may grow.

**Versioned, content-hashed window.** :class:`TemporalProximityConfig`
mirrors :class:`attribution_platform.detection.rules.RulePack`'s own
``content_hash`` convention exactly (SHA-256 over a canonical
representation) — reused via the *existing*
``CorrelationProvenance.method_content_hash`` field, unchanged. No second
hashing scheme is introduced, and the caller cannot fabricate an arbitrary
hash: :func:`TemporalProximityConfig.__post_init__` computes it itself from
the config's own fields.

**Deterministic identity.** Every id here comes from G2.0's own
``compute_link_id`` (unchanged, collision-safe) — no second id scheme.

**Uncertainty is explicit, not numeric.** Every link's
``CorrelationBasis.uncertainty_note`` states, in fixed plain language, that
temporal proximity indicates coincidence only — never causality, ordering,
or attribution. No probability, confidence, weight, or numeric score is
ever attached (G2.0's own ``CorrelationBasis`` already makes this
structurally impossible).

**Multi-Observation Evidence.** Uses the exact same fail-closed
single-Observation pairing boundary G2.1/G2.2 established, reimplemented
locally here (this project's established convention of each layer owning
its own local validation rather than reaching into another module's
private helpers).

**Source-agnostic, ATT&CK-free.** Imports only
:mod:`attribution_platform.correlation` (its own package) and
:mod:`attribution_platform.domain` — never ``sources``, ``dataplane``,
``replay``, ``api``, or ``attack_knowledge`` (enforced by a guard test,
mirroring ``structural.py``/``contextual.py``'s own).

**Deliberately NOT here (forbidden this gate):** G2.1's structural matching
or G2.2's five existing contextual dimensions (neither imported nor
reimplemented); any ``SequenceEdge``/``SequenceGap``/``SequenceParallelGroup``
construction (G2.4.0/G2.4.1, both frozen and untouched by this module —
this module never imports :mod:`attribution_platform.correlation.sequence`
or :mod:`attribution_platform.correlation.sequence_engine`); ATT&CK of any
kind; Elastic/EQL; scoring, weighting, likelihood, confidence, ACH, or
attribution of any kind.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import timedelta

from attribution_platform.correlation.contextual import ContextualCorrelationResult
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
from attribution_platform.domain import Evidence, Observation, TimePrecision

#: Schema version of the TemporalProximityConfig contract (this module's own).
TEMPORAL_PROXIMITY_CONFIG_SCHEMA_VERSION = "temporal-proximity-config/1"

#: Default ``CorrelationProvenance.method``/``method_version`` this engine
#: stamps onto every TEMPORAL_PROXIMITY link it produces, unless the caller
#: overrides them. Mirrors ``structural.py``/``contextual.py``'s own
#: ``*_CORRELATION_METHOD`` convention.
TEMPORAL_PROXIMITY_METHOD = "temporal-proximity-correlation"
TEMPORAL_PROXIMITY_METHOD_VERSION = "1.0"

#: field_path recorded on every TEMPORAL_PROXIMITY CorrelationBasis.
_FIELD_PATH = "observation.timestamp"

#: Fixed, plain-language uncertainty note -- never numeric, never omitted.
_UNCERTAINTY_NOTE = (
    "temporal proximity indicates coincidence in time only; it does not establish "
    "causality, does not establish ordering, and does not establish attribution -- two "
    "observations within the configured window may be entirely unrelated"
)

#: The wall-clock granularity each declared ``TimePrecision`` represents,
#: used only to *truncate* two real timestamps to their common (coarser)
#: granularity before the window comparison (ADR-0004 D6's own convention,
#: reused here for tolerance rather than order) -- never to alter a stored
#: value. ``NANOSECOND`` is mapped to the same granularity as
#: ``MICROSECOND`` because Python's ``datetime`` has no finer resolution;
#: this is a stdlib limitation, not a new semantic invented here. A local
#: copy, not an import of ``sequence_engine.py``'s private table -- this
#: module must not import ``sequence_engine`` at all (see module docstring).
_PRECISION_GRANULARITY: dict[TimePrecision, timedelta] = {
    TimePrecision.SECOND: timedelta(seconds=1),
    TimePrecision.MILLISECOND: timedelta(milliseconds=1),
    TimePrecision.MICROSECOND: timedelta(microseconds=1),
    TimePrecision.NANOSECOND: timedelta(microseconds=1),
}


def _require_nonempty_str(value: object, field_name: str) -> str:
    """Local copy of the correlation-layer non-empty-string check -- each
    layer owns its own, matching this project's established convention."""
    if not isinstance(value, str) or not value.strip():
        raise CorrelationError(
            f"{field_name} must be a non-empty, non-whitespace string, got {value!r}"
        )
    return value


def _sha256_hex(value: str) -> str:
    """SHA-256 hex digest of one caller-supplied, free-text identity
    component -- local copy of G2.0's own helper (never Python's ``hash()``,
    never a random UUID, never wall-clock-derived)."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class TemporalProximityConfig:
    """The versioned, content-hashed TEMPORAL_PROXIMITY window
    configuration (ADR-0003 D4: "any temporal window is external, versioned
    configuration, hashed exactly like a G1.0 rule pack" -- never a literal
    threshold in engine code).

    - ``window``: a ``timedelta``, so the unit is unambiguous by
      construction (never a bare, unit-less number). Must be non-negative;
      a negative window is nonsensical and is rejected here, fail-closed,
      at construction/load time -- never silently clamped to zero.
      ``timedelta(0)`` is valid and well-defined: it matches only Observation
      pairs whose truncated timestamps are exactly equal.
    - ``schema_version``: this contract's own schema identity.
    - ``content_hash``: **computed here, from the config's own fields** --
      never accepted as a caller-supplied value, so a caller cannot
      fabricate an arbitrary hash that does not actually describe this
      config. Reuses the existing SHA-256/hex-digest convention this
      project already uses everywhere else (:func:`_sha256_hex`) -- no
      second, incompatible hashing scheme.
    """

    window: timedelta
    schema_version: str = field(default=TEMPORAL_PROXIMITY_CONFIG_SCHEMA_VERSION)
    content_hash: str = field(init=False)

    def __post_init__(self) -> None:
        if not isinstance(self.window, timedelta):
            raise CorrelationError(
                f"TemporalProximityConfig.window must be a timedelta, "
                f"got {type(self.window).__name__}"
            )
        if self.window < timedelta(0):
            raise CorrelationError(
                f"TemporalProximityConfig.window must be non-negative, got {self.window!r}"
            )
        _require_nonempty_str(self.schema_version, "TemporalProximityConfig.schema_version")
        canonical = f"{self.schema_version}::{self.window.total_seconds()!r}"
        object.__setattr__(self, "content_hash", _sha256_hex(canonical))


@dataclass(frozen=True)
class TemporalProximityResult:
    """What :func:`compute_temporal_proximity` produced: every
    ``TEMPORAL_PROXIMITY`` link found (including any that touch no
    structural group at all), and the *same* groups the input
    ``ContextualCorrelationResult`` had, now carrying the union of their
    existing ``contextual_link_ids`` plus any newly-touching
    ``TEMPORAL_PROXIMITY`` link ids. Group identity, membership, structural
    links, and provenance are otherwise byte-for-byte unchanged from the
    input."""

    temporal_proximity_links: tuple[CorrelationLink, ...]
    groups: tuple[CorrelationGroup, ...]


@dataclass(frozen=True)
class _Node:
    """One (Evidence, its supporting Observation) pair, validated at input.
    Deliberately a local, private re-declaration of the identical shape
    ``structural.py``/``contextual.py`` each already duplicate -- see the
    module docstring for why this is duplicated rather than imported."""

    evidence: Evidence
    observation: Observation


def _validate_nodes(items: Sequence[tuple[Evidence, Observation]]) -> tuple[_Node, ...]:
    """The exact same fail-closed Evidence/Observation pairing boundary
    G2.1/G2.2 established: the Observation must be the Evidence's *sole*
    source Observation, and evidence ids must be unique across ``items``."""
    seen_evidence_ids: set[str] = set()
    nodes: list[_Node] = []
    for i, (evidence, observation) in enumerate(items):
        if not isinstance(evidence, Evidence):
            raise CorrelationError(
                f"compute_temporal_proximity: items[{i}][0] must be a domain Evidence, "
                f"got {type(evidence).__name__}"
            )
        if not isinstance(observation, Observation):
            raise CorrelationError(
                f"compute_temporal_proximity: items[{i}][1] must be a domain Observation, "
                f"got {type(observation).__name__}"
            )
        if evidence.provenance.source_observation_ids != (observation.observation_id,):
            raise CorrelationError(
                f"compute_temporal_proximity: items[{i}]: evidence {evidence.evidence_id!r} "
                f"does not have exactly the supplied observation "
                f"{observation.observation_id!r} as its sole source (source_observation_ids="
                f"{evidence.provenance.source_observation_ids!r}). G2.4.3 requires "
                f"single-Observation Evidence, matching G2.1/G2.2's own scope."
            )
        if evidence.evidence_id in seen_evidence_ids:
            raise CorrelationError(
                f"compute_temporal_proximity: duplicate evidence_id "
                f"{evidence.evidence_id!r} in items"
            )
        seen_evidence_ids.add(evidence.evidence_id)
        nodes.append(_Node(evidence=evidence, observation=observation))
    return tuple(nodes)


def _truncate_to_common_granularity(node_a: _Node, node_b: _Node) -> tuple[float, float] | None:
    """Truncate both Observations' timestamps to the coarser of their two
    declared ``TimePrecision`` granularities (ADR-0004 D6's own convention,
    reused for window tolerance rather than order), returning each as
    epoch-relative seconds for a simple, deterministic comparison. Returns
    ``None`` if either side's precision is absent/``UNKNOWN`` -- in that
    case the raw (untruncated) timestamps are compared instead, exactly
    mirroring ``sequence_engine.py``'s own "unknown precision -> compare
    raw values" rule for ordering, applied here to windowing."""
    prec_a = node_a.observation.timestamp_precision
    prec_b = node_b.observation.timestamp_precision
    if (
        prec_a is None
        or prec_b is None
        or prec_a is TimePrecision.UNKNOWN
        or prec_b is TimePrecision.UNKNOWN
    ):
        return None
    granularity = max(_PRECISION_GRANULARITY[prec_a], _PRECISION_GRANULARITY[prec_b])
    granularity_seconds = granularity.total_seconds()
    ts_a = node_a.observation.timestamp.timestamp()
    ts_b = node_b.observation.timestamp.timestamp()
    truncated_a = (ts_a // granularity_seconds) * granularity_seconds
    truncated_b = (ts_b // granularity_seconds) * granularity_seconds
    return truncated_a, truncated_b


def _within_window(node_a: _Node, node_b: _Node, config: TemporalProximityConfig) -> bool:
    """``True`` iff the two Observations' (precision-truncated where
    possible) timestamps differ by no more than ``config.window``,
    inclusive (``elapsed_time <= configured_window``)."""
    truncated = _truncate_to_common_granularity(node_a, node_b)
    if truncated is not None:
        ts_a, ts_b = truncated
    else:
        ts_a = node_a.observation.timestamp.timestamp()
        ts_b = node_b.observation.timestamp.timestamp()
    elapsed = abs(ts_a - ts_b)
    return elapsed <= config.window.total_seconds()


def _raw_elapsed_seconds(node_a: _Node, node_b: _Node) -> float:
    """The RAW (never truncated) elapsed delta between the two
    Observations' timestamps -- what is actually reported in
    ``CorrelationBasis.observed_value``. Truncation is a match-tolerance
    mechanism for the window comparison only; the reported fact must be the
    honest, un-distorted observed delta."""
    ts_a = node_a.observation.timestamp.timestamp()
    ts_b = node_b.observation.timestamp.timestamp()
    return abs(ts_a - ts_b)


def _make_temporal_proximity_link(
    node_a: _Node,
    node_b: _Node,
    *,
    method: str,
    method_version: str,
    method_content_hash: str,
) -> CorrelationLink:
    # Deterministic endpoint ordering (lower evidence_id first) -- an
    # id-composition artifact only, exactly like SAME_PROCESS_ENTITY's own
    # basis-field order (ADR-0004 D5). NEVER an ordering/chronology claim.
    ordered_a, ordered_b = sorted((node_a, node_b), key=lambda n: n.evidence.evidence_id)
    observed_value = repr(_raw_elapsed_seconds(ordered_a, ordered_b))
    link_id = compute_link_id(
        link_class=LinkClass.TEMPORAL_PROXIMITY,
        observed_value=observed_value,
        anchor_a=ordered_a.evidence.evidence_id,
        anchor_b=ordered_b.evidence.evidence_id,
        method_content_hash=method_content_hash,
    )
    basis = CorrelationBasis(
        link_class=LinkClass.TEMPORAL_PROXIMITY,
        field_path=_FIELD_PATH,
        observed_value=observed_value,
        observation_id_a=ordered_a.observation.observation_id,
        observation_id_b=ordered_b.observation.observation_id,
        uncertainty_note=_UNCERTAINTY_NOTE,
    )
    source_observation_ids = tuple(
        {ordered_a.observation.observation_id, ordered_b.observation.observation_id}
    )
    provenance = CorrelationProvenance(
        method=method,
        method_version=method_version,
        source_evidence_ids=(ordered_a.evidence.evidence_id, ordered_b.evidence.evidence_id),
        source_observation_ids=source_observation_ids,
        method_content_hash=method_content_hash,
    )
    return CorrelationLink(
        link_id=link_id,
        anchor_a=ordered_a.evidence.evidence_id,
        anchor_b=ordered_b.evidence.evidence_id,
        link_class=LinkClass.TEMPORAL_PROXIMITY,
        basis=basis,
        provenance=provenance,
    )


def compute_temporal_proximity(
    structural_result: StructuralCorrelationResult,
    contextual_result: ContextualCorrelationResult,
    items: Sequence[tuple[Evidence, Observation]],
    config: TemporalProximityConfig,
    *,
    method: str = TEMPORAL_PROXIMITY_METHOD,
    method_version: str = TEMPORAL_PROXIMITY_METHOD_VERSION,
) -> TemporalProximityResult:
    """Compute every ``TEMPORAL_PROXIMITY`` link across ``items`` (pairwise,
    symmetric, ``elapsed_time <= config.window``, inclusive), and attach
    each one to every *existing* group in ``contextual_result.groups`` that
    has at least one member the link touches.

    This function never forms, merges, or creates a ``CorrelationGroup``.
    It takes ``contextual_result.groups`` as fixed input and returns the
    same groups, each carrying the **union** of its existing
    ``contextual_link_ids`` and any newly-touching ``TEMPORAL_PROXIMITY``
    link ids -- never a replacement of the existing set.
    ``group_id``/``member_evidence_ids``/``member_observation_ids``/
    ``structural_link_ids``/``provenance`` are always identical to the
    input. A ``TEMPORAL_PROXIMITY`` link between two Evidence items in two
    *different* structural groups is attached to *both* independently -- it
    never relates the groups to each other, and two groups sharing a
    temporal-proximity link are never merged.

    ``structural_result`` supplies the real structural ``CorrelationLink``
    objects needed to re-verify each group's own ``structural_link_ids``
    through :func:`~attribution_platform.correlation.contracts.build_correlation_group`
    (defense in depth, unchanged from G2.2's own usage of it) -- this
    function never constructs a structural link itself.

    Pure and deterministic: no I/O, no ATT&CK knowledge, no randomness, no
    wall-clock. ``O(n^2)`` pairwise -- the minimum correct algorithm for
    this gate, not a graph framework, mirroring G2.1's own stated
    precedent.
    """
    if not isinstance(structural_result, StructuralCorrelationResult):
        raise CorrelationError(
            f"compute_temporal_proximity: structural_result must be a "
            f"StructuralCorrelationResult, got {type(structural_result).__name__}"
        )
    if not isinstance(contextual_result, ContextualCorrelationResult):
        raise CorrelationError(
            f"compute_temporal_proximity: contextual_result must be a "
            f"ContextualCorrelationResult, got {type(contextual_result).__name__}"
        )
    if not isinstance(config, TemporalProximityConfig):
        raise CorrelationError(
            f"compute_temporal_proximity: config must be a TemporalProximityConfig, "
            f"got {type(config).__name__}"
        )

    nodes = _validate_nodes(items)
    ordered_nodes = sorted(nodes, key=lambda n: n.evidence.evidence_id)

    links: dict[str, CorrelationLink] = {}
    for i, node_a in enumerate(ordered_nodes):
        for node_b in ordered_nodes[i + 1 :]:
            if not _within_window(node_a, node_b, config):
                continue
            link = _make_temporal_proximity_link(
                node_a,
                node_b,
                method=method,
                method_version=method_version,
                method_content_hash=config.content_hash,
            )
            links[link.link_id] = link
    sorted_links = tuple(sorted(links.values(), key=lambda link_: link_.link_id))

    contextual_links_by_id = {link.link_id: link for link in contextual_result.contextual_links}
    structural_links_by_id = {link.link_id: link for link in structural_result.links}

    updated_groups: list[CorrelationGroup] = []
    for group in contextual_result.groups:
        member_ids = set(group.member_evidence_ids)
        touching = tuple(
            link
            for link in sorted_links
            if link.anchor_a in member_ids or link.anchor_b in member_ids
        )
        if not touching:
            updated_groups.append(group)
            continue

        existing_contextual_links = tuple(
            contextual_links_by_id[link_id] for link_id in group.contextual_link_ids
        )
        combined_contextual_links_by_id = {
            link.link_id: link for link in (*existing_contextual_links, *touching)
        }
        combined_contextual_links = tuple(
            sorted(combined_contextual_links_by_id.values(), key=lambda link_: link_.link_id)
        )
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
                contextual_links=combined_contextual_links,
            )
        )

    sorted_groups = tuple(sorted(updated_groups, key=lambda group_: group_.group_id))
    return TemporalProximityResult(temporal_proximity_links=sorted_links, groups=sorted_groups)
