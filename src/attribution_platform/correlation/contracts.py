"""Correlation domain contracts (gate G2.0): the immutable shapes defined by
`ADR-0003 <../../../docs/architecture/adr/0003-correlation-and-behavioral-chain-layer.md>`_.

**Contracts only — no correlation is performed here.** This module defines
what a correlation relationship and a correlation group *are*; it contains
no connected-component algorithm, no structural-matching logic, no
temporal/ordering logic, and no ATT&CK-aware reasoning. Those are later,
separately-gated pieces of Phase 2 (G2.1+) built *against* these contracts,
never inside them.

Five contracts, mirroring ADR-0003 §"Domain model":

- :class:`LinkClass` — the closed, eleven-value vocabulary of correlation
  relationships ADR-0003 (+ Amendment A)/ADR-0004 D20 approved. Four values
  are **structural** (group-forming): ``SHARED_OBSERVATION``,
  ``SAME_PROCESS_ENTITY``, ``PROCESS_LINEAGE``, ``PROCESS_INTERACTION``.
  Seven are **contextual** (attach-only, never group-forming):
  ``SAME_HOST_ID``, ``SAME_HOST_NAME``, ``SAME_USER_ID``, ``SAME_USER_NAME``,
  ``SAME_DESTINATION_IP``, ``TEMPORAL_PROXIMITY`` (gate G2.4.3),
  ``PROCESS_ACCESS_TARGET``. The classification is a single
  authoritative property (:attr:`LinkClass.is_structural`) backed by one
  frozen set, not duplicated logic scattered across call sites — this is
  the one place "is this class allowed to form a group" can ever be asked.
- :class:`CorrelationBasis` — the machine-readable explanation for one link:
  the matched field/value and the two Observation ids it was matched on,
  plus an optional ``uncertainty_note`` that — per ADR-0003 — only a
  *contextual* basis may carry (a structural basis asserts an unhedged
  fact and has nothing to hedge; enforced, not just documented).
- :class:`CorrelationProvenance` — deliberately parallel to
  :class:`attribution_platform.domain.provenance.DerivationProvenance`:
  method identity, an optional content hash, and non-empty,
  canonicalized (sorted-unique) source evidence/observation ids. No
  correlation object may exist without a populated path back to at least
  one Observation, exactly as ``DerivationProvenance`` already guarantees
  one layer down.
- :class:`CorrelationLink` — one relationship between two *distinct*
  Evidence items (``anchor_a``/``anchor_b``, canonicalized to sorted order
  so the object is symmetric regardless of construction-time argument
  order — directionality, where a dimension has one, lives on the *basis*
  instead, never on the link's own anchors). Carries a ``link_class`` that
  must agree with its own ``basis.link_class`` — a link can never claim one
  class while its own explanation names another.
- :class:`CorrelationGroup` — a connected component of Evidence joined
  **only** through structural links (ADR-0003's explicit CR-1
  de-duplication unit). Stores link *ids*, not link objects (lightweight,
  serializable, consistent with how ``DetectionResult`` stores
  ``supporting_observation_ids`` rather than ``Observation`` objects) — but
  see :func:`build_correlation_group` for the one sanctioned way to
  construct one that can actually *enforce* "every structural-link id
  really is structural," since an id alone cannot self-verify that.

**Deterministic identity, not correlation logic.** :func:`compute_link_id`
and :func:`compute_group_id` are pure string-composition helpers over
already-known, caller-supplied values (mirroring the inline
``detection_id`` construction in
:meth:`attribution_platform.detection.rules.DetectionRule.evaluate`) — they
perform no comparison, matching, or graph traversal of their own. They exist
here, not deferred to the G2.1 engine, because ADR-0003 fixes the exact
id-construction formula as part of this layer's determinism contract, and a
future engine (or a test) needs a canonical, tested place to call it from.

Nothing in this module imports :mod:`attribution_platform.domain`,
:mod:`attribution_platform.sources`, :mod:`attribution_platform.dataplane`,
or :mod:`attribution_platform.attack_knowledge` — ADR-0003 D8's
source-agnostic boundary starts at G2.0: these contracts reference
Evidence/Observations only by opaque ``str`` id, never by importing their
types, so nothing here can ever depend on a collector- or Elastic-specific
shape. (A future engine gate *will* need to import ``domain`` to read real
``Evidence``/``Observation`` objects when it actually computes links — that
import boundary is enforced by a guard test in ``tests/test_correlation.py``,
not by this module needing to stay empty of dependencies forever.)

**No attribution, no ATT&CK actor knowledge, no scoring.** No field here is
a likelihood, confidence, weight, score, candidate, actor, campaign, or
ATT&CK group/intrusion-set/software reference — ADR-0003 D3/D10 forbid all
of that in this layer, and a guard test enforces it against this module's
own source, the same discipline already applied to ``detection/*.py``.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from enum import Enum

from attribution_platform.correlation.errors import CorrelationError

#: Version of the CorrelationLink contract (this module's schema).
CORRELATION_LINK_SCHEMA_VERSION = "correlation-link/1"

#: Version of the CorrelationGroup contract (this module's schema).
CORRELATION_GROUP_SCHEMA_VERSION = "correlation-group/2"  # /2: single-Evidence groups (Amendment F)


def _require_nonempty_str(value: object, field_name: str) -> str:
    """Correlation-layer non-empty-string check (raises ``CorrelationError``)."""
    if not isinstance(value, str) or not value.strip():
        raise CorrelationError(
            f"{field_name} must be a non-empty, non-whitespace string, got {value!r}"
        )
    return value


def _sha256_hex(value: str) -> str:
    """SHA-256 hex digest of one caller-supplied, free-text identity
    component (never Python's ``hash()``, never a random UUID, never
    wall-clock-derived).

    Used only inside :func:`compute_link_id`/:func:`compute_group_id` to
    make ``"::"``-delimited id composition unambiguous: a real
    ``evidence_id``/``observed_value`` in this project routinely contains
    ``"::"`` itself (e.g. ``evidence_id = f"{detection_id}::{external_id}"``
    in :mod:`attribution_platform.detection.evidence`), so joining raw,
    unescaped free-text values with ``"::"`` is not collision-safe — two
    different ``(observed_value, anchor_a, anchor_b)`` tuples could produce
    an identical joined string. A fixed-length (64 hex character) digest
    cannot itself contain ``"::"``, so concatenating digests removes the
    ambiguity structurally rather than by convention or escaping.
    """
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _member_set_digest(canonical_members: Iterable[str]) -> str:
    """One fixed-length digest of an already sorted, de-duplicated member id
    list (ADR-0003 Amendment D): SHA-256 over the concatenated per-member
    digests. Each per-member digest is exactly 64 hex characters, so the
    concatenation is unambiguous and two different member lists cannot share
    it; the outer digest keeps the id's length independent of the member count
    (an id listing one hash per member reached 596,980 characters on real
    telemetry — past Elasticsearch's 512-byte document-id limit)."""
    return _sha256_hex("".join(_sha256_hex(member) for member in canonical_members))


class LinkClass(Enum):
    """The closed, twelve-value correlation-relationship vocabulary ADR-0003
    (+ Amendments A, G)/ADR-0004 D20 approved. Exactly five values are
    structural (group-forming); the remaining seven are contextual
    (attach-only).
    Membership is closed — constructing ``LinkClass(x)`` with an unknown
    ``x`` raises ``ValueError`` (fail-closed enum validation), exactly like
    :class:`attribution_platform.domain.enums.EvidenceType`.

    This single enum fulfills the role ADR-0003's domain-model section
    describes as two separate concepts, ``CorrelationDimension`` (the
    specific field-level relationship) and ``LinkClass`` (structural vs.
    contextual) — consolidated here because the ADR itself specifies the
    latter is always derived from the former, never set independently, so
    a second enum would only duplicate what :attr:`is_structural` already
    computes.

    **Structural — may form a CorrelationGroup:**

    - ``SHARED_OBSERVATION`` — two Evidence items derived from the exact
      same Observation. Not even a relationship between two events; one
      piece of telemetry interpreted twice.
    - ``SAME_PROCESS_ENTITY`` — two Observations share a stable
      ``process.entity_id``: the same running process instance.
    - ``PROCESS_LINEAGE`` — one Observation's ``process.parent_entity_id``
      equals another's ``process.entity_id``: a direct, collector-asserted
      causal creation relationship.
    - ``PROCESS_INTERACTION`` (ADR-0003 Amendment A) — a remote-thread
      injection: the sensor asserts code from one process instance began
      executing inside another. Links Evidence on the injecting instance to
      Evidence on the target instance at/after the injection.

    - ``SAME_AUDIT_EVENT`` (ADR-0003 Amendment G) — two Linux Audit records
      with the same kernel event serial on the same host: the records of one
      audit event (one syscall), which the kernel itself asserts belong
      together. Like ``SHARED_OBSERVATION``, one instance described twice.

    **Contextual — attach-only, never group-forming:**

    - ``SAME_HOST_ID`` / ``SAME_HOST_NAME`` — shared host (a container for
      unrelated activity, however reliably identified).
    - ``SAME_USER_ID`` / ``SAME_USER_NAME`` — shared user/service identity
      (an unbounded-action actor, not a causal participant).
    - ``SAME_DESTINATION_IP`` — shared network infrastructure.
    - ``TEMPORAL_PROXIMITY`` (gate G2.4.3, ADR-0004 D20) — two Observations'
      timestamps fall within a versioned, content-hashed window of each
      other. Closeness in time is a coincidental/environmental fact, not
      instance-identity or causation — despite its name, it is exactly as
      contextual as the other five, never a sixth structural dimension. It
      may coexist with, and never substitutes for, ``SAME_PROCESS_ENTITY``
      (which remains the only fact establishing "same running process
      instance," unconditionally, regardless of any time gap).
    - ``PROCESS_ACCESS_TARGET`` (ADR-0003 Amendment A4) — one process
      instance opened a handle to another. Extremely common benign
      behaviour, so explanatory context only, never group-forming.

    ADR-0003's own words on why host/user identity is never structural
    regardless of how reliable the identifier is: *"A stable identifier
    does not become structural merely because it is reliable."*
    ``SAME_HOST_ID``/``SAME_USER_ID`` are exactly as contextual as their
    name-based counterparts — the two id-based members exist for
    explanatory precision (``CorrelationBasis.field_path`` records *which*
    field actually matched), not because id-based matches are ever allowed
    to form a group. ``TEMPORAL_PROXIMITY`` is held to the identical
    standard: a reliable-looking temporal signal is not automatically the
    right semantic category for it (ADR-0004 D20's own explicit reservation
    of this exact failure mode, made in advance of this dimension's own
    implementation).
    """

    SHARED_OBSERVATION = "shared_observation"
    SAME_PROCESS_ENTITY = "same_process_entity"
    PROCESS_LINEAGE = "process_lineage"
    SAME_HOST_ID = "same_host_id"
    SAME_HOST_NAME = "same_host_name"
    SAME_USER_ID = "same_user_id"
    SAME_USER_NAME = "same_user_name"
    SAME_DESTINATION_IP = "same_destination_ip"
    TEMPORAL_PROXIMITY = "temporal_proximity"
    PROCESS_INTERACTION = "process_interaction"
    PROCESS_ACCESS_TARGET = "process_access_target"
    SAME_AUDIT_EVENT = "same_audit_event"

    @property
    def is_structural(self) -> bool:
        """``True`` for the five group-forming classes, ``False`` for the
        seven contextual ones. The single authoritative classification —
        every other invariant in this module (and every future caller)
        must ask *this*, never re-derive the split independently."""
        return self in _STRUCTURAL_LINK_CLASSES


#: The complete, closed set of structural (group-forming) classes. Defined
#: once, after the enum, and consulted only through ``LinkClass.is_structural``
#: — this is the one place the structural/contextual split is spelled out.
_STRUCTURAL_LINK_CLASSES: frozenset[LinkClass] = frozenset(
    {
        LinkClass.SHARED_OBSERVATION,
        LinkClass.SAME_PROCESS_ENTITY,
        LinkClass.PROCESS_LINEAGE,
        LinkClass.PROCESS_INTERACTION,
        LinkClass.SAME_AUDIT_EVENT,
    }
)

#: Every ``LinkClass`` member not in the structural set — used only by tests
#: to assert the two sets partition the full vocabulary with no overlap and
#: no omission.
CONTEXTUAL_LINK_CLASSES: frozenset[LinkClass] = frozenset(LinkClass) - _STRUCTURAL_LINK_CLASSES


@dataclass(frozen=True)
class CorrelationBasis:
    """The machine-readable explanation for one ``CorrelationLink``.

    - ``link_class``: which of the eight approved relationships this is —
      also determines whether ``uncertainty_note`` may be present (below).
    - ``field_path``: the dotted Observation field that was matched, e.g.
      ``"process.entity_id"`` (mirrors the G1.0 ``MatchedField.field_path``
      convention).
    - ``observed_value``: the shared value that justified the link, recorded
      as a string (mirrors ``MatchedField.observed``) so the *why* is
      self-contained and auditable without re-deriving it from the
      Observations later.
    - ``observation_id_a`` / ``observation_id_b``: the two Observation ids
      the match was found between. **Not canonicalized/sorted** — where a
      dimension is directional (``PROCESS_LINEAGE``), the caller is expected
      to put the causally-prior Observation (the parent) in ``_a`` and the
      caused one (the child) in ``_b``; for symmetric dimensions the order
      carries no meaning and either order is valid. For ``SHARED_OBSERVATION``
      the two ids are legitimately equal (it is the same Observation).
    - ``uncertainty_note``: populated **only** for a contextual basis, naming
      the specific reason the match does not imply behavioral relatedness
      (e.g. "shared/service accounts are common and do not imply a causal
      relationship"). A structural basis must leave this ``None`` — per
      ADR-0003, a structural fact has nothing to hedge; enforced below, not
      merely documented.
    """

    link_class: LinkClass
    field_path: str
    observed_value: str
    observation_id_a: str
    observation_id_b: str
    uncertainty_note: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.link_class, LinkClass):
            raise CorrelationError(
                f"CorrelationBasis.link_class must be a LinkClass, "
                f"got {type(self.link_class).__name__}"
            )
        _require_nonempty_str(self.field_path, "CorrelationBasis.field_path")
        _require_nonempty_str(self.observed_value, "CorrelationBasis.observed_value")
        _require_nonempty_str(self.observation_id_a, "CorrelationBasis.observation_id_a")
        _require_nonempty_str(self.observation_id_b, "CorrelationBasis.observation_id_b")

        if self.uncertainty_note is not None:
            _require_nonempty_str(self.uncertainty_note, "CorrelationBasis.uncertainty_note")
            if self.link_class.is_structural:
                raise CorrelationError(
                    f"CorrelationBasis.uncertainty_note must be absent for structural "
                    f"link_class {self.link_class.value!r} — a structural basis asserts an "
                    f"unhedged fact and has nothing to hedge (ADR-0003)"
                )


@dataclass(frozen=True)
class CorrelationProvenance:
    """Provenance for a correlation object — deliberately parallel to
    :class:`attribution_platform.domain.provenance.DerivationProvenance`,
    one layer up: same non-empty-and-canonicalized id-set pattern, same
    optional content-hash field, same "provenance cannot be silently
    dropped" invariant. This module does not import ``DerivationProvenance``
    itself (ADR-0003 D8's source-agnostic boundary keeps this layer free of
    a ``domain`` dependency for G2.0), but the shape and rules are the same
    contract by convention, not a parallel incompatible scheme.

    - ``method`` / ``method_version``: identity of the correlation logic
      that produced this object (e.g. ``"structural-correlation"`` / a
      version string) — the G2.1+ engine's own identity, supplied by the
      caller, never fabricated here.
    - ``method_content_hash``: optional content hash of the exact
      correlation configuration used (which dimensions were enabled — see
      ADR-0003 D4), mirroring
      :attr:`attribution_platform.domain.provenance.DerivationProvenance.method_content_hash`
      /
      :attr:`attribution_platform.detection.rules.RulePack.content_hash`.
      Left absent (``None``) rather than fabricated when no such
      configuration hash is available.
    - ``source_evidence_ids``: the Evidence id(s) this correlation object
      was derived from — **required and non-empty**, canonicalized to a
      sorted-unique tuple so equality is order-independent.
    - ``source_observation_ids``: the Observation id(s) reachable from
      those Evidence items — **required and non-empty**, canonicalized the
      same way. This is what keeps a correlation object navigable all the
      way back to raw telemetry even without importing ``domain`` types.
    """

    method: str
    method_version: str
    source_evidence_ids: tuple[str, ...] = ()
    source_observation_ids: tuple[str, ...] = ()
    method_content_hash: str | None = None

    def __post_init__(self) -> None:
        _require_nonempty_str(self.method, "CorrelationProvenance.method")
        _require_nonempty_str(self.method_version, "CorrelationProvenance.method_version")

        if not self.source_evidence_ids:
            raise CorrelationError(
                "CorrelationProvenance.source_evidence_ids must be non-empty: a correlation "
                "object must retain provenance to at least one supporting Evidence item"
            )
        for eid in self.source_evidence_ids:
            _require_nonempty_str(eid, "CorrelationProvenance.source_evidence_ids[]")
        canonical_evidence = tuple(sorted(set(self.source_evidence_ids)))
        object.__setattr__(self, "source_evidence_ids", canonical_evidence)

        if not self.source_observation_ids:
            raise CorrelationError(
                "CorrelationProvenance.source_observation_ids must be non-empty: a correlation "
                "object must retain provenance to at least one supporting Observation"
            )
        for oid in self.source_observation_ids:
            _require_nonempty_str(oid, "CorrelationProvenance.source_observation_ids[]")
        canonical_obs = tuple(sorted(set(self.source_observation_ids)))
        object.__setattr__(self, "source_observation_ids", canonical_obs)

        if self.method_content_hash is not None:
            _require_nonempty_str(
                self.method_content_hash, "CorrelationProvenance.method_content_hash"
            )


@dataclass(frozen=True)
class CorrelationLink:
    """One relationship between two distinct Evidence items.

    - ``link_id``: stable, opaque identifier. **Composed deterministically**
      by the caller (typically via :func:`compute_link_id`) from the link's
      own class/value/anchors — never randomly generated, never
      wall-clock-derived. This contract validates only that it is a
      non-empty string; it does not recompute or cross-check it (the same
      division of responsibility G1.0 uses: ``DetectionRule.evaluate``
      computes ``detection_id``, ``DetectionResult.__post_init__`` only
      validates its shape).
    - ``anchor_a`` / ``anchor_b``: the two Evidence ids this link connects —
      **required to be distinct** (a link to oneself is meaningless) and
      **canonicalized to sorted order** on construction, so the object
      compares equal regardless of which argument order the caller used.
      Any directionality a dimension has (``PROCESS_LINEAGE``) lives on
      ``basis.observation_id_a``/``_b`` instead, which are *not*
      canonicalized — see :class:`CorrelationBasis`.
    - ``link_class``: one of the eight approved :class:`LinkClass` values.
      Must agree with ``basis.link_class`` — a link cannot claim one class
      while its own explanation names another.
    - ``basis``: the machine-readable *why* (:class:`CorrelationBasis`).
    - ``provenance``: :class:`CorrelationProvenance` — non-empty back-links
      to the supporting Evidence/Observation ids.

    ``schema_version`` defaults to the current contract version.
    """

    link_id: str
    anchor_a: str
    anchor_b: str
    link_class: LinkClass
    basis: CorrelationBasis
    provenance: CorrelationProvenance
    schema_version: str = field(default=CORRELATION_LINK_SCHEMA_VERSION)

    def __post_init__(self) -> None:
        _require_nonempty_str(self.link_id, "CorrelationLink.link_id")
        _require_nonempty_str(self.anchor_a, "CorrelationLink.anchor_a")
        _require_nonempty_str(self.anchor_b, "CorrelationLink.anchor_b")
        if self.anchor_a == self.anchor_b:
            raise CorrelationError(
                f"CorrelationLink.anchor_a and anchor_b must be distinct Evidence ids, "
                f"both were {self.anchor_a!r}"
            )
        # Canonicalize to sorted order: the link is symmetric, so equal
        # inputs in either argument order must produce an equal object.
        canonical_a, canonical_b = sorted((self.anchor_a, self.anchor_b))
        object.__setattr__(self, "anchor_a", canonical_a)
        object.__setattr__(self, "anchor_b", canonical_b)

        if not isinstance(self.link_class, LinkClass):
            raise CorrelationError(
                f"CorrelationLink.link_class must be a LinkClass, "
                f"got {type(self.link_class).__name__}"
            )
        if not isinstance(self.basis, CorrelationBasis):
            raise CorrelationError(
                f"CorrelationLink.basis must be a CorrelationBasis, "
                f"got {type(self.basis).__name__}"
            )
        if self.basis.link_class != self.link_class:
            raise CorrelationError(
                f"CorrelationLink.link_class {self.link_class.value!r} does not match "
                f"basis.link_class {self.basis.link_class.value!r} — a link's declared class "
                f"and its own explanation must agree"
            )
        if not isinstance(self.provenance, CorrelationProvenance):
            raise CorrelationError(
                f"CorrelationLink.provenance must be a CorrelationProvenance, "
                f"got {type(self.provenance).__name__}"
            )
        _require_nonempty_str(self.schema_version, "CorrelationLink.schema_version")


@dataclass(frozen=True)
class CorrelationGroup:
    """A connected component of Evidence joined **only** through structural
    links — ADR-0003's CR-1 de-duplication unit.

    Means exactly: *"these Evidence items arose from a chain of observations
    that are provably the same process instance or in a direct parent→child
    creation relationship."* Never means "same host," "same user," "same
    technique," or "malicious" — those facts, when true, belong in
    ``contextual_link_ids``, never in the reason the group exists.

    - ``group_id``: stable, opaque identifier, composed deterministically
      (typically via :func:`compute_group_id`) from the sorted member
      Evidence ids — never randomly generated.
    - ``member_evidence_ids``: the Evidence items in this component —
      **required, non-empty**. A component of one Evidence (no structural
      link touches it) is a group too (ADR-0003 Amendment F): it is one
      independent behavior, so attribution must see it as its own unit.
      Canonicalized to sorted-unique.
    - ``member_observation_ids``: the Observation ids reachable from those
      Evidence items, for direct raw-telemetry navigation without walking
      through Evidence first. Required, non-empty, canonicalized.
    - ``structural_link_ids``: the structural ``CorrelationLink`` ids that
      actually formed this component — **non-empty exactly when the group
      has two or more members** (members are joined only by structural
      links) and **empty for a single-Evidence group** (Amendment F).
      This contract cannot verify from an id string alone that a given id
      truly names a structural link; use :func:`build_correlation_group`,
      which can (it receives the actual link objects).
    - ``contextual_link_ids``: contextual links that happen to touch a
      member of this group. Optional, may be empty. Must be disjoint from
      ``structural_link_ids`` — the same link cannot be both.
    - ``provenance``: :class:`CorrelationProvenance` — non-empty back-links.

    ``schema_version`` defaults to the current contract version.
    """

    group_id: str
    member_evidence_ids: tuple[str, ...]
    member_observation_ids: tuple[str, ...]
    structural_link_ids: tuple[str, ...]
    provenance: CorrelationProvenance
    contextual_link_ids: tuple[str, ...] = ()
    schema_version: str = field(default=CORRELATION_GROUP_SCHEMA_VERSION)

    def __post_init__(self) -> None:
        _require_nonempty_str(self.group_id, "CorrelationGroup.group_id")

        if not self.member_evidence_ids:
            raise CorrelationError("CorrelationGroup.member_evidence_ids must be non-empty")
        for eid in self.member_evidence_ids:
            _require_nonempty_str(eid, "CorrelationGroup.member_evidence_ids[]")
        canonical_members = tuple(sorted(set(self.member_evidence_ids)))
        object.__setattr__(self, "member_evidence_ids", canonical_members)

        if not self.member_observation_ids:
            raise CorrelationError(
                "CorrelationGroup.member_observation_ids must be non-empty: a correlation "
                "group must retain provenance to at least one supporting Observation"
            )
        for oid in self.member_observation_ids:
            _require_nonempty_str(oid, "CorrelationGroup.member_observation_ids[]")
        object.__setattr__(
            self, "member_observation_ids", tuple(sorted(set(self.member_observation_ids)))
        )

        if len(canonical_members) >= 2 and not self.structural_link_ids:
            raise CorrelationError(
                "CorrelationGroup.structural_link_ids must be non-empty for a group of two or "
                "more Evidence: members are joined only by structural links"
            )
        if len(canonical_members) == 1 and self.structural_link_ids:
            raise CorrelationError(
                "CorrelationGroup: a single-Evidence group has no structural link "
                "(ADR-0003 Amendment F)"
            )
        for lid in self.structural_link_ids:
            _require_nonempty_str(lid, "CorrelationGroup.structural_link_ids[]")
        canonical_structural = tuple(sorted(set(self.structural_link_ids)))
        object.__setattr__(self, "structural_link_ids", canonical_structural)

        for lid in self.contextual_link_ids:
            _require_nonempty_str(lid, "CorrelationGroup.contextual_link_ids[]")
        canonical_contextual = tuple(sorted(set(self.contextual_link_ids)))
        object.__setattr__(self, "contextual_link_ids", canonical_contextual)

        overlap = set(canonical_structural) & set(canonical_contextual)
        if overlap:
            raise CorrelationError(
                f"CorrelationGroup: link id(s) {sorted(overlap)!r} appear in both "
                f"structural_link_ids and contextual_link_ids — a single link cannot be both"
            )

        if not isinstance(self.provenance, CorrelationProvenance):
            raise CorrelationError(
                f"CorrelationGroup.provenance must be a CorrelationProvenance, "
                f"got {type(self.provenance).__name__}"
            )
        _require_nonempty_str(self.schema_version, "CorrelationGroup.schema_version")


# ===========================================================================
# Deterministic identity helpers (pure string composition — NOT correlation
# logic: no comparison, matching, or graph traversal of Evidence/Observations
# happens here, only assembly of an id string from already-known values).
# ===========================================================================


def compute_link_id(
    *,
    link_class: LinkClass,
    observed_value: str,
    anchor_a: str,
    anchor_b: str,
    method_content_hash: str | None = None,
) -> str:
    """Deterministically compose a ``CorrelationLink.link_id``.

    ``f"corr::{link_class}::{sha256(observed_value)}::{sha256(lo)}::{sha256(hi)}[::{method_content_hash}]"``
    with the two anchors sorted (by their original values) before hashing,
    so the same relationship always produces the same id regardless of
    argument order — never a randomly generated id, never wall-clock-derived.

    ``observed_value``/``anchor_a``/``anchor_b`` are SHA-256-hashed
    (:func:`_sha256_hex`) rather than joined as raw text: real
    ``evidence_id``/``observed_value`` strings in this project already
    contain ``"::"`` themselves (see :func:`_sha256_hex`'s docstring), so
    joining them unhashed would make two semantically different link
    identities collide on the same id string. ``"corr"`` and
    ``link_class.value`` stay plain text — both are tokens this project
    controls (a literal prefix and a closed enum value), never
    caller-supplied, so they can never contain ``"::"``.

    Including ``method_content_hash`` when present means two correlation
    configurations that share a ``(link_class, observed_value, anchors)``
    tuple but differ in actual enabled-dimension content produce *different*
    ids, exactly mirroring how G1.0's ``detection_id`` includes the rule
    pack's own content hash. It is not re-hashed here: by this project's own
    convention (see :attr:`attribution_platform.detection.rules.RulePack.content_hash`)
    a content hash is already a fixed-length SHA-256 hex digest and so is
    already collision-safe to concatenate.
    """
    if not isinstance(link_class, LinkClass):
        raise CorrelationError(
            f"compute_link_id: link_class must be a LinkClass, got {type(link_class).__name__}"
        )
    _require_nonempty_str(observed_value, "compute_link_id(observed_value=...)")
    _require_nonempty_str(anchor_a, "compute_link_id(anchor_a=...)")
    _require_nonempty_str(anchor_b, "compute_link_id(anchor_b=...)")
    if anchor_a == anchor_b:
        raise CorrelationError(
            f"compute_link_id: anchor_a and anchor_b must be distinct, both were {anchor_a!r}"
        )
    lo, hi = sorted((anchor_a, anchor_b))
    parts = [
        "corr",
        link_class.value,
        _sha256_hex(observed_value),
        _sha256_hex(lo),
        _sha256_hex(hi),
    ]
    if method_content_hash is not None:
        _require_nonempty_str(method_content_hash, "compute_link_id(method_content_hash=...)")
        parts.append(method_content_hash)
    return "::".join(parts)


def compute_group_id(
    member_evidence_ids: Iterable[str],
    *,
    method_content_hash: str | None = None,
) -> str:
    """Deterministically compose a ``CorrelationGroup.group_id`` from the
    sorted, de-duplicated set of member Evidence ids (+ the correlation
    configuration's content hash, when known) — never a randomly generated
    id. Replaying the same telemetry through the same configuration always
    yields the same member set and therefore the same ``group_id``.

    The sorted member ids are reduced to one fixed-length digest
    (:func:`_member_set_digest`, ADR-0003 Amendment D): a real
    ``evidence_id`` already contains ``"::"`` by this project's own
    convention, so joining raw ids would let two different member sets
    produce the same ``group_id`` string, and one hash per member would make
    the id grow with the group. ``method_content_hash``
    is appended unhashed, unchanged from before — it is already a
    fixed-length SHA-256 hex digest by convention and so is already
    collision-safe to concatenate.
    """
    canonical = sorted(set(member_evidence_ids))
    if not canonical:
        raise CorrelationError("compute_group_id: requires at least one member Evidence id")
    for eid in canonical:
        _require_nonempty_str(eid, "compute_group_id(member_evidence_ids=...)[]")
    parts = ["corr-group", _member_set_digest(canonical)]
    if method_content_hash is not None:
        _require_nonempty_str(method_content_hash, "compute_group_id(method_content_hash=...)")
        parts.append(method_content_hash)
    return "::".join(parts)


def build_correlation_group(
    *,
    group_id: str,
    member_evidence_ids: Iterable[str],
    member_observation_ids: Iterable[str],
    structural_links: Sequence[CorrelationLink],
    provenance: CorrelationProvenance,
    contextual_links: Sequence[CorrelationLink] = (),
    schema_version: str = CORRELATION_GROUP_SCHEMA_VERSION,
) -> CorrelationGroup:
    """The one sanctioned way to construct a ``CorrelationGroup`` that can
    actually *enforce* ADR-0003's class-membership invariant.

    ``CorrelationGroup`` itself stores link *ids* (a lightweight,
    serializable shape — see the class docstring), which cannot self-verify
    "this id really names a structural link." This helper accepts the real
    :class:`CorrelationLink` objects instead, validates
    ``link.link_class.is_structural`` for every entry in ``structural_links``
    (must be ``True``) and every entry in ``contextual_links`` (must be
    ``False``), fail-closed, then returns the ids-only ``CorrelationGroup``.

    This is **not** the connected-component algorithm: it performs no
    search, comparison, or graph traversal — the caller (the future G2.1
    engine, or a test) has already decided which links belong to this
    group; this function only enforces that the decision was legal.
    """
    for link in structural_links:
        if not isinstance(link, CorrelationLink):
            raise CorrelationError(
                f"build_correlation_group: structural_links must contain CorrelationLink "
                f"objects, got {type(link).__name__}"
            )
        if not link.link_class.is_structural:
            raise CorrelationError(
                f"build_correlation_group: link {link.link_id!r} has contextual link_class "
                f"{link.link_class.value!r} and cannot form a CorrelationGroup "
                f"(only structural links may — ADR-0003)"
            )
    for link in contextual_links:
        if not isinstance(link, CorrelationLink):
            raise CorrelationError(
                f"build_correlation_group: contextual_links must contain CorrelationLink "
                f"objects, got {type(link).__name__}"
            )
        if link.link_class.is_structural:
            raise CorrelationError(
                f"build_correlation_group: link {link.link_id!r} has structural link_class "
                f"{link.link_class.value!r} and must not be stored as a contextual link "
                f"(it belongs in structural_links)"
            )

    return CorrelationGroup(
        group_id=group_id,
        member_evidence_ids=tuple(member_evidence_ids),
        member_observation_ids=tuple(member_observation_ids),
        structural_link_ids=tuple(link.link_id for link in structural_links),
        provenance=provenance,
        contextual_link_ids=tuple(link.link_id for link in contextual_links),
        schema_version=schema_version,
    )
