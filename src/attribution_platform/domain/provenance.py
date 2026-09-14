"""First-class provenance contracts (gate G0.3).

Two immutable structures answer the provenance questions from
docs/architecture/13 (G0.3 §3):

- :class:`SourceRef` — attached to an Observation, answers *what source
  produced this and which raw source record did it originate from*.
- :class:`DerivationProvenance` — attached to derived Evidence, answers
  *which normalized Observation(s) support it, which transformation/rule
  produced it, which version of that rule, and (only if genuinely needed)
  when the derivation was performed*.

Neither is a generic mutable bag: both are ``@dataclass(frozen=True)`` with
fixed, typed fields. Absence of genuinely-unavailable information is
represented explicitly (``None`` / empty), never fabricated. Nothing here is
source-specific.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime

from attribution_platform.domain.errors import (
    DomainContractError,
    ensure_aware_datetime,
    ensure_nonempty_str,
)


@dataclass(frozen=True)
class SourceRef:
    """A reference from a normalized Observation back to its raw source record.

    - ``source_type``: identity of the source/adapter that produced the
      telemetry (an opaque label supplied by the adapter, e.g. ``"sysmon"``,
      ``"winlogbeat"``, ``"synthetic"`` — never interpreted here).
    - ``source_event_id``: the raw record's stable identifier in its origin
      system (e.g. an Elastic ``_index``/``_id``, or a dataset-relative id).
    - ``dataset_ref``: optional ``name@content-hash`` of the replay dataset,
      when the telemetry came from a pinned dataset rather than live.
    - ``raw_payload_ref``: optional locator for the retained raw payload
      (a pointer, **not** the payload itself; the raw bytes are not copied
      into the domain layer).

    Required identifiers are validated non-empty (fail closed).
    """

    source_type: str
    source_event_id: str
    dataset_ref: str | None = None
    raw_payload_ref: str | None = None

    def __post_init__(self) -> None:
        ensure_nonempty_str(self.source_type, "SourceRef.source_type")
        ensure_nonempty_str(self.source_event_id, "SourceRef.source_event_id")
        if self.dataset_ref is not None:
            ensure_nonempty_str(self.dataset_ref, "SourceRef.dataset_ref")
        if self.raw_payload_ref is not None:
            ensure_nonempty_str(self.raw_payload_ref, "SourceRef.raw_payload_ref")


@dataclass(frozen=True)
class DerivationProvenance:
    """Provenance for a derived object (Evidence): how it was produced.

    - ``method``: identifier of the extraction/derivation rule or analytic
      that produced the derived object (supplied by the extraction layer;
      not fabricated here). Generalizes doc 06's ``rule_ref``.
    - ``method_version``: the version of that rule/analytic/schema, so a
      derivation is reproducible and traceable to the logic that made it.
    - ``method_content_hash``: optional content hash of the *exact* method
      definition used (e.g. a detection rule-pack's SHA-256 — gate G1.0).
      ``method``/``method_version`` are a human-assigned identity; nothing
      technical guarantees ``method_version`` changes when the method's
      actual content does. This field closes that gap when a caller has a
      real content hash to record — optional and additive, because not
      every derivation method is content-hashable (or has been, prior to
      this gate). Left absent (``None``) rather than fabricated.
    - ``source_observation_ids``: the Observation id(s) this was derived
      from — **required and non-empty** for any derived object. Stored as a
      canonical, de-duplicated, sorted tuple so equality is order-independent
      and serialization is deterministic.
    - ``derived_at``: optional derivation timestamp. Optional *by design*:
      putting "now" into a domain object at construction would break
      determinism (docs/architecture/13, G0.3 §5), so this is only ever set
      when a caller has a real, meaningful derivation time to record.

    All required strings are validated non-empty; ``method_content_hash`` if
    present must also be non-empty; ``derived_at`` if present must be
    timezone-aware (fail closed).
    """

    method: str
    method_version: str
    source_observation_ids: tuple[str, ...] = ()
    derived_at: datetime | None = field(default=None)
    method_content_hash: str | None = None

    def __post_init__(self) -> None:
        ensure_nonempty_str(self.method, "DerivationProvenance.method")
        ensure_nonempty_str(self.method_version, "DerivationProvenance.method_version")

        if not self.source_observation_ids:
            raise DomainContractError(
                "DerivationProvenance.source_observation_ids must be non-empty: a derived "
                "object must retain provenance to at least one supporting Observation"
            )
        for oid in self.source_observation_ids:
            ensure_nonempty_str(oid, "DerivationProvenance.source_observation_ids[]")

        # Canonicalize to sorted-unique so equality is order-independent and
        # serialization deterministic (frozen dataclass -> object.__setattr__).
        canonical = tuple(sorted(set(self.source_observation_ids)))
        object.__setattr__(self, "source_observation_ids", canonical)

        if self.derived_at is not None:
            ensure_aware_datetime(self.derived_at, "DerivationProvenance.derived_at")

        if self.method_content_hash is not None:
            ensure_nonempty_str(
                self.method_content_hash, "DerivationProvenance.method_content_hash"
            )

    @classmethod
    def create(
        cls,
        *,
        method: str,
        method_version: str,
        source_observation_ids: Iterable[str],
        derived_at: datetime | None = None,
    ) -> DerivationProvenance:
        """Keyword-only constructor accepting any iterable of observation ids.

        Convenience over the positional dataclass constructor; canonicalizes
        the ids (via ``__post_init__``) the same way.
        """
        return cls(
            method=method,
            method_version=method_version,
            source_observation_ids=tuple(source_observation_ids),
            derived_at=derived_at,
        )
