"""The SourceAdapter interface: source-native input -> domain Observation(s).

Gate G0.4 (docs/architecture/13-phase-0-implementation-plan.md). This is the
whole ingestion boundary described in
docs/architecture/12-deployment-and-endpoint-scope.md §D.1/§D.2 (layers
1-3: telemetry source -> collector/agent -> normalization -> the domain
boundary). It defines exactly two things, deliberately nothing more:

1. a **stable source identifier** (``source_type``);
2. a **pure conversion** from one source-native raw record to zero-or-more
   normalized :class:`~attribution_platform.domain.Observation` objects
   (``to_observations``).

``SourceAdapter`` is a :class:`typing.Protocol` (structural typing), not an
abstract base class: a new source is addable by writing any object with this
shape — no inheritance, no registry, no plugin discovery, no lifecycle
hooks. This is intentional (G0.4 explicitly forbids speculative plugin
frameworks): the *only* requirement for "a new source is addable purely as
an adapter; nothing above the boundary changes"
(docs/architecture/12-deployment-and-endpoint-scope.md §D.1.6) is that the
adapter satisfy this shape and hand back valid ``Observation`` objects.

Raw-record handling stays inside the existing G0.3 provenance boundary:
every returned ``Observation`` must carry a
:class:`~attribution_platform.domain.SourceRef` (``raw_reference``) whose
``source_type`` matches the adapter's own declared ``source_type`` — checked
by :func:`convert`, not left to convention. Source-native fields/schemas
never leak above this module: nothing in ``attribution_platform.domain`` (or
any future extraction/attribution code) may import from this package or any
adapter module (enforced by a guard test, not just documented).

Deliberately out of scope at this gate: any real source (Sysmon, Windows
Event Log, Linux, network, EDR, cloud) — only the interface plus one trivial
synthetic reference adapter (:mod:`attribution_platform.sources.synthetic`);
Elastic integration, collectors, ingestion pipelines, detection logic, ATT&CK
matching, attribution, and the "detection-match record" contract (that is
gate G0.5's extraction boundary, not this one).
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from attribution_platform.domain import Observation
from attribution_platform.sources.errors import SourceAdapterError


@runtime_checkable
class SourceAdapter(Protocol):
    """Structural interface every telemetry-source adapter must satisfy.

    Exactly two members:

    - ``source_type`` (property or attribute): a stable, non-empty string
      identifying the source (e.g. ``"sysmon"``, ``"synthetic"``). Adapters
      choose their own identifier; nothing here enumerates known sources.
    - ``to_observations(raw_record)``: converts one source-native raw record
      into a ``tuple`` of zero or more ``Observation`` objects. Must not
      return a partially-constructed or invalid ``Observation`` — since
      ``Observation`` itself validates at construction (gate G0.3), an
      adapter that cannot produce a valid one should raise rather than
      fabricate placeholder values.
    """

    @property
    def source_type(self) -> str: ...

    def to_observations(self, raw_record: Any) -> tuple[Observation, ...]: ...


def convert(adapter: SourceAdapter, raw_record: Any) -> tuple[Observation, ...]:
    """Fail-closed invocation of a ``SourceAdapter``.

    Validates the adapter's own contract before trusting its output:

    1. ``adapter.source_type`` must be present and a non-empty string.
    2. ``adapter.to_observations(raw_record)`` must return a ``tuple``.
    3. Every element must be an ``Observation`` instance.
    4. Every returned ``Observation.raw_reference.source_type`` must equal
       ``adapter.source_type`` — the adapter cannot mislabel the provenance
       of what it produces.

    Raises :class:`SourceAdapterError` on any violation, with a message
    naming exactly which invariant failed. This is the one place callers
    should invoke an adapter through, rather than calling
    ``adapter.to_observations`` directly, so the contract is enforced
    uniformly regardless of which adapter is plugged in.
    """
    source_type = getattr(adapter, "source_type", None)
    if not isinstance(source_type, str) or not source_type.strip():
        raise SourceAdapterError(
            f"{adapter!r}.source_type must be a non-empty str, got {source_type!r}"
        )

    observations = adapter.to_observations(raw_record)

    if not isinstance(observations, tuple):
        raise SourceAdapterError(
            f"{adapter!r}.to_observations() must return a tuple, "
            f"got {type(observations).__name__}"
        )

    for obs in observations:
        if not isinstance(obs, Observation):
            raise SourceAdapterError(
                f"{adapter!r}.to_observations() returned a non-Observation element: {obs!r}"
            )
        if obs.raw_reference.source_type != source_type:
            raise SourceAdapterError(
                f"{adapter!r}: Observation {obs.observation_id!r} has "
                f"raw_reference.source_type={obs.raw_reference.source_type!r}, "
                f"which does not match adapter.source_type={source_type!r}"
            )

    return observations
