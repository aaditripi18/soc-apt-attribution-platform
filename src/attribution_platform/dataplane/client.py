"""The ElasticClient abstraction: the one boundary above which nothing knows
which Elastic client implementation is in use (gate G0.8).

Mirrors the pattern already established by
:class:`attribution_platform.sources.adapter.SourceAdapter`: a
:class:`typing.Protocol` (structural typing), not an abstract base class, so
a conforming object needs no inheritance or registration — it only needs the
right shape. This is deliberately the *entire* Elastic surface this project
depends on: four operations, nothing more.

``search`` (gate G1.1) is the one addition since G0.8, added only because a
bounded, read-only query became genuinely necessary (reading Elastic
Detection Engine alerts — see
:mod:`attribution_platform.elastic_detections.alerts` — cannot be done with
``get_document``, which requires an already-known document id). It is
deliberately minimal: one page, one caller-supplied ``size`` cap, no
scroll/point-in-time/pagination support and no way to request "all"
results — genuinely unbounded retrieval is out of scope, not just
undocumented.

Two implementations exist:

- :class:`attribution_platform.dataplane.http_client.ElasticsearchHttpClient`
  — a thin, stdlib-only (``urllib``) REST client against a real cluster.
- :class:`attribution_platform.dataplane.fake_client.FakeElasticClient` — an
  in-memory fake with the identical shape, used by tests (and usable by any
  future in-process caller) with no network, Docker, or Elasticsearch
  required.

Persistence logic (:mod:`attribution_platform.dataplane.persistence`) and any
future caller (the Attribution Engine, G0.9's replay loader, G0.10's API)
depend only on this ``Protocol`` — never on ``ElasticsearchHttpClient``
directly — so they are indifferent to which implementation is plugged in.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class ElasticClient(Protocol):
    """Structural interface every Elastic client implementation must satisfy.

    Exactly three members, all synchronous and side-effect-documented:

    - ``ensure_index(index, mappings)``: idempotently create ``index`` with
      the given field ``mappings`` if it does not already exist. Calling this
      twice with the same arguments must be a no-op the second time (never an
      error) — this is what "deterministic index configuration" means in
      practice: re-running it is always safe.
    - ``index_document(index, document_id, document)``: write ``document``
      into ``index`` under the explicit ``document_id`` (an upsert — create
      or fully replace). Because the id is caller-supplied (the domain
      object's own id), calling this twice with the same arguments produces
      the same end state — that is the idempotency guarantee gate G0.8
      requires, achieved structurally rather than by a separate dedup step.
    - ``get_document(index, document_id)``: return the stored document as a
      plain ``Mapping``, or ``None`` if no document with that id exists in
      that index.
    - ``search(index, query, *, size)``: a **bounded, read-only** query —
      return up to ``size`` matching documents' source bodies (Elasticsearch
      Query DSL in ``query``, e.g. ``{"match_all": {}}``). ``size`` is
      required (no default that could silently mean "everything") and must
      be positive. No scrolling, no point-in-time, no "give me all matches"
      mode — a caller needing more than one bounded page is out of scope for
      this Protocol. ``sort`` names mapped keyword/date fields to order
      the matches by (ascending, in priority order) *before* the ``size``
      cap applies, so a capped page is the first ``size`` matches in that
      order rather than an arbitrary subset.

    Implementations must raise
    :class:`~attribution_platform.dataplane.errors.ElasticIntegrationError`
    (not a raw transport/HTTP exception) on failure, so callers depending
    only on this Protocol have exactly one error type to handle.
    """

    def ensure_index(self, index: str, mappings: Mapping[str, Any]) -> None: ...

    def index_document(self, index: str, document_id: str, document: Mapping[str, Any]) -> None: ...

    def get_document(self, index: str, document_id: str) -> Mapping[str, Any] | None: ...

    def search(
        self,
        index: str,
        query: Mapping[str, Any],
        *,
        size: int,
        sort: Sequence[str] = (),
    ) -> tuple[Mapping[str, Any], ...]: ...
