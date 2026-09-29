"""An in-memory :class:`~attribution_platform.dataplane.client.ElasticClient`
fake (gate G0.8).

Exists so persistence logic can be tested — including its idempotency and
fail-closed behavior — with **no live Elasticsearch instance, no Docker, and
no network access**, per the gate's testing requirement. It satisfies the
``ElasticClient`` Protocol exactly (a structural type: no inheritance
needed), so anywhere a real
:class:`~attribution_platform.dataplane.http_client.ElasticsearchHttpClient`
is accepted, this fake is too.

This is a faithful-enough model of real Elasticsearch semantics for what
:mod:`attribution_platform.dataplane.persistence` needs: an index must be
created (``ensure_index``) before a document can be written to it;
``index_document`` with the same ``document_id`` overwrites in place
(idempotent upsert); ``get_document`` returns ``None`` for a missing id
rather than raising. It does **not** attempt to model real Elasticsearch
mapping enforcement, analysis, or query behavior — that would be
over-engineering a fake whose only job is to let the persistence contract be
tested deterministically and offline.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from attribution_platform.dataplane.errors import ElasticIntegrationError


def _check_properties(index: str, properties: Mapping[str, Any], path: str = "") -> None:
    for name, spec in properties.items():
        where = f"{path}{name}"
        if not isinstance(spec, Mapping) or ("type" not in spec and "properties" not in spec):
            raise ElasticIntegrationError(
                f"mapping for {index!r} field {where!r} has neither 'type' nor 'properties'"
            )
        nested = spec.get("properties")
        if nested is not None:
            if not isinstance(nested, Mapping):
                raise ElasticIntegrationError(f"mapping for {index!r} field {where!r} is malformed")
            _check_properties(index, nested, f"{where}.")


class FakeElasticClient:
    """In-memory stand-in for a real Elasticsearch client. Not thread-safe."""

    def __init__(self) -> None:
        self._mappings: dict[str, dict[str, Any]] = {}
        self._documents: dict[str, dict[str, dict[str, Any]]] = {}

    def ensure_index(self, index: str, mappings: Mapping[str, Any]) -> None:
        # The one piece of mapping enforcement modelled: every field definition
        # must be one Elasticsearch accepts as a "properties" entry (a "type"
        # or nested "properties"), so a wrongly nested mapping fails here as it
        # does on a real cluster.
        _check_properties(index, mappings)
        # Idempotent: re-creating an existing index is a documented no-op,
        # matching the real client's "already exists -> treat as success".
        if index not in self._mappings:
            self._mappings[index] = dict(mappings)
            self._documents[index] = {}

    def index_document(self, index: str, document_id: str, document: Mapping[str, Any]) -> None:
        if index not in self._documents:
            raise ElasticIntegrationError(
                f"cannot index into {index!r}: index does not exist (call ensure_index first)"
            )
        # Store a defensive copy so a caller mutating their own dict afterward
        # can never retroactively change what was "persisted".
        self._documents[index][document_id] = dict(document)

    def get_document(self, index: str, document_id: str) -> Mapping[str, Any] | None:
        stored = self._documents.get(index, {}).get(document_id)
        return dict(stored) if stored is not None else None

    def search(
        self,
        index: str,
        query: Mapping[str, Any],
        *,
        size: int,
        sort: Sequence[str] = (),
    ) -> tuple[Mapping[str, Any], ...]:
        """Bounded, read-only search (gate G1.1). This fake does **not**
        implement Elasticsearch's Query DSL -- ``query`` is accepted (to
        satisfy the Protocol) but ignored; it returns up to ``size`` of the
        documents already stored in ``index`` via ``index_document``, in
        insertion order. Real query matching is exactly the kind of
        Elasticsearch behavior this fake deliberately does not model (see
        the module docstring) -- a test needing to verify actual query
        construction should patch ``urllib.request.urlopen`` against
        ``ElasticsearchHttpClient`` instead. ``sort`` is honoured (ascending
        string order of each named top-level field, before the ``size``
        cap), as the cap's meaning depends on it."""
        if size <= 0:
            raise ElasticIntegrationError(f"search size must be positive, got {size}")
        documents = list(self._documents.get(index, {}).values())
        if sort:
            documents.sort(key=lambda doc: tuple(str(doc.get(name, "")) for name in sort))
        return tuple(dict(doc) for doc in documents[:size])

    # --- test-introspection helpers (not part of the ElasticClient Protocol) ---

    def document_count(self, index: str) -> int:
        """Number of documents currently stored in ``index`` (test convenience)."""
        return len(self._documents.get(index, {}))

    def mappings_for(self, index: str) -> Mapping[str, Any] | None:
        """The mappings ``ensure_index`` recorded for ``index`` (test convenience)."""
        return self._mappings.get(index)
