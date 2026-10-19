"""Poll Elasticsearch for new telemetry documents (ADR-0028 D1).

An :class:`ElasticsearchSource` reads, on each call, the documents of an index
pattern whose time field is at or after its checkpoint, in ascending time order,
and returns each document's ``_source`` as one JSON line — the shape the
recording pipeline already reads for Winlogbeat / Elastic Agent event logs.
It is read-only and bounded (one page per request).

The checkpoint is the last time read plus the ids already read *at* that time;
the query excludes those ids, so documents sharing a timestamp are neither
skipped nor read twice, however many there are.

Which time field: ``event.ingested`` (set by the ingest pipeline of Elastic
Agent integrations) only ever grows as documents arrive, so a late-arriving
event is still read; ``@timestamp`` is the event's own time, and a document
that arrives after newer ones were read is missed. The field is the caller's
choice, stated in the status view.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol


class HitSearcher(Protocol):
    def search_hits(
        self, index: str, query: Mapping[str, Any], *, size: int, sort: Sequence[str]
    ) -> tuple[tuple[str, Mapping[str, Any]], ...]: ...


def _time_of(document: Mapping[str, Any], dotted: str) -> Any:
    value: Any = document
    for part in dotted.split("."):
        if not isinstance(value, Mapping) or part not in value:
            # a flattened key ("event.ingested") is also valid in _source
            return document.get(dotted) if isinstance(document, Mapping) else None
        value = value[part]
    return value


@dataclass
class ElasticsearchSource:
    client: HitSearcher
    index: str
    time_field: str = "event.ingested"
    page_size: int = 500
    max_pages: int = 20
    checkpoint: str | None = None
    ids_at_checkpoint: set[str] = field(default_factory=set)
    documents_read: int = 0
    documents_without_time: int = 0

    @property
    def path(self) -> str:  # the status view names a source by this
        return f"elasticsearch:{self.index} ({self.time_field})"

    @property
    def offset(self) -> int:
        return self.documents_read

    dropped_partial_lines = 0
    undecodable_lines = 0

    def read(self) -> list[str]:
        lines: list[str] = []
        for _ in range(self.max_pages):
            filters: list[dict[str, Any]] = [{"exists": {"field": self.time_field}}]
            if self.checkpoint is not None:
                filters.append({"range": {self.time_field: {"gte": self.checkpoint}}})
            query: dict[str, Any] = {"bool": {"filter": filters}}
            if self.ids_at_checkpoint:
                query["bool"]["must_not"] = [{"ids": {"values": sorted(self.ids_at_checkpoint)}}]
            hits = self.client.search_hits(
                self.index, query, size=self.page_size, sort=(self.time_field,)
            )
            fresh = 0
            for document_id, source in hits:
                when = _time_of(source, self.time_field)
                if when is None:
                    self.documents_without_time += 1
                    continue
                when = str(when)
                if when != self.checkpoint:
                    self.checkpoint, self.ids_at_checkpoint = when, set()
                self.ids_at_checkpoint.add(document_id)
                lines.append(json.dumps(source, sort_keys=True, separators=(",", ":")))
                fresh += 1
            self.documents_read += fresh
            if len(hits) < self.page_size:
                break
        return lines


__all__ = ["ElasticsearchSource", "HitSearcher"]
