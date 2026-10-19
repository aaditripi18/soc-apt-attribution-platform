"""A thin, stdlib-only Elasticsearch REST client (gate G0.8).

Doc 13's G0.8 objective is explicit: "a **thin** Elastic client against the
running cluster." This talks directly to the documented Elasticsearch HTTP
API (index-create, document index, document get) using only
``urllib.request``/``ssl``/``json`` from the standard library — the same
"no new dependency unless genuinely required" discipline every prior gate
followed (G0.1/G0.2 read raw ATT&CK STIX JSON without ``mitreattack-python``;
``scripts/acquire_attack_bundle.py`` fetches over HTTPS with ``urllib``, not
``requests``). The official ``elasticsearch`` Python package was considered
and rejected for this gate: it is not required for four REST calls, and
adding it would mean pinning and vendoring a client whose version must track
the server's major version — a real cost for a "thin client" gate. Revisit
this decision if a later gate's needs (bulk ingestion at scale, scroll/PIT
search, query DSL ergonomics) make the hand-rolled client materially worse
than the official one; that is a deliberate future trade-off, not an
oversight now.

Every failure — connection refused, TLS failure, auth failure, a non-2xx
response, a response that is not valid JSON — is wrapped in
:class:`~attribution_platform.dataplane.errors.ElasticIntegrationError`
(the ``ElasticClient`` Protocol's one error type). Request construction and
error handling are unit-tested with a patched ``urllib.request.urlopen``; the
whole read model is verified against a real Elasticsearch 8.15.3 cluster (the
G0.7 compose stack) by the opt-in ``tests/test_live_elasticsearch.py``
(ADR-0009 Amendment B).
"""

from __future__ import annotations

import base64
import json
import ssl
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping, Sequence
from typing import Any

from attribution_platform.dataplane.errors import ElasticIntegrationError


def _segment(value: str) -> str:
    """One URL path segment: index names and document ids are caller data
    (ids embed host names and rule ids), so every reserved character is
    percent-encoded — a ``/``, ``?`` or ``#`` can never re-route a request."""
    return urllib.parse.quote(value, safe="")


class ElasticsearchHttpClient:
    """A minimal REST client implementing the ``ElasticClient`` Protocol.

    - ``base_url``: e.g. ``"https://localhost:9200"`` (the G0.7 compose stack
      maps Elasticsearch to this address by default).
    - ``username``/``password``: HTTP Basic credentials (the G0.7 compose
      stack's ``elastic`` superuser, or a narrower-scoped user in a later
      gate).
    - ``ca_cert_path``: path to the CA certificate that signed the cluster's
      TLS certificate (the G0.7 compose stack's ``setup`` container generates
      one at ``config/certs/ca/ca.crt`` inside its shared volume). Required
      for real TLS verification against that self-signed CA.
    - ``verify_tls``: set ``False`` only for a throwaway local experiment
      where extracting the CA file is inconvenient — this disables all TLS
      certificate validation and must never be used against anything but a
      disposable dev cluster.
    - ``timeout``: per-request timeout in seconds.
    """

    def __init__(
        self,
        base_url: str,
        *,
        username: str,
        password: str,
        ca_cert_path: str | None = None,
        verify_tls: bool = True,
        timeout: float = 10.0,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._auth_header = "Basic " + base64.b64encode(f"{username}:{password}".encode()).decode(
            "ascii"
        )
        self._timeout = timeout
        if not verify_tls:
            self._ssl_context = ssl._create_unverified_context()  # noqa: S323 - explicit opt-in, dev-only
        else:
            self._ssl_context = ssl.create_default_context(cafile=ca_cert_path)

    def _request(self, method: str, path: str, body: Mapping[str, Any] | None) -> tuple[int, Any]:
        url = f"{self._base_url}{path}"
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Authorization", self._auth_header)
        req.add_header("Content-Type", "application/json")
        req.add_header("Accept", "application/json")
        try:
            with urllib.request.urlopen(  # noqa: S310 - fixed https base_url, JSON only
                req, timeout=self._timeout, context=self._ssl_context
            ) as resp:
                status = resp.status
                raw = resp.read()
        except urllib.error.HTTPError as exc:
            status = exc.code
            raw = exc.read()
        except (urllib.error.URLError, TimeoutError, ssl.SSLError, OSError) as exc:
            raise ElasticIntegrationError(
                f"{method} {path} failed to reach Elasticsearch: {exc}"
            ) from exc

        parsed: Any = None
        if raw:
            try:
                parsed = json.loads(raw.decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                raise ElasticIntegrationError(
                    f"{method} {path} returned a non-JSON response (status {status}): {exc}"
                ) from exc
        return status, parsed

    def ensure_index(self, index: str, mappings: Mapping[str, Any]) -> None:
        status, parsed = self._request(
            "PUT", f"/{_segment(index)}", {"mappings": {"properties": dict(mappings)}}
        )
        if status in (200, 201):
            return
        error_type = None
        if isinstance(parsed, dict):
            error_type = (
                parsed.get("error", {}).get("type")
                if isinstance(parsed.get("error"), dict)
                else None
            )
        if status == 400 and error_type == "resource_already_exists_exception":
            return  # idempotent: already created, nothing to do
        raise ElasticIntegrationError(
            f"failed to create index {index!r} (status {status}): {parsed!r}"
        )

    def index_document(self, index: str, document_id: str, document: Mapping[str, Any]) -> None:
        status, parsed = self._request(
            "PUT", f"/{_segment(index)}/_doc/{_segment(document_id)}", dict(document)
        )
        if status not in (200, 201):
            raise ElasticIntegrationError(
                f"failed to index document {document_id!r} into {index!r} "
                f"(status {status}): {parsed!r}"
            )

    def get_document(self, index: str, document_id: str) -> Mapping[str, Any] | None:
        status, parsed = self._request(
            "GET", f"/{_segment(index)}/_doc/{_segment(document_id)}", None
        )
        if status == 404:
            return None
        if status != 200:
            raise ElasticIntegrationError(
                f"failed to get document {document_id!r} from {index!r} "
                f"(status {status}): {parsed!r}"
            )
        if not isinstance(parsed, dict) or "_source" not in parsed:
            raise ElasticIntegrationError(
                f"unexpected response shape reading {document_id!r} from {index!r}: {parsed!r}"
            )
        source = parsed["_source"]
        if not isinstance(source, dict):
            raise ElasticIntegrationError(
                f"'_source' for {document_id!r} in {index!r} was not an object: {source!r}"
            )
        return source

    def search(
        self,
        index: str,
        query: Mapping[str, Any],
        *,
        size: int,
        sort: Sequence[str] = (),
    ) -> tuple[Mapping[str, Any], ...]:
        """Bounded, read-only search (gate G1.1): ``POST /{index}/_search``
        with the given Query DSL body, an optional ascending ``sort`` and a
        hard ``size`` cap. Returns each hit's ``_source``. No
        scroll/point-in-time — a single bounded page."""
        if size <= 0:
            raise ElasticIntegrationError(f"search size must be positive, got {size}")
        body: dict[str, Any] = {"query": dict(query), "size": size}
        if sort:
            body["sort"] = [{name: {"order": "asc"}} for name in sort]
        status, parsed = self._request("POST", f"/{_segment(index)}/_search", body)
        if status != 200:
            raise ElasticIntegrationError(
                f"search on {index!r} failed (status {status}): {parsed!r}"
            )
        if not isinstance(parsed, dict) or not isinstance(parsed.get("hits"), dict):
            raise ElasticIntegrationError(
                f"unexpected search response shape from {index!r}: {parsed!r}"
            )
        raw_hits = parsed["hits"].get("hits")
        if not isinstance(raw_hits, list):
            raise ElasticIntegrationError(
                f"unexpected search response shape from {index!r}: {parsed!r}"
            )
        sources: list[Mapping[str, Any]] = []
        for hit in raw_hits:
            if not isinstance(hit, dict) or not isinstance(hit.get("_source"), dict):
                raise ElasticIntegrationError(
                    f"a search hit from {index!r} had an unexpected shape: {hit!r}"
                )
            sources.append(hit["_source"])
        return tuple(sources)

    def search_hits(
        self,
        index: str,
        query: Mapping[str, Any],
        *,
        size: int,
        sort: Sequence[str],
    ) -> tuple[tuple[str, Mapping[str, Any]], ...]:
        """Like :meth:`search`, read-only and bounded, but each hit with its
        document id: ``(_id, _source)``. Live polling (ADR-0028 D1) needs the
        id to tell a document already read from a new one at the same time."""
        if size <= 0:
            raise ElasticIntegrationError(f"search size must be positive, got {size}")
        body = {
            "query": dict(query),
            "size": size,
            "sort": [{name: {"order": "asc"}} for name in sort],
        }
        status, parsed = self._request("POST", f"/{_segment(index)}/_search", body)
        if status != 200:
            raise ElasticIntegrationError(
                f"search on {index!r} failed (status {status}): {parsed!r}"
            )
        hits = parsed.get("hits", {}).get("hits") if isinstance(parsed, dict) else None
        if not isinstance(hits, list):
            raise ElasticIntegrationError(
                f"unexpected search response shape from {index!r}: {parsed!r}"
            )
        found: list[tuple[str, Mapping[str, Any]]] = []
        for hit in hits:
            if (
                not isinstance(hit, dict)
                or not isinstance(hit.get("_id"), str)
                or not isinstance(hit.get("_source"), dict)
            ):
                raise ElasticIntegrationError(
                    f"a search hit from {index!r} had an unexpected shape: {hit!r}"
                )
            found.append((hit["_id"], hit["_source"]))
        return tuple(found)
