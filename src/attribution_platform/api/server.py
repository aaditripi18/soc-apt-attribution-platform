"""A minimal, stdlib-only HTTP surface over the read-model (gate G0.10).

"Use the smallest reasonable HTTP implementation; avoid introducing a web
framework unless strictly necessary" — this gate's instructions, and the
same "no new dependency unless genuinely required" discipline every prior
gate followed (G0.1/G0.2 read raw ATT&CK STIX JSON without
``mitreattack-python``; G0.8 talks to Elasticsearch with ``urllib``, not the
official client). docs/architecture/04-component-boundaries.md's original
sketch named FastAPI for the eventual read-model API; that remains a
reasonable choice **once** this layer needs routing/validation/OpenAPI
ergonomics it doesn't have yet (search/filter/query is explicitly deferred —
"NOT yet" in doc 13's G0.10 entry). For exactly two ID-addressed GET routes
with no query parameters and no request body, ``http.server`` from the
standard library is sufficient and adds nothing to pin or vendor. Revisit if
G0.10 grows real query capability; not a permanent constraint.

Routes (all GET, nothing else) — G0.10 plus ADR-0009 v1:

- ``GET /health``
- ``GET /investigations`` and ``GET /investigations/<investigation_id>``
- ``GET /units/<group_id>`` (correlation group + behavioral sequence +
  uncalibrated attribution analysis)
- ``GET /observations/<observation_id>``
- ``GET /evidence/<evidence_id>``

Routing and response-body construction are the **only** things this module
does. All read/validation/error-mapping logic lives in
:mod:`attribution_platform.api.read_model`; this module calls it, catches
:class:`~attribution_platform.api.errors.ApiError`, and writes the
corresponding HTTP status + JSON body. A successful body is exactly
:func:`attribution_platform.domain.to_canonical_json` applied to the returned
domain object (deterministic, sorted-key JSON — the same canonical form
G0.3 already defined; no second schema). An unrecognized route or HTTP
method needs no special handling: :class:`http.server.BaseHTTPRequestHandler`
returns 404/501 on its own when no route matches or no ``do_<METHOD>`` is
defined — there is deliberately no ``do_POST``/``do_PUT``/``do_DELETE`` here
(no mutation endpoints, per this gate's requirements).
"""

from __future__ import annotations

import json
from collections.abc import Callable
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import unquote, urlsplit

from attribution_platform.api.errors import ApiError, NotFoundError
from attribution_platform.api.read_model import (
    get_evidence,
    get_health,
    get_investigation,
    get_observation,
    get_unit,
    list_investigation_summaries,
)
from attribution_platform.dataplane import ElasticClient
from attribution_platform.domain import Evidence, Observation, to_canonical_json

#: Identifier-addressed routes -- resource name -> read-model function.
_ROUTES: dict[str, Callable[[ElasticClient, str], Any]] = {
    "observations": get_observation,
    "evidence": get_evidence,
    "investigations": get_investigation,
    "units": get_unit,
}
#: Collection routes (no identifier).
_COLLECTIONS: dict[str, Callable[[ElasticClient], Any]] = {
    "health": get_health,
    "investigations": list_investigation_summaries,
}


def _serialize(result: Any) -> str:
    """Domain objects in their canonical JSON form; read-model records as
    sorted-key JSON -- deterministic either way."""
    if isinstance(result, Observation | Evidence):
        return to_canonical_json(result)
    return json.dumps(result, sort_keys=True, separators=(",", ":"))


def _dispatch(path: str, client: ElasticClient) -> Any:
    """Resolve one request path to a stored domain object, or raise ApiError.

    ``path.lstrip("/").split("/", 1)`` (not a filtered split) deliberately
    distinguishes a genuinely missing identifier segment (``"/observations/"``
    -> ``["observations", ""]`` -> :class:`InvalidIdentifierError`, 400) from
    an unrecognized route shape (``"/observations"`` with no trailing slash,
    or an unknown resource name) -> :class:`NotFoundError`, 404.
    """
    segments = path.lstrip("/").split("/", 1)
    if len(segments) == 1:
        collection = _COLLECTIONS.get(segments[0])
        if collection is None:
            raise NotFoundError(f"no such route: {path!r}")
        return collection(client)
    resource, raw_identifier = segments
    read_model_fn = _ROUTES.get(resource)
    if read_model_fn is None:
        raise NotFoundError(f"no such route: {path!r}")
    return read_model_fn(client, unquote(raw_identifier))


def make_handler(client: ElasticClient) -> type[BaseHTTPRequestHandler]:
    """Build a ``BaseHTTPRequestHandler`` subclass bound to ``client``.

    A closure, not a constructor argument, because ``http.server`` always
    instantiates its handler class itself (once per request) with a fixed
    signature — this is the standard way to hand it per-server state.
    """

    class ReadModelHandler(BaseHTTPRequestHandler):
        server_version = "AttributionPlatformReadModelAPI/1.0"

        def do_GET(self) -> None:  # noqa: N802 - fixed name required by the base class
            path = urlsplit(self.path).path
            try:
                self._write_json(HTTPStatus.OK, _serialize(_dispatch(path, client)))
            except ApiError as exc:
                self._write_json(
                    exc.status_code, json.dumps({"error": exc.message}, sort_keys=True)
                )
            except Exception as exc:  # noqa: BLE001 - last-resort safety net, never silent
                self._write_json(
                    HTTPStatus.INTERNAL_SERVER_ERROR,
                    json.dumps({"error": f"unexpected server error: {exc}"}, sort_keys=True),
                )

        def _write_json(self, status: int, json_body: str) -> None:
            body = json_body.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            pass  # silence default stderr access logging; not needed at this gate

    return ReadModelHandler


def create_server(
    client: ElasticClient, *, host: str = "127.0.0.1", port: int = 0
) -> ThreadingHTTPServer:
    """Build (but do not start) a server bound to ``client``.

    ``port=0`` (the default) asks the OS for any free port — used by tests so
    they never collide with something already listening. Call
    ``server.serve_forever()`` to actually accept connections;
    ``server.server_address`` gives the bound ``(host, port)`` once created.
    """
    handler_cls = make_handler(client)
    return ThreadingHTTPServer((host, port), handler_cls)
