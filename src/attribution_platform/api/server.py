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
- ``GET /units?investigation=&technique=&host=&candidate=&limit=`` and
  ``GET /investigations/<investigation_id>/units`` (ADR-0009 Amendment A)
- ``GET /observations/<observation_id>``
- ``GET /evidence/<evidence_id>``
- ADR-0016 (the analyst frontend's reads; need an :class:`ApiContext`):
  ``GET /units/<group_id>/evidence``, ``GET /investigations/<id>/dossier``,
  ``GET /investigations/<id>/assessment`` (ADR-0017),
  ``GET /investigations/<id>/activity`` and ``GET /investigations/<id>/emulation``
  (ADR-0019), ``GET /investigations/<id>/profile-match`` (ADR-0021),
  ``GET /coverage``, ``GET /attack/techniques``, ``GET /attack/groups`` (ADR-0021),
  ``GET /validation`` (ADR-0017)

Every route also answers under ``/api`` (``/api/units/...``): the frontend
calls that prefix, so the same paths work behind the Vite dev proxy and when
this server hands out the built frontend itself. With a ``static_dir`` in the
context, ``/``, ``/index.html``, ``/assets/...`` and the favicon are served from
it (files only, never outside it); the frontend routes by URL fragment, so no
page path collides with a JSON route.

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
defined. Mutation methods (``POST``/``PUT``/``PATCH``/``DELETE``) are explicitly
refused with 501 — no stored record can be changed. The one route that
accepts input is ``POST /uploads`` (ADR-0020): it hands the server a new
recording to investigate, only when the server was started with an upload
service; ``GET /uploads`` and ``GET /uploads/<job_id>`` report on it.
``POST /assistant`` (ADR-0022) answers an analyst's question about one
investigation with a language model served by Ollama on this machine;
``GET /assistant`` says whether that model is ready. For a refused method the request body is
drained first so the refusal always reaches the client (a real, intermittent
connection-reset on Windows when it was not).
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import parse_qs, unquote, urlsplit

from attribution_platform.api.assistant import AssistantDisabledError, AssistantService
from attribution_platform.api.assistant import disabled as assistant_disabled
from attribution_platform.api.context import ApiContext
from attribution_platform.api.errors import ApiError, InvalidIdentifierError, NotFoundError
from attribution_platform.api.read_model import (
    UNIT_SEARCH_PARAMETERS,
    get_assessment,
    get_assistant_digest,
    get_attack_groups,
    get_attack_techniques,
    get_coverage,
    get_dossier,
    get_emulation_comparison,
    get_evidence,
    get_health,
    get_investigation,
    get_investigation_activity,
    get_investigation_context,
    get_investigation_observables,
    get_measurements,
    get_observation,
    get_profile_match,
    get_unit,
    get_unit_evidence,
    get_validation,
    list_investigation_summaries,
    search_units,
)
from attribution_platform.api.uploads import (
    LengthRequiredError,
    UploadRefusedError,
    UploadsDisabledError,
    UploadService,
    disabled,
    is_loopback,
    same_origin,
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
#: Largest request body drained before refusing a mutation method.
_MAX_DRAINED_BODY = 1 << 20

#: Collection routes (no identifier).
_COLLECTIONS: dict[str, Callable[[ElasticClient, Mapping[str, str]], Any]] = {
    "health": lambda client, _params: get_health(client),
    "investigations": lambda client, _params: list_investigation_summaries(client),
    "units": search_units,
}
#: Query parameters each collection accepts (anything else -> 400).
_COLLECTION_PARAMETERS: dict[str, frozenset[str]] = {
    "health": frozenset(),
    "investigations": frozenset(),
    "units": UNIT_SEARCH_PARAMETERS,
}
_UNITS_SUFFIX = "/units"
_DOSSIER_SUFFIX = "/dossier"
#: /investigations/<id>/<suffix> routes over stored records alone.
_INVESTIGATION_VIEWS: dict[str, Callable[[ElasticClient, str], Any]] = {
    "/assessment": get_assessment,
    "/activity": get_investigation_activity,
    "/context": get_investigation_context,
    "/emulation": get_emulation_comparison,
    "/profile-match": get_profile_match,
    "/observables": get_investigation_observables,
}
_EVIDENCE_SUFFIX = "/evidence"
#: Reference routes answered from the :class:`ApiContext` alone.
_REFERENCE: dict[str, Callable[[ApiContext], Any]] = {
    "coverage": get_coverage,
    "attack/techniques": get_attack_techniques,
    "attack/groups": get_attack_groups,
    "validation": get_validation,
    "validation/measurements": get_measurements,
}
_API_PREFIX = "/api"
#: ADR-0020: the one route that accepts input.
_UPLOADS = "/uploads"
#: ADR-0022: the analyst assistant (a question in, a generated answer out).
_ASSISTANT = "/assistant"
#: ADR-0028: the status of a live session (sources, window, recent cycles).
_LIVE = "/live"
#: Largest assistant request body read.
_MAX_ASSISTANT_BODY = 256 * 1024
#: Built-frontend paths served from ``static_dir`` (everything else is JSON).
_STATIC_EXACT = frozenset({"/", "/index.html", "/favicon.svg", "/favicon.ico"})
_STATIC_PREFIX = "/assets/"
_CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".svg": "image/svg+xml",
    ".json": "application/json",
    ".woff2": "font/woff2",
    ".woff": "font/woff",
    ".ico": "image/x-icon",
    ".png": "image/png",
}


def _parameters(query: str) -> dict[str, str]:
    """Query-string parameters; a repeated parameter is refused (400)."""
    parsed = parse_qs(query, keep_blank_values=True, strict_parsing=False)
    repeated = sorted(name for name, values in parsed.items() if len(values) > 1)
    if repeated:
        raise InvalidIdentifierError(
            f"query parameter(s) given more than once: {', '.join(repeated)}"
        )
    return {name: values[0] for name, values in parsed.items()}


def _serialize(result: Any) -> str:
    """Domain objects in their canonical JSON form; read-model records as
    sorted-key JSON -- deterministic either way."""
    if isinstance(result, Observation | Evidence):
        return to_canonical_json(result)
    return json.dumps(result, sort_keys=True, separators=(",", ":"))


def static_file(static_dir: Path, path: str) -> Path | None:
    """The file under ``static_dir`` a request path names, or ``None`` when the
    path is not a frontend path, escapes the directory or is not a file."""
    if path not in _STATIC_EXACT and not path.startswith(_STATIC_PREFIX):
        return None
    relative = "index.html" if path == "/" else unquote(path).lstrip("/")
    root = static_dir.resolve()
    candidate = (root / relative).resolve()
    if not candidate.is_relative_to(root) or not candidate.is_file():
        return None
    return candidate


def _dispatch(
    path: str, client: ElasticClient, query: str = "", context: ApiContext | None = None
) -> Any:
    """Resolve one request path to a stored domain object, or raise ApiError.

    ``path.lstrip("/").split("/", 1)`` (not a filtered split) deliberately
    distinguishes a genuinely missing identifier segment (``"/observations/"``
    -> ``["observations", ""]`` -> :class:`InvalidIdentifierError`, 400) from
    an unrecognized route shape (``"/observations"`` with no trailing slash,
    or an unknown resource name) -> :class:`NotFoundError`, 404.
    """
    context = context if context is not None else ApiContext()
    params = _parameters(query)
    reference = _REFERENCE.get(path.strip("/"))
    if reference is not None:
        if params:
            raise InvalidIdentifierError("this route takes no query parameters")
        return reference(context)
    segments = path.lstrip("/").split("/", 1)
    if len(segments) == 1:
        collection = _COLLECTIONS.get(segments[0])
        if collection is None:
            raise NotFoundError(f"no such route: {path!r}")
        unknown = sorted(set(params) - _COLLECTION_PARAMETERS[segments[0]])
        if unknown:
            raise InvalidIdentifierError(f"unknown query parameter(s): {', '.join(unknown)}")
        return collection(client, params)
    resource, raw_identifier = segments
    if resource == "investigations" and raw_identifier.endswith(_UNITS_SUFFIX):
        # /investigations/{id}/units: the unit search scoped to one investigation
        if "investigation" in params:
            raise InvalidIdentifierError("the investigation is given by the path, not a parameter")
        investigation_id = unquote(raw_identifier[: -len(_UNITS_SUFFIX)])
        get_investigation(client, investigation_id)  # 400 / 404 if absent
        return search_units(client, {**params, "investigation": investigation_id})
    if params:
        raise InvalidIdentifierError("this route takes no query parameters")
    if resource == "investigations":
        for suffix, view in _INVESTIGATION_VIEWS.items():
            if raw_identifier.endswith(suffix):
                return view(client, unquote(raw_identifier[: -len(suffix)]))
    if resource == "investigations" and raw_identifier.endswith(_DOSSIER_SUFFIX):
        return get_dossier(client, context, unquote(raw_identifier[: -len(_DOSSIER_SUFFIX)]))
    if resource == "units" and raw_identifier.endswith(_EVIDENCE_SUFFIX):
        return get_unit_evidence(client, context, unquote(raw_identifier[: -len(_EVIDENCE_SUFFIX)]))
    read_model_fn = _ROUTES.get(resource)
    if read_model_fn is None:
        raise NotFoundError(f"no such route: {path!r}")
    return read_model_fn(client, unquote(raw_identifier))


class LiveStatus(Protocol):
    """A live session as the server sees it: something that describes itself."""

    def describe(self) -> dict[str, Any]: ...


def make_handler(
    client: ElasticClient,
    context: ApiContext | None = None,
    uploads: UploadService | None = None,
    assistant: AssistantService | None = None,
    live: LiveStatus | None = None,
) -> type[BaseHTTPRequestHandler]:
    """Build a ``BaseHTTPRequestHandler`` subclass bound to ``client``.

    A closure, not a constructor argument, because ``http.server`` always
    instantiates its handler class itself (once per request) with a fixed
    signature — this is the standard way to hand it per-server state.
    """

    class ReadModelHandler(BaseHTTPRequestHandler):
        server_version = "AttributionPlatformReadModelAPI/1.0"

        def do_GET(self) -> None:  # noqa: N802 - fixed name required by the base class
            parts = urlsplit(self.path)
            path, query = parts.path, parts.query
            if path == _API_PREFIX or path.startswith(_API_PREFIX + "/"):
                path = path[len(_API_PREFIX) :] or "/"
            elif context is not None and context.static_dir is not None:
                found = static_file(context.static_dir, path)
                if found is not None:
                    self._write_file(found, immutable=path.startswith(_STATIC_PREFIX))
                    return
            try:
                if path == _ASSISTANT:
                    described = assistant.describe() if assistant else assistant_disabled()
                    self._write_json(HTTPStatus.OK, _serialize(described))
                    return
                if path == _UPLOADS or path.startswith(_UPLOADS + "/"):
                    self._write_json(HTTPStatus.OK, _serialize(self._uploads(path)))
                    return
                if path == _LIVE:
                    status = live.describe() if live is not None else {"enabled": False}
                    self._write_json(HTTPStatus.OK, _serialize(status))
                    return
                self._write_json(HTTPStatus.OK, _serialize(_dispatch(path, client, query, context)))
            except ApiError as exc:
                self._write_json(
                    exc.status_code, json.dumps({"error": exc.message}, sort_keys=True)
                )
            except Exception as exc:  # noqa: BLE001 - last-resort safety net, never silent
                self._write_json(
                    HTTPStatus.INTERNAL_SERVER_ERROR,
                    json.dumps({"error": f"unexpected server error: {exc}"}, sort_keys=True),
                )

        def _uploads(self, path: str) -> Any:
            """``GET /uploads`` (the service and its jobs) and ``GET /uploads/<job_id>``."""
            if path == _UPLOADS:
                return uploads.describe() if uploads is not None else disabled()
            if uploads is None:
                raise NotFoundError(f"no such route: {path!r}")
            return uploads.job(unquote(path[len(_UPLOADS) + 1 :]))

        def do_POST(self) -> None:  # noqa: N802 - fixed name required by the base class
            """``POST /api/uploads?name=<file name>`` with the archive as the raw
            body (ADR-0020). Every other POST is refused like any mutation."""
            parts = urlsplit(self.path)
            if parts.path in (_ASSISTANT, _API_PREFIX + _ASSISTANT):
                self._ask_assistant()
                return
            if parts.path not in (_UPLOADS, _API_PREFIX + _UPLOADS):
                self._refuse_mutation()
                return
            # The body is not read on a refusal, so the connection cannot be reused.
            self.close_connection = True
            try:
                if uploads is None:
                    raise UploadsDisabledError("this server was started without the upload service")
                if not is_loopback(str(self.client_address[0])):
                    raise UploadRefusedError("uploads are accepted from this machine only")
                if not same_origin(self.headers.get("Origin"), self.headers.get("Host")):
                    raise UploadRefusedError("uploads are accepted from this console only")
                params = _parameters(parts.query)
                if set(params) != {"name"}:
                    raise InvalidIdentifierError("give the file name as ?name=<file name>")
                raw_length = self.headers.get("Content-Length")
                if raw_length is None or not raw_length.isdigit():
                    raise LengthRequiredError("the upload must declare its Content-Length")
                job = uploads.receive(params["name"], self.rfile, int(raw_length))
                self.close_connection = False
                self._write_json(HTTPStatus.ACCEPTED, _serialize(job))
            except ApiError as exc:
                self._write_json(
                    exc.status_code, json.dumps({"error": exc.message}, sort_keys=True)
                )
            except Exception as exc:  # noqa: BLE001 - last-resort safety net, never silent
                self._write_json(
                    HTTPStatus.INTERNAL_SERVER_ERROR,
                    json.dumps({"error": f"unexpected server error: {exc}"}, sort_keys=True),
                )

        def _ask_assistant(self) -> None:
            """``POST /api/assistant`` — ``{investigation_id, messages}`` in, a
            generated answer out (ADR-0022). Same callers as an upload: this
            machine, this console."""
            self.close_connection = True
            try:
                if assistant is None:
                    raise AssistantDisabledError("the assistant is turned off on this server")
                if not is_loopback(str(self.client_address[0])):
                    raise UploadRefusedError("the assistant answers this machine only")
                if not same_origin(self.headers.get("Origin"), self.headers.get("Host")):
                    raise UploadRefusedError("the assistant answers this console only")
                raw_length = self.headers.get("Content-Length")
                if raw_length is None or not raw_length.isdigit():
                    raise LengthRequiredError("the request must declare its Content-Length")
                if int(raw_length) > _MAX_ASSISTANT_BODY:
                    raise InvalidIdentifierError("the request is too large")
                try:
                    request = json.loads(self.rfile.read(int(raw_length)).decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise InvalidIdentifierError("the request body is not JSON") from exc
                self.close_connection = False
                if not isinstance(request, dict) or not isinstance(
                    request.get("investigation_id"), str
                ):
                    raise InvalidIdentifierError("give investigation_id and messages")
                digest = get_assistant_digest(
                    client, context or ApiContext(), request["investigation_id"]
                )
                answer = assistant.answer(digest, request.get("messages"))
                self._write_json(HTTPStatus.OK, _serialize(answer))
            except ApiError as exc:
                self._write_json(
                    exc.status_code, json.dumps({"error": exc.message}, sort_keys=True)
                )
            except Exception as exc:  # noqa: BLE001 - last-resort safety net, never silent
                self._write_json(
                    HTTPStatus.INTERNAL_SERVER_ERROR,
                    json.dumps({"error": f"unexpected server error: {exc}"}, sort_keys=True),
                )

        def _refuse_mutation(self) -> None:
            """Every mutation method is refused with 501 (read-only API). The
            request body is drained first (bounded) so the client always
            receives the response instead of a connection reset."""
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                length = 0
            if 0 < length <= _MAX_DRAINED_BODY:
                self.rfile.read(length)
            else:
                self.close_connection = True
            self._write_json(
                HTTPStatus.NOT_IMPLEMENTED,
                json.dumps(
                    {"error": f"read-only API: {self.command} is not supported"}, sort_keys=True
                ),
            )

        do_PUT = do_PATCH = do_DELETE = _refuse_mutation  # noqa: N815

        def _write_json(self, status: int, json_body: str) -> None:
            body = json_body.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)

        def _write_file(self, path: Path, *, immutable: bool) -> None:
            """A built-frontend file. Hashed assets may be cached for good; the
            page itself is always revalidated so a rebuild is picked up."""
            body = path.read_bytes()
            self.send_response(HTTPStatus.OK)
            self.send_header(
                "Content-Type", _CONTENT_TYPES.get(path.suffix.lower(), "application/octet-stream")
            )
            self.send_header("Content-Length", str(len(body)))
            self.send_header(
                "Cache-Control", "public, max-age=31536000, immutable" if immutable else "no-cache"
            )
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            pass  # silence default stderr access logging; not needed at this gate

    return ReadModelHandler


def create_server(
    client: ElasticClient,
    *,
    host: str = "127.0.0.1",
    port: int = 0,
    context: ApiContext | None = None,
    uploads: UploadService | None = None,
    assistant: AssistantService | None = None,
    live: LiveStatus | None = None,
) -> ThreadingHTTPServer:
    """Build (but do not start) a server bound to ``client``.

    ``context`` (ADR-0016) adds the reference routes and, when it names a built
    frontend, serves it; without one the server is the plain record API.

    ``port=0`` (the default) asks the OS for any free port — used by tests so
    they never collide with something already listening. Call
    ``server.serve_forever()`` to actually accept connections;
    ``server.server_address`` gives the bound ``(host, port)`` once created.
    """
    handler_cls = make_handler(client, context, uploads, assistant, live)
    return ThreadingHTTPServer((host, port), handler_cls)
