"""Read-model API boundary.

Per ADR-0001 (D11) and docs/architecture/04-component-boundaries.md: serves
stored investigations/evidence/results as read-model JSON. This layer
performs NO computation — no attribution, no scoring, no correlation. The
(future) analyst frontend renders what this API returns; it never computes
anything itself either.

Gate status:

- **G0.10 (implemented):** ``errors`` — the typed, HTTP-status-carrying
  ``ApiError`` hierarchy (``InvalidIdentifierError`` 400,
  ``NotFoundError`` 404, ``BackendError`` 502); ``read_model`` —
  ``get_observation``/``get_evidence``, the entire "L3 -> L4" contract
  (ID-addressed reads returning the stored domain object or a typed error),
  depending only on the G0.8 ``ElasticClient`` abstraction; ``server`` — a
  minimal, stdlib-only (``http.server``) HTTP surface exposing exactly
  ``GET /observations/<observation_id>`` and ``GET /evidence/<evidence_id>``,
  with no mutation endpoints; ``__main__`` — an optional manual entrypoint
  (``python -m attribution_platform.api``) to run the API against a real
  Elasticsearch once one is available.
- **Not yet implemented:** search/filter/query endpoints; authentication;
  attribution endpoints; any frontend files.
"""

from __future__ import annotations

from attribution_platform.api.errors import (
    ApiError,
    BackendError,
    InvalidIdentifierError,
    NotFoundError,
)
from attribution_platform.api.read_model import get_evidence, get_observation
from attribution_platform.api.server import create_server, make_handler

__all__ = [
    "ApiError",
    "InvalidIdentifierError",
    "NotFoundError",
    "BackendError",
    "get_observation",
    "get_evidence",
    "create_server",
    "make_handler",
]
