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
- **ADR-0009 v1 (implemented):** ``GET /health``, ``GET /investigations``,
  ``GET /investigations/<id>`` and ``GET /units/<group_id>`` over the records an
  engine investigation run persists (``attribution_platform.investigation``);
  attribution analyses are explicitly uncalibrated (no likelihood, confidence
  or ranking field exists).
- **ADR-0009 Amendment A (implemented):** unit search and filtering.
- **ADR-0016 (implemented):** ``context`` — pinned reference data (ATT&CK
  technique catalogue, coverage report, rule index) shaped once at start-up;
  ``GET /units/<id>/evidence``, ``GET /investigations/<id>/dossier``,
  ``GET /coverage``, ``GET /attack/techniques``; every route also under
  ``/api``; the built analyst frontend (``frontend/dist``) served as files.
- **Not yet implemented:** authentication (the server binds to localhost and is
  read-only); calibrated decisions (need a ``calibration_version``).
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
