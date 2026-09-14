"""Typed, HTTP-status-carrying errors for the read-model API (gate G0.10).

Continues the per-layer fail-closed error pattern already used throughout
(:class:`attribution_platform.domain.errors.DomainContractError`,
:class:`attribution_platform.dataplane.errors.ElasticIntegrationError`, ...),
adapted for a boundary that must answer with an HTTP status, not just raise.
Each subclass fixes exactly one ``status_code`` — the HTTP server layer
(:mod:`attribution_platform.api.server`) never has to decide a status itself,
only read the one the read-model layer (:mod:`attribution_platform.api.read_model`)
already chose.

Four categories, matching the gate's requirement exactly:

- :class:`InvalidIdentifierError` (400) — the caller supplied an empty/
  malformed identifier; never reaches the dataplane.
- :class:`NotFoundError` (404) — a well-formed identifier with no matching
  stored document (or an unrecognized route).
- :class:`BackendError` (502) — the dataplane could not fulfill the read, for
  *any* reason: a stored document that fails to reconstruct into a valid
  domain object (malformed stored data), or a transport/auth/connectivity
  failure. Both surface from the dataplane as the same
  :class:`~attribution_platform.dataplane.errors.ElasticIntegrationError`, so
  both are represented as the same 502 at this boundary rather than the API
  layer guessing which one occurred from a message string.
"""

from __future__ import annotations


class ApiError(Exception):
    """Base class for every typed API error. Never raised directly."""

    status_code: int

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class InvalidIdentifierError(ApiError):
    """The caller supplied an empty or malformed identifier (HTTP 400)."""

    status_code = 400


class NotFoundError(ApiError):
    """No stored document (or no such route) matches the request (HTTP 404)."""

    status_code = 404


class BackendError(ApiError):
    """The dataplane could not fulfill the read (HTTP 502) — malformed stored
    data or a transport/auth/connectivity failure; see the module docstring
    for why both map here."""

    status_code = 502
