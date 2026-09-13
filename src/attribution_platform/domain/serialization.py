"""Deterministic, framework-free serialization for domain contracts (gate G0.3).

Provides a minimal, stdlib-only representation suitable for *future*
persistence/API work without tying the domain layer to Elasticsearch, Kibana,
FastAPI, Pydantic, a database ORM, or any frontend model. G0.3 builds neither
the API nor Elastic mappings — this is only the canonical shape they will
later consume.

- :func:`to_serializable` converts a domain object into JSON-native Python
  types (``dict``/``list``/``str``/``int``/``float``/``bool``/``None``):
  frozen dataclasses -> ``dict`` (declaration field order), ``Enum`` -> its
  ``value``, ``datetime`` -> ISO-8601 string, ``tuple`` -> ``list``. Scalars
  pass through. The returned structure is a fresh, mutable copy — mutating it
  never affects the immutable source object.
- :func:`to_canonical_json` produces a stable, sorted-key JSON string,
  suitable as a deterministic hashing input in a later gate.

Determinism: for the same object, output is byte-stable. No timestamps,
randomness, or host state are introduced.
"""

from __future__ import annotations

import dataclasses
import json
from datetime import datetime
from enum import Enum
from typing import Any


def to_serializable(obj: Any) -> Any:
    """Recursively convert a domain object to JSON-native Python types."""
    if obj is None or isinstance(obj, str | int | float | bool):
        return obj
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, datetime):
        return obj.isoformat()
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return {f.name: to_serializable(getattr(obj, f.name)) for f in dataclasses.fields(obj)}
    if isinstance(obj, tuple | list):
        return [to_serializable(v) for v in obj]
    if isinstance(obj, dict):
        # Not used by the current contracts (they hold no mappings), but
        # handled defensively so a future mapping field serializes sanely.
        return {str(k): to_serializable(v) for k, v in obj.items()}
    raise TypeError(f"to_serializable: unsupported type {type(obj).__name__}")


def to_canonical_json(obj: Any) -> str:
    """Serialize ``obj`` to a deterministic, sorted-key, compact JSON string."""
    return json.dumps(
        to_serializable(obj),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
