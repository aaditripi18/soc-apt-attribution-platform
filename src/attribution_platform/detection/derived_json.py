"""How Elastic pipelines render a logged JSON object (ADR-0015 D2).

Two renderings recur across Elastic's integrations, and rules read both:

* **Java's ``Map.toString()``** — a painless ``obj.toString()`` puts the whole
  object in one keyword field (CloudTrail's ``aws.cloudtrail.request_parameters``):
  ``{userName=Bob, tags=[{key=a, value=b}], force=true}``, with the keys in
  ``java.util.HashMap`` iteration order (:func:`java_hashmap_order`). Reproduced
  by :func:`java_to_string`.
* **A ``flattened`` field** — the object is indexed with every leaf reachable by
  its dotted key path, arrays transparent, every leaf a keyword string
  (``aws.cloudtrail.flattened.request_parameters.userName``). Reproduced by
  :func:`flattened_leaves`.

Pipelines first remove empty values (``null``, ``""``, sometimes ``"-"`` /
``"none"``, and containers left empty); each caller names the scalars its
pipeline removes.

Both work from the object's compact JSON text as the adapter kept it.
"""

from __future__ import annotations

import functools
import json
from collections.abc import Mapping, Sequence
from decimal import Decimal
from types import MappingProxyType
from typing import Any


def java_double(value: float) -> str:
    """Java's ``Double.toString`` (shortest repr; JDK 19+): plain decimal for
    ``1e-3 <= |d| < 1e7``, otherwise computerized scientific notation."""
    if value != value:
        return "NaN"
    if value in (float("inf"), float("-inf")):
        return "Infinity" if value > 0 else "-Infinity"
    if value == 0:
        return "-0.0" if str(value).startswith("-") else "0.0"
    magnitude = abs(value)
    # The shortest decimal that round-trips (Python's repr), as digits x 10^exponent.
    _, digit_tuple, exponent = Decimal(repr(magnitude)).as_tuple()
    significant = "".join(str(d) for d in digit_tuple)
    stripped = significant.rstrip("0") or "0"
    exponent = int(exponent) + len(significant) - len(stripped)
    significant = stripped
    exp10 = len(significant) - 1 + exponent  # the scientific exponent
    sign = "-" if value < 0 else ""
    if 1e-3 <= magnitude < 1e7:
        if exp10 >= 0:
            integer = significant[: exp10 + 1].ljust(exp10 + 1, "0")
            fraction = significant[exp10 + 1 :] or "0"
        else:
            integer = "0"
            fraction = "0" * (-exp10 - 1) + significant
        return f"{sign}{integer}.{fraction}"
    return f"{sign}{significant[0]}.{significant[1:] or '0'}E{exp10}"


def _scalar_text(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, float):
        return java_double(value)
    return str(value)


def _java_string_hash(text: str) -> int:
    """``String.hashCode()``: ``s[0]*31^(n-1) + ...`` over UTF-16 code units, as int32."""
    h = 0
    units = text.encode("utf-16-be", "surrogatepass")
    for i in range(0, len(units), 2):
        h = (31 * h + ((units[i] << 8) | units[i + 1])) & 0xFFFFFFFF
    return h


def java_hashmap_order(keys: Sequence[str]) -> list[str]:
    """The iteration order of a ``java.util.HashMap`` the keys were put into, in
    the given order. Elasticsearch parses a JSON object into a ``HashMap``, so a
    painless ``toString()`` lists keys in this order, not the logged one.

    A key lands in bucket ``(h ^ (h >>> 16)) & (capacity - 1)``; the table starts
    at 16 buckets and doubles whenever the size exceeds 0.75 x capacity (a resize
    keeps a bucket's entries in insertion order); iteration walks the buckets in
    index order. (Buckets are not treeified below 8 colliding keys.)"""
    capacity = 16
    while len(keys) > capacity * 0.75:
        capacity *= 2

    def bucket(key: str) -> int:
        h = _java_string_hash(key)
        return (h ^ (h >> 16)) & (capacity - 1)

    return [key for _, key in sorted(enumerate(keys), key=lambda pair: (bucket(pair[1]), pair[0]))]


_REMOVED = object()


def _pruned(value: Any, removed_scalars: frozenset[str]) -> Any:
    """``value`` after a pipeline's "remove empty values" pass: ``null``, the
    listed scalar strings and containers left empty are dropped, depth first.
    A mapping keeps its ``java.util.HashMap`` iteration order (a removal does not
    shrink the table, so the order is that of the original key set)."""
    if isinstance(value, Mapping):
        kept: dict[str, Any] = {}
        for key in java_hashmap_order(list(value)):
            child = _pruned(value[key], removed_scalars)
            if child is not _REMOVED:
                kept[key] = child
        return kept if kept else _REMOVED
    if isinstance(value, list):
        children = [c for c in (_pruned(v, removed_scalars) for v in value) if c is not _REMOVED]
        return children if children else _REMOVED
    if value is None or (isinstance(value, str) and value in removed_scalars):
        return _REMOVED
    return value


def _to_string(value: Any) -> str:
    if isinstance(value, Mapping):
        return "{" + ", ".join(f"{k}={_to_string(v)}" for k, v in value.items()) + "}"
    if isinstance(value, list):
        return "[" + ", ".join(_to_string(v) for v in value) + "]"
    return _scalar_text(value)


_EMPTY_ONLY = frozenset({""})


@functools.lru_cache(maxsize=2048)
def _object(text: str, removed_scalars: frozenset[str]) -> Any:
    """The pruned, HashMap-ordered object, or ``None`` when nothing is left."""
    pruned = _pruned(json.loads(text), removed_scalars)
    return None if pruned is _REMOVED else pruned


def java_to_string(text: str | None, removed_scalars: frozenset[str] = _EMPTY_ONLY) -> str | None:
    """``Map.toString()`` of the JSON object in ``text`` after the pipeline's
    empty-value removal (``removed_scalars``: the scalar strings it drops)."""
    if text is None:
        return None
    value = _object(text, removed_scalars)
    return None if value is None else _to_string(value)


def _collect(value: Any, path: str, out: dict[str, list[str]]) -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            _collect(child, f"{path}.{key}" if path else str(key), out)
    elif isinstance(value, list):
        for child in value:
            _collect(child, path, out)
    elif path:
        out.setdefault(path, []).append(_scalar_text(value))


@functools.lru_cache(maxsize=2048)
def _leaves(text: str, removed_scalars: frozenset[str]) -> Mapping[str, tuple[str, ...]]:
    out: dict[str, list[str]] = {}
    value = _object(text, removed_scalars)
    if value is not None:
        _collect(value, "", out)
    return MappingProxyType({path: tuple(values) for path, values in out.items()})


def flattened_leaves(
    text: str | None, sub_path: str, removed_scalars: frozenset[str] = _EMPTY_ONLY
) -> tuple[str, ...] | None:
    """The keyword leaves of ``sub_path`` in the JSON object in ``text``."""
    if text is None:
        return None
    return _leaves(text, removed_scalars).get(sub_path)


def all_leaf_paths(
    text: str | None, removed_scalars: frozenset[str] = _EMPTY_ONLY
) -> tuple[str, ...]:
    """Every leaf path of the object (for conformance tests)."""
    return tuple(_leaves(text, removed_scalars)) if text is not None else ()


__all__ = [
    "all_leaf_paths",
    "flattened_leaves",
    "java_double",
    "java_hashmap_order",
    "java_to_string",
]
