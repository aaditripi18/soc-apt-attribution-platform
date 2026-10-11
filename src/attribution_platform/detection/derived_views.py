"""Shared machinery for derived ECS views (ADR-0015 D2).

A *view set* is one Elastic data stream's ECS fields as the rule engine may read
them from this platform's Observations: ``<namespace>.<ECS field>`` -> a pure
function of one Observation that reproduces what Elastic's ingest pipeline for
that stream puts in the field, with the index mapping's ``ignore_above`` applied.
The per-stream modules (:mod:`.derived_fields` for Sysmon, :mod:`.derived_cloud`,
:mod:`.derived_security`) define the derivations; :mod:`.derived_registry` is the
one place the engine looks them up.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from attribution_platform.domain import Observation

#: ECS ``keyword`` fields carry ``ignore_above: 1024``: a longer value is not
#: indexed, so no query (term, wildcard or exists) can match it.
KEYWORD_IGNORE_ABOVE = 1024

View = Callable[[Observation], Any]


class _Undetermined:
    """See :data:`UNDETERMINED`."""

    def __repr__(self) -> str:
        return "UNDETERMINED"


#: A view's answer when the pipeline's value depends on something the adapter
#: does not keep. It is neither a value nor "absent": the engine makes **every**
#: condition on it a non-match, negated or not, so a rule can only fail to fire
#: -- never fire on a guess.
UNDETERMINED = _Undetermined()
#: A family of fields under one prefix (an Elasticsearch ``flattened`` object):
#: ``(observation, sub-path) -> tuple of leaf values`` or ``None``.
DynamicView = Callable[[Observation, str], Any]


def attr(obj: Any, *path: str) -> Any:
    """``obj.a.b.c`` where any hop may be ``None``."""
    for name in path:
        if obj is None:
            return None
        obj = getattr(obj, name, None)
    return obj


@dataclass(frozen=True)
class ViewSet:
    """One data stream's derived views.

    ``types`` gives each field's Elasticsearch type (``keyword`` / ``wildcard`` /
    ``long`` / ``boolean`` / ``text``); ``arrays`` names the fields whose value is a tuple
    (the engine's ``element_*`` operators only). ``dynamic`` maps a field-name
    prefix (ending in a dot) to a family of sub-fields — an Elasticsearch
    ``flattened`` object, whose leaves are keyword strings and always read as a
    tuple."""

    namespace: str
    views: Mapping[str, View]
    types: Mapping[str, str]
    arrays: frozenset[str]
    dynamic: Mapping[str, DynamicView] = MappingProxyType({})
    #: For each analysed ``text`` field: a query value -> the form in which a
    #: phrase match on the field is a substring match of the view's value
    #: (``None``: the value has no token and matches nothing).
    analyzers: Mapping[str, Callable[[str], str | None]] = MappingProxyType({})

    def path(self, ecs_field: str) -> str:
        return f"{self.namespace}.{ecs_field}"

    def _dynamic(self, ecs_field: str) -> tuple[DynamicView, str] | None:
        for prefix, family in self.dynamic.items():
            if ecs_field.startswith(prefix) and len(ecs_field) > len(prefix):
                return family, ecs_field[len(prefix) :]
        return None

    def type_of(self, ecs_field: str) -> str | None:
        """The field's Elasticsearch type, or ``None`` if the set has no such field."""
        if ecs_field in self.types:
            return self.types[ecs_field]
        return "flattened" if self._dynamic(ecs_field) else None

    def is_array(self, ecs_field: str) -> bool:
        return ecs_field in self.arrays or (
            ecs_field not in self.types and self._dynamic(ecs_field) is not None
        )

    def resolve(self, ecs_field: str, observation: Observation) -> Any:
        """The field's queryable value; ``KeyError`` for an unknown field."""
        view = self.views.get(ecs_field)
        if view is not None:
            return view(observation)
        family = self._dynamic(ecs_field)
        if family is None:
            raise KeyError(ecs_field)
        return family[0](observation, family[1])


def _indexed(ecs_type: str, limit: int, value: Any) -> Any:
    """``value`` as the index holds it for querying."""
    if value is None or value is UNDETERMINED or ecs_type != "keyword":
        return value
    if isinstance(value, tuple):
        kept = tuple(v for v in value if len(v) <= limit)
        return kept or None
    return value if len(value) <= limit else None


def build_view_set(
    namespace: str,
    pipeline_fields: Mapping[str, View],
    *,
    non_keyword: Mapping[str, str] | None = None,
    arrays: frozenset[str] = frozenset(),
    dynamic: Mapping[str, DynamicView] | None = None,
    ignore_above: Mapping[str, int] | None = None,
    analyzers: Mapping[str, Callable[[str], str | None]] | None = None,
) -> ViewSet:
    """Wrap pipeline-level derivations with the index mapping. Every field is a
    ``keyword`` with ``ignore_above: 1024`` unless ``non_keyword`` gives another
    type or ``ignore_above`` the integration's own limit for it."""
    types = {name: (non_keyword or {}).get(name, "keyword") for name in pipeline_fields}
    unknown = (set(non_keyword or {}) | set(arrays) | set(ignore_above or {})) - set(
        pipeline_fields
    )
    if unknown:
        raise ValueError(f"{namespace}: types/arrays name unknown fields {sorted(unknown)}")
    text_fields = {name for name, ecs_type in types.items() if ecs_type == "text"}
    if text_fields != set(analyzers or {}):
        raise ValueError(f"{namespace}: every text field needs its analyzer, and only those")

    def view(name: str) -> View:
        derive, ecs_type = pipeline_fields[name], types[name]
        limit = (ignore_above or {}).get(name, KEYWORD_IGNORE_ABOVE)
        return lambda observation: _indexed(ecs_type, limit, derive(observation))

    return ViewSet(
        namespace=namespace,
        views=MappingProxyType({name: view(name) for name in pipeline_fields}),
        types=MappingProxyType(types),
        arrays=arrays,
        dynamic=MappingProxyType(dict(dynamic or {})),
        analyzers=MappingProxyType(dict(analyzers or {})),
    )


__all__ = [
    "KEYWORD_IGNORE_ABOVE",
    "UNDETERMINED",
    "DynamicView",
    "View",
    "ViewSet",
    "attr",
    "build_view_set",
]
