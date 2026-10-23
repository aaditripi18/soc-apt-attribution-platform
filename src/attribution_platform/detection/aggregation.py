"""What a multi-event rule adds to a single-event match (ADR-0015 Amendment C).

A rule with an :class:`Aggregation` does not fire on an Observation by itself.
Its conditions select *matching events*; the aggregation says which sets of
matching events are a detection:

- ``threshold`` — at least ``count`` matching events that agree on every
  ``fields`` value, within ``span_seconds`` of each other, and (where given) at
  least the stated number of distinct values of each ``cardinality`` field.
- ``new_terms`` — a matching event whose ``fields`` values were not seen on any
  matching event in the ``history_seconds`` before it, **and** whose data stream
  is known to have been recorded for that whole period.

Evaluation is :mod:`attribution_platform.detection.stateful`. The specification
is part of the rule pack, so it is covered by the pack's content hash.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from attribution_platform.detection.errors import DetectionError

AGGREGATION_KINDS = ("threshold", "new_terms", "sequence")
#: How a sequence key is compared: a Windows file path, case-insensitively and
#: without an NTFS stream suffix (``file.exe:Zone.Identifier`` is ``file.exe``).
KEY_FORMS = (None, "windows_path")


@dataclass(frozen=True)
class AggregationField:
    """One grouping value: read from the Observation at ``field_path``, or the
    same ``constant`` for every event of the rule's data stream."""

    name: str
    field_path: str | None = None
    constant: str | None = None

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise DetectionError("AggregationField.name must be non-empty")
        if (self.field_path is None) == (self.constant is None):
            raise DetectionError(
                f"AggregationField {self.name!r} needs exactly one of field_path / constant"
            )


@dataclass(frozen=True)
class Aggregation:
    kind: str
    fields: tuple[AggregationField, ...] = ()
    #: threshold: the number of matching events needed
    count: int = 1
    #: threshold: the longest time between the first and the last of them
    span_seconds: float = 0.0
    #: threshold: ``(field, distinct values needed)``
    cardinality: tuple[tuple[AggregationField, int], ...] = ()
    #: new_terms: how far back the values must not have been seen
    history_seconds: float = 0.0
    #: sequence: 1 for the event that must come first, 2 for the event that detects
    stage: int = 0
    #: sequence: how the key value is normalised before comparison (:data:`KEY_FORMS`)
    key_form: str | None = None

    def __post_init__(self) -> None:
        if self.kind not in AGGREGATION_KINDS:
            raise DetectionError(f"Aggregation.kind must be one of {AGGREGATION_KINDS}")
        if self.kind == "sequence":
            # Key fields beyond the host: none (same host only), one, or several
            # compared together in order (ADR-0015 Amendment E).
            if self.stage not in (1, 2) or self.span_seconds <= 0:
                raise DetectionError("a sequence needs stage 1 or 2 and span_seconds > 0")
            if self.key_form not in KEY_FORMS or self.cardinality:
                raise DetectionError(f"a sequence key_form must be one of {KEY_FORMS}")
            return
        if self.kind == "threshold":
            if self.count < 1 or self.span_seconds <= 0:
                raise DetectionError("a threshold needs count >= 1 and span_seconds > 0")
            if any(needed < 1 for _, needed in self.cardinality):
                raise DetectionError("a cardinality needs at least one distinct value")
        else:
            if not self.fields or self.history_seconds <= 0:
                raise DetectionError("new_terms needs fields and history_seconds > 0")
            if self.cardinality:
                raise DetectionError("new_terms takes no cardinality")


def _field(raw: Any, *, where: str) -> AggregationField:
    if not isinstance(raw, dict) or not isinstance(raw.get("name"), str):
        raise DetectionError(f"{where}: an aggregation field must be an object with a name")
    path, constant = raw.get("field_path"), raw.get("constant")
    if (path is not None and not isinstance(path, str)) or (
        constant is not None and not isinstance(constant, str)
    ):
        raise DetectionError(f"{where}: field_path / constant must be strings")
    try:
        return AggregationField(name=raw["name"], field_path=path, constant=constant)
    except DetectionError as exc:
        raise DetectionError(f"{where}: {exc}") from exc


def _number(raw: Any, *, where: str, key: str) -> float:
    if isinstance(raw, bool) or not isinstance(raw, int | float):
        raise DetectionError(f"{where}: {key!r} must be a number")
    return float(raw)


def aggregation_from_dict(raw: Any, *, where: str) -> Aggregation:
    """Parse and validate the ``aggregation`` object of a rule-pack rule."""
    if not isinstance(raw, dict):
        raise DetectionError(f"{where}: 'aggregation' must be a JSON object")
    kind = raw.get("kind")
    if kind not in AGGREGATION_KINDS:
        raise DetectionError(f"{where}: aggregation kind must be one of {AGGREGATION_KINDS}")
    raw_fields = raw.get("fields", [])
    if not isinstance(raw_fields, list):
        raise DetectionError(f"{where}: aggregation 'fields' must be a list")
    fields = tuple(_field(f, where=where) for f in raw_fields)
    try:
        if kind == "sequence":
            stage = _number(raw.get("stage"), where=where, key="stage")
            key_form = raw.get("key_form")
            if key_form is not None and not isinstance(key_form, str):
                raise DetectionError(f"{where}: 'key_form' must be a string")
            return Aggregation(
                kind=kind,
                fields=fields,
                span_seconds=_number(raw.get("span_seconds"), where=where, key="span_seconds"),
                stage=int(stage),
                key_form=key_form,
            )
        if kind == "new_terms":
            return Aggregation(
                kind=kind,
                fields=fields,
                history_seconds=_number(
                    raw.get("history_seconds"), where=where, key="history_seconds"
                ),
            )
        raw_cardinality = raw.get("cardinality", [])
        if not isinstance(raw_cardinality, list):
            raise DetectionError(f"{where}: aggregation 'cardinality' must be a list")
        cardinality = []
        for entry in raw_cardinality:
            if not isinstance(entry, dict):
                raise DetectionError(f"{where}: a cardinality must be an object")
            needed = _number(entry.get("count"), where=where, key="cardinality count")
            cardinality.append((_field(entry.get("field"), where=where), int(needed)))
        count = _number(raw.get("count"), where=where, key="count")
        if count != int(count):
            raise DetectionError(f"{where}: 'count' must be a whole number")
        return Aggregation(
            kind=kind,
            fields=fields,
            count=int(count),
            span_seconds=_number(raw.get("span_seconds"), where=where, key="span_seconds"),
            cardinality=tuple(cardinality),
        )
    except DetectionError as exc:
        if str(exc).startswith(where):
            raise
        raise DetectionError(f"{where}: {exc}") from exc


__all__ = [
    "AGGREGATION_KINDS",
    "KEY_FORMS",
    "Aggregation",
    "AggregationField",
    "aggregation_from_dict",
]
