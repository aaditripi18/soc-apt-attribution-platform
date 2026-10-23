"""Evaluation of multi-event rules over one recording (ADR-0015 Amendment C).

:meth:`DetectionEngine.evaluate_split` gives, per Observation, the single-event
matches of rules that carry an :class:`~.aggregation.Aggregation`. This module
decides which of those matches complete a detection, in event-time order, and
returns one :class:`DetectionResult` per detection, anchored on the Observation
that completed it.

**Never broader than the source rule.**

- *Threshold.* Elastic counts the matching events of each scheduled look-back
  window, so whether events further apart than ``look-back - interval`` are
  counted together depends on when the rule happens to run. ``span_seconds`` is
  that guaranteed distance (set by the importer): events this close are in one
  window whatever the schedule. A detection here is therefore one Elastic would
  raise under every schedule. After a detection the group starts again from
  empty, so one burst is one detection.
- *New terms.* Elastic compares with the history it has indexed. A recording is
  all the history there is, so a value is called new only if (a) no matching
  event carried it in the ``history_seconds`` before, and (b) the recording holds
  an event of the same log source at least that long before — otherwise the history
  is unknown and nothing is claimed.

A branch of one source rule is one rule of a ``rule_family``; state is kept per
family, so the count is over the events matching the source rule's query.
An event without a value for a grouping field is not counted (as in an
Elasticsearch terms aggregation); a multi-valued field counts once per value.

- *Sequence* (ADR-0026). Two rules of one family: a stage-2 match detects only
  when a stage-1 match on the same host with the same key value preceded it
  within the span. The detection names both Observations.
"""

from __future__ import annotations

import dataclasses
import itertools
from collections import deque
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from attribution_platform.detection.aggregation import Aggregation, AggregationField
from attribution_platform.detection.contracts import DetectionResult
from attribution_platform.detection.derived_views import UNDETERMINED
from attribution_platform.detection.rules import DetectionRule, _resolve_field
from attribution_platform.domain import Observation

#: The most value combinations one event may contribute (multi-valued fields).
MAX_COMBINATIONS = 64


@dataclass(frozen=True)
class AggregatedMatch:
    """One single-event match of an aggregated rule."""

    rule: DetectionRule
    result: DetectionResult
    observation: Observation


def _values(field: AggregationField, observation: Observation) -> tuple[str, ...]:
    if field.constant is not None:
        return (field.constant,)
    resolved: Any = _resolve_field(observation, str(field.field_path))
    if resolved is None or resolved is UNDETERMINED:
        return ()
    if isinstance(resolved, tuple | list):
        return tuple(dict.fromkeys(str(v) for v in resolved))
    return (str(resolved),)


def _keys(fields: tuple[AggregationField, ...], observation: Observation) -> list[tuple[str, ...]]:
    per_field = [_values(f, observation) for f in fields]
    if any(not values for values in per_field):
        return []
    return list(itertools.islice(itertools.product(*per_field), MAX_COMBINATIONS))


def _describe(fields: tuple[AggregationField, ...], key: tuple[str, ...]) -> str:
    return ", ".join(f"{f.name}={v!r}" for f, v in zip(fields, key, strict=True)) or "all events"


def _stamp(moment: datetime) -> str:
    return moment.isoformat().replace("+00:00", "Z")


@dataclass
class _Entry:
    match: AggregatedMatch
    distinct: tuple[tuple[str, ...], ...]


def _threshold(
    spec: Aggregation, matches: list[AggregatedMatch]
) -> Iterable[tuple[AggregatedMatch, tuple[str, ...], str]]:
    windows: dict[tuple[str, ...], deque[_Entry]] = {}
    span = timedelta(seconds=spec.span_seconds)
    for match in matches:
        observation = match.observation
        distinct = tuple(_values(f, observation) for f, _ in spec.cardinality)
        fired = False
        for key in _keys(spec.fields, observation):
            window = windows.setdefault(key, deque())
            window.append(_Entry(match, distinct))
            while observation.timestamp - window[0].match.observation.timestamp > span:
                window.popleft()
            if fired or len(window) < spec.count:
                # one detection per event: a second group it completes stays pending
                continue
            seen = [
                len({v for entry in window for v in entry.distinct[i]})
                for i in range(len(spec.cardinality))
            ]
            if any(have < needed for have, (_, needed) in zip(seen, spec.cardinality, strict=True)):
                continue
            first = window[0].match.observation.timestamp
            note = (
                f"threshold: {len(window)} matching events (needs {spec.count}) for "
                f"{_describe(spec.fields, key)} within {spec.span_seconds:g}s, "
                f"first at {_stamp(first)}"
            )
            for have, (field, needed) in zip(seen, spec.cardinality, strict=True):
                note += f"; {have} distinct {field.name} (needs {needed})"
            ids = tuple(dict.fromkeys(e.match.observation.observation_id for e in window))
            yield match, ids, note
            fired = True
            window.clear()


def _new_terms(
    spec: Aggregation, matches: list[AggregatedMatch], source_start: Mapping[str, datetime]
) -> Iterable[tuple[AggregatedMatch, tuple[str, ...], str]]:
    history = timedelta(seconds=spec.history_seconds)
    last_seen: dict[tuple[str, ...], datetime] = {}
    for match in matches:
        observation = match.observation
        moment = observation.timestamp
        recorded_since = source_start.get(observation.raw_reference.source_type)
        covered = recorded_since is not None and recorded_since <= moment - history
        fired = False
        for key in _keys(spec.fields, observation):
            previous = last_seen.get(key)
            last_seen[key] = moment
            if fired or not covered or (previous is not None and previous >= moment - history):
                continue
            fired = True  # one detection per event, as one alert per document
            note = (
                f"new terms: {_describe(spec.fields, key)} not seen on a matching event in the "
                f"{spec.history_seconds / 86400:g} days before; this log source is recorded since "
                f"{_stamp(recorded_since)}"  # type: ignore[arg-type]
            )
            yield match, (observation.observation_id,), note


def _normalised(value: str, key_form: str | None) -> str:
    if key_form != "windows_path":
        return value
    folder, separator, name = value.rpartition("\\")
    return (folder + separator + name.split(":", 1)[0]).casefold()


def _sequence(
    matches: list[AggregatedMatch],
) -> Iterable[tuple[AggregatedMatch, tuple[str, ...], str]]:
    """Stage 2 detects when a stage-1 event of the same family, on the same
    host and with the same key, came before it within the stage-2 rule's span.
    The most recent such stage-1 event is the one named. The key is every key
    field's value, in order (none: the same host is the whole key); an event
    missing a key value, or with several, is not part of any sequence."""
    earlier: dict[tuple[str, ...], AggregatedMatch] = {}
    for match in matches:
        spec = match.rule.aggregation
        assert spec is not None  # noqa: S101 - callers pass aggregated matches only
        observation = match.observation
        host = observation.host.name if observation.host is not None else None
        per_field = [_values(f, observation) for f in spec.fields]
        if not host or any(len(values) != 1 for values in per_field):
            continue
        values = [values[0] for values in per_field]
        key = (str(host).casefold(), *(_normalised(v, spec.key_form) for v in values))
        if spec.stage == 1:
            earlier[key] = match
            continue
        first = earlier.get(key)
        if first is None:
            continue
        gap = (observation.timestamp - first.observation.timestamp).total_seconds()
        if not 0 <= gap <= spec.span_seconds:
            continue
        if spec.key_form == "windows_path":  # ADR-0026: one path, the file saved and run
            writer = first.observation.process.executable if first.observation.process else None
            note = (
                f"sequence: {spec.fields[0].name}={values[0]!r} follows an event on the same "
                f"host and path {gap:g}s earlier, at {_stamp(first.observation.timestamp)}"
                + (f", by {writer!r}" if writer else "")
            )
        else:
            joined = ", ".join(f"{f.name}={v!r}" for f, v in zip(spec.fields, values, strict=True))
            note = (
                "sequence: follows an event on the same host"
                + (f" with the same {joined}" if joined else "")
                + f" {gap:g}s earlier, at {_stamp(first.observation.timestamp)}"
            )
        yield match, (first.observation.observation_id, observation.observation_id), note


def source_starts(observations: Iterable[Observation]) -> dict[str, datetime]:
    """The earliest event time of each log source type among ``observations``."""
    starts: dict[str, datetime] = {}
    for observation in observations:
        source = observation.raw_reference.source_type
        if source not in starts or observation.timestamp < starts[source]:
            starts[source] = observation.timestamp
    return starts


def evaluate_aggregations(
    matches: Iterable[AggregatedMatch], *, source_start: Mapping[str, datetime]
) -> tuple[tuple[DetectionResult, Observation], ...]:
    """The detections completed among ``matches``: each is the anchoring match's
    result, naming every supporting Observation and saying what was counted.
    Deterministic: independent of the order ``matches`` are given in."""
    by_family: dict[str, list[AggregatedMatch]] = {}
    for match in matches:
        if match.rule.aggregation is None:
            raise ValueError("evaluate_aggregations takes matches of aggregated rules only")
        family = match.rule.rule_family or match.rule.rule_ref.rule_id
        by_family.setdefault(family, []).append(match)
    out: list[tuple[DetectionResult, Observation]] = []
    for family in sorted(by_family):
        ordered = sorted(
            by_family[family],
            key=lambda m: (m.observation.timestamp, m.observation.observation_id),
        )
        # one event counts once per family, whichever branch matched it
        unique = list({m.observation.observation_id: m for m in reversed(ordered)}.values())
        unique.reverse()
        spec = unique[0].rule.aggregation
        assert spec is not None  # noqa: S101 - checked above
        if spec.kind == "sequence":
            fired = _sequence(unique)
        elif spec.kind == "threshold":
            fired = _threshold(spec, unique)
        else:
            fired = _new_terms(spec, unique, source_start)
        for match, supporting, note in fired:
            out.append(
                (
                    dataclasses.replace(
                        match.result,
                        supporting_observation_ids=supporting,
                        aggregate_note=note,
                    ),
                    match.observation,
                )
            )
    out.sort(key=lambda pair: (pair[1].observation_id, pair[0].detection_id))
    return tuple(out)


__all__ = [
    "MAX_COMBINATIONS",
    "AggregatedMatch",
    "source_starts",
    "evaluate_aggregations",
]
