"""Shared harness: Elastic's pipeline test fixtures vs. this platform's derived views.

A fixture is a raw input file (``.log``: one event per line; ``.json``:
``{"events": [...]}``) and ``<file>-expected.json`` (``{"expected": [...]}``, one
ECS document per input event, in order). :func:`compare` runs an adapter over
every input it accepts and compares each view with the expected document.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
from collections.abc import Callable, Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from attribution_platform.detection.derived_views import UNDETERMINED, ViewSet
from attribution_platform.domain import Observation
from attribution_platform.sources.errors import SourceAdapterError

CONFORMANCE = Path(__file__).resolve().parents[1] / "data" / "detection" / "elastic" / "conformance"


def verify_manifest(stream: str) -> int:
    """Every vendored file equals its manifest SHA-256 and git blob id."""
    directory = CONFORMANCE / stream
    manifest = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
    for entry in manifest["files"]:
        raw = (directory / entry["path"]).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == entry["sha256"], entry["path"]
        blob = hashlib.sha1(b"blob %d\0" % len(raw) + raw).hexdigest()  # noqa: S324 - git id
        assert blob == entry["blob_id"], entry["path"]
    return len(manifest["files"])


def get(document: Any, dotted: str) -> Any:
    """``a.b.c`` in a nested ECS document; a list of objects yields the list of
    its members' values (Elasticsearch flattens arrays of objects the same way)."""
    current: Any = document
    for part in dotted.split("."):
        if isinstance(current, list):
            values = [get(item, part) for item in current]
            flat: list[Any] = []
            for value in values:
                if isinstance(value, list):
                    flat.extend(value)
                elif value is not None:
                    flat.append(value)
            current = flat or None
        elif isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return None
    return current


def fixture_events(stream: str) -> Iterator[tuple[str, Any, dict[str, Any] | None]]:
    """``(file name, raw input event, expected document)`` for every fixture event."""
    fixtures = CONFORMANCE / stream / "fixtures"
    for expected_path in sorted(fixtures.glob("*-expected.json")):
        source = expected_path.with_name(expected_path.name.removesuffix("-expected.json"))
        config = source.with_name(source.name + "-config.yml")
        if config.exists() and "_conf:" in config.read_text(encoding="utf-8"):
            continue  # exercises a non-default integration setting
        expected = json.loads(expected_path.read_text(encoding="utf-8"))["expected"]
        if source.suffix == ".json":
            events = json.loads(source.read_text(encoding="utf-8"))["events"]
        else:
            # One event per line; a blank line is an event too (Elastic's test
            # runner feeds it to the pipeline), except the file's final newline.
            events = source.read_text(encoding="utf-8").split("\n")
            if events and events[-1] == "":
                events.pop()
        if len(events) != len(expected):
            continue  # a multi-line or split-input fixture: no 1:1 pairing
        for event, document in zip(events, expected, strict=True):
            yield source.name, event, document


@dataclass
class Comparison:
    events: int = 0
    accepted: int = 0
    compared: dict[str, int] = field(default_factory=dict)
    undetermined: dict[str, int] = field(default_factory=dict)
    divergent: list[tuple[str, str, Any, Any]] = field(default_factory=list)


def _normalise(value: Any) -> Any:
    if isinstance(value, list):
        return tuple(str(v) for v in value)
    if isinstance(value, bool):
        return "true" if value else "false"
    return None if value is None else str(value)


def _expected_leaves(value: Any, path: str, out: dict[str, list[str]]) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            _expected_leaves(child, f"{path}.{key}" if path else str(key), out)
    elif isinstance(value, list):
        for child in value:
            _expected_leaves(child, path, out)
    elif value is not None and path:
        out.setdefault(path, []).append(str(_normalise(value)))


def compare(
    stream: str,
    views: ViewSet,
    to_observations: Callable[[Any], tuple[Observation, ...]],
    decode: Callable[[Any], Any],
    dynamic_paths: Mapping[str, Callable[[Observation], Iterable[str]]] | None = None,
) -> Comparison:
    """Compare every view with Elastic's expected document for every fixture
    event the adapter accepts. ``decode`` turns a fixture event into the raw
    record the adapter reads (or ``None`` to skip it)."""
    result = Comparison()
    for name, event, document in fixture_events(stream):
        result.events += 1
        if document is None:
            continue
        record = decode(event)
        if record is None:
            continue
        try:
            observations = to_observations(record)
        except SourceAdapterError:
            continue
        if len(observations) != 1:
            continue
        result.accepted += 1
        for ecs_field, view in views.views.items():
            ours = view(observations[0])
            theirs = _normalise(get(document, ecs_field))
            if ecs_field in views.arrays and isinstance(theirs, str):
                theirs = (theirs,)
            if ecs_field in views.analyzers and isinstance(theirs, str):
                # an analysed text field: queries see its tokens, so compare those
                theirs = views.analyzers[ecs_field](theirs)
            if views.types.get(ecs_field) == "ip" and isinstance(theirs, str):
                # an ip field: the document keeps the address as written, queries
                # compare addresses, so compare the canonical form (as the view holds it)
                theirs = str(ipaddress.ip_address(theirs))
            if ours is None and theirs is None:
                continue
            if ours is UNDETERMINED:  # never matches anything: nothing to compare
                result.undetermined[ecs_field] = result.undetermined.get(ecs_field, 0) + 1
                continue
            result.compared[ecs_field] = result.compared.get(ecs_field, 0) + 1
            if ours != theirs:
                result.divergent.append((name, ecs_field, ours, theirs))
        # Flattened families: every expected leaf, and every leaf we would offer.
        for prefix, our_paths in (dynamic_paths or {}).items():
            expected_leaves: dict[str, list[str]] = {}
            _expected_leaves(get(document, prefix.rstrip(".")), "", expected_leaves)
            for sub_path in sorted(set(expected_leaves) | set(our_paths(observations[0]))):
                ecs_field = prefix + sub_path
                ours = views.resolve(ecs_field, observations[0])
                theirs_leaf = (
                    tuple(expected_leaves[sub_path]) if sub_path in expected_leaves else None
                )
                result.compared[prefix + "*"] = result.compared.get(prefix + "*", 0) + 1
                if ours != theirs_leaf:
                    result.divergent.append((name, ecs_field, ours, theirs_leaf))
    return result
