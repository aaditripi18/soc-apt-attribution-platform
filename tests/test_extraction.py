"""Tests for gate G0.5: the detection-match -> Observation extraction boundary.

Covers valid conversion (one Observation per matched event, order preserved),
determinism, required-field validation on the record contracts, malformed
input (naive timestamp, non-SourceRef provenance, empty matched events,
non-MatchedEvent element), provenance preservation (Observation.raw_reference
is the matched event's SourceRef), source-agnosticism (Observations carry no
source-native fields), and the dependency-direction guard (domain never
imports extraction).

Does NOT touch the G0.0-G0.4 test files. Offline, deterministic, stdlib-only.
"""

from __future__ import annotations

import ast
from datetime import UTC, datetime
from pathlib import Path

import pytest

from attribution_platform.domain import (
    EventMetadata,
    HostRef,
    Observation,
    ProcessRef,
    SourceRef,
    TimePrecision,
    to_canonical_json,
)
from attribution_platform.extraction import (
    DetectionMatchRecord,
    ExtractionError,
    MatchedEvent,
    RuleRef,
    extract_observations,
)

T0 = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)

REPO_ROOT = Path(__file__).resolve().parents[1]
DOMAIN_DIR = REPO_ROOT / "src" / "attribution_platform" / "domain"


def _source_ref(event_id: str = "raw-1") -> SourceRef:
    return SourceRef(source_type="synthetic", source_event_id=event_id)


def _matched_event(obs_id: str = "obs-1", event_id: str = "raw-1") -> MatchedEvent:
    return MatchedEvent(observation_id=obs_id, source_ref=_source_ref(event_id), timestamp=T0)


def _record(*matched: MatchedEvent) -> DetectionMatchRecord:
    events = matched or (_matched_event(),)
    return DetectionMatchRecord(
        rule_ref=RuleRef(rule_id="R1", rule_version="1.0"), matched_events=events
    )


# ===========================================================================
# 1. Valid conversion
# ===========================================================================


def test_extracts_one_observation_per_matched_event_in_order() -> None:
    record = _record(
        _matched_event("obs-a", "raw-a"),
        _matched_event("obs-b", "raw-b"),
        _matched_event("obs-c", "raw-c"),
    )
    observations = extract_observations(record)

    assert isinstance(observations, tuple)
    assert [o.observation_id for o in observations] == ["obs-a", "obs-b", "obs-c"]
    assert all(isinstance(o, Observation) for o in observations)


def test_extracted_observation_carries_normalized_fields() -> None:
    matched = MatchedEvent(
        observation_id="obs-1",
        source_ref=_source_ref(),
        timestamp=T0,
        timestamp_precision=TimePrecision.MILLISECOND,
        event=EventMetadata(category=("process",), type=("start",)),
        host=HostRef(name="HOST1"),
        process=ProcessRef(pid=1234, name="p.exe", command_line="p -x"),
    )
    (observation,) = extract_observations(_record(matched))

    assert observation.timestamp == T0
    assert observation.timestamp_precision is TimePrecision.MILLISECOND
    assert observation.host is not None and observation.host.name == "HOST1"
    assert observation.process is not None and observation.process.pid == 1234
    assert observation.event is not None and observation.event.category == ("process",)


# ===========================================================================
# 2. Determinism
# ===========================================================================


def test_extraction_is_deterministic() -> None:
    record = _record(_matched_event("o1"), _matched_event("o2"))
    first = extract_observations(record)
    second = extract_observations(record)
    assert first == second
    # identical logical inputs -> identical canonical serialization
    assert [to_canonical_json(o) for o in first] == [to_canonical_json(o) for o in second]


def test_extraction_injects_no_wall_clock_or_generated_ids() -> None:
    (observation,) = extract_observations(_record(_matched_event("supplied-id")))
    # id comes straight from the input; timestamp is exactly the input timestamp
    assert observation.observation_id == "supplied-id"
    assert observation.timestamp == T0


# ===========================================================================
# 3. Required-field validation (fail-closed at construction)
# ===========================================================================


def test_rule_ref_requires_id_and_version() -> None:
    with pytest.raises(ExtractionError, match="rule_id"):
        RuleRef(rule_id="", rule_version="1.0")
    with pytest.raises(ExtractionError, match="rule_version"):
        RuleRef(rule_id="R1", rule_version="  ")


def test_matched_event_requires_observation_id() -> None:
    with pytest.raises(ExtractionError, match="observation_id"):
        MatchedEvent(observation_id="", source_ref=_source_ref(), timestamp=T0)


def test_record_requires_nonempty_matched_events() -> None:
    with pytest.raises(ExtractionError, match="non-empty tuple"):
        DetectionMatchRecord(rule_ref=RuleRef(rule_id="R1", rule_version="1.0"), matched_events=())


def test_record_rejects_empty_matched_field_name() -> None:
    with pytest.raises(ExtractionError, match="matched_fields"):
        DetectionMatchRecord(
            rule_ref=RuleRef(rule_id="R1", rule_version="1.0"),
            matched_events=(_matched_event(),),
            matched_fields=("ok", ""),
        )


# ===========================================================================
# 4. Malformed input
# ===========================================================================


def test_matched_event_rejects_non_source_ref_provenance() -> None:
    with pytest.raises(ExtractionError, match="SourceRef"):
        MatchedEvent(
            observation_id="o",
            source_ref="not-a-source-ref",  # type: ignore[arg-type]
            timestamp=T0,
        )


def test_record_rejects_non_matched_event_element() -> None:
    with pytest.raises(ExtractionError, match="must be a MatchedEvent"):
        DetectionMatchRecord(
            rule_ref=RuleRef(rule_id="R1", rule_version="1.0"),
            matched_events=("not-a-matched-event",),  # type: ignore[arg-type]
        )


def test_naive_timestamp_fails_closed_as_extraction_error() -> None:
    naive_event = MatchedEvent(
        observation_id="obs-x",
        source_ref=_source_ref(),
        timestamp=datetime(2026, 1, 1, 12, 0, 0),  # no tzinfo
    )
    record = _record(naive_event)
    with pytest.raises(ExtractionError, match="obs-x") as excinfo:
        extract_observations(record)
    # the underlying domain violation is preserved as the cause
    assert excinfo.value.__cause__ is not None
    assert "timezone-aware" in str(excinfo.value)


# ===========================================================================
# 5. Provenance preservation
# ===========================================================================


def test_observation_raw_reference_is_the_matched_event_source_ref() -> None:
    src = _source_ref("raw-99")
    matched = MatchedEvent(observation_id="obs-1", source_ref=src, timestamp=T0)
    (observation,) = extract_observations(_record(matched))

    assert observation.raw_reference is src  # same object, not a copy
    assert observation.raw_reference.source_type == "synthetic"
    assert observation.raw_reference.source_event_id == "raw-99"


# ===========================================================================
# 6. Source-agnosticism & dependency direction
# ===========================================================================


def test_extracted_observations_have_no_source_native_fields() -> None:
    """Guard: nothing source-specific rides through extraction — the produced
    Observation exposes only the generic G0.3 domain field names."""
    import dataclasses

    (observation,) = extract_observations(_record(_matched_event()))
    names = {f.name for f in dataclasses.fields(observation)}
    for forbidden in ("sysmon", "winlog", "elastic", "rule", "matched"):
        assert not any(forbidden in n for n in names), f"unexpected field containing {forbidden!r}"


def test_domain_package_never_imports_extraction() -> None:
    """Static AST check: no domain/*.py module imports attribution_platform.extraction
    (domain must not depend on the layer above it)."""
    offending: list[str] = []
    for path in sorted(DOMAIN_DIR.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module and "extraction" in node.module:
                offending.append(f"{path.name}: from {node.module}")
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if "extraction" in alias.name:
                        offending.append(f"{path.name}: import {alias.name}")
    assert not offending, f"domain/ must not import extraction/: {offending}"
