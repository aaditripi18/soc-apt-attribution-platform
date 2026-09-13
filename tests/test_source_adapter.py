"""Tests for gate G0.4: the SourceAdapter abstraction.

Covers: the SyntheticSourceAdapter reference implementation, the fail-closed
convert() boundary (missing/empty source_type, wrong return type, non-
Observation elements, provenance source_type mismatch), that a second,
independently-defined adapter satisfies the interface without touching the
domain layer ("a new source is addable purely as an adapter"), and the
dependency-direction guard (domain never imports from sources).

Does NOT touch the G0.0-G0.3 test files. All tests are offline,
deterministic, stdlib-only.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from attribution_platform.domain import Observation, SourceRef
from attribution_platform.sources.adapter import SourceAdapter, convert
from attribution_platform.sources.errors import SourceAdapterError
from attribution_platform.sources.synthetic import SyntheticRecord, SyntheticSourceAdapter

T0 = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)

REPO_ROOT = Path(__file__).resolve().parents[1]
DOMAIN_DIR = REPO_ROOT / "src" / "attribution_platform" / "domain"


# ===========================================================================
# 1. The reference (synthetic) adapter
# ===========================================================================


def test_synthetic_adapter_satisfies_the_protocol() -> None:
    adapter = SyntheticSourceAdapter()
    assert isinstance(adapter, SourceAdapter)
    assert adapter.source_type == "synthetic"


def test_synthetic_adapter_converts_a_record_to_one_observation() -> None:
    adapter = SyntheticSourceAdapter()
    record = SyntheticRecord(record_id="raw-1", timestamp=T0)

    observations = convert(adapter, record)

    assert isinstance(observations, tuple)
    assert len(observations) == 1
    obs = observations[0]
    assert isinstance(obs, Observation)
    assert obs.observation_id == "raw-1"
    assert obs.timestamp == T0
    assert obs.raw_reference.source_type == "synthetic"
    assert obs.raw_reference.source_event_id == "raw-1"


def test_synthetic_adapter_honors_explicit_observation_id() -> None:
    adapter = SyntheticSourceAdapter()
    record = SyntheticRecord(record_id="raw-2", timestamp=T0, observation_id="obs-custom")

    observations = convert(adapter, record)

    assert observations[0].observation_id == "obs-custom"
    # the raw source_event_id is still the record_id, independent of observation_id
    assert observations[0].raw_reference.source_event_id == "raw-2"


def test_synthetic_adapter_rejects_wrong_raw_record_type() -> None:
    adapter = SyntheticSourceAdapter()
    with pytest.raises(SourceAdapterError, match="SyntheticRecord"):
        adapter.to_observations({"not": "a SyntheticRecord"})


def test_synthetic_adapter_is_deterministic() -> None:
    adapter = SyntheticSourceAdapter()
    record = SyntheticRecord(record_id="raw-3", timestamp=T0)
    assert convert(adapter, record) == convert(adapter, record)


# ===========================================================================
# 2. The fail-closed convert() boundary
# ===========================================================================


class _MissingSourceTypeAdapter:
    """No source_type attribute at all."""

    def to_observations(self, raw_record: Any) -> tuple[Observation, ...]:
        return ()


class _EmptySourceTypeAdapter:
    @property
    def source_type(self) -> str:
        return "   "

    def to_observations(self, raw_record: Any) -> tuple[Observation, ...]:
        return ()


class _ReturnsListAdapter:
    @property
    def source_type(self) -> str:
        return "broken"

    def to_observations(self, raw_record: Any) -> Any:
        return []  # a list, not a tuple


class _ReturnsNonObservationAdapter:
    @property
    def source_type(self) -> str:
        return "broken"

    def to_observations(self, raw_record: Any) -> Any:
        return ({"fake": "observation"},)


@dataclass(frozen=True)
class _MismatchedProvenanceAdapter:
    """Produces a valid Observation, but stamps the WRONG source_type into
    raw_reference — the exact mislabeling convert() must catch."""

    @property
    def source_type(self) -> str:
        return "claims-to-be-x"

    def to_observations(self, raw_record: Any) -> tuple[Observation, ...]:
        return (
            Observation(
                observation_id="o",
                timestamp=T0,
                raw_reference=SourceRef(source_type="actually-y", source_event_id="e"),
            ),
        )


def test_convert_rejects_missing_source_type() -> None:
    with pytest.raises(SourceAdapterError, match="source_type"):
        # Deliberately passing an object that does NOT satisfy SourceAdapter
        # (no source_type at all) to verify convert()'s runtime fail-closed
        # check -- mypy correctly flags this as a protocol violation, which
        # is exactly the case under test.
        convert(_MissingSourceTypeAdapter(), None)  # type: ignore[arg-type]


def test_convert_rejects_empty_source_type() -> None:
    with pytest.raises(SourceAdapterError, match="source_type"):
        convert(_EmptySourceTypeAdapter(), None)


def test_convert_rejects_non_tuple_return() -> None:
    with pytest.raises(SourceAdapterError, match="must return a tuple"):
        convert(_ReturnsListAdapter(), None)


def test_convert_rejects_non_observation_elements() -> None:
    with pytest.raises(SourceAdapterError, match="non-Observation"):
        convert(_ReturnsNonObservationAdapter(), None)


def test_convert_rejects_provenance_source_type_mismatch() -> None:
    with pytest.raises(SourceAdapterError, match="does not match adapter.source_type"):
        convert(_MismatchedProvenanceAdapter(), None)


# ===========================================================================
# 3. "A new source is addable purely as an adapter" (acceptance criterion)
# ===========================================================================


class _SecondIndependentAdapter:
    """An adapter defined entirely outside sources/ (here, in the test
    module), with no shared base class with SyntheticSourceAdapter, proving
    the interface is structural/duck-typed and genuinely adapter-agnostic."""

    @property
    def source_type(self) -> str:
        return "second-independent-source"

    def to_observations(self, raw_record: Any) -> tuple[Observation, ...]:
        return (
            Observation(
                observation_id=str(raw_record),
                timestamp=T0,
                raw_reference=SourceRef(
                    source_type=self.source_type, source_event_id=str(raw_record)
                ),
            ),
        )


def test_a_second_independently_defined_adapter_works_without_touching_domain() -> None:
    """Demonstrates the G0.4 acceptance criterion: adding a new source is
    purely a new adapter object; nothing in domain/ or adapter.py itself
    changes to support it."""
    adapter = _SecondIndependentAdapter()
    assert isinstance(adapter, SourceAdapter)

    observations = convert(adapter, "raw-42")

    assert len(observations) == 1
    assert observations[0].raw_reference.source_type == "second-independent-source"


# ===========================================================================
# 4. Guard: the domain layer never imports a source adapter's native types
# ===========================================================================


def test_domain_package_never_imports_from_sources() -> None:
    """Static AST check over every module in domain/: no import statement
    references attribution_platform.sources (in either direction of the
    dependency: domain must not know sources exists)."""
    domain_files = sorted(DOMAIN_DIR.glob("*.py"))
    assert domain_files, "expected to find domain/*.py files"

    offending: list[str] = []
    for path in domain_files:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module and "sources" in node.module:
                offending.append(f"{path.name}: from {node.module} import ...")
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if "sources" in alias.name:
                        offending.append(f"{path.name}: import {alias.name}")

    assert not offending, f"domain/ must not import from sources/: {offending}"
