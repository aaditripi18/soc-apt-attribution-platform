"""Loading a hand-authored synthetic fixture file into replayable scenarios
(gate G0.9).

The fixture format is deliberately small and specific — **not** a general
dataset framework. One JSON file holds:

    {
      "fixture_id": "<stable name>",
      "scenarios": [
        {
          "scenario_id": "<stable name, unique within the file>",
          "raw_record": {"record_id": "...", "timestamp": "<ISO-8601>", "observation_id": "..."},
          "rule": {"rule_id": "...", "rule_version": "..."},
          "evidence": {
            "evidence_id": "...",
            "evidence_type": "behavioral|evidentiary|procedural|contextual",
            "claim": "...",
            "attack_ref": {"stix_id": "...", "object_type": "...", "attack_kb_version": "...",
                            "external_id": "..."}   // optional
          }
        },
        ...
      ]
    }

``raw_record`` is exactly the shape
:class:`attribution_platform.sources.synthetic.SyntheticRecord` (the
existing G0.4 reference adapter) accepts — no new raw-record shape is
introduced, and G0.4's adapter is used completely unmodified. ``rule`` is
exactly a G0.5 :class:`~attribution_platform.extraction.detection_match.RuleRef`.
``evidence`` supplies exactly the caller-provided fields G0.6's
:func:`~attribution_platform.extraction.evidence_derivation.derive_evidence`
needs beyond the Observations it derives from; ``attack_ref``, when present,
is a G0.3 :class:`~attribution_platform.domain.AttackRef` (a real reference,
resolved against the pinned KB when the fixture is replayed — never
duplicated ATT&CK content).

Fail-closed: any structural problem (invalid JSON, a missing/wrong-typed
field, an unrecognized ``evidence_type``, a malformed timestamp, a duplicate
``scenario_id``) raises :class:`~attribution_platform.replay.errors.ReplayError`
naming exactly what and where. A fixture that parses cleanly but whose
*content* a downstream pipeline stage rejects (e.g. an ``attack_ref`` absent
from the KB) is NOT this module's concern — see
:mod:`attribution_platform.replay.errors`.

Deterministic and repeatable: the fixture's SHA-256 content hash is computed
here once (over the exact file bytes, no re-serialization) and exposed as
``Fixture.dataset_ref`` (``"<fixture_id>@<sha256>"``) — the
``SourceRef.dataset_ref`` doc 13 G0.9 requires ("content-hash the fixture
set"). Re-loading and re-replaying the same file always produces the same
hash and the same scenarios; nothing here reads the clock or generates an id.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from attribution_platform.domain import AttackRef, DomainContractError, EvidenceType
from attribution_platform.extraction.detection_match import RuleRef
from attribution_platform.extraction.errors import ExtractionError
from attribution_platform.replay.errors import ReplayError
from attribution_platform.sources.synthetic import SyntheticRecord

_REQUIRED_SCENARIO_FIELDS = ("scenario_id", "raw_record", "rule", "evidence")


@dataclass(frozen=True)
class EvidenceSpec:
    """The caller-supplied Evidence fields a fixture scenario declares."""

    evidence_id: str
    evidence_type: EvidenceType
    claim: str
    attack_ref: AttackRef | None


@dataclass(frozen=True)
class ReplayScenario:
    """One fixture scenario, parsed into the exact types the G0.4-G0.8
    pipeline functions accept."""

    scenario_id: str
    raw_record: SyntheticRecord
    rule_ref: RuleRef
    evidence_spec: EvidenceSpec


@dataclass(frozen=True)
class Fixture:
    """A loaded fixture file: its identity, content hash, and scenarios."""

    fixture_id: str
    content_hash: str
    scenarios: tuple[ReplayScenario, ...]

    @property
    def dataset_ref(self) -> str:
        """The ``SourceRef.dataset_ref`` value for every Observation replayed
        from this fixture: ``"<fixture_id>@<sha256 of the file bytes>"``."""
        return f"{self.fixture_id}@{self.content_hash}"


def load_fixture_file(path: Path) -> Fixture:
    """Read and validate one fixture JSON file from disk."""
    try:
        raw_bytes = path.read_bytes()
    except OSError as exc:
        raise ReplayError(f"could not read fixture file {path}: {exc}") from exc

    content_hash = hashlib.sha256(raw_bytes).hexdigest()

    try:
        data = json.loads(raw_bytes.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ReplayError(f"{path}: not valid JSON: {exc}") from exc

    return _fixture_from_dict(data, content_hash=content_hash, source=str(path))


def _fixture_from_dict(data: Any, *, content_hash: str, source: str) -> Fixture:
    if not isinstance(data, dict):
        raise ReplayError(f"{source}: fixture root must be a JSON object")

    fixture_id = data.get("fixture_id")
    if not isinstance(fixture_id, str) or not fixture_id.strip():
        raise ReplayError(f"{source}: 'fixture_id' must be a non-empty string")

    scenarios_raw = data.get("scenarios")
    if not isinstance(scenarios_raw, list) or not scenarios_raw:
        raise ReplayError(f"{source}: 'scenarios' must be a non-empty list")

    scenarios = tuple(
        _scenario_from_dict(s, index=i, source=source) for i, s in enumerate(scenarios_raw)
    )

    scenario_ids = [s.scenario_id for s in scenarios]
    if len(scenario_ids) != len(set(scenario_ids)):
        raise ReplayError(f"{source}: duplicate scenario_id values: {scenario_ids}")

    return Fixture(fixture_id=fixture_id, content_hash=content_hash, scenarios=scenarios)


def _scenario_from_dict(s: Any, *, index: int, source: str) -> ReplayScenario:
    if not isinstance(s, dict):
        raise ReplayError(f"{source}: scenarios[{index}] must be a JSON object")
    for field_name in _REQUIRED_SCENARIO_FIELDS:
        if field_name not in s:
            raise ReplayError(f"{source}: scenarios[{index}] missing required field {field_name!r}")

    scenario_id = s["scenario_id"]
    if not isinstance(scenario_id, str) or not scenario_id.strip():
        raise ReplayError(f"{source}: scenarios[{index}].scenario_id must be a non-empty string")

    return ReplayScenario(
        scenario_id=scenario_id,
        raw_record=_synthetic_record_from_dict(s["raw_record"], index=index, source=source),
        rule_ref=_rule_ref_from_dict(s["rule"], index=index, source=source),
        evidence_spec=_evidence_spec_from_dict(s["evidence"], index=index, source=source),
    )


def _synthetic_record_from_dict(d: Any, *, index: int, source: str) -> SyntheticRecord:
    if not isinstance(d, dict):
        raise ReplayError(f"{source}: scenarios[{index}].raw_record must be a JSON object")
    if "record_id" not in d or "timestamp" not in d:
        raise ReplayError(
            f"{source}: scenarios[{index}].raw_record requires 'record_id' and 'timestamp'"
        )
    try:
        timestamp = datetime.fromisoformat(d["timestamp"])
    except (TypeError, ValueError) as exc:
        raise ReplayError(
            f"{source}: scenarios[{index}].raw_record.timestamp is not a valid ISO-8601 "
            f"timestamp: {exc}"
        ) from exc
    record_id = d["record_id"]
    if not isinstance(record_id, str) or not record_id.strip():
        raise ReplayError(
            f"{source}: scenarios[{index}].raw_record.record_id must be a non-empty string"
        )
    observation_id = d.get("observation_id")
    if observation_id is not None and not isinstance(observation_id, str):
        raise ReplayError(
            f"{source}: scenarios[{index}].raw_record.observation_id must be a string if present"
        )
    return SyntheticRecord(record_id=record_id, timestamp=timestamp, observation_id=observation_id)


def _rule_ref_from_dict(d: Any, *, index: int, source: str) -> RuleRef:
    if not isinstance(d, dict):
        raise ReplayError(f"{source}: scenarios[{index}].rule must be a JSON object")
    try:
        return RuleRef(rule_id=d["rule_id"], rule_version=d["rule_version"])
    except KeyError as exc:
        raise ReplayError(f"{source}: scenarios[{index}].rule missing {exc}") from exc
    except ExtractionError as exc:
        raise ReplayError(f"{source}: scenarios[{index}].rule invalid: {exc}") from exc


def _evidence_spec_from_dict(d: Any, *, index: int, source: str) -> EvidenceSpec:
    if not isinstance(d, dict):
        raise ReplayError(f"{source}: scenarios[{index}].evidence must be a JSON object")
    for field_name in ("evidence_id", "evidence_type", "claim"):
        if field_name not in d:
            raise ReplayError(
                f"{source}: scenarios[{index}].evidence missing required field {field_name!r}"
            )

    evidence_id = d["evidence_id"]
    if not isinstance(evidence_id, str) or not evidence_id.strip():
        raise ReplayError(
            f"{source}: scenarios[{index}].evidence.evidence_id must be a non-empty string"
        )
    claim = d["claim"]
    if not isinstance(claim, str) or not claim.strip():
        raise ReplayError(f"{source}: scenarios[{index}].evidence.claim must be a non-empty string")
    try:
        evidence_type = EvidenceType(d["evidence_type"])
    except ValueError as exc:
        raise ReplayError(
            f"{source}: scenarios[{index}].evidence.evidence_type invalid: {exc}"
        ) from exc

    attack_ref_dict = d.get("attack_ref")
    attack_ref: AttackRef | None = None
    if attack_ref_dict is not None:
        if not isinstance(attack_ref_dict, dict):
            raise ReplayError(
                f"{source}: scenarios[{index}].evidence.attack_ref must be a JSON object"
            )
        try:
            attack_ref = AttackRef(
                stix_id=attack_ref_dict["stix_id"],
                object_type=attack_ref_dict["object_type"],
                attack_kb_version=attack_ref_dict["attack_kb_version"],
                external_id=attack_ref_dict.get("external_id"),
            )
        except KeyError as exc:
            raise ReplayError(
                f"{source}: scenarios[{index}].evidence.attack_ref missing {exc}"
            ) from exc
        except DomainContractError as exc:
            raise ReplayError(
                f"{source}: scenarios[{index}].evidence.attack_ref invalid: {exc}"
            ) from exc

    return EvidenceSpec(
        evidence_id=evidence_id, evidence_type=evidence_type, claim=claim, attack_ref=attack_ref
    )
