"""Tests for gate G0.6: Evidence derivation + ATT&CK technique reference.

Covers: valid Observation -> Evidence derivation, provenance preservation
(supporting observation ids + rule context), valid technique and sub-technique
references validated against the real pinned v19.0 KB, nonexistent-reference
rejection, wrong-STIX-object-type rejection, KB-version mismatch, determinism,
fail-closed derivation errors, and a guard that no ATT&CK actor/technique data
is hard-coded in the G0.6 source.

Does NOT touch the G0.0-G0.5 test files. Offline (loads only the vendored KB),
deterministic, stdlib-only.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from attribution_platform.attack_knowledge.loader import (
    AttackKnowledge,
    load_attack_knowledge,
)
from attribution_platform.attack_knowledge.resolution import (
    AttackReferenceError,
    resolve_attack_ref,
)
from attribution_platform.domain import (
    AttackRef,
    Evidence,
    EvidenceType,
    Observation,
    SourceRef,
    to_canonical_json,
)
from attribution_platform.extraction import (
    DetectionMatchRecord,
    MatchedEvent,
    RuleRef,
    derive_evidence,
    extract_observations,
)
from attribution_platform.extraction.evidence_derivation import EvidenceDerivationError

T0 = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)

RESOLUTION_SRC = (
    Path(__file__).resolve().parents[1]
    / "src"
    / "attribution_platform"
    / "attack_knowledge"
    / "resolution.py"
)
EVIDENCE_DERIVATION_SRC = (
    Path(__file__).resolve().parents[1]
    / "src"
    / "attribution_platform"
    / "extraction"
    / "evidence_derivation.py"
)


@pytest.fixture(scope="module")
def knowledge() -> AttackKnowledge:
    """Load the pinned v19.0 KB once for the whole module."""
    return load_attack_knowledge()


def _rule() -> RuleRef:
    return RuleRef(rule_id="rule-x", rule_version="1.0")


def _observations(*ids: str) -> tuple[Observation, ...]:
    ids = ids or ("obs-1",)
    record = DetectionMatchRecord(
        rule_ref=_rule(),
        matched_events=tuple(
            MatchedEvent(
                observation_id=oid,
                source_ref=SourceRef(source_type="synthetic", source_event_id=f"raw-{oid}"),
                timestamp=T0,
            )
            for oid in ids
        ),
    )
    return extract_observations(record)


# ===========================================================================
# 1. Valid Observation -> Evidence derivation  &  2. provenance preservation
# ===========================================================================


def test_valid_derivation_without_attack_ref() -> None:
    observations = _observations("obs-1", "obs-2")
    evidence = derive_evidence(
        evidence_id="ev-1",
        evidence_type=EvidenceType.BEHAVIORAL,
        claim="something happened",
        observations=observations,
        rule_ref=_rule(),
    )
    assert isinstance(evidence, Evidence)
    assert evidence.evidence_id == "ev-1"
    assert evidence.attack_ref is None


def test_provenance_retains_observation_ids_and_rule_context() -> None:
    observations = _observations("obs-b", "obs-a")
    evidence = derive_evidence(
        evidence_id="ev-1",
        evidence_type=EvidenceType.BEHAVIORAL,
        claim="c",
        observations=observations,
        rule_ref=RuleRef(rule_id="R-42", rule_version="3.1"),
    )
    # rule context -> method/method_version
    assert evidence.provenance.method == "R-42"
    assert evidence.provenance.method_version == "3.1"
    # supporting observation ids retained (canonicalized sorted+unique by G0.3)
    assert evidence.provenance.source_observation_ids == ("obs-a", "obs-b")


# ===========================================================================
# 3. Valid technique and sub-technique references (against the real KB)
# ===========================================================================


def _attack_ref_from(obj: Any, kb: AttackKnowledge) -> AttackRef:
    return AttackRef(
        stix_id=obj["id"],
        object_type=obj["type"],
        attack_kb_version=kb.attack_kb_version,
    )


def test_valid_technique_reference_resolves_and_attaches(knowledge: AttackKnowledge) -> None:
    technique = knowledge.techniques()[0]
    ref = _attack_ref_from(technique, knowledge)

    # resolve_attack_ref returns the pinned object
    resolved = resolve_attack_ref(knowledge, ref)
    assert resolved["id"] == technique["id"]

    evidence = derive_evidence(
        evidence_id="ev-1",
        evidence_type=EvidenceType.BEHAVIORAL,
        claim="technique observed",
        observations=_observations(),
        rule_ref=_rule(),
        attack_ref=ref,
        knowledge=knowledge,
    )
    assert evidence.attack_ref is ref


def test_valid_sub_technique_reference_resolves(knowledge: AttackKnowledge) -> None:
    sub_technique = knowledge.sub_techniques()[0]
    ref = _attack_ref_from(sub_technique, knowledge)
    resolved = resolve_attack_ref(knowledge, ref)
    assert resolved["id"] == sub_technique["id"]
    assert resolved.get("x_mitre_is_subtechnique") is True


# ===========================================================================
# 4. Nonexistent ATT&CK reference rejection
# ===========================================================================


def test_nonexistent_reference_rejected_by_resolver(knowledge: AttackKnowledge) -> None:
    # Well-formed STIX id (prefix matches object_type, so AttackRef accepts it),
    # but absent from the KB.
    ref = AttackRef(
        stix_id="attack-pattern--00000000-0000-0000-0000-000000000000",
        object_type="attack-pattern",
        attack_kb_version=knowledge.attack_kb_version,
    )
    with pytest.raises(AttackReferenceError, match="does not exist"):
        resolve_attack_ref(knowledge, ref)


def test_nonexistent_reference_fails_derivation(knowledge: AttackKnowledge) -> None:
    ref = AttackRef(
        stix_id="attack-pattern--00000000-0000-0000-0000-000000000000",
        object_type="attack-pattern",
        attack_kb_version=knowledge.attack_kb_version,
    )
    with pytest.raises(AttackReferenceError):
        derive_evidence(
            evidence_id="ev-1",
            evidence_type=EvidenceType.BEHAVIORAL,
            claim="c",
            observations=_observations(),
            rule_ref=_rule(),
            attack_ref=ref,
            knowledge=knowledge,
        )


def test_kb_version_mismatch_rejected(knowledge: AttackKnowledge) -> None:
    technique = knowledge.techniques()[0]
    ref = AttackRef(
        stix_id=technique["id"],
        object_type=technique["type"],
        attack_kb_version="enterprise-attack-18.0",  # not the loaded version
    )
    with pytest.raises(AttackReferenceError, match="does not match the loaded"):
        resolve_attack_ref(knowledge, ref)


# ===========================================================================
# 5. Wrong STIX object-type rejection
# ===========================================================================


class _StubKnowledge:
    """A minimal KB test double exposing only what ``resolve_attack_ref`` uses
    (``attack_kb_version`` + ``get_by_id``).

    Needed because ``resolve_attack_ref``'s object-type check is
    defence-in-depth: on the real KB every STIX id truthfully prefixes its own
    type, and G0.3's ``AttackRef`` already requires ``object_type`` to equal
    that prefix — so a genuine type mismatch is only reachable with a crafted
    object whose stored ``type`` differs from a truthful-looking id prefix.
    """

    def __init__(self, objects: dict[str, dict[str, Any]]) -> None:
        self.attack_kb_version = "enterprise-attack-19.0"
        self._objects = objects

    def get_by_id(self, stix_id: str) -> dict[str, Any] | None:
        return self._objects.get(stix_id)


def test_wrong_object_type_rejected() -> None:
    # id prefix says "attack-pattern" (so AttackRef accepts object_type
    # "attack-pattern"), but the stored object is actually an intrusion-set.
    stix_id = "attack-pattern--11111111-1111-1111-1111-111111111111"
    stub = _StubKnowledge({stix_id: {"id": stix_id, "type": "intrusion-set"}})
    ref = AttackRef(
        stix_id=stix_id,
        object_type="attack-pattern",
        attack_kb_version="enterprise-attack-19.0",
    )
    with pytest.raises(AttackReferenceError, match="resolves to a 'intrusion-set'"):
        resolve_attack_ref(stub, ref)  # type: ignore[arg-type]


# ===========================================================================
# 6. Deterministic output
# ===========================================================================


def test_derivation_is_deterministic(knowledge: AttackKnowledge) -> None:
    ref = _attack_ref_from(knowledge.techniques()[0], knowledge)

    def build() -> Evidence:
        return derive_evidence(
            evidence_id="ev-1",
            evidence_type=EvidenceType.BEHAVIORAL,
            claim="c",
            observations=_observations("o1", "o2"),
            rule_ref=_rule(),
            attack_ref=ref,
            knowledge=knowledge,
        )

    first, second = build(), build()
    assert first == second
    assert to_canonical_json(first) == to_canonical_json(second)


def test_derivation_injects_no_wall_clock_or_ids() -> None:
    evidence = derive_evidence(
        evidence_id="supplied-id",
        evidence_type=EvidenceType.BEHAVIORAL,
        claim="c",
        observations=_observations(),
        rule_ref=_rule(),
    )
    assert evidence.evidence_id == "supplied-id"
    assert evidence.provenance.derived_at is None  # nothing stamped


# ===========================================================================
# Fail-closed derivation errors
# ===========================================================================


def test_no_observations_fails_closed() -> None:
    with pytest.raises(EvidenceDerivationError, match="at least one supporting Observation"):
        derive_evidence(
            evidence_id="ev-1",
            evidence_type=EvidenceType.BEHAVIORAL,
            claim="c",
            observations=(),
            rule_ref=_rule(),
        )


def test_non_observation_input_fails_closed() -> None:
    bad: Sequence[Observation] = ["not-an-observation"]  # type: ignore[list-item]
    with pytest.raises(EvidenceDerivationError, match="must be a domain Observation"):
        derive_evidence(
            evidence_id="ev-1",
            evidence_type=EvidenceType.BEHAVIORAL,
            claim="c",
            observations=bad,
            rule_ref=_rule(),
        )


def test_attack_ref_without_knowledge_fails_closed() -> None:
    ref = AttackRef(
        stix_id="attack-pattern--22222222-2222-2222-2222-222222222222",
        object_type="attack-pattern",
        attack_kb_version="enterprise-attack-19.0",
    )
    with pytest.raises(EvidenceDerivationError, match="no loaded ATT&CK knowledge"):
        derive_evidence(
            evidence_id="ev-1",
            evidence_type=EvidenceType.BEHAVIORAL,
            claim="c",
            observations=_observations(),
            rule_ref=_rule(),
            attack_ref=ref,
            knowledge=None,
        )


# ===========================================================================
# 7. No hard-coded ATT&CK actor/technique data in the G0.6 source
# ===========================================================================

_TECHNIQUE_ID = re.compile(r"\bT\d{4}(\.\d{3})?\b")
_TACTIC_ID = re.compile(r"\bTA\d{4}\b")


def test_g06_source_has_no_hard_coded_attack_ids() -> None:
    for path in (RESOLUTION_SRC, EVIDENCE_DERIVATION_SRC):
        text = path.read_text(encoding="utf-8")
        assert not _TECHNIQUE_ID.search(text), f"hard-coded technique id in {path.name}"
        assert not _TACTIC_ID.search(text), f"hard-coded tactic id in {path.name}"
