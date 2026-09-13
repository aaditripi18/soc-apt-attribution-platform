"""Tests for gate G0.3: the source-agnostic domain contracts.

Covers valid construction of every contract, required invariants,
fail-closed rejection of invalid input, Observation<-Evidence provenance
linkage, deterministic equality/serialization, deep immutability at every
exposed level, absence of source-specific requirements in the core
Observation, and absence of any attribution/scoring semantics.

Does NOT touch the G0.0/G0.1/G0.2 test files. All tests are offline,
deterministic, stdlib-only: no network, Docker, Windows APIs, or Elastic.
"""

from __future__ import annotations

import dataclasses
from datetime import UTC, datetime

import pytest

from attribution_platform.domain import (
    EVIDENCE_SCHEMA_VERSION,
    OBSERVATION_SCHEMA_VERSION,
    AttackRef,
    DerivationProvenance,
    DomainContractError,
    EventMetadata,
    Evidence,
    EvidenceQuality,
    EvidenceType,
    FileRef,
    HashSet,
    HostRef,
    NetworkEndpoint,
    NetworkInfo,
    Observation,
    ProcessRef,
    SourceRef,
    TimePrecision,
    TimeSpan,
    UserRef,
    to_canonical_json,
    to_serializable,
)

T0 = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
T1 = datetime(2026, 1, 1, 12, 5, 0, tzinfo=UTC)


def _source_ref() -> SourceRef:
    return SourceRef(source_type="synthetic", source_event_id="raw-1")


def _observation(obs_id: str = "obs-1") -> Observation:
    return Observation(observation_id=obs_id, timestamp=T0, raw_reference=_source_ref())


def _provenance(ids: tuple[str, ...] = ("obs-1",)) -> DerivationProvenance:
    return DerivationProvenance(method="rule-x", method_version="1.0", source_observation_ids=ids)


def _evidence(ev_id: str = "ev-1") -> Evidence:
    return Evidence(
        evidence_id=ev_id,
        evidence_type=EvidenceType.BEHAVIORAL,
        claim="a claim",
        provenance=_provenance(),
    )


# ===========================================================================
# 1. Valid construction
# ===========================================================================


def test_valid_source_ref() -> None:
    ref = SourceRef(
        source_type="sysmon", source_event_id="e1", dataset_ref="d@h", raw_payload_ref="p"
    )
    assert ref.source_type == "sysmon"
    assert ref.source_event_id == "e1"


def test_valid_observation_minimal() -> None:
    obs = _observation()
    assert obs.observation_id == "obs-1"
    assert obs.timestamp == T0
    assert obs.schema_version == OBSERVATION_SCHEMA_VERSION
    # every telemetry field is optional and absent by default
    assert obs.host is None and obs.user is None and obs.process is None
    assert obs.network is None and obs.file is None and obs.event is None
    assert obs.timestamp_precision is None


def test_valid_observation_full() -> None:
    obs = Observation(
        observation_id="obs-2",
        timestamp=T0,
        raw_reference=_source_ref(),
        timestamp_precision=TimePrecision.MILLISECOND,
        event=EventMetadata(kind="event", category=("process",), type=("start",), action="exec"),
        host=HostRef(id="h", name="HOST1", ip=("10.0.0.1", "10.0.0.2")),
        user=UserRef(id="u", name="alice", domain="CORP"),
        process=ProcessRef(
            pid=10,
            name="p.exe",
            executable="C:/p.exe",
            command_line="p -x",
            entity_id="pe",
            parent_pid=1,
            parent_name="svc.exe",
            parent_entity_id="ppe",
        ),
        network=NetworkInfo(
            source=NetworkEndpoint(ip="1.1.1.1", port=1000),
            destination=NetworkEndpoint(ip="2.2.2.2", port=443),
            protocol="tls",
            transport="tcp",
            direction="outbound",
        ),
        file=FileRef(path="C:/f", name="f", hashes=HashSet(sha256="a" * 64)),
    )
    assert obs.process is not None and obs.process.parent_name == "svc.exe"
    assert obs.file is not None and obs.file.hashes is not None
    assert obs.file.hashes.sha256 == "a" * 64


def test_valid_provenance_and_dedup_sort() -> None:
    prov = DerivationProvenance(
        method="m", method_version="v", source_observation_ids=("b", "a", "b", "c")
    )
    # canonicalized: deduped + sorted -> order-independent equality
    assert prov.source_observation_ids == ("a", "b", "c")


def test_valid_provenance_create_helper_accepts_any_iterable() -> None:
    prov = DerivationProvenance.create(
        method="m", method_version="v", source_observation_ids=iter(["x", "y"])
    )
    assert prov.source_observation_ids == ("x", "y")


def test_valid_evidence_minimal() -> None:
    ev = _evidence()
    assert ev.evidence_id == "ev-1"
    assert ev.evidence_type is EvidenceType.BEHAVIORAL
    assert ev.schema_version == EVIDENCE_SCHEMA_VERSION
    assert ev.attack_ref is None and ev.quality is None and ev.time_span is None


def test_valid_evidence_full() -> None:
    ev = Evidence(
        evidence_id="ev-2",
        evidence_type=EvidenceType.EVIDENTIARY,
        claim="ioc seen",
        provenance=_provenance(("obs-1", "obs-2")),
        attack_ref=AttackRef(
            stix_id="attack-pattern--1234",
            object_type="attack-pattern",
            attack_kb_version="enterprise-attack-19.0",
            external_id="T1059",
        ),
        quality=EvidenceQuality.LOW,
        time_span=TimeSpan(start=T0, end=T1),
        host=HostRef(name="HOST1"),
        user=UserRef(name="alice"),
    )
    assert ev.attack_ref is not None and ev.attack_ref.external_id == "T1059"
    assert ev.time_span is not None and ev.time_span.end == T1


def test_valid_attack_ref_without_external_id() -> None:
    ref = AttackRef(
        stix_id="intrusion-set--abcd",
        object_type="intrusion-set",
        attack_kb_version="enterprise-attack-19.0",
    )
    assert ref.external_id is None


# ===========================================================================
# 2. Fail-closed rejection of invalid input
# ===========================================================================


@pytest.mark.parametrize("bad_id", ["", "   ", "\t\n"])
def test_empty_observation_id_rejected(bad_id: str) -> None:
    with pytest.raises(DomainContractError, match="observation_id"):
        Observation(observation_id=bad_id, timestamp=T0, raw_reference=_source_ref())


def test_naive_timestamp_rejected() -> None:
    naive = datetime(2026, 1, 1, 12, 0, 0)  # no tzinfo
    with pytest.raises(DomainContractError, match="timezone-aware"):
        Observation(observation_id="o", timestamp=naive, raw_reference=_source_ref())


def test_source_ref_requires_source_type_and_event_id() -> None:
    with pytest.raises(DomainContractError, match="source_type"):
        SourceRef(source_type="", source_event_id="e")
    with pytest.raises(DomainContractError, match="source_event_id"):
        SourceRef(source_type="s", source_event_id="  ")


def test_evidence_requires_supporting_observations() -> None:
    with pytest.raises(DomainContractError, match="source_observation_ids must be non-empty"):
        DerivationProvenance(method="m", method_version="v", source_observation_ids=())


def test_provenance_requires_method_and_version() -> None:
    with pytest.raises(DomainContractError, match="method"):
        DerivationProvenance(method="", method_version="v", source_observation_ids=("o",))
    with pytest.raises(DomainContractError, match="method_version"):
        DerivationProvenance(method="m", method_version="", source_observation_ids=("o",))


def test_provenance_rejects_empty_observation_id_member() -> None:
    with pytest.raises(DomainContractError, match="source_observation_ids"):
        DerivationProvenance(method="m", method_version="v", source_observation_ids=("ok", ""))


def test_evidence_empty_claim_rejected() -> None:
    with pytest.raises(DomainContractError, match="claim"):
        Evidence(
            evidence_id="e",
            evidence_type=EvidenceType.BEHAVIORAL,
            claim="  ",
            provenance=_provenance(),
        )


def test_evidence_type_must_be_enum_not_raw_string() -> None:
    with pytest.raises(TypeError, match="evidence_type"):
        Evidence(
            evidence_id="e",
            evidence_type="behavioral",  # type: ignore[arg-type]
            claim="c",
            provenance=_provenance(),
        )


def test_unknown_enum_value_rejected() -> None:
    with pytest.raises(ValueError):
        EvidenceType("not-a-real-type")


def test_attack_ref_invalid_shapes_rejected() -> None:
    # missing "--" separator
    with pytest.raises(DomainContractError, match="well-formed STIX id"):
        AttackRef(stix_id="T1059", object_type="attack-pattern", attack_kb_version="k")
    # prefix does not match object_type
    with pytest.raises(DomainContractError, match="type-prefix"):
        AttackRef(stix_id="malware--abc", object_type="attack-pattern", attack_kb_version="k")
    # empty kb version
    with pytest.raises(DomainContractError, match="attack_kb_version"):
        AttackRef(stix_id="attack-pattern--abc", object_type="attack-pattern", attack_kb_version="")


def test_timespan_rejects_reversed_and_naive_bounds() -> None:
    with pytest.raises(DomainContractError, match="must not be after"):
        TimeSpan(start=T1, end=T0)
    with pytest.raises(DomainContractError, match="timezone-aware"):
        TimeSpan(start=datetime(2026, 1, 1), end=T1)


# ===========================================================================
# 3. Provenance linkage (Observation <- Evidence)
# ===========================================================================


def test_evidence_retains_provenance_to_observations() -> None:
    obs_a = _observation("obs-A")
    obs_b = _observation("obs-B")
    ev = Evidence(
        evidence_id="ev",
        evidence_type=EvidenceType.BEHAVIORAL,
        claim="derived from A and B",
        provenance=_provenance((obs_a.observation_id, obs_b.observation_id)),
    )
    assert set(ev.provenance.source_observation_ids) == {"obs-A", "obs-B"}


# ===========================================================================
# 4. Deterministic equality & serialization
# ===========================================================================


def test_value_equality_and_order_independent_provenance() -> None:
    assert _observation() == _observation()
    assert _evidence() == _evidence()
    # provenance equality is order-independent (canonicalized)
    p1 = DerivationProvenance(method="m", method_version="v", source_observation_ids=("a", "b"))
    p2 = DerivationProvenance(method="m", method_version="v", source_observation_ids=("b", "a"))
    assert p1 == p2


def test_canonical_json_is_deterministic_and_stable() -> None:
    ev = _evidence()
    assert to_canonical_json(ev) == to_canonical_json(_evidence())
    # equal objects -> identical canonical json
    assert to_canonical_json(_observation()) == to_canonical_json(_observation())


def test_serialization_converts_types_correctly() -> None:
    obs = Observation(
        observation_id="o",
        timestamp=T0,
        raw_reference=_source_ref(),
        timestamp_precision=TimePrecision.SECOND,
        host=HostRef(ip=("10.0.0.1",)),
    )
    data = to_serializable(obs)
    assert isinstance(data, dict)
    assert data["timestamp"] == T0.isoformat()  # datetime -> iso string
    assert data["timestamp_precision"] == "second"  # enum -> value
    assert data["host"]["ip"] == ["10.0.0.1"]  # tuple -> list
    assert data["schema_version"] == OBSERVATION_SCHEMA_VERSION


def test_serialization_output_is_a_detached_copy() -> None:
    obs = _observation()
    data = to_serializable(obs)
    data["observation_id"] = "MUTATED"  # mutating the output must not affect the object
    assert obs.observation_id == "obs-1"


# ===========================================================================
# 5. Deep immutability at every exposed level
# ===========================================================================


def test_top_level_contracts_reject_attribute_assignment() -> None:
    for obj in (_source_ref(), _observation(), _provenance(), _evidence()):
        with pytest.raises(dataclasses.FrozenInstanceError):
            obj.__setattr__("observation_id", "x")  # frozen -> raises regardless of field


def test_nested_frozen_dataclass_fields_reject_mutation() -> None:
    obs = Observation(
        observation_id="o",
        timestamp=T0,
        raw_reference=_source_ref(),
        process=ProcessRef(pid=1, name="p"),
        file=FileRef(hashes=HashSet(sha256="a" * 64)),
    )
    assert obs.process is not None
    with pytest.raises(dataclasses.FrozenInstanceError):
        obs.process.__setattr__("pid", 999)
    # two levels deep: FileRef -> HashSet
    assert obs.file is not None and obs.file.hashes is not None
    with pytest.raises(dataclasses.FrozenInstanceError):
        obs.file.hashes.__setattr__("sha256", "b" * 64)
    # the raw_reference provenance object too
    with pytest.raises(dataclasses.FrozenInstanceError):
        obs.raw_reference.__setattr__("source_type", "x")


def test_tuple_fields_are_immutable_sequences() -> None:
    obs = Observation(
        observation_id="o",
        timestamp=T0,
        raw_reference=_source_ref(),
        host=HostRef(ip=("10.0.0.1", "10.0.0.2")),
    )
    assert obs.host is not None
    assert isinstance(obs.host.ip, tuple)
    assert not hasattr(obs.host.ip, "append")
    with pytest.raises(TypeError):
        obs.host.ip[0] = "9.9.9.9"  # type: ignore[index]

    prov = _provenance(("a", "b"))
    assert isinstance(prov.source_observation_ids, tuple)
    with pytest.raises(TypeError):
        prov.source_observation_ids[0] = "z"  # type: ignore[index]


def test_no_domain_contract_exposes_a_mutable_mapping_or_list() -> None:
    """Exhaustive scan: no field of any constructed contract is a plain
    dict or list (the whole design uses frozen dataclasses + tuples)."""

    def assert_no_mutable_containers(obj: object, path: str) -> None:
        if isinstance(obj, dict):
            pytest.fail(f"mutable dict exposed at {path}")
        if isinstance(obj, list):
            pytest.fail(f"mutable list exposed at {path}")
        if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
            for f in dataclasses.fields(obj):
                assert_no_mutable_containers(getattr(obj, f.name), f"{path}.{f.name}")
        elif isinstance(obj, tuple):
            for i, v in enumerate(obj):
                assert_no_mutable_containers(v, f"{path}[{i}]")

    ev = Evidence(
        evidence_id="e",
        evidence_type=EvidenceType.BEHAVIORAL,
        claim="c",
        provenance=_provenance(("a", "b")),
        attack_ref=AttackRef(
            stix_id="attack-pattern--x",
            object_type="attack-pattern",
            attack_kb_version="enterprise-attack-19.0",
        ),
        time_span=TimeSpan(start=T0, end=T1),
        host=HostRef(ip=("1.1.1.1",)),
    )
    assert_no_mutable_containers(ev, "Evidence")


# ===========================================================================
# 6. Source-agnosticism & absence of attribution/scoring semantics
# ===========================================================================


def test_observation_has_no_source_specific_required_fields() -> None:
    """The core Observation must be constructible with only source-agnostic
    identity/timestamp/provenance — no Sysmon/Windows/Elastic field required."""
    obs = _observation()  # constructed with zero source-specific fields
    field_names = {f.name for f in dataclasses.fields(obs)}
    # no field name encodes a specific source/collector schema
    for forbidden in ("sysmon", "winlog", "elastic", "ecs_raw"):
        assert not any(forbidden in n for n in field_names)


def test_no_attribution_or_scoring_fields_on_contracts() -> None:
    """Evidence/Observation must carry no attribution likelihood/confidence,
    score, ACH, or candidate fields (those belong to later gates/ADR-0002)."""
    forbidden = (
        "likelihood",
        "attribution_confidence",
        "score",
        "weight",
        "ach",
        "candidate",
        "hypothesis",
        "diagnosticity",
        "probability",
    )
    for contract in (Observation, Evidence, DerivationProvenance, AttackRef):
        names = {f.name.lower() for f in dataclasses.fields(contract)}
        for bad in forbidden:
            assert not any(bad in n for n in names), f"{contract.__name__} exposes {bad!r}"


def test_evidence_quality_is_not_a_numeric_score() -> None:
    """EvidenceQuality is a closed qualitative vocabulary, not a number."""
    for member in EvidenceQuality:
        assert isinstance(member.value, str)
    ev = Evidence(
        evidence_id="e",
        evidence_type=EvidenceType.BEHAVIORAL,
        claim="c",
        provenance=_provenance(),
        quality=EvidenceQuality.MODERATE,
    )
    assert ev.quality is EvidenceQuality.MODERATE
    assert not isinstance(ev.quality.value, int | float)


def test_no_wall_clock_time_is_injected_at_construction() -> None:
    """Constructing contracts must not stamp 'now' anywhere — derived_at is
    only what the caller supplies (None by default)."""
    prov = _provenance()
    assert prov.derived_at is None
    ev = _evidence()
    # nothing in the serialized evidence should be a fresh timestamp we didn't set
    data = to_serializable(ev)
    assert data["provenance"]["derived_at"] is None
