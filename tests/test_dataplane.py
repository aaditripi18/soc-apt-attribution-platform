"""Tests for gate G0.8: Elastic integration (persistence of Observation/Evidence).

Covers: write->read round trip for Observation and Evidence (incl. entity
groups, ATT&CK reference, and derivation provenance); idempotent writes using
the domain id as the document id; deterministic, pinned index names/mappings;
fail-closed rejection of non-domain-object input and of a stored document
with an unrecognized schema_version; the ElasticClient abstraction (the same
persistence functions work against any conforming implementation); the
stdlib-only HTTP client's request construction and error handling (via a
patched ``urlopen`` — no network, no live Elasticsearch); and the
dependency-direction guard (domain never imports dataplane).

None of these tests require Docker, a live Elasticsearch instance, or
network access — per the gate's testing requirement, everything runs against
either ``FakeElasticClient`` (an in-memory Protocol-conforming double) or a
patched ``urllib.request.urlopen``.

Does NOT touch the G0.0-G0.7 test files. Offline, deterministic.
"""

from __future__ import annotations

import ast
import email.message
import io
import json
import urllib.error
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from attribution_platform.attack_knowledge.loader import load_attack_knowledge
from attribution_platform.dataplane import (
    EVIDENCE_INDEX,
    EVIDENCE_MAPPING,
    OBSERVATIONS_INDEX,
    OBSERVATIONS_MAPPING,
    ElasticClient,
    ElasticIntegrationError,
    ElasticsearchHttpClient,
    FakeElasticClient,
    PersistResult,
    load_evidence,
    load_observation,
    persist_evidence,
    persist_observation,
)
from attribution_platform.domain import (
    AttackRef,
    DerivationProvenance,
    EventMetadata,
    Evidence,
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
)

REPO_ROOT = Path(__file__).resolve().parents[1]
DOMAIN_DIR = REPO_ROOT / "src" / "attribution_platform" / "domain"

T0 = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
T1 = datetime(2026, 1, 1, 12, 5, 0, tzinfo=UTC)


def _full_observation(observation_id: str = "o1") -> Observation:
    """An Observation exercising every optional field, so the round trip
    covers every entity group, not just the required ones."""
    return Observation(
        observation_id=observation_id,
        timestamp=T0,
        raw_reference=SourceRef(
            source_type="synthetic", source_event_id="raw-1", dataset_ref="ds@abc123"
        ),
        timestamp_precision=TimePrecision.MILLISECOND,
        event=EventMetadata(
            kind="event",
            category=("process",),
            type=("start",),
            action="created",
            outcome="success",
        ),
        host=HostRef(id="h1", name="WIN-HOST", ip=("10.0.0.1", "10.0.0.2")),
        user=UserRef(id="u1", name="alice", domain="CORP"),
        process=ProcessRef(
            pid=4242, name="evil.exe", command_line="evil.exe --run", parent_pid=100
        ),
        network=NetworkInfo(
            source=NetworkEndpoint(ip="10.0.0.1", port=51234),
            destination=NetworkEndpoint(ip="93.184.216.34", port=443),
            protocol="tcp",
            transport="tcp",
            direction="outbound",
        ),
        file=FileRef(path="C:\\evil.exe", name="evil.exe", hashes=HashSet(sha256="a" * 64)),
    )


def _rule_evidence(evidence_id: str = "ev1", *, attack_ref: AttackRef | None = None) -> Evidence:
    return Evidence(
        evidence_id=evidence_id,
        evidence_type=EvidenceType.BEHAVIORAL,
        claim="process X spawned Y",
        provenance=DerivationProvenance(
            method="rule-x", method_version="1.0", source_observation_ids=("o1", "o2")
        ),
        attack_ref=attack_ref,
        time_span=TimeSpan(start=T0, end=T1),
        host=HostRef(id="h1", name="WIN-HOST"),
    )


# ===========================================================================
# 1. Write -> read round trip
# ===========================================================================


def test_observation_round_trip_preserves_every_field() -> None:
    client = FakeElasticClient()
    original = _full_observation()
    persist_observation(client, original)
    loaded = load_observation(client, "o1")
    assert loaded == original


def test_evidence_round_trip_preserves_attack_ref_and_provenance() -> None:
    knowledge = load_attack_knowledge()
    technique = knowledge.techniques()[0]
    ref = AttackRef(
        stix_id=technique["id"],
        object_type=technique["type"],
        attack_kb_version=knowledge.attack_kb_version,
    )
    client = FakeElasticClient()
    original = _rule_evidence(attack_ref=ref)
    persist_evidence(client, original)
    loaded = load_evidence(client, "ev1")
    assert loaded == original
    assert loaded is not None
    assert loaded.attack_ref == ref
    assert loaded.provenance.source_observation_ids == ("o1", "o2")


def test_evidence_round_trip_without_attack_ref() -> None:
    client = FakeElasticClient()
    original = _rule_evidence(attack_ref=None)
    persist_evidence(client, original)
    loaded = load_evidence(client, "ev1")
    assert loaded == original
    assert loaded is not None
    assert loaded.attack_ref is None


def test_load_missing_document_returns_none() -> None:
    client = FakeElasticClient()
    assert load_observation(client, "does-not-exist") is None
    assert load_evidence(client, "does-not-exist") is None


# ===========================================================================
# 2. Idempotent, deterministic writes keyed by the domain id
# ===========================================================================


def test_persist_observation_is_idempotent_and_uses_domain_id() -> None:
    client = FakeElasticClient()
    obs = _full_observation("stable-id")
    result_1 = persist_observation(client, obs)
    result_2 = persist_observation(client, obs)  # re-persist the identical object
    assert result_1 == result_2 == PersistResult(index=OBSERVATIONS_INDEX, document_id="stable-id")
    assert client.document_count(OBSERVATIONS_INDEX) == 1  # not duplicated


def test_persist_evidence_overwrites_in_place_for_same_id() -> None:
    client = FakeElasticClient()
    persist_evidence(client, _rule_evidence("ev-x"))
    # A different claim text under the SAME evidence_id must replace, not duplicate.
    updated = Evidence(
        evidence_id="ev-x",
        evidence_type=EvidenceType.BEHAVIORAL,
        claim="revised claim",
        provenance=DerivationProvenance(
            method="rule-x", method_version="1.1", source_observation_ids=("o1",)
        ),
    )
    persist_evidence(client, updated)
    assert client.document_count(EVIDENCE_INDEX) == 1
    loaded = load_evidence(client, "ev-x")
    assert loaded == updated


# ===========================================================================
# 3. Pinned, deterministic index names/mappings
# ===========================================================================


def test_index_names_are_pinned_and_schema_derived() -> None:
    assert OBSERVATIONS_INDEX == "attribution-platform-observations-v1"
    assert EVIDENCE_INDEX == "attribution-platform-evidence-v1"


def test_required_fields_have_explicit_non_dynamic_mappings() -> None:
    for field in ("observation_id", "timestamp", "schema_version", "raw_reference"):
        assert field in OBSERVATIONS_MAPPING
    assert OBSERVATIONS_MAPPING["timestamp"] == {"type": "date"}
    assert OBSERVATIONS_MAPPING["observation_id"] == {"type": "keyword"}

    for field in ("evidence_id", "schema_version", "provenance", "attack_ref"):
        assert field in EVIDENCE_MAPPING
    assert EVIDENCE_MAPPING["evidence_id"] == {"type": "keyword"}
    assert EVIDENCE_MAPPING["attack_ref"]["properties"]["stix_id"] == {"type": "keyword"}


def test_ensure_index_is_idempotent_on_the_fake_client() -> None:
    client = FakeElasticClient()
    client.ensure_index(OBSERVATIONS_INDEX, OBSERVATIONS_MAPPING)
    client.ensure_index(OBSERVATIONS_INDEX, OBSERVATIONS_MAPPING)  # must not raise / duplicate
    assert client.mappings_for(OBSERVATIONS_INDEX) == OBSERVATIONS_MAPPING


# ===========================================================================
# 4. Fail closed
# ===========================================================================


def test_persist_observation_rejects_non_observation() -> None:
    client = FakeElasticClient()
    with pytest.raises(ElasticIntegrationError, match="requires an Observation"):
        persist_observation(client, "not-an-observation")  # type: ignore[arg-type]


def test_persist_evidence_rejects_non_evidence() -> None:
    client = FakeElasticClient()
    with pytest.raises(ElasticIntegrationError, match="requires an Evidence"):
        persist_evidence(client, {"evidence_id": "ev1"})  # type: ignore[arg-type]


def test_index_document_before_ensure_index_fails_closed() -> None:
    client = FakeElasticClient()
    with pytest.raises(ElasticIntegrationError, match="does not exist"):
        client.index_document(OBSERVATIONS_INDEX, "o1", {"observation_id": "o1"})


def test_load_rejects_unrecognized_schema_version() -> None:
    client = FakeElasticClient()
    client.ensure_index(OBSERVATIONS_INDEX, OBSERVATIONS_MAPPING)
    stale_document = {
        "observation_id": "o1",
        "timestamp": T0.isoformat(),
        "raw_reference": {"source_type": "synthetic", "source_event_id": "raw-1"},
        "schema_version": "observation/999",  # not the current contract version
    }
    client.index_document(OBSERVATIONS_INDEX, "o1", stale_document)
    with pytest.raises(ElasticIntegrationError, match="schema_version"):
        load_observation(client, "o1")


def test_load_rejects_malformed_stored_document() -> None:
    client = FakeElasticClient()
    client.ensure_index(OBSERVATIONS_INDEX, OBSERVATIONS_MAPPING)
    # Missing required 'raw_reference' entirely.
    client.index_document(
        OBSERVATIONS_INDEX, "o1", {"observation_id": "o1", "timestamp": T0.isoformat()}
    )
    with pytest.raises(ElasticIntegrationError, match="could not be reconstructed"):
        load_observation(client, "o1")


# ===========================================================================
# 5. The ElasticClient abstraction: persistence logic is client-agnostic
# ===========================================================================


def test_fake_client_satisfies_the_elastic_client_protocol() -> None:
    assert isinstance(FakeElasticClient(), ElasticClient)


def test_persistence_functions_accept_any_conforming_client() -> None:
    """The same persist/load calls work unmodified against a second,
    independently-implemented conforming client -- proving the Attribution
    Engine (and this test) never needs to know which implementation is
    plugged in."""

    class _MinimalDictClient:
        def __init__(self) -> None:
            self._docs: dict[str, dict[str, dict[str, Any]]] = {}

        def ensure_index(self, index: str, mappings: Mapping[str, Any]) -> None:
            self._docs.setdefault(index, {})

        def index_document(self, index: str, document_id: str, document: Mapping[str, Any]) -> None:
            self._docs[index][document_id] = dict(document)

        def get_document(self, index: str, document_id: str) -> Mapping[str, Any] | None:
            return self._docs.get(index, {}).get(document_id)

        def search(
            self, index: str, query: Mapping[str, Any], *, size: int, sort: Any = ()
        ) -> tuple[Mapping[str, Any], ...]:
            return tuple(dict(d) for d in list(self._docs.get(index, {}).values())[:size])

    client = _MinimalDictClient()
    assert isinstance(client, ElasticClient)
    obs = _full_observation("via-second-client")
    persist_observation(client, obs)
    assert load_observation(client, "via-second-client") == obs


# ===========================================================================
# 6. The stdlib-only HTTP client: request construction + error handling
#    (patched urlopen -- no network, no live Elasticsearch)
# ===========================================================================


class _FakeHttpResponse:
    def __init__(self, status: int, body: object) -> None:
        self.status = status
        self._body = json.dumps(body).encode("utf-8")

    def read(self) -> bytes:
        return self._body

    def __enter__(self) -> _FakeHttpResponse:
        return self

    def __exit__(self, *exc: object) -> None:
        return None


def _http_error(status: int, body: object) -> urllib.error.HTTPError:
    return urllib.error.HTTPError(
        "https://localhost:9200/x",
        status,
        "err",
        email.message.Message(),
        io.BytesIO(json.dumps(body).encode("utf-8")),
    )


def _client() -> ElasticsearchHttpClient:
    return ElasticsearchHttpClient(
        "https://localhost:9200", username="elastic", password="secret", verify_tls=False
    )


def test_http_client_sends_basic_auth_and_json_body() -> None:
    client = _client()
    with patch(
        "urllib.request.urlopen", return_value=_FakeHttpResponse(201, {"result": "created"})
    ) as m:
        client.index_document("idx", "id1", {"a": 1})
    request = m.call_args[0][0]
    assert request.full_url == "https://localhost:9200/idx/_doc/id1"
    assert request.get_method() == "PUT"
    assert request.get_header("Authorization", "").startswith("Basic ")
    assert json.loads(request.data) == {"a": 1}


def test_http_client_get_document_404_returns_none() -> None:
    client = _client()
    with patch("urllib.request.urlopen", side_effect=_http_error(404, {"found": False})):
        assert client.get_document("idx", "missing") is None


def test_http_client_ensure_index_already_exists_is_idempotent() -> None:
    client = _client()
    with patch(
        "urllib.request.urlopen",
        side_effect=_http_error(400, {"error": {"type": "resource_already_exists_exception"}}),
    ):
        client.ensure_index("idx", OBSERVATIONS_MAPPING)  # must not raise


def test_http_client_wraps_transport_and_auth_errors() -> None:
    client = _client()
    with (
        patch(
            "urllib.request.urlopen",
            side_effect=_http_error(401, {"error": {"type": "security_exception"}}),
        ),
        pytest.raises(ElasticIntegrationError, match="status 401"),
    ):
        client.get_document("idx", "id1")

    with (
        patch("urllib.request.urlopen", side_effect=urllib.error.URLError("connection refused")),
        pytest.raises(ElasticIntegrationError, match="failed to reach Elasticsearch"),
    ):
        client.get_document("idx", "id1")


# ===========================================================================
# 7. Guard: the domain layer never imports the dataplane
# ===========================================================================


def test_domain_package_never_imports_from_dataplane() -> None:
    """Static AST check over every module in domain/: no import statement
    references attribution_platform.dataplane (domain must not know
    Elasticsearch exists)."""
    domain_files = sorted(DOMAIN_DIR.glob("*.py"))
    assert domain_files, "expected to find domain/*.py files"

    offending: list[str] = []
    for path in domain_files:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module and "dataplane" in node.module:
                offending.append(f"{path.name}: from {node.module} import ...")
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if "dataplane" in alias.name:
                        offending.append(f"{path.name}: import {alias.name}")

    assert not offending, f"domain/ must not import from dataplane/: {offending}"


def test_the_in_memory_store_filters_before_it_caps() -> None:
    """ADR-0027 re-run: with more documents than ``size``, a filter applied
    after the cap dropped matches - an investigation was listed with no units."""
    from attribution_platform.dataplane.fake_client import FakeElasticClient

    store = FakeElasticClient()
    store.ensure_index("u", {})
    for n in range(30):
        store.index_document("u", f"d{n:02d}", {"k": f"{n:02d}", "inv": "a" if n < 25 else "b"})
    store.index_document("u", "tagged", {"k": "99", "inv": "b", "tags": ["x", "y"]})
    only_b = {"bool": {"filter": [{"term": {"inv": "b"}}]}}
    assert [d["k"] for d in store.search("u", only_b, size=10, sort=("k",))] == [
        "25",
        "26",
        "27",
        "28",
        "29",
        "99",
    ]
    in_array = {"bool": {"filter": [{"term": {"inv": "b"}}, {"term": {"tags": "y"}}]}}
    assert [d["k"] for d in store.search("u", in_array, size=10)] == ["99"]
    assert len(store.search("u", {"match_all": {}}, size=10)) == 10
    with pytest.raises(ElasticIntegrationError):
        store.search("u", {"range": {"k": {"gte": "10"}}}, size=10)


def test_a_released_publication_keeps_what_others_still_use() -> None:
    """ADR-0028 Amendment B: a live session withdraws its oldest cycles; documents
    that a retained cycle (or a direct write) also holds stay."""
    from attribution_platform.dataplane.fake_client import FakeElasticClient, SharedMemoryClient

    def publication(*ids: str) -> FakeElasticClient:
        part = FakeElasticClient()
        part.ensure_index("e", {})
        for i in ids:
            part.index_document("e", i, {"id": i})
        return part

    store = SharedMemoryClient()
    store.ensure_index("e", {})
    store.index_document("e", "direct", {"id": "direct"})
    store.absorb(publication("shared", "only-1", "direct"), owner="cycle-1")
    store.absorb(publication("shared", "only-2"), owner="cycle-2")
    assert store.release("cycle-1") == 1  # only-1; 'shared' is still cycle-2's, 'direct' is pinned
    assert {d["id"] for d in store.search("e", {}, size=10)} == {"direct", "shared", "only-2"}
    assert store.release("cycle-2") == 2 and store.release("cycle-2") == 0
    assert {d["id"] for d in store.search("e", {}, size=10)} == {"direct"}
