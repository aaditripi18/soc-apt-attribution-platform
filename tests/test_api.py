"""Tests for gate G0.10: the read-model API.

Covers: the read_model functions (`get_observation`/`get_evidence`) against
`FakeElasticClient` — success, invalid identifier (400), not found (404),
and backend failure (502, both the "malformed stored document" and
"transport failure" cases); deterministic JSON body content (provenance,
timestamps, ATT&CK reference, schema_version all preserved); the full HTTP
surface end-to-end (a real `ThreadingHTTPServer` on an OS-assigned port,
driven with real `urllib.request` calls — still no live Elasticsearch, only
`FakeElasticClient` underneath); unsupported HTTP methods; and the
dependency-direction guard (domain never imports api).

None of these tests require Docker, a live Elasticsearch instance, or
external network access — the HTTP-level tests talk only to a server this
process starts itself, on localhost.

Does NOT touch the G0.0-G0.9 test files. Deterministic.
"""

from __future__ import annotations

import ast
import json
import threading
import urllib.error
import urllib.request
from collections.abc import Iterator
from datetime import UTC, datetime
from http.server import ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

from attribution_platform.api import (
    BackendError,
    InvalidIdentifierError,
    NotFoundError,
    create_server,
    get_evidence,
    get_observation,
)
from attribution_platform.dataplane import (
    OBSERVATIONS_INDEX,
    OBSERVATIONS_MAPPING,
    FakeElasticClient,
    persist_evidence,
    persist_observation,
)
from attribution_platform.domain import (
    AttackRef,
    DerivationProvenance,
    Evidence,
    EvidenceType,
    HostRef,
    Observation,
    SourceRef,
    to_canonical_json,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
API_DIR = REPO_ROOT / "src" / "attribution_platform" / "api"
DOMAIN_DIR = REPO_ROOT / "src" / "attribution_platform" / "domain"

T0 = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)


def _observation(observation_id: str = "o1") -> Observation:
    return Observation(
        observation_id=observation_id,
        timestamp=T0,
        raw_reference=SourceRef(source_type="synthetic", source_event_id="raw-1"),
        host=HostRef(id="h1", name="host-1"),
    )


def _evidence(evidence_id: str = "ev1", *, attack_ref: AttackRef | None = None) -> Evidence:
    return Evidence(
        evidence_id=evidence_id,
        evidence_type=EvidenceType.BEHAVIORAL,
        claim="a claim",
        provenance=DerivationProvenance(
            method="rule-x", method_version="1.0", source_observation_ids=("o1",)
        ),
        attack_ref=attack_ref,
    )


# ===========================================================================
# 1. read_model functions against FakeElasticClient
# ===========================================================================


def test_get_observation_returns_the_stored_object() -> None:
    client = FakeElasticClient()
    original = _observation()
    persist_observation(client, original)
    assert get_observation(client, "o1") == original


def test_get_evidence_returns_the_stored_object_with_attack_ref() -> None:
    ref = AttackRef(
        stix_id="attack-pattern--970a3432-3237-47ad-bcca-7d8cbb217736",
        object_type="attack-pattern",
        attack_kb_version="enterprise-attack-19.0",
        external_id="T1059.001",
    )
    client = FakeElasticClient()
    original = _evidence(attack_ref=ref)
    persist_evidence(client, original)
    loaded = get_evidence(client, "ev1")
    assert loaded == original
    assert loaded.attack_ref == ref


@pytest.mark.parametrize("bad_id", ["", "   "])
def test_get_observation_rejects_invalid_identifier(bad_id: str) -> None:
    client = FakeElasticClient()
    with pytest.raises(InvalidIdentifierError, match="non-empty identifier"):
        get_observation(client, bad_id)


@pytest.mark.parametrize("bad_id", ["", "   "])
def test_get_evidence_rejects_invalid_identifier(bad_id: str) -> None:
    client = FakeElasticClient()
    with pytest.raises(InvalidIdentifierError, match="non-empty identifier"):
        get_evidence(client, bad_id)


def test_get_observation_not_found() -> None:
    client = FakeElasticClient()
    with pytest.raises(NotFoundError, match="no Observation found"):
        get_observation(client, "does-not-exist")


def test_get_evidence_not_found() -> None:
    client = FakeElasticClient()
    with pytest.raises(NotFoundError, match="no Evidence found"):
        get_evidence(client, "does-not-exist")


def test_get_observation_wraps_malformed_stored_document_as_backend_error() -> None:
    client = FakeElasticClient()
    client.ensure_index(OBSERVATIONS_INDEX, OBSERVATIONS_MAPPING)
    client.index_document(OBSERVATIONS_INDEX, "o1", {"observation_id": "o1"})  # missing fields
    with pytest.raises(BackendError, match="could not load Observation"):
        get_observation(client, "o1")


class _AlwaysFailsClient:
    """A conforming ElasticClient whose get_document always raises, to prove
    a transport/connectivity-style failure also maps to BackendError."""

    def ensure_index(self, index: str, mappings: Any) -> None:
        pass

    def index_document(self, index: str, document_id: str, document: Any) -> None:
        pass

    def get_document(self, index: str, document_id: str) -> Any:
        raise ConnectionError("simulated transport failure")

    def search(self, index: str, query: Any, *, size: int, sort: Any = ()) -> tuple[Any, ...]:
        return ()


def test_get_observation_wraps_transport_failure_as_backend_error() -> None:
    with pytest.raises(BackendError, match="could not load Observation"):
        get_observation(_AlwaysFailsClient(), "o1")


# ===========================================================================
# 2. Deterministic JSON: provenance, timestamps, ATT&CK ref, schema_version
# ===========================================================================


def test_observation_response_preserves_every_required_field() -> None:
    client = FakeElasticClient()
    original = _observation()
    persist_observation(client, original)
    body = json.loads(to_canonical_json(get_observation(client, "o1")))
    assert body["observation_id"] == "o1"
    assert body["timestamp"] == T0.isoformat()
    assert body["raw_reference"] == {
        "source_type": "synthetic",
        "source_event_id": "raw-1",
        "dataset_ref": None,
        "raw_payload_ref": None,
    }
    assert body["schema_version"] == "observation/1"


def test_evidence_response_preserves_provenance_and_attack_ref() -> None:
    ref = AttackRef(
        stix_id="attack-pattern--970a3432-3237-47ad-bcca-7d8cbb217736",
        object_type="attack-pattern",
        attack_kb_version="enterprise-attack-19.0",
    )
    client = FakeElasticClient()
    persist_evidence(client, _evidence(attack_ref=ref))
    body = json.loads(to_canonical_json(get_evidence(client, "ev1")))
    assert body["provenance"]["method"] == "rule-x"
    assert body["provenance"]["source_observation_ids"] == ["o1"]
    assert body["attack_ref"]["stix_id"] == ref.stix_id
    assert body["schema_version"] == "evidence/1"


# ===========================================================================
# 3. Full HTTP surface, end-to-end (real socket, no live Elasticsearch)
# ===========================================================================


@pytest.fixture
def running_server() -> Iterator[tuple[str, FakeElasticClient]]:
    client = FakeElasticClient()
    server: ThreadingHTTPServer = create_server(client, port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = str(server.server_address[0]), server.server_address[1]
    try:
        yield f"http://{host}:{port}", client
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _http_get(base_url: str, path: str) -> tuple[int, dict[str, Any]]:
    try:
        with urllib.request.urlopen(base_url + path, timeout=5) as resp:  # noqa: S310
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def test_http_get_observation_success(running_server: tuple[str, FakeElasticClient]) -> None:
    base_url, client = running_server
    persist_observation(client, _observation())
    status, body = _http_get(base_url, "/observations/o1")
    assert status == 200
    assert body["observation_id"] == "o1"
    assert body["host"] == {"id": "h1", "name": "host-1", "ip": [], "os_type": None}


def test_http_get_evidence_success(running_server: tuple[str, FakeElasticClient]) -> None:
    base_url, client = running_server
    persist_evidence(client, _evidence())
    status, body = _http_get(base_url, "/evidence/ev1")
    assert status == 200
    assert body["evidence_id"] == "ev1"


def test_http_not_found(running_server: tuple[str, FakeElasticClient]) -> None:
    base_url, _client = running_server
    status, body = _http_get(base_url, "/observations/does-not-exist")
    assert status == 404
    assert "error" in body


def test_http_invalid_identifier(running_server: tuple[str, FakeElasticClient]) -> None:
    base_url, _client = running_server
    status, body = _http_get(base_url, "/observations/")
    assert status == 400
    assert "non-empty identifier" in body["error"]


def test_http_unknown_route_is_404(running_server: tuple[str, FakeElasticClient]) -> None:
    base_url, _client = running_server
    status, _body = _http_get(base_url, "/unknown/thing")
    assert status == 404
    status, _body = _http_get(base_url, "/observations")
    assert status == 404


def test_http_mutation_methods_are_not_implemented(
    running_server: tuple[str, FakeElasticClient],
) -> None:
    base_url, client = running_server
    persist_observation(client, _observation())
    req = urllib.request.Request(base_url + "/observations/o1", method="POST", data=b"{}")
    with pytest.raises(urllib.error.HTTPError) as exc_info:
        urllib.request.urlopen(req, timeout=5)  # noqa: S310
    assert exc_info.value.code == 501


# ===========================================================================
# 4. Guard: the domain layer never imports the API
# ===========================================================================


def test_domain_package_never_imports_from_api() -> None:
    """Static AST check over every module in domain/: no import statement
    references attribution_platform.api (domain must not know the API
    boundary exists)."""
    domain_files = sorted(DOMAIN_DIR.glob("*.py"))
    assert domain_files, "expected to find domain/*.py files"

    offending: list[str] = []
    for path in domain_files:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.ImportFrom)
                and node.module
                and node.module.startswith("attribution_platform.api")
            ):
                offending.append(f"{path.name}: from {node.module} import ...")
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.startswith("attribution_platform.api"):
                        offending.append(f"{path.name}: import {alias.name}")

    assert not offending, f"domain/ must not import from api/: {offending}"


def test_api_never_imports_a_concrete_elastic_client_module() -> None:
    """Static AST check over every module in api/: no import statement
    references attribution_platform.dataplane.http_client or
    attribution_platform.dataplane.fake_client directly — only the
    ElasticClient Protocol (and the load_*/persist_* functions typed against
    it) via the dataplane package's public surface."""
    api_files = sorted(p for p in API_DIR.glob("*.py") if p.name != "__main__.py")
    assert api_files, "expected to find api/*.py files"

    offending: list[str] = []
    for path in api_files:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module in (
                "attribution_platform.dataplane.http_client",
                "attribution_platform.dataplane.fake_client",
            ):
                offending.append(f"{path.name}: from {node.module} import ...")

    assert not offending, f"api/ (excl. __main__.py) must not import a concrete client: {offending}"
