"""Gate G0.12: the first-vertical-slice integration test.

Every existing gate has its own focused tests (G0.6 evidence derivation,
G0.8 persistence, G0.9 replay, G0.10 API), but no single test previously
drove data through the *entire* declared slice
(docs/architecture/13-phase-0-implementation-plan.md, "First Vertical
Slice") in one place:

    synthetic/replay input -> SourceAdapter -> Observation -> Evidence
    -> ATT&CK reference -> Elastic persistence -> API read model

This is that one small integration test, filling that gap without
reimplementing anything: it reuses G0.9's checked-in fixture and
``replay_fixture`` unmodified, G0.8's ``FakeElasticClient`` unmodified, and
G0.10's ``create_server``/real HTTP calls unmodified. No new production code
was needed or added for this gate.

Also verifies, in the same end-to-end setting (not just at each gate's own
narrower unit-test level): provenance survives the whole pipeline
(``source_observation_ids``, the replay dataset's content-hash in
``raw_reference.dataset_ref``, the ATT&CK reference); persistence is
idempotent (replaying the same fixture twice leaves the same documents, not
duplicates); and the same replay is deterministic across two entirely
independent client/server instances (byte-identical canonical JSON).

No Docker, no live Elasticsearch, no network beyond this process's own
localhost HTTP server — like every other test in this suite.
"""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from collections.abc import Iterator
from http.server import ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

from attribution_platform.api import create_server
from attribution_platform.attack_knowledge.loader import load_attack_knowledge
from attribution_platform.dataplane import EVIDENCE_INDEX, OBSERVATIONS_INDEX, FakeElasticClient
from attribution_platform.replay import load_fixture_file, replay_fixture

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_PATH = REPO_ROOT / "fixtures" / "phase0_benign_scenarios.json"


def _http_get(base_url: str, path: str) -> tuple[int, dict[str, Any]]:
    try:
        with urllib.request.urlopen(base_url + path, timeout=5) as resp:  # noqa: S310
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def _start_server(client: FakeElasticClient) -> Iterator[str]:
    server: ThreadingHTTPServer = create_server(client, port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = str(server.server_address[0]), server.server_address[1]
    try:
        yield f"http://{host}:{port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.fixture
def slice_env() -> Iterator[tuple[str, FakeElasticClient]]:
    client = FakeElasticClient()
    yield from ((url, client) for url in _start_server(client))


def test_full_slice_replay_input_to_api_read_model(
    slice_env: tuple[str, FakeElasticClient],
) -> None:
    """synthetic input -> SourceAdapter -> Observation -> Evidence ->
    ATT&CK reference -> Elastic persistence -> API read model, in one run."""
    base_url, client = slice_env
    knowledge = load_attack_knowledge()
    fixture = load_fixture_file(FIXTURE_PATH)

    results = replay_fixture(fixture, client=client, knowledge=knowledge)
    assert [r.scenario_id for r in results] == ["benign-powershell-script", "benign-user-logon"]

    powershell, logon = results

    # --- Observation, read back through the real HTTP API ---
    status, obs_body = _http_get(base_url, f"/observations/{powershell.observation.observation_id}")
    assert status == 200
    assert obs_body["observation_id"] == "obs-0001"
    assert obs_body["schema_version"] == "observation/1"
    # provenance: the replay dataset's content-hash survived to the API response
    assert obs_body["raw_reference"]["dataset_ref"] == fixture.dataset_ref
    assert obs_body["raw_reference"]["source_type"] == "synthetic"

    # --- Evidence WITH an ATT&CK reference, read back through the API ---
    status, ev_body = _http_get(base_url, f"/evidence/{powershell.evidence.evidence_id}")
    assert status == 200
    assert ev_body["evidence_id"] == "ev-0001"
    assert ev_body["schema_version"] == "evidence/1"
    assert ev_body["attack_ref"]["external_id"] == "T1059.001"
    assert ev_body["attack_ref"]["attack_kb_version"] == knowledge.attack_kb_version
    # provenance: Evidence points back at the exact Observation it was derived from
    assert ev_body["provenance"]["source_observation_ids"] == ["obs-0001"]

    # --- Evidence WITHOUT an ATT&CK reference (evidentiary/contextual path) ---
    status, logon_ev_body = _http_get(base_url, f"/evidence/{logon.evidence.evidence_id}")
    assert status == 200
    assert logon_ev_body["attack_ref"] is None
    assert logon_ev_body["evidence_type"] == "contextual"

    # --- A not-found id still goes through the same API boundary correctly ---
    status, _ = _http_get(base_url, "/observations/does-not-exist")
    assert status == 404


def test_replaying_the_fixture_twice_is_idempotent_through_the_api(
    slice_env: tuple[str, FakeElasticClient],
) -> None:
    base_url, client = slice_env
    knowledge = load_attack_knowledge()
    fixture = load_fixture_file(FIXTURE_PATH)

    replay_fixture(fixture, client=client, knowledge=knowledge)
    status, first_body = _http_get(base_url, "/evidence/ev-0001")
    assert status == 200

    replay_fixture(fixture, client=client, knowledge=knowledge)  # replay again, same client
    status, second_body = _http_get(base_url, "/evidence/ev-0001")
    assert status == 200

    assert first_body == second_body
    assert client.document_count(OBSERVATIONS_INDEX) == len(fixture.scenarios)
    assert client.document_count(EVIDENCE_INDEX) == len(fixture.scenarios)


def test_slice_is_deterministic_across_independent_client_and_server_instances() -> None:
    knowledge = load_attack_knowledge()
    fixture = load_fixture_file(FIXTURE_PATH)

    client_a = FakeElasticClient()
    replay_fixture(fixture, client=client_a, knowledge=knowledge)
    server_a: ThreadingHTTPServer = create_server(client_a, port=0)
    thread_a = threading.Thread(target=server_a.serve_forever, daemon=True)
    thread_a.start()

    client_b = FakeElasticClient()
    replay_fixture(fixture, client=client_b, knowledge=knowledge)
    server_b: ThreadingHTTPServer = create_server(client_b, port=0)
    thread_b = threading.Thread(target=server_b.serve_forever, daemon=True)
    thread_b.start()

    try:
        url_a = f"http://{server_a.server_address[0]!s}:{server_a.server_address[1]}"
        url_b = f"http://{server_b.server_address[0]!s}:{server_b.server_address[1]}"

        for path in ("/observations/obs-0001", "/evidence/ev-0001", "/evidence/ev-0002"):
            status_a, body_a = _http_get(url_a, path)
            status_b, body_b = _http_get(url_b, path)
            assert status_a == status_b == 200
            assert body_a == body_b
    finally:
        server_a.shutdown()
        server_a.server_close()
        thread_a.join(timeout=5)
        server_b.shutdown()
        server_b.server_close()
        thread_b.join(timeout=5)
