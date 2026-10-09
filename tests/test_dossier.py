"""The attribution dossier: rendered only from the persisted read model,
deterministic, answering CLAUDE.md's questions per unit — and never ranking."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

import pytest

from attribution_platform.attack_knowledge.loader import load_attack_knowledge
from attribution_platform.dataplane import FakeElasticClient
from attribution_platform.investigation.__main__ import investigate
from attribution_platform.investigation.dossier import render_dossier

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_end_to_end_formats import NO_PINNED_RECORDINGS, RECORDINGS  # noqa: E402
from test_indicators import ADVISORY_SHA256, _event_data, _sysmon_1, _with_hash  # noqa: E402

SECTIONS = (
    "### 1. What was observed",
    "### 2. Evidence extracted",
    "### 3. ATT&CK techniques supported — and why",
    "### 4. Actors consistent with the evidence",
    "### 5. How strong is this — and what remains uncertain",
    "### 6. What additional evidence would help",
    "### 7. Indicator context (advisories — not part of attribution)",
)


def _investigate(tmp_path: Path, name: str, text: str) -> tuple[FakeElasticClient, str]:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8", newline="\n")
    client = FakeElasticClient()
    session = investigate(str(path), client=client, recordings=NO_PINNED_RECORDINGS)
    return client, session.record.investigation_id


@pytest.fixture(scope="module")
def cloud(tmp_path_factory: pytest.TempPathFactory) -> tuple[FakeElasticClient, str]:
    name, text = RECORDINGS["cloud"]
    return _investigate(tmp_path_factory.mktemp("dossier"), name, text)


def test_every_unit_answers_every_question(cloud: tuple[FakeElasticClient, str]) -> None:
    client, investigation_id = cloud
    text = render_dossier(client, load_attack_knowledge(), investigation_id)
    units = text.count("\n## Unit ")
    assert units == 7
    for heading in SECTIONS:
        assert text.count(heading) == units, heading


def test_dossier_is_deterministic(cloud: tuple[FakeElasticClient, str]) -> None:
    client, investigation_id = cloud
    knowledge = load_attack_knowledge()
    assert render_dossier(client, knowledge, investigation_id) == render_dossier(
        client, knowledge, investigation_id
    )


def test_candidates_are_alphabetical_and_nothing_is_ranked(
    cloud: tuple[FakeElasticClient, str],
) -> None:
    client, investigation_id = cloud
    text = render_dossier(client, load_attack_knowledge(), investigation_id)
    for block in text.split("### 4. Actors consistent with the evidence")[1:]:
        names = re.findall(r"^- (?:[GC]\d{4} )?(.+?) — \d+ of \d+$", block.split("###")[0], re.M)
        assert names == sorted(names, key=str.lower)
    lowered = text.lower()
    for ranking_word in ("most likely", "top candidate", "ranked first", "probability"):
        assert ranking_word not in lowered


def test_indicator_context_quotes_the_publisher(tmp_path: Path) -> None:
    record: dict[str, Any] = _with_hash(_sysmon_1(), ADVISORY_SHA256)
    _event_data(record).update(
        Image="C:\Windows\System32\whoami.exe",
        CommandLine="whoami /all",
        OriginalFileName="whoami.exe",
    )
    client, investigation_id = _investigate(tmp_path, "ioc.jsonl", json.dumps(record) + "\n")
    text = render_dossier(client, load_attack_knowledge(), investigation_id)
    assert "The publisher names **Volt Typhoon** (G1017)" in text
    assert "outside its validity window" in text  # a 2019 record, a 2024 indicator


def test_unknown_investigation_is_refused() -> None:
    with pytest.raises(KeyError):
        render_dossier(FakeElasticClient(), load_attack_knowledge(), "investigation::none")
