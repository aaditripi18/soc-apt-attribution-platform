"""Reproducibility as a tested property: the same recording investigated in
fresh interpreters under different ``PYTHONHASHSEED`` values persists
byte-identical documents (``scripts/check_reproducibility.py``). ADR-0003
revision H2.3 found a real hash-seed dependence on APT29; this guards the class."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from check_reproducibility import digest_under_seed  # noqa: E402

SAMPLES = REPO_ROOT / "data" / "telemetry-samples"


def _golden(name: str) -> dict[str, Any]:
    rows = (SAMPLES / name / "golden-records.jsonl").read_text(encoding="utf-8").splitlines()
    return {r["golden_id"]: r["record"] for r in map(json.loads, rows)}


@pytest.fixture(scope="module")
def mixed_recording(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Real records of several families in one recording: Windows Sysmon (incl. a
    detected process start), cloud, Linux — so correlation and every adapter run."""
    windows = _golden("otrf-compound")
    cloud = _golden("splunk-attack-data-cloud")
    linux = _golden("splunk-attack-data")
    lines = [json.dumps(v) for g, v in sorted(windows.items()) if g.startswith("wlb6-sysmon")]
    lines += [
        cloud[g] for g in sorted(cloud) if g.startswith(("aws-console", "okta-mfa", "entra-audit"))
    ]
    lines += [v for g, v in sorted(linux.items()) if g.startswith("linux-sysmon-1")]
    path = tmp_path_factory.mktemp("repro") / "mixed.log"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    return path


def test_investigation_is_identical_under_different_hash_seeds(mixed_recording: Path) -> None:
    results = [digest_under_seed(str(mixed_recording), seed) for seed in (0, 1, 7)]
    assert isinstance(results[0]["documents"], int) and results[0]["documents"] > 0
    assert len({r["digest"] for r in results}) == 1, results
