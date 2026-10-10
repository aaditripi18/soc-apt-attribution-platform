#!/usr/bin/env python3
"""Extract lookup tables from Elastic's pinned ingest pipelines (ADR-0015).

Some ECS fields are a pure table lookup in Elastic's pipeline (CloudTrail's
``event.category`` / ``event.type`` by event name, …). Rather than re-typing such
a table, it is read from the vendored, blob-pinned pipeline YAML
(``data/detection/elastic/conformance/<stream>/pipeline/``) and written as JSON
beside the derived views that use it. ``tests/test_elastic_cloud_conformance.py``
regenerates each table and compares it with the committed file.

    python scripts/extract_elastic_pipeline_tables.py
"""

from __future__ import annotations

import json
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
CONFORMANCE = REPO_ROOT / "data" / "detection" / "elastic" / "conformance"
OUT = REPO_ROOT / "src" / "attribution_platform" / "detection" / "pipeline_tables"


def _processors(stream: str, pipeline: str) -> list[dict[str, Any]]:
    path = CONFORMANCE / stream / "pipeline" / pipeline
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    return list(document["processors"])


def cloudtrail_categorization() -> dict[str, dict[str, list[str]]]:
    """``script_add_ecs_categorization`` params: event name -> category / type."""
    for processor in _processors("aws_cloudtrail", "default.yml"):
        script = processor.get("script")
        if script and script.get("tag") == "script_add_ecs_categorization":
            return {
                str(name): {str(k): [str(v) for v in values] for k, values in sorted(entry.items())}
                for name, entry in sorted(script["params"].items())
            }
    raise RuntimeError("CloudTrail categorization script not found in the pinned pipeline")


def o365_record_types() -> dict[str, str]:
    """The ``RecordType`` -> ``event.code`` script params (audit schema names)."""
    for processor in _processors("o365_audit", "default.yml"):
        script = processor.get("script")
        if script and "schemaId" in str(script.get("source", "")):
            return {str(k): str(v) for k, v in sorted(script["params"].items())}
    raise RuntimeError("O365 RecordType script not found in the pinned pipeline")


def security_categorization() -> dict[str, dict[str, Any]]:
    """``Set ECS categorization fields``: event code -> category / type / action."""
    for processor in _processors("system_security", "standard.yml"):
        script = processor.get("script")
        if script and script.get("tag") == "Set ECS categorization fields":
            table: dict[str, dict[str, Any]] = {}
            for code, entry in sorted(script["params"].items()):
                table[str(code)] = {
                    str(k): [str(x) for x in v] if isinstance(v, list) else str(v)
                    for k, v in sorted(entry.items())
                }
            return table
    raise RuntimeError("Security categorization script not found in the pinned pipeline")


TABLES: dict[str, Callable[[], dict[str, Any]]] = {
    "security_categorization.json": security_categorization,
    "cloudtrail_categorization.json": cloudtrail_categorization,
    "o365_record_types.json": o365_record_types,
}


def render(table: Any) -> str:
    return json.dumps(table, indent=1, sort_keys=True) + "\n"


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    for name, build in TABLES.items():
        table = build()
        (OUT / name).write_text(render(table), encoding="utf-8", newline="\n")
        print(f"{name}: {len(table)} entries")
    return 0


if __name__ == "__main__":
    sys.exit(main())
