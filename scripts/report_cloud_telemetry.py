#!/usr/bin/env python3
"""Conversion and detection report for the cached cloud telemetry
(``data/cache/splunk-attack-data/``, the ``--set cloud`` files of
``acquire_linux_telemetry.py``; ADR-0011 D8).

Each source is read through its own adapter — batch A: **Entra ID**
(Azure Monitor diagnostic export) and **Office 365** (Management Activity API);
batch B: **AWS CloudTrail** (native records); batch C: **Azure Activity** (REST
form), **Okta** System Log, **GitHub** audit log, **Kubernetes** audit.
A log may hold several record shapes; only the source's own records are read,
recognised by the pipeline's own tests (``is_entra_record`` / ``is_o365_record``),
so nothing is routed by guess. Observations are de-duplicated by id per source
and run through the production Sigma pack (every rule, endpoint ones included).

Writes ``data/telemetry-samples/splunk-attack-data-cloud/conversion-report.json``
with the same per-source sections as the Linux report: totals, refusals by
reason, every fired rule with its Sigma product (the D4 scope proof: only
the source's own product may appear), and per dataset its documented ATT&CK label
(from its YAML descriptor), the label resolved through ATT&CK ``revoked-by``,
and the techniques detected. Deterministic for a given cache, pack and code.

    python scripts/report_cloud_telemetry.py [--pack-dir DIR]
"""

from __future__ import annotations

import argparse
import functools
import json
import sys
from collections.abc import Callable, Iterable, Mapping
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from report_linux_telemetry import GENERATED, _sha256, _source_section  # noqa: E402

from attribution_platform.attack_knowledge.external_ids import ExternalIdResolver  # noqa: E402
from attribution_platform.attack_knowledge.loader import load_attack_knowledge  # noqa: E402
from attribution_platform.detection import DetectionEngine, load_rule_pack  # noqa: E402
from attribution_platform.sources.azure_activity import (  # noqa: E402
    AzureActivitySourceAdapter,
    is_azure_activity_record,
)
from attribution_platform.sources.cloudtrail import (  # noqa: E402
    CloudTrailSourceAdapter,
    is_cloudtrail_record,
)
from attribution_platform.sources.entra import EntraIdSourceAdapter, is_entra_record  # noqa: E402
from attribution_platform.sources.github_audit import (  # noqa: E402
    GitHubAuditSourceAdapter,
    is_github_audit_record,
)
from attribution_platform.sources.kubernetes_audit import (  # noqa: E402
    KubernetesAuditSourceAdapter,
    is_kubernetes_audit_record,
)
from attribution_platform.sources.o365 import O365SourceAdapter, is_o365_record  # noqa: E402
from attribution_platform.sources.okta import OktaSourceAdapter, is_okta_record  # noqa: E402

SAMPLES = REPO_ROOT / "data" / "telemetry-samples" / "splunk-attack-data-cloud"
PACK_NAME = "sigma-r2026-07-01-sigma_core++"
#: report section -> (record test, adapter).
SOURCES: Mapping[str, tuple[Callable[[Mapping[str, Any]], bool], Any]] = {
    "entra_id": (is_entra_record, EntraIdSourceAdapter()),
    "o365": (is_o365_record, O365SourceAdapter()),
    "aws_cloudtrail": (is_cloudtrail_record, CloudTrailSourceAdapter()),
    "azure_activity": (is_azure_activity_record, AzureActivitySourceAdapter()),
    "okta": (is_okta_record, OktaSourceAdapter()),
    "github_audit": (is_github_audit_record, GitHubAuditSourceAdapter()),
    "kubernetes_audit": (is_kubernetes_audit_record, KubernetesAuditSourceAdapter()),
}


def _same_adapter(adapter: Any, _directory: Path) -> Any:
    """Cloud records name their own tenant / organization: no per-dataset host."""
    return adapter


def _json_records(path: Path) -> Iterable[Mapping[str, Any]]:
    """Every JSON-object line of ``path`` (other lines are not records)."""
    with path.open(encoding="utf-8", errors="replace") as handle:
        for line in handle:
            try:
                record = json.loads(line)
            except ValueError:
                continue
            if isinstance(record, Mapping):
                yield record


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pack-dir", type=Path, default=GENERATED)
    args = parser.parse_args(argv)
    pack = args.pack_dir / f"{PACK_NAME}.rules.json"
    knowledge = load_attack_knowledge()
    engine = DetectionEngine(rules=load_rule_pack(pack, knowledge=knowledge).rules)
    resolver = ExternalIdResolver(knowledge, ("attack-pattern",))
    rows = json.loads((args.pack_dir / f"{PACK_NAME}.import-report.json").read_text("utf-8"))
    rule_info = {r["sigma_id"]: (r["logsource"].split("/")[0], r["title"]) for r in rows["rules"]}

    manifest = json.loads((SAMPLES / "manifest.json").read_text(encoding="utf-8"))
    logs = [
        REPO_ROOT / entry["cache_path"]
        for entry in manifest["files"]
        if not entry["cache_path"].endswith((".yml", ".yaml"))
    ]
    report: dict[str, object] = {
        "report_version": 1,
        "source_manifest_sha256": _sha256(SAMPLES / "manifest.json"),
        "sigma_pack_sha256": _sha256(pack),
    }
    for name, (is_record, adapter) in SOURCES.items():
        grouped: dict[Path, list[Path]] = {}
        for log in sorted(logs, key=lambda p: p.as_posix()):
            if any(is_record(r) for r in _json_records(log)):
                grouped.setdefault(log.parent, []).append(log)

        def records(path: Path, is_record: Callable[[Mapping[str, Any]], bool] = is_record) -> Any:
            return (r for r in _json_records(path) if is_record(r))

        report[name] = _source_section(
            sorted(grouped.items(), key=lambda item: item[0].as_posix()),
            records,
            functools.partial(_same_adapter, adapter),
            engine,
            rule_info,
            resolver,
        )
    out = SAMPLES / "conversion-report.json"
    out.write_text(json.dumps(report, indent=1) + "\n", encoding="utf-8", newline="\n")
    for name in SOURCES:
        section: Any = report[name]
        products = sorted({rule["product"] for rule in section["fired_rules"]})
        print(
            f"{name}: {section['observations']} observations; refused "
            f"{section['refused_by_reason']}; fired products {products}; "
            f"{section['labelled_datasets_with_documented_technique_detected']}/"
            f"{section['labelled_datasets_with_observations']} labelled datasets detected"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
