"""Per-technique detectability of the loaded detection content (ADR-0005
Amendment E), read from the pack's own generated reports — never re-derived or
guessed.

- ``coverage-report.json`` gives each active technique's status (``covered``,
  ``telemetry_gap``, ``translation_gap``, ``not_observable_on_supported_platforms``,
  ``no_sigma_rule``) and the telemetry blockers of its rejected rules;
- the Sigma import report gives the logsource of every imported / partial rule.

The coverage report records the content hash of the rule pack it was built
from; it must equal the loaded pack's, or this fails closed (a stale report
would describe other content).
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path
from types import MappingProxyType
from typing import Any

from attribution_platform.attribution.collection_guidance import Detectability


class DetectabilityError(ValueError):
    """The generated reports cannot describe the loaded pack."""


def load_detectability(
    coverage_report: Path,
    import_reports: Path | Sequence[Path],
    *,
    pack_content_hash: str | Sequence[str],
) -> MappingProxyType[str, Detectability]:
    """Technique id (``T1059.002``) -> :class:`Detectability`.

    ``import_reports`` / ``pack_content_hash`` may name several packs (Sigma and
    Elastic, ADR-0015); the coverage report must have been built from exactly
    the loaded packs. A Sigma report row names one ``logsource``, an Elastic row
    the ``logsources`` of its event profiles."""
    coverage: dict[str, Any] = json.loads(coverage_report.read_text(encoding="utf-8"))
    hashes = {p["content_hash"] for p in coverage["provenance"]["rule_packs"]}
    loaded = {pack_content_hash} if isinstance(pack_content_hash, str) else set(pack_content_hash)
    if loaded != hashes:
        raise DetectabilityError(
            f"{coverage_report.name} was built from rule pack(s) {sorted(hashes)}, not the loaded "
            f"pack(s) {sorted(loaded)}: regenerate it (scripts/build_coverage_report.py)"
        )
    reports = [import_reports] if isinstance(import_reports, Path) else list(import_reports)
    logsources: dict[str, set[str]] = {}
    for report in reports:
        for row in json.loads(report.read_text(encoding="utf-8"))["rules"]:
            if row["status"] in ("imported", "partial"):
                names = row["logsources"] if "logsources" in row else [row["logsource"]]
                for attack_id in row["attack_ids"]:
                    logsources.setdefault(attack_id, set()).update(names)
    return MappingProxyType(
        {
            t["attack_id"]: Detectability(
                status=t["status"],
                logsources=tuple(sorted(logsources.get(t["attack_id"], ())))
                if t["status"] == "covered"
                else (),
                blocked_by=tuple(t.get("rejected_rules_blocked_by") or ()),
            )
            for t in coverage["techniques"]
        }
    )


__all__ = ["DetectabilityError", "load_detectability"]
