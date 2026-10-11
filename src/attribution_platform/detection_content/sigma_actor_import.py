"""Actor-specific detection content from Sigma (ADR-0018).

Technique overlap does not identify an actor (ADR-0005 record 2026-10-11;
ADR-0017). What can is evidence specific to one actor: a file name, path, hash,
address or payload fragment published for that Group's own tooling. SigmaHQ
carries such rules, tagged with an ATT&CK Group id (``attack.gNNNN``) — and
carries many more whose Group tag sits on a generic technique or a public
framework. So the tag alone is never trusted:

- every ``(rule, Group tag)`` in the pinned archive must have a decision in the
  reviewed file (``actor-tag-review.json``) or the import fails closed;
- only an **accepted** tag becomes a mapping, and then the rule maps to that
  Group **only** — its technique tags are not mapped here (the same rule, where
  it is in the Core++ pack, already yields technique Evidence there);
- the rule's conditions are translated by the same exact translation as every
  other Sigma rule (:func:`~.sigma_import._import_rule`); a branch that cannot be
  translated is dropped, never loosened.

The result is a separate rule pack (``sigma-<release>-actor-specific``; rule ids
``sigma-actor:<sigma id>:NNN``) whose Evidence carries an ``attack_ref`` of type
``intrusion-set``. The main Sigma pack is untouched and stays byte-identical.
"""

from __future__ import annotations

import hashlib
import io
import json
import zipfile
from importlib.metadata import version as installed_version
from pathlib import Path
from typing import Any

from sigma.exceptions import SigmaError
from sigma.rule import SigmaRule

from attribution_platform.attack_knowledge.external_ids import ExternalIdResolver, external_id
from attribution_platform.attack_knowledge.loader import AttackKnowledge
from attribution_platform.detection_content.sigma_field_map import FIELD_MAP_VERSION
from attribution_platform.detection_content.sigma_import import (
    DEFAULT_DNF_BOUND,
    IMPORTER_VERSION,
    RejectionReason,
    ResolvedMapping,
    RuleOutcome,
    RuleStatus,
    SigmaImportError,
    SigmaImportResult,
    _AttackIndex,
    _import_rule,
)

ACTOR_IMPORTER_METHOD = "sigma-actor-importer"
ACTOR_IMPORTER_VERSION = "1.0"
ACTOR_RULE_PREFIX = "sigma-actor"
_GROUP_TYPE = "intrusion-set"


def load_actor_tag_review(path: Path) -> dict[tuple[str, str], tuple[bool, str]]:
    """``(sigma_id, tag) -> (accepted, reason)``. Fails closed on a duplicate
    decision, an unknown decision value or a missing reason."""
    data = json.loads(path.read_text(encoding="utf-8"))
    decisions: dict[tuple[str, str], tuple[bool, str]] = {}
    for entry in data.get("decisions", []):
        key = (str(entry["sigma_id"]), str(entry["tag"]).lower())
        if key in decisions:
            raise SigmaImportError(f"{path}: duplicate actor-tag decision for {key}")
        if entry.get("decision") not in ("accept", "reject"):
            raise SigmaImportError(f"{path}: decision for {key} must be 'accept' or 'reject'")
        reason = str(entry.get("reason", "")).strip()
        if not reason:
            raise SigmaImportError(f"{path}: decision for {key} has no reason")
        decisions[key] = (entry["decision"] == "accept", reason)
    return decisions


def _group_tags(rule: SigmaRule) -> list[str]:
    tags = []
    for tag in rule.tags:
        text = str(tag).lower()
        namespace, _, name = text.partition(".")
        if namespace == "attack" and name[:1] == "g" and name[1:].isdigit():
            tags.append(text)
    return sorted(set(tags))


def import_sigma_actor_archive(
    archive_path: Path,
    *,
    knowledge: AttackKnowledge,
    release_tag: str,
    archive_sha256: str,
    actor_tag_review: Path,
    dnf_bound: int = DEFAULT_DNF_BOUND,
) -> SigmaImportResult:
    """Import the pinned actor-specific archive. Pure function of its inputs."""
    raw = archive_path.read_bytes()
    actual = hashlib.sha256(raw).hexdigest()
    if actual != archive_sha256:
        raise SigmaImportError(
            f"{archive_path}: SHA-256 {actual} does not match the pinned {archive_sha256}"
        )
    review = load_actor_tag_review(actor_tag_review)
    groups = ExternalIdResolver(knowledge, (_GROUP_TYPE,))
    index = _AttackIndex(knowledge)
    rows: list[dict[str, Any]] = []
    rules: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        for member in sorted(n for n in archive.namelist() if n.endswith((".yml", ".yaml"))):
            try:
                rule = SigmaRule.from_yaml(archive.read(member).decode("utf-8"))
            except SigmaError as exc:
                raise SigmaImportError(f"{member}: cannot be parsed ({exc})") from exc
            sigma_id = str(rule.id)
            mappings: list[ResolvedMapping] = []
            tag_rows: list[dict[str, Any]] = []
            for tag in _group_tags(rule):
                decision = review.get((sigma_id, tag))
                if decision is None:
                    raise SigmaImportError(
                        f"{member}: Group tag {tag} of rule {sigma_id} has no reviewed decision"
                    )
                seen.add((sigma_id, tag))
                accepted, reason = decision
                resolved = groups.resolve(tag.split(".", 1)[1].upper())
                tag_row: dict[str, Any] = {
                    "tag": tag,
                    "decision": "accept" if accepted else "reject",
                    "reason": reason,
                    "group_id": None,
                    "group_name": None,
                }
                if resolved is not None:
                    obj, _revoked_from = resolved
                    tag_row["group_id"] = external_id(obj)
                    tag_row["group_name"] = str(obj.get("name", ""))
                    if accepted:
                        mappings.append(
                            ResolvedMapping(
                                stix_id=str(obj["id"]),
                                object_type=_GROUP_TYPE,
                                external_id=str(external_id(obj)),
                                tag=tag,
                                note=f"accepted by the actor-tag review: {reason}",
                            )
                        )
                elif accepted:
                    raise SigmaImportError(
                        f"{member}: accepted tag {tag} names no Group in the pinned ATT&CK version"
                    )
                tag_rows.append(tag_row)
            if mappings:
                outcome, rule_dicts = _import_rule(
                    rule,
                    member,
                    index=index,
                    attack_kb_version=knowledge.attack_kb_version,
                    release_tag=release_tag,
                    bound=dnf_bound,
                    software_review={},
                    mapping_override=mappings,
                    rule_prefix=ACTOR_RULE_PREFIX,
                )
            else:
                outcome = RuleOutcome(
                    sigma_id=sigma_id,
                    title=str(rule.title),
                    path=member,
                    logsource=f"{rule.logsource.product or ''}/"
                    f"{rule.logsource.category or rule.logsource.service or ''}",
                    status=RuleStatus.REJECTED,
                    rejection=RejectionReason.EXCLUDED_BY_POLICY,
                    reasons={"actor_review:no_accepted_group_tag": 1},
                )
                rule_dicts = []
            rows.append({**outcome.to_json(release_tag), "actor_tags": tag_rows})
            rules.extend(rule_dicts)
    unused = sorted(set(review) - seen)
    if unused:
        raise SigmaImportError(
            f"{actor_tag_review}: decisions for rules not in the archive: {unused[:3]}"
        )
    rows.sort(key=lambda r: (str(r["sigma_id"]), str(r["path"])))
    rules.sort(key=lambda r: str(r["rule_id"]))
    provenance = {
        "importer": f"{ACTOR_IMPORTER_METHOD}/{ACTOR_IMPORTER_VERSION}",
        "sigma_importer": f"sigma-importer/{IMPORTER_VERSION}",
        "sigma_release": release_tag,
        "sigma_archive": archive_path.name,
        "sigma_archive_sha256": archive_sha256,
        "pysigma_version": installed_version("pySigma"),
        "field_map_version": FIELD_MAP_VERSION,
        "attack_kb_version": knowledge.attack_kb_version,
        "dnf_bound": dnf_bound,
        "actor_tag_review": {
            "file": actor_tag_review.name,
            "sha256": hashlib.sha256(actor_tag_review.read_bytes()).hexdigest(),
            "accepted": sorted(f"{sid}:{tag}" for (sid, tag), (ok, _) in review.items() if ok),
        },
        "license": "Sigma rules: Detection Rule License (DRL) 1.1 — see NOTICE.md",
    }
    by_status: dict[str, int] = {s.value: 0 for s in RuleStatus}
    for row in rows:
        by_status[str(row["status"])] += 1
    usable = [r for r in rows if r["status"] != RuleStatus.REJECTED.value]
    report = {
        "provenance": provenance,
        "summary": {
            "sigma_rules_total": len(rows),
            "group_tags_reviewed": len(review),
            "group_tags_accepted": sum(1 for ok, _ in review.values() if ok),
            "by_status": by_status,
            "generated_rules": len(rules),
            "groups_with_a_usable_rule": sorted(
                {
                    str(t["group_id"])
                    for r in usable
                    for t in r["actor_tags"]
                    if t["decision"] == "accept"
                }
            ),
        },
        "rules": rows,
    }
    pack = {
        "pack_id": f"sigma-{release_tag}-actor-specific",
        "description": (
            "Generated by the ADR-0018 actor-specific importer from the pinned SigmaHQ release "
            "and the reviewed actor-tag decisions. Do not edit by hand; regenerate with "
            "scripts/import_sigma_actor_rules.py."
        ),
        "provenance": provenance,
        "rules": rules,
    }
    return SigmaImportResult(pack=pack, report=report)


__all__ = [
    "ACTOR_RULE_PREFIX",
    "import_sigma_actor_archive",
    "load_actor_tag_review",
]
