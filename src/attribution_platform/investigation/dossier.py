"""The attribution dossier: one investigation explained in plain language.

CLAUDE.md asks the platform to explain, for every attribution: what was
observed, what evidence was extracted, which ATT&CK techniques are supported and
why, which actors are consistent with the evidence, how strong the attribution
is and what uncertainty remains, and what additional evidence would improve it.
This module answers exactly those questions, per unit, as Markdown — rendered
**only** from the persisted read model (the same objects the API serves), so the
document can never say more than the system computed.

Rules the text obeys:

- **No ranking, no confidence** before a ``calibration_version`` exists
  (ADR-0009): candidates are listed alphabetically; counts are facts (how many
  observed techniques a candidate's ATT&CK profile includes), never scores.
- Every technique is tied to the Evidence that supports it, and every Evidence
  to its rule, matched values and mapping basis (the Evidence's own ``claim``).
- Enrich-tier (low-level) Evidence is labelled and shown as context; it adds no
  attribution feature (ADR-0003 Amendment H).
- Indicator matches are context (ADR-0013), shown with the publisher's own
  attribution sentence and the indicator's validity.
- Deterministic: the same read model renders the same bytes.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from attribution_platform.attack_knowledge.loader import AttackKnowledge
from attribution_platform.attack_knowledge.traversal import (
    active_groups,
    groups_using_technique,
    techniques_used_by,
)
from attribution_platform.dataplane import ElasticClient
from attribution_platform.dataplane.behavioral_sequence_persistence import (
    load_behavioral_sequence,
)
from attribution_platform.dataplane.correlation_persistence import load_correlation_group
from attribution_platform.dataplane.persistence import load_evidence, load_observation
from attribution_platform.domain import Evidence, EvidenceQuality, Observation
from attribution_platform.investigation.records import (
    load_attribution_analysis,
    load_investigation,
)

DOSSIER_VERSION = "dossier/1"
_MAX_CANDIDATES_LISTED = 25
_MAX_QUESTIONS = 5


def _external(knowledge: AttackKnowledge, stix_id: str) -> tuple[str, str]:
    obj = knowledge.get_by_id(stix_id)
    if obj is None:
        return stix_id, ""
    for ref in obj.get("external_references") or ():
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return str(ref["external_id"]), str(obj.get("name", ""))
    return stix_id, str(obj.get("name", ""))


def _describe(observation: Observation) -> str:
    """One factual line about what an Observation recorded."""
    parts: list[str] = []
    if observation.host is not None and (observation.host.name or observation.host.id):
        parts.append(f"host `{observation.host.name or observation.host.id}`")
    if observation.user is not None and (observation.user.name or observation.user.id):
        parts.append(f"user `{observation.user.name or observation.user.id}`")
    process = observation.process
    if process is not None and process.executable:
        parts.append(f"process `{process.executable}`")
        if process.command_line:
            command = process.command_line
            parts.append(f"command `{command[:160]}{'…' if len(command) > 160 else ''}`")
    if observation.event is not None and observation.event.action and process is None:
        parts.append(f"action `{observation.event.action}`")
    if observation.event is not None and observation.event.dataset:
        parts.append(f"source `{observation.event.dataset}`")
    return "; ".join(parts) or observation.observation_id


def _evidence_rows(
    evidence: Sequence[Evidence], observations: Mapping[str, Observation]
) -> list[str]:
    rows = ["| Time (UTC) | Technique | Tier | Observed |", "|---|---|---|---|"]
    for item in sorted(
        evidence,
        key=lambda e: (e.time_span.start.isoformat() if e.time_span else "", e.evidence_id),
    ):
        observation = observations.get(item.provenance.source_observation_ids[0])
        when = item.time_span.start.isoformat() if item.time_span else "—"
        technique = item.attack_ref.external_id if item.attack_ref else "—"
        tier = "low-level (context)" if item.quality is EvidenceQuality.LOW else "core"
        seen = _describe(observation) if observation else "—"
        rows.append(f"| {when} | {technique} | {tier} | {seen} |")
    return rows


def _section_unit(
    client: ElasticClient, knowledge: AttackKnowledge, group_id: str, number: int
) -> list[str]:
    group = load_correlation_group(client, group_id)
    analysis = load_attribution_analysis(client, group_id)
    if group is None or analysis is None:
        return [f"## Unit {number}", "", f"Unit `{group_id}` is not in the read model.", ""]
    sequence = load_behavioral_sequence(client, str(analysis["sequence_id"]))
    evidence = [e for e in (load_evidence(client, i) for i in group.member_evidence_ids) if e]
    observations = {
        o.observation_id: o
        for o in (load_observation(client, i) for i in group.member_observation_ids)
        if o is not None
    }
    times = sorted(o.timestamp for o in observations.values())
    hosts = sorted({o.host.name or o.host.id or "" for o in observations.values() if o.host} - {""})
    core = [e for e in evidence if e.quality is not EvidenceQuality.LOW]
    low = [e for e in evidence if e.quality is EvidenceQuality.LOW]
    lines = [
        f"## Unit {number}",
        "",
        f"`{group_id}`",
        "",
        "### 1. What was observed",
        "",
        f"- {len(observations)} observation(s) from {times[0].isoformat() if times else '—'} to "
        f"{times[-1].isoformat() if times else '—'}"
        + (f" on {', '.join(f'`{h}`' for h in hosts)}" if hosts else "")
        + ".",
        f"- {len(sequence.steps) if sequence else 0} behavioural step(s), joined by "
        f"{len(group.structural_link_ids)} structural link(s) (same process, lineage, injection, "
        "same audit event — never shared host or user alone, ADR-0003).",
        "",
        "### 2. Evidence extracted",
        "",
        f"{len(core)} core and {len(low)} low-level Evidence item(s). Each is one detection rule "
        "matching one observation:",
        "",
        *_evidence_rows(evidence, observations),
        "",
        "### 3. ATT&CK techniques supported — and why",
        "",
    ]
    total_groups = len(active_groups(knowledge))
    observed = list(analysis["observed_feature_technique_ids"])
    if not observed:
        lines += ["No core Evidence maps to an ATT&CK technique; nothing to attribute.", ""]
    for technique_stix in observed:
        technique_id, name = _external(knowledge, technique_stix)
        supporting = [e for e in core if e.attack_ref and e.attack_ref.stix_id == technique_stix]
        users = len(groups_using_technique(knowledge, technique_stix))
        share = users / total_groups if total_groups else 0.0
        lines += [
            f"- **{technique_id} {name}** — {len(supporting)} Evidence item(s); used by {users} of "
            f"{total_groups} active ATT&CK Groups (g = {share:.3f}, D = {1 - share:.3f}: "
            "the rarer, the "
            "more it separates candidates).",
        ]
        for item in supporting[:3]:
            lines.append(f"  - {item.claim}")
        if len(supporting) > 3:
            lines.append(f"  - … and {len(supporting) - 3} more with the same technique.")
    lines += ["", "### 4. Actors consistent with the evidence", ""]
    candidates = sorted(
        analysis["candidates"], key=lambda c: (str(c["name"]).lower(), c["candidate_id"])
    )
    if not candidates:
        lines += ["No ATT&CK Group or Campaign uses any observed technique.", ""]
    else:
        lines += [
            f"{len(candidates)} candidate(s) — every ATT&CK Group or Campaign whose recorded "
            "profile "
            "includes at least one observed technique. Listed **alphabetically**; the count is how "
            f"many of the {len(observed)} observed technique(s) the profile includes — a "
            "fact, not a "
            "score.",
            "",
        ]
        observed_set = set(observed)
        full = []
        for candidate in candidates[:_MAX_CANDIDATES_LISTED]:
            profile = set(techniques_used_by(knowledge, candidate["stix_id"]))
            hits = len(profile & observed_set)
            if hits == len(observed_set):
                full.append(candidate["name"])
            label = f"{candidate['attack_external_id'] or ''} {candidate['name']}".strip()
            lines.append(f"- {label} — {hits} of {len(observed_set)}")
        if len(candidates) > _MAX_CANDIDATES_LISTED:
            lines.append(
                f"- … {len(candidates) - _MAX_CANDIDATES_LISTED} more (full list in the API)."
            )
        lines.append("")
    lines += [
        "### 5. How strong is this — and what remains uncertain",
        "",
        f"- {analysis['calibration_note']}",
        "- Low-level Evidence is context: it joins the unit but adds no technique to the "
        "comparison "
        "(ADR-0003 Amendment H)."
        if low
        else "- All Evidence here is core detection content.",
        f"- Unattributed baseline (support if no Group is involved): "
        f"{float(analysis['unattributed_decision_support']):.3f}.",
        "",
        "### 6. What additional evidence would help",
        "",
    ]
    guidance = analysis.get("collection_guidance") or {}
    questions = list(guidance.get("questions") or ())[:_MAX_QUESTIONS]
    if not questions:
        lines += ["No unobserved technique separates these candidates.", ""]
    for question in questions:
        lines.append(
            f"- **{question['technique_id']} {question['technique_name']}** — "
            f"{question['rationale']}"
        )
        if question.get("data_components"):
            lines.append(f"  - ATT&CK data components: {', '.join(question['data_components'])}.")
    lines += ["", "### 7. Indicator context (advisories — not part of attribution)", ""]
    matches = list(analysis.get("indicator_matches") or ())
    if not matches:
        lines += ["No observed value matches a pinned advisory indicator.", ""]
    for match in matches:
        validity = {True: "inside", False: "outside", None: "no stated"}[match["within_validity"]]
        lines.append(
            f"- `{match['value']}` ({match['kind']}) on `{match['observation_id']}` equals "
            "indicator "
            f"*{match['indicator_name']}* in {match['report_name']} "
            f"({validity} its validity window)."
        )
        if match.get("named_actor"):
            lines.append(
                f"  - The publisher names **{match['named_actor']}** "
                f"({match['named_actor_attack_id']}): “{match['attribution_quote']}”"
            )
    lines.append("")
    return lines


def render_dossier(client: ElasticClient, knowledge: AttackKnowledge, investigation_id: str) -> str:
    """The dossier of one persisted investigation (module docstring)."""
    investigation: Mapping[str, Any] | None = load_investigation(client, investigation_id)
    if investigation is None:
        raise KeyError(f"no investigation {investigation_id!r} in the read model")
    lines = [
        f"# Attribution dossier — {investigation['source_id']}",
        "",
        "_Generated from the persisted read model by `attribution_platform.investigation.dossier` "
        f"({DOSSIER_VERSION}). Every statement below is a fact the pipeline computed; nothing is "
        "ranked or scored before calibration._",
        "",
        "## Provenance",
        "",
        f"- Investigation `{investigation['investigation_id']}`",
        f"- Source `{investigation['source_id']}` (SHA-256 `{investigation['source_sha256']}`)",
        f"- ATT&CK `{investigation['attack_kb_version']}`; detection pack "
        f"`{investigation['detection_pack_content_hash']}`",
        "- Methods: "
        + ", ".join(f"{k} {v}" for k, v in sorted(dict(investigation["method_versions"]).items())),
        f"- {investigation['evidence']} Evidence item(s) in {len(investigation['units'])} unit(s).",
        "",
    ]
    for number, group_id in enumerate(investigation["units"], start=1):
        lines += _section_unit(client, knowledge, str(group_id), number)
    return "\n".join(lines).rstrip() + "\n"


__all__ = ["DOSSIER_VERSION", "render_dossier"]
