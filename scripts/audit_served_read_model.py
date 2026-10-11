#!/usr/bin/env python3
"""Audit a running read-model API against independent recomputation (ADR-0016).

The analyst console only displays what the API serves, so "the site answers
correctly" reduces to: is every served statement true? This script answers that
for a live server without reusing the code paths that produced the statements:

- **Evidence**: each Evidence's rule is loaded from the pinned rule pack and
  re-evaluated on the served Observation; it must fire and carry the technique.
- **Techniques**: g is recomputed from the ATT&CK knowledge base and compared
  with every served single-feature contribution.
- **Candidates**: the candidate set is rebuilt from ATT&CK ``uses``
  relationships (every active Group / Campaign whose profile includes an
  observed feature) and compared with the served set; each matrix cell is
  compared with the profile.
- **Collection guidance**: users, split and "not yet observed" are recomputed.
- **Summaries, search, counts**: each is compared with the records it sums up.
- **No decision field** (likelihood, confidence, verdict, rank, probability).

    python scripts/audit_served_read_model.py http://127.0.0.1:8000

Exit code 0 only when every check passes. Read-only: GET requests alone.
"""

from __future__ import annotations

import json
import sys
import urllib.parse
import urllib.request
from collections import Counter
from collections.abc import Iterator
from typing import Any

from attribution_platform.attack_knowledge.loader import load_attack_knowledge
from attribution_platform.attack_knowledge.traversal import (
    active_campaigns,
    active_groups,
    groups_using_technique,
    techniques_used_by,
)
from attribution_platform.dataplane.persistence import _observation_from_document
from attribution_platform.detection import load_rule_pack
from attribution_platform.detection_content.pinned import ELASTIC_PACK, SIGMA_PACK

#: The analysis also stores the candidate-independent "Unattributed" hypothesis.
UNATTRIBUTED = "candidate::unattributed"
FORBIDDEN = ("likelihood", "confidence", "wep", "verdict", "probability")


class Audit:
    def __init__(self, base: str) -> None:
        self.base = base.rstrip("/") + "/api"
        self.checks: Counter[str] = Counter()
        self.failures: list[str] = []

    def get(self, path: str) -> Any:
        with urllib.request.urlopen(self.base + path, timeout=120) as response:  # noqa: S310
            return json.loads(response.read())

    def check(self, name: str, ok: bool, detail: str = "") -> None:
        self.checks[name] += 1
        if not ok and len(self.failures) < 60:
            self.failures.append(f"{name}: {detail}")


def _quote(identifier: str) -> str:
    return urllib.parse.quote(identifier, safe="")


def _keys(value: Any) -> Iterator[str]:
    if isinstance(value, dict):
        for key, inner in value.items():
            yield str(key).lower()
            yield from _keys(inner)
    elif isinstance(value, list):
        for inner in value:
            yield from _keys(inner)


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print(__doc__)
        return 2
    audit = Audit(argv[0])
    knowledge = load_attack_knowledge()
    rules = {
        rule.rule_ref.rule_id: rule
        for path in (SIGMA_PACK, ELASTIC_PACK)
        for rule in load_rule_pack(path, knowledge=knowledge).rules
    }
    total_groups = len(active_groups(knowledge))
    actors = {str(o["id"]): o for o in (*active_groups(knowledge), *active_campaigns(knowledge))}
    profiles = {stix_id: set(techniques_used_by(knowledge, stix_id)) for stix_id in actors}

    catalogue = audit.get("/attack/techniques")
    audit.check("catalogue.active_groups", catalogue["active_groups"] == total_groups)
    by_stix = {t["stix_id"]: t for t in catalogue["techniques"]}
    for technique in catalogue["techniques"]:
        users = len(groups_using_technique(knowledge, technique["stix_id"]))
        audit.check(
            "catalogue.groups_using", technique["groups_using"] == users, technique["attack_id"]
        )

    investigations = audit.get("/investigations")
    all_units = audit.get("/units?limit=1000")["units"]
    audit.check(
        "search.all_units",
        len(all_units) == sum(i["units"] for i in investigations),
        f"{len(all_units)} units listed",
    )

    for summary in investigations:
        investigation = audit.get(f"/investigations/{_quote(summary['investigation_id'])}")
        listed = audit.get(
            f"/investigations/{_quote(summary['investigation_id'])}/units?limit=1000"
        )
        audit.check(
            "investigation.units_listed",
            sorted(u["group_id"] for u in listed["units"]) == sorted(investigation["units"]),
            summary["source_id"],
        )
        starts = [u["first_seen"] for u in listed["units"]]
        audit.check("investigation.units_time_ordered", starts == sorted(starts))
        evidence_total = 0

        for unit_summary in listed["units"]:
            group_id = unit_summary["group_id"]
            unit = audit.get(f"/units/{_quote(group_id)}")
            joined = audit.get(f"/units/{_quote(group_id)}/evidence")
            analysis = unit["attribution_analysis"]
            evidence, observations = joined["evidence"], joined["observations"]
            evidence_total += len(evidence)

            bad_keys = [
                k for k in set(_keys(unit)) if any(f in k for f in FORBIDDEN) or k == "rank"
            ]
            audit.check("unit.no_decision_field", not bad_keys, str(bad_keys))

            # --- Evidence: the rule really fires on the observation -------------
            for item in evidence:
                rule = rules.get(item["provenance"]["method"])
                audit.check("evidence.rule_in_pinned_pack", rule is not None, item["evidence_id"])
                observation_id = item["provenance"]["source_observation_ids"][0]
                document = observations.get(observation_id)
                audit.check("evidence.observation_served", document is not None, observation_id)
                if rule is None or document is None:
                    continue
                detection = rule.evaluate(_observation_from_document(document))
                audit.check(
                    "evidence.rule_fires_on_observation", detection is not None, item["evidence_id"]
                )
                mapped = {m.attack_ref.stix_id for m in rule.technique_mappings}
                ref = item["attack_ref"]
                audit.check(
                    "evidence.technique_is_the_rules_mapping",
                    (ref is None and not mapped) or (ref is not None and ref["stix_id"] in mapped),
                    item["evidence_id"],
                )
                label = joined["rules"].get(":".join(item["provenance"]["method"].split(":")[:2]))
                audit.check(
                    "evidence.rule_labelled", label is not None, item["provenance"]["method"]
                )
                if label is not None:
                    low = item["quality"] == "low"
                    audit.check(
                        "evidence.tier_matches_quality",
                        (label["content_tier"] == "enrich") == low,
                        f"{item['evidence_id']} tier={label['content_tier']}",
                    )

            # --- Decision features = techniques of core Evidence ----------------
            core = {
                e["attack_ref"]["stix_id"]
                for e in evidence
                if e["attack_ref"] and e["quality"] != "low"
            }
            observed = set(analysis["observed_feature_technique_ids"])
            # A decision feature is a core-Evidence technique that places a candidate:
            # one no active Group or Campaign uses yields no assessment (ADR-0005).
            placing = {t for t in core if any(t in profile for profile in profiles.values())}
            audit.check(
                "unit.features_are_core_techniques_some_actor_uses", observed == placing, group_id
            )

            # --- Unit summary --------------------------------------------------
            external = {e["attack_ref"]["external_id"] for e in evidence if e["attack_ref"]}
            with_parents = external | {x.split(".")[0] for x in external}
            audit.check(
                "summary.techniques", set(unit_summary["technique_ids"]) == with_parents, group_id
            )
            audit.check(
                "summary.evidence_count", unit_summary["evidence"] == len(evidence), group_id
            )
            audit.check(
                "summary.steps", unit_summary["steps"] == len(unit["sequence"]["steps"]), group_id
            )
            times = sorted(o["timestamp"] for o in observations.values())
            audit.check(
                "summary.time_span",
                times != []
                and (unit_summary["first_seen"], unit_summary["last_seen"])
                == (times[0], times[-1]),
                group_id,
            )
            hosts = sorted(
                {
                    o["host"]["name"].lower()
                    for o in observations.values()
                    if o["host"] and o["host"]["name"]
                }
            )
            audit.check("summary.hosts", unit_summary["host_names"] == hosts, group_id)

            # --- Candidates: rebuilt from ATT&CK relationships -------------------
            expected = {stix_id for stix_id, profile in profiles.items() if profile & observed}
            served = {c["stix_id"]: c for c in analysis["candidates"]}
            audit.check(
                "candidates.set_equals_attack_profiles",
                set(served) == expected,
                f"{group_id}: served {len(served)}, ATT&CK {len(expected)}",
            )
            audit.check(
                "summary.candidate_ids",
                set(unit_summary["candidate_ids"])
                == {c["attack_external_id"] for c in served.values() if c["attack_external_id"]},
                group_id,
            )
            hypotheses = {h["candidate_id"]: h for h in analysis["hypotheses"]}
            for stix_id, candidate in served.items():
                cells = set(candidate["generation_basis"]) & observed
                for contribution in hypotheses.get(candidate["candidate_id"], {}).get(
                    "contributions", ()
                ):
                    cells |= set(contribution["feature_technique_ids"]) & observed
                audit.check(
                    "candidates.matrix_cells_equal_profile",
                    cells == profiles.get(stix_id, set()) & observed,
                    f"{candidate['name']} in {group_id}",
                )
                audit.check(
                    "candidates.name", candidate["name"] == actors[stix_id].get("name"), stix_id
                )

            # --- g and D ---------------------------------------------------------
            for hypothesis in analysis["hypotheses"]:
                for contribution in hypothesis["contributions"]:
                    features = contribution["feature_technique_ids"]
                    if contribution["g_value"] is None:
                        continue
                    audit.check(
                        "contribution.d_is_one_minus_g",
                        abs(contribution["d_value"] - (1 - contribution["g_value"])) < 1e-12,
                    )
                    if len(features) == 1:
                        users = len(groups_using_technique(knowledge, features[0]))
                        audit.check(
                            "contribution.g_equals_group_share",
                            abs(contribution["g_value"] - users / total_groups) < 1e-12,
                            features[0],
                        )
                        shown = by_stix.get(features[0])
                        audit.check(
                            "catalogue.g_shown_equals_g_served",
                            shown is not None
                            and abs(
                                shown["groups_using"] / catalogue["active_groups"]
                                - contribution["g_value"]
                            )
                            < 1e-12,
                            features[0],
                        )
            if analysis["comparison_status"] == "computed":
                audit.check(
                    "hypotheses.one_per_candidate_plus_unattributed",
                    set(hypotheses)
                    == {c["candidate_id"] for c in served.values()} | {UNATTRIBUTED},
                    group_id,
                )
            else:
                audit.check(
                    "comparison.not_computed_has_no_quantities",
                    analysis["hypotheses"] == []
                    and analysis["unattributed_decision_support"] is None
                    and bool(analysis["comparison_note"]),
                    group_id,
                )

            # --- Collection guidance --------------------------------------------
            by_candidate = {c["candidate_id"]: c["stix_id"] for c in served.values()}
            for question in (analysis["collection_guidance"] or {}).get("questions", ()):
                technique = question["technique_stix_id"]
                users_now = {
                    cid for cid, stix in by_candidate.items() if technique in profiles[stix]
                }
                k, n = len(users_now), len(by_candidate)
                audit.check(
                    "guidance.technique_not_observed",
                    technique not in observed,
                    question["technique_id"],
                )
                audit.check(
                    "guidance.users",
                    set(question["candidates_using"]) == users_now,
                    question["technique_id"],
                )
                audit.check(
                    "guidance.split",
                    question["candidates_total"] == n and question["split"] == min(k, n - k) > 0,
                    question["technique_id"],
                )

            # --- Sequence --------------------------------------------------------
            steps = {s["step_id"] for s in unit["sequence"]["steps"]}
            step_evidence = [e for s in unit["sequence"]["steps"] for e in s["evidence_ids"]]
            audit.check(
                "sequence.steps_cover_evidence_once",
                sorted(step_evidence) == sorted(unit["group"]["member_evidence_ids"]),
                group_id,
            )
            audit.check(
                "sequence.edges_join_known_steps",
                all(
                    e["from_step_id"] in steps and e["to_step_id"] in steps
                    for e in unit["sequence"]["edges"]
                ),
                group_id,
            )
            stamp = {
                s["step_id"]: observations[s["observation_id"]]["timestamp"]
                for s in unit["sequence"]["steps"]
            }
            audit.check(
                "sequence.edge_against_time_is_flagged_lineage",
                all(
                    stamp[e["from_step_id"]] <= stamp[e["to_step_id"]]
                    or (
                        e["basis"]["basis_kind"] == "process_lineage"
                        and e["basis"]["timestamp_agreement"] is False
                    )
                    for e in unit["sequence"]["edges"]
                ),
                group_id,
            )

            # --- Search returns this unit for each of its own facts -------------
            for name, values in (
                ("technique", unit_summary["technique_ids"][:2]),
                ("host", unit_summary["host_names"][:1]),
                ("candidate", unit_summary["candidate_ids"][:1]),
            ):
                for value in values:
                    hits = audit.get(f"/units?{name}={_quote(value)}&limit=1000")["units"]
                    expected_hits = sorted(
                        u["group_id"]
                        for u in all_units
                        if value
                        in u[
                            {
                                "technique": "technique_ids",
                                "host": "host_names",
                                "candidate": "candidate_ids",
                            }[name]
                        ]
                    )
                    audit.check(
                        f"search.{name}_filter_is_exact",
                        sorted(h["group_id"] for h in hits) == expected_hits,
                        f"{name}={value}",
                    )

        audit.check(
            "investigation.evidence_in_units",
            evidence_total == investigation["evidence_in_units"]
            and investigation["evidence_in_units"] + investigation["evidence_outside_units"]
            == investigation["evidence"],
            f"{summary['source_id']}: {evidence_total} in units",
        )
        dossier = audit.get(f"/investigations/{_quote(summary['investigation_id'])}/dossier")[
            "markdown"
        ]
        audit.check(
            "dossier.names_every_unit",
            all(f"`{group_id}`" in dossier for group_id in investigation["units"]),
            summary["source_id"],
        )

    coverage = audit.get("/coverage")
    statuses = Counter(t["status"] for t in coverage["techniques"])
    audit.check(
        "coverage.status_counts", dict(statuses) == coverage["summary"]["techniques_by_status"]
    )
    used = {t["attack_id"] for t in catalogue["techniques"] if t["groups_using"] > 0}
    used_statuses = Counter(t["status"] for t in coverage["techniques"] if t["attack_id"] in used)
    audit.check(
        "coverage.group_used_status_counts",
        dict(used_statuses) == coverage["summary"]["group_used_techniques_by_status"],
        str(dict(used_statuses)),
    )
    covered_ids = {
        t.external_id for r in rules.values() for t in (m.attack_ref for m in r.technique_mappings)
    }
    audit.check(
        "coverage.covered_means_a_pinned_rule_maps_to_it",
        all(
            t["attack_id"] in covered_ids
            for t in coverage["techniques"]
            if t["status"] == "covered"
        ),
    )

    width = max(len(name) for name in audit.checks)
    for name in sorted(audit.checks):
        print(f"  {name:<{width}}  {audit.checks[name]:>7,} checked")
    total = sum(audit.checks.values())
    print(
        f"\n{total:,} checks over {len(investigations)} investigation(s), {len(all_units)} unit(s)"
    )
    if audit.failures:
        print(f"\nFAILED ({len(audit.failures)} shown):")
        for failure in audit.failures:
            print("  " + failure)
        return 1
    print("every check passed")
    return 0


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[union-attr]
    raise SystemExit(main(sys.argv[1:]))
