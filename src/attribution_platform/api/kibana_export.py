"""Results as flat documents a Kibana dashboard can chart (ADR-0024).

The stored records are shaped for provenance (nested, linked by id), which
Kibana's aggregations cannot chart. After an investigation is stored, this
module writes two derived, flat indices from the same read model the console
serves — nothing is computed here that the console does not already show:

- :data:`DETECTIONS_INDEX` — one document per detection inside an activity
  cluster that maps to an ATT&CK technique: when, which host, which technique
  and tactics, which cluster.
- :data:`GROUP_MATCHES_INDEX` — one document per ATT&CK Group or Campaign whose
  profile shares an observed technique: the behavioural overlap as a
  percentage, how many techniques matched, whether evidence specific to the
  group identified it, and — separately — whether an indicator a published
  advisory attributes to it was seen (a lead, not an identification).

The overlap is a similarity (ADR-0021), and the field is named so: no document
here carries a confidence, a probability or a rank. Command lines and raw
events are not exported (the activity route holds none). Document ids are
derived from the investigation, so exporting again overwrites, never duplicates.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from attribution_platform.api.context import ApiContext
from attribution_platform.api.errors import NotFoundError
from attribution_platform.api.read_model import (
    get_investigation,
    get_investigation_activity,
    get_profile_match,
)
from attribution_platform.dataplane.client import ElasticClient

KIBANA_EXPORT_VERSION = "kibana-export/3"
DETECTIONS_INDEX = "attribution-kibana-detections"
GROUP_MATCHES_INDEX = "attribution-kibana-group-matches"

_KEYWORD = {"type": "keyword"}
#: Field mappings (the ``properties`` of each index).
_DETECTIONS: Mapping[str, Any] = {
    "properties_": {
        "@timestamp": {"type": "date"},
        "export_version": _KEYWORD,
        "investigation": {"properties": {"id": _KEYWORD, "source": _KEYWORD}},
        "host": {"properties": {"name": _KEYWORD}},
        "activity": {"properties": {"label": _KEYWORD, "cluster_id": _KEYWORD}},
        "evidence": {
            "properties": {
                "id": _KEYWORD,
                "tier": _KEYWORD,
                "decision_feature": {"type": "boolean"},
            }
        },
        "threat": {
            "properties": {
                "technique": {"properties": {"id": _KEYWORD, "name": _KEYWORD}},
                "tactic": {"properties": {"name": _KEYWORD}},
            }
        },
    },
}
_GROUP_MATCHES: Mapping[str, Any] = {
    "properties_": {
        "@timestamp": {"type": "date"},
        "export_version": _KEYWORD,
        "investigation": {"properties": {"id": _KEYWORD, "source": _KEYWORD}},
        "threat": {
            "properties": {
                "group": {"properties": {"id": _KEYWORD, "name": _KEYWORD, "kind": _KEYWORD}}
            }
        },
        "behavioural_overlap_percent": {"type": "float"},
        "matched_techniques": {"type": "integer"},
        "profile_techniques": {"type": "integer"},
        # what the percentage rests on: techniques counted in the investigation
        "counted_techniques": {"type": "integer"},
        "matched_technique_ids": _KEYWORD,
        "identified": {"type": "boolean"},
        "advisory_lead": {"type": "boolean"},
        "identified_by": _KEYWORD,
        "cluster_id": _KEYWORD,
    },
}

DETECTIONS_MAPPING: Mapping[str, Any] = _DETECTIONS["properties_"]
GROUP_MATCHES_MAPPING: Mapping[str, Any] = _GROUP_MATCHES["properties_"]


def build_documents(
    investigation: Mapping[str, Any],
    activity: Mapping[str, Any],
    profile_match: Mapping[str, Any] | None,
    techniques: Mapping[str, Mapping[str, Any]],
) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    """``(detections by document id, group matches by document id)``.
    ``techniques``: ATT&CK id -> ``{name, tactics}`` (the served catalogue)."""
    scope = {
        "id": str(investigation["investigation_id"]),
        "source": str(investigation.get("source_id") or ""),
    }
    detections: dict[str, dict[str, Any]] = {}
    times: list[str] = []
    for event in activity.get("events") or ():
        if event.get("attack_object_type") != "attack-pattern" or not event.get("time"):
            continue
        attack_id = str(event["attack_id"])
        known = techniques.get(attack_id, {})
        times.append(str(event["time"]))
        detections[f"{scope['id']}::{event['evidence_id']}"] = {
            "@timestamp": event["time"],
            "export_version": KIBANA_EXPORT_VERSION,
            "investigation": scope,
            "host": {"name": event.get("host")},
            "activity": {"label": event.get("label"), "cluster_id": event.get("group_id")},
            "evidence": {
                "id": event["evidence_id"],
                "tier": "context" if event.get("context") else "core",
                "decision_feature": bool(event.get("decision_feature")),
            },
            "threat": {
                "technique": {"id": attack_id, "name": known.get("name")},
                "tactic": {"name": list(known.get("tactics") or ())},
            },
        }
    matches: dict[str, dict[str, Any]] = {}
    if times:  # a match is dated by the last detection, so time filters keep both together
        for match in (profile_match or {}).get("matches") or ():
            matches[f"{scope['id']}::{match['stix_id']}"] = {
                "@timestamp": max(times),
                "export_version": KIBANA_EXPORT_VERSION,
                "investigation": scope,
                "threat": {
                    "group": {
                        "id": match["candidate_id"],
                        "name": match["name"],
                        "kind": match["kind"],
                    }
                },
                "behavioural_overlap_percent": round(100 * float(match["overlap"]), 2),
                "matched_techniques": int(match["matched"]),
                "profile_techniques": int(match["profile_techniques"]),
                "counted_techniques": len((profile_match or {}).get("observed") or ()),
                "matched_technique_ids": list(match["matched_technique_ids"]),
                # identified: evidence specific to the group's own tooling (ADR-0018);
                # advisory_lead: an indicator a published advisory attributes to it
                "identified": match.get("named_by") == "actor_specific",
                "advisory_lead": match.get("named_by") == "advisory_indicator",
                "identified_by": match.get("named_by"),
                "cluster_id": match.get("cluster_id"),
            }
    return detections, matches


def export_investigation(
    client: ElasticClient, context: ApiContext, investigation_id: str
) -> dict[str, int]:
    """Write one stored investigation's chartable documents; returns how many."""
    investigation = get_investigation(client, investigation_id)
    try:
        profile_match: Mapping[str, Any] | None = get_profile_match(client, investigation_id)
    except NotFoundError:
        profile_match = None
    catalogue = (context.techniques or {}).get("techniques") or ()
    detections, matches = build_documents(
        investigation,
        get_investigation_activity(client, investigation_id),
        profile_match,
        {str(t["attack_id"]): {"name": t["name"], "tactics": t["tactics"]} for t in catalogue},
    )
    client.ensure_index(DETECTIONS_INDEX, DETECTIONS_MAPPING)
    client.ensure_index(GROUP_MATCHES_INDEX, GROUP_MATCHES_MAPPING)
    for document_id, document in detections.items():
        client.index_document(DETECTIONS_INDEX, document_id, document)
    for document_id, document in matches.items():
        client.index_document(GROUP_MATCHES_INDEX, document_id, document)
    return {"detections": len(detections), "group_matches": len(matches)}


__all__ = [
    "DETECTIONS_INDEX",
    "DETECTIONS_MAPPING",
    "GROUP_MATCHES_INDEX",
    "GROUP_MATCHES_MAPPING",
    "KIBANA_EXPORT_VERSION",
    "build_documents",
    "export_investigation",
]
