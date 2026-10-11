"""Observables of an investigation: the indicator candidates an analyst can
pivot on (ADR-0022).

An observable is a concrete value taken from an Observation that grounds
Evidence in one of the investigation's units — a file hash, a network address,
a queried domain, the path of a file written or an image run from a
user-writable location is *not* inferred: only values the event states are
listed, each exactly as observed.

Nothing here judges a value malicious. An observable is "seen in activity a
detection rule matched", with the techniques of that Evidence beside it, how
often and when it was seen, and — where it equals an indicator a pinned
government advisory published (ADR-0013) — that advisory and the actor it
names. Whether to block or hunt on it is the analyst's call; the page says so.

Addresses are labelled ``internal`` (private, loopback, link-local or otherwise
not globally routable, by the standard library's own classification) or
``external``; nothing is dropped.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable, Mapping
from typing import Any

from attribution_platform.domain import Evidence, Observation

OBSERVABLES_METHOD_VERSION = "1.0"
#: Kinds, in display order.
KINDS = ("sha256", "sha1", "md5", "ip", "domain")
_TECHNIQUE_TYPE = "attack-pattern"


def _address_scope(value: str) -> str | None:
    try:
        return "external" if ipaddress.ip_address(value).is_global else "internal"
    except ValueError:
        return None


def observed_values(observation: Observation) -> Iterable[tuple[str, str, str | None]]:
    """``(kind, value, what it is of)`` for every observable one Observation states."""
    process, file = observation.process, observation.file
    process_name = (process.name or process.executable) if process else None
    file_name = (file.name or file.path) if file else None
    for hashes, owner in (
        (process.hashes if process else None, process_name),
        (file.hashes if file else None, file_name),
    ):
        if hashes is None:
            continue
        for kind in ("sha256", "sha1", "md5"):
            value = getattr(hashes, kind)
            if value:
                yield kind, str(value).lower(), str(owner) if owner else None
    network = observation.network
    if network is not None and network.destination is not None and network.destination.ip:
        port = network.destination.port
        yield "ip", str(network.destination.ip), f"destination port {port}" if port else None
    if observation.dns is not None and observation.dns.question_name:
        yield "domain", observation.dns.question_name.lower().rstrip("."), None


def collect_observables(
    members: Iterable[tuple[str, Evidence, Observation]],
    advisory_matches: Mapping[tuple[str, str], Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """``members``: ``(unit id, Evidence, its Observation)`` for every Evidence in
    a unit. ``advisory_matches``: ``(kind, value)`` -> the stored indicator match.
    Returns one row per distinct ``(kind, value)``, in kind then value order."""
    rows: dict[tuple[str, str], dict[str, Any]] = {}
    seen: set[tuple[str, str, str]] = set()
    for unit_id, evidence, observation in members:
        ref = evidence.attack_ref
        technique = (
            ref.external_id if ref is not None and ref.object_type == _TECHNIQUE_TYPE else None
        )
        for kind, value, context in observed_values(observation):
            row = rows.setdefault(
                (kind, value),
                {
                    "kind": kind,
                    "value": value,
                    "context": set(),
                    "hosts": set(),
                    "unit_ids": set(),
                    "technique_ids": set(),
                    "observations": 0,
                    "first_seen": observation.timestamp,
                    "last_seen": observation.timestamp,
                },
            )
            if context:
                row["context"].add(context)
            if observation.host is not None and (observation.host.name or observation.host.id):
                row["hosts"].add(str(observation.host.name or observation.host.id))
            row["unit_ids"].add(unit_id)
            if technique:
                row["technique_ids"].add(technique)
            if (kind, value, observation.observation_id) not in seen:
                seen.add((kind, value, observation.observation_id))
                row["observations"] += 1
            row["first_seen"] = min(row["first_seen"], observation.timestamp)
            row["last_seen"] = max(row["last_seen"], observation.timestamp)
    out = []
    for (kind, value), row in rows.items():
        match = advisory_matches.get((kind, value))
        out.append(
            {
                "kind": kind,
                "value": value,
                "scope": _address_scope(value) if kind == "ip" else None,
                "context": sorted(row["context"]),
                "hosts": sorted(row["hosts"]),
                "unit_ids": sorted(row["unit_ids"]),
                "technique_ids": sorted(row["technique_ids"]),
                "observations": row["observations"],
                "first_seen": row["first_seen"].isoformat(),
                "last_seen": row["last_seen"].isoformat(),
                "advisory": (
                    {
                        "indicator_name": match.get("indicator_name"),
                        "report_name": match.get("report_name"),
                        "named_actor": match.get("named_actor"),
                        "named_actor_attack_id": match.get("named_actor_attack_id"),
                        "within_validity": match.get("within_validity"),
                    }
                    if match is not None
                    else None
                ),
            }
        )
    out.sort(key=lambda r: (KINDS.index(r["kind"]), r["value"]))
    return out


__all__ = ["KINDS", "OBSERVABLES_METHOD_VERSION", "collect_observables", "observed_values"]
