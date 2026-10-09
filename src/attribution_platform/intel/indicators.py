"""Advisory indicators: pinned STIX 2.1 bundles -> exact-value matching (ADR-0013).

**Contextual only.** A match states that a value observed here equals a value a
government advisory published, and which actor that advisory names — a
third-party claim, never an ATT&CK feature, never part of any ACH quantity
(ADR-0013 D1). It is shown beside the unit; nothing scores it.

**Patterns.** Only STIX patterns that are one observation expression of
equality comparisons joined by ``OR`` are read —
``[file:hashes.'SHA-256' = '…' OR file:hashes.'MD5' = '…']``,
``[ipv4-addr:value = '…']``, ``[ipv6-addr:value = '…']``,
``[domain-name:value = '…']``, ``[url:value = '…']`` — because each such
comparison is an exact value with an exact meaning. ``AND``, other operators,
qualifiers (``WITHIN``, ``START``…), multiple observation expressions and other
object paths are refused and counted (``unsupported``), never approximated.

**Attribution.** An indicator is attributed only through the reviewed
``data/intel/advisory-attributions.json``: the actor the publisher names in the
bundle's own report, with the naming sentence quoted verbatim — and the quote
must occur in the pinned bundle, or loading fails closed.

**Matching** is exact: hashes and domains compared lower-case (both are
case-insensitive by definition), IPs in canonical form, URLs byte-exact.
Observation values matched: process image hashes, file hashes, Zeek ``files``
MD5 / SHA-1, network source / destination IPs, DNS question names, Zeek DNS
queries, TLS server names and HTTP hosts.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from attribution_platform.domain import Observation

INDICATOR_MATCHING_METHOD_VERSION = "1.0"
_COMPARISON = re.compile(
    r"\A(?P<path>file:hashes\.'(?P<algo>MD5|SHA-1|SHA-256|SHA-512)'|ipv4-addr:value|"
    r"ipv6-addr:value|domain-name:value|url:value)\s*=\s*'(?P<value>(?:[^'\\]|\\.)*)'\Z"
)
#: STIX hash algorithm -> the kind matched against Observation hashes.
_HASH_KINDS = {"MD5": "md5", "SHA-1": "sha1", "SHA-256": "sha256", "SHA-512": "sha512"}


class IndicatorError(ValueError):
    """A bundle or attribution review that cannot be trusted as given."""


@dataclass(frozen=True)
class AdvisoryIndicator:
    indicator_id: str
    name: str
    valid_from: str | None
    valid_until: str | None
    values: tuple[
        tuple[str, str], ...
    ]  # (kind, value): md5 / sha1 / sha256 / sha512 / ip / domain / url
    bundle_file: str
    bundle_sha256: str
    report_name: str | None
    actor_name: str | None
    attack_group_id: str | None
    attribution_quote: str | None


@dataclass(frozen=True)
class IndicatorMatch:
    indicator_id: str
    indicator_name: str
    kind: str
    value: str
    observation_id: str
    observed_at: str
    within_validity: bool | None  # None: the indicator states no validity window
    bundle_file: str
    report_name: str | None
    actor_name: str | None
    attack_group_id: str | None
    attribution_quote: str | None


@dataclass(frozen=True)
class IndicatorSet:
    indicators: tuple[AdvisoryIndicator, ...]
    unsupported_patterns: int
    method_version: str = INDICATOR_MATCHING_METHOD_VERSION

    def index(self) -> Mapping[tuple[str, str], tuple[AdvisoryIndicator, ...]]:
        out: dict[tuple[str, str], list[AdvisoryIndicator]] = {}
        for indicator in self.indicators:
            for key in indicator.values:
                out.setdefault(key, []).append(indicator)
        return {k: tuple(v) for k, v in out.items()}


def _split_or(pattern: str) -> list[str] | None:
    """The comparisons of ``[a OR b OR …]`` (``None`` if not that shape). ``OR``
    inside a quoted value is not a separator."""
    text = pattern.strip()
    if not (text.startswith("[") and text.endswith("]")) or text.count("[") != 1:
        return None
    body, parts, current, quoted, i = text[1:-1], [], [], False, 0
    while i < len(body):
        char = body[i]
        if char == "\\" and quoted:
            current.append(body[i : i + 2])
            i += 2
            continue
        if char == "'":
            quoted = not quoted
        if not quoted and body[i : i + 4] == " OR ":
            parts.append("".join(current).strip())
            current, i = [], i + 4
            continue
        if not quoted and (body[i : i + 5] == " AND " or body[i : i + 3] in (" !=", " IN")):
            return None
        current.append(char)
        i += 1
    parts.append("".join(current).strip())
    return parts


def _normalize(kind: str, value: str) -> str | None:
    if kind in _HASH_KINDS.values():
        return value.lower()
    if kind == "domain":
        return value.lower().rstrip(".")
    if kind == "ip":
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            return None
    return value


def _comparison_values(pattern: str) -> tuple[tuple[str, str], ...] | None:
    comparisons = _split_or(pattern)
    if not comparisons:
        return None
    values = []
    for comparison in comparisons:
        match = _COMPARISON.match(comparison)
        if match is None:
            return None
        path, raw = match["path"], match["value"].replace("\\'", "'").replace("\\\\", "\\")
        kind = (
            _HASH_KINDS[match["algo"]]
            if match["algo"]
            else "ip"
            if path.startswith("ipv")
            else "domain"
            if path.startswith("domain")
            else "url"
        )
        normalized = _normalize(kind, raw)
        if normalized is None:
            return None
        values.append((kind, normalized))
    return tuple(values)


def load_indicator_set(advisories_dir: Path, attributions_file: Path) -> IndicatorSet:
    """Every supported indicator of the pinned bundles listed in the directory's
    ``manifest.json`` (each verified against its pinned SHA-256), attributed
    through the reviewed attributions file."""
    manifest = json.loads((advisories_dir / "manifest.json").read_text(encoding="utf-8"))
    reviews = json.loads(attributions_file.read_text(encoding="utf-8"))["attributions"]
    indicators: list[AdvisoryIndicator] = []
    unsupported = 0
    for entry in manifest["bundles"]:
        raw = (advisories_dir / entry["file"]).read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        if digest != entry["sha256"]:
            raise IndicatorError(f"{entry['file']}: SHA-256 differs from its manifest pin")
        objects: list[dict[str, Any]] = json.loads(raw)["objects"]
        reports = {o["id"]: o for o in objects if o.get("type") == "report"}
        review = next((r for r in reviews if r["bundle_file"] == entry["file"]), None)
        report = reports.get(review["report_id"]) if review else None
        if review is not None:
            if report is None:
                raise IndicatorError(
                    f"{entry['file']}: reviewed report {review['report_id']} absent"
                )
            if review["quote"] not in str(report.get("description", "")):
                raise IndicatorError(f"{entry['file']}: the reviewed quote is not in the report")
        attributed = set(report.get("object_refs", ())) if report else set()
        for obj in objects:
            if obj.get("type") != "indicator":
                continue
            values = (
                _comparison_values(str(obj.get("pattern", "")))
                if obj.get("pattern_type") == "stix"
                else None
            )
            if values is None:
                unsupported += 1
                continue
            named = review is not None and obj["id"] in attributed
            indicators.append(
                AdvisoryIndicator(
                    indicator_id=obj["id"],
                    name=str(obj.get("name", obj["id"])),
                    valid_from=obj.get("valid_from"),
                    valid_until=obj.get("valid_until"),
                    values=values,
                    bundle_file=entry["file"],
                    bundle_sha256=digest,
                    report_name=report["name"] if report else None,
                    actor_name=review["actor_name"] if named and review else None,
                    attack_group_id=review["attack_group_id"] if named and review else None,
                    attribution_quote=review["quote"] if named and review else None,
                )
            )
    return IndicatorSet(
        indicators=tuple(sorted(indicators, key=lambda i: i.indicator_id)),
        unsupported_patterns=unsupported,
    )


def _observed_values(observation: Observation) -> Iterable[tuple[str, str]]:
    for hashes in (
        observation.process.hashes if observation.process else None,
        observation.file.hashes if observation.file else None,
    ):
        if hashes is not None:
            for kind in ("md5", "sha1", "sha256"):
                value = getattr(hashes, kind)
                if value:
                    yield kind, value.lower()
    zeek = observation.zeek
    if zeek is not None:
        for kind, value in (("md5", zeek.md5), ("sha1", zeek.sha1)):
            if value:
                yield kind, value.lower()
        for name in (zeek.query, zeek.server_name, zeek.http_host):
            if name:
                yield "domain", name.lower().rstrip(".")
    network = observation.network
    if network is not None:
        for endpoint in (network.source, network.destination):
            if endpoint is not None and endpoint.ip:
                normalized = _normalize("ip", endpoint.ip)
                if normalized:
                    yield "ip", normalized
    if observation.dns is not None and observation.dns.question_name:
        yield "domain", observation.dns.question_name.lower().rstrip(".")


def _within(indicator: AdvisoryIndicator, at: datetime) -> bool | None:
    if indicator.valid_from is None and indicator.valid_until is None:
        return None

    def parse(text: str) -> datetime:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))

    if indicator.valid_from is not None and at < parse(indicator.valid_from):
        return False
    return not (indicator.valid_until is not None and at > parse(indicator.valid_until))


def match_observations(
    indicator_set: IndicatorSet, observations: Iterable[Observation]
) -> tuple[IndicatorMatch, ...]:
    """Every exact match, sorted (observation id, indicator id, kind)."""
    index = indicator_set.index()
    matches = set()
    for observation in observations:
        for key in set(_observed_values(observation)):
            for indicator in index.get(key, ()):
                matches.add(
                    IndicatorMatch(
                        indicator_id=indicator.indicator_id,
                        indicator_name=indicator.name,
                        kind=key[0],
                        value=key[1],
                        observation_id=observation.observation_id,
                        observed_at=observation.timestamp.isoformat(),
                        within_validity=_within(indicator, observation.timestamp),
                        bundle_file=indicator.bundle_file,
                        report_name=indicator.report_name,
                        actor_name=indicator.actor_name,
                        attack_group_id=indicator.attack_group_id,
                        attribution_quote=indicator.attribution_quote,
                    )
                )
    return tuple(sorted(matches, key=lambda m: (m.observation_id, m.indicator_id, m.kind)))


__all__ = [
    "INDICATOR_MATCHING_METHOD_VERSION",
    "AdvisoryIndicator",
    "IndicatorError",
    "IndicatorMatch",
    "IndicatorSet",
    "load_indicator_set",
    "match_observations",
]
