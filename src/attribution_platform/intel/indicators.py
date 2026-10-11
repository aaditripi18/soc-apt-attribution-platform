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
comparison is an exact value with an exact meaning. Redundant parentheses around
a comparison or an ``OR`` group are read as written.

One ``AND`` shape is read too (1.1), because advisories publish most file
indicators that way: file-hash comparisons joined with ``file:name`` and
``file:size`` — ``[(file:name = 'x') AND file:size = 1 AND (file:hashes.MD5 = '…'
OR …)]``, or several hashes of one file joined by ``AND``. Its meaning is kept
exactly as far as an Observation can show it: equality of a hash identifies the
file's content, which fixes its size and its other hashes, so those conjuncts
add nothing to check; the **name does not follow from the content**, so the
observed file name must equal a published one (case-insensitively) or there is
no match. Every other use of ``AND``, other operators, qualifiers (``WITHIN``,
``START``…), multiple observation expressions and other object paths are refused
and counted (``unsupported``), never approximated.

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

INDICATOR_MATCHING_METHOD_VERSION = "1.1"
_COMPARISON = re.compile(
    r"\A(?P<path>file:hashes\.(?:'(?P<algo>MD5|SHA-1|SHA-256|SHA-512)'|(?P<bare>MD5))|ipv4-addr:value|"
    r"ipv6-addr:value|domain-name:value|url:value)\s*=\s*'(?P<value>(?:[^'\\]|\\.)*)'\Z"
)
_FILE_NAME = re.compile(r"\Afile:name\s*=\s*'(?P<value>(?:[^'\\]|\\.)*)'\Z")
_FILE_SIZE = re.compile(r"\Afile:size\s*=\s*\d+\Z")
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
    #: Lower-case file names, one of which the observed file must carry (an
    #: ``AND file:name`` pattern); empty: no name condition.
    required_names: tuple[str, ...] = ()


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


def _split_top(body: str, separator: str) -> list[str] | None:
    """``body`` split on ``separator`` outside quotes and parentheses (``None``
    if quotes or parentheses do not balance)."""
    parts: list[str] = []
    current: list[str] = []
    quoted, depth, i = False, 0, 0
    while i < len(body):
        char = body[i]
        if char == "\\" and quoted:
            current.append(body[i : i + 2])
            i += 2
            continue
        if char == "'":
            quoted = not quoted
        elif not quoted and char == "(":
            depth += 1
        elif not quoted and char == ")":
            depth -= 1
            if depth < 0:
                return None
        if not quoted and depth == 0 and body.startswith(separator, i):
            parts.append("".join(current))
            current, i = [], i + len(separator)
            continue
        current.append(char)
        i += 1
    if quoted or depth != 0:
        return None
    parts.append("".join(current))
    return parts


def _unwrap(text: str) -> str:
    """``text`` without parentheses that enclose all of it."""
    text = text.strip()
    while text.startswith("(") and text.endswith(")"):
        inner = _split_top(text[1:-1], "\x00")  # balance check only
        if inner is None:
            break
        text = text[1:-1].strip()
    return text


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


def _value(comparison: str) -> tuple[str, str] | None:
    match = _COMPARISON.match(comparison)
    if match is None:
        return None
    path, raw = match["path"], match["value"].replace("\\'", "'").replace("\\\\", "\\")
    kind = (
        _HASH_KINDS[match["algo"] or match["bare"]]
        if match["algo"] or match["bare"]
        else "ip"
        if path.startswith("ipv")
        else "domain"
        if path.startswith("domain")
        else "url"
    )
    normalized = _normalize(kind, raw)
    return (kind, normalized) if normalized is not None else None


def _parse_pattern(pattern: str) -> tuple[tuple[tuple[str, str], ...], tuple[str, ...]] | None:
    """``(values, required file names)`` of a supported pattern, else ``None``
    (module docstring)."""
    text = pattern.strip()
    if not (text.startswith("[") and text.endswith("]")) or text.count("[") != 1:
        return None
    terms = _split_top(text[1:-1], " AND ")
    if terms is None:
        return None
    values: list[tuple[str, str]] = []
    names: list[str] = []
    hash_terms = name_terms = 0
    for term in terms:
        comparisons = _split_top(_unwrap(term), " OR ")
        if not comparisons:
            return None
        parsed = [_unwrap(c) for c in comparisons]
        if all(_FILE_SIZE.match(c) for c in parsed) and len(parsed) == 1:
            continue  # fixed by the content a hash identifies
        found_names = [_FILE_NAME.match(c) for c in parsed]
        if all(found_names):
            name_terms += 1
            names.extend(
                m["value"].replace("\\'", "'").replace("\\\\", "\\").lower()
                for m in found_names
                if m is not None
            )
            continue
        found = [_value(c) for c in parsed]
        if any(v is None for v in found):
            return None
        term_values = [v for v in found if v is not None]
        is_hash = all(kind in _HASH_KINDS.values() for kind, _ in term_values)
        if len(terms) > 1 and not is_hash:
            return None  # AND is read for file hashes only
        hash_terms += is_hash
        values.extend(term_values)
    if not values or name_terms > 1 or (len(terms) > 1 and hash_terms == 0):
        return None
    return tuple(dict.fromkeys(values)), tuple(sorted(set(names)))


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
            parsed = (
                _parse_pattern(str(obj.get("pattern", "")))
                if obj.get("pattern_type") == "stix"
                else None
            )
            if parsed is None:
                unsupported += 1
                continue
            values, required_names = parsed
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
                    required_names=required_names,
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


def _observed_names(observation: Observation) -> frozenset[str]:
    """The file names an Observation states, lower-case: of its process image
    and of its file."""
    names: set[str] = set()
    process, file = observation.process, observation.file
    for value in (
        process.name if process else None,
        process.executable if process else None,
        file.name if file else None,
        file.path if file else None,
    ):
        if value:
            names.add(str(value).replace("\\", "/").rsplit("/", 1)[-1].lower())
    return frozenset(names)


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
        names = _observed_names(observation)
        for key in set(_observed_values(observation)):
            for indicator in index.get(key, ()):
                if indicator.required_names and not names.intersection(indicator.required_names):
                    continue  # the published name is part of the pattern
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
