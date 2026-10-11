"""Advisory indicators (ADR-0013): the pinned CISA bundle, the reviewed
attribution, the strict STIX pattern subset, exact matching — and the proof that
a match is context only: attribution quantities are identical with or without it."""

from __future__ import annotations

import copy
import dataclasses
import hashlib
import json
import shutil
from pathlib import Path
from typing import Any

import pytest

from attribution_platform.attack_knowledge.loader import load_attack_knowledge
from attribution_platform.dataplane import FakeElasticClient
from attribution_platform.detection import DetectionEngine, load_rule_pack
from attribution_platform.domain import HashSet
from attribution_platform.intel.indicators import (
    IndicatorError,
    _parse_pattern,
    load_indicator_set,
    match_observations,
)
from attribution_platform.investigation.records import load_attribution_analysis
from attribution_platform.investigation.run import run_investigation
from attribution_platform.replay.recording_pipeline import RecordingSource
from attribution_platform.sources.sysmon import SysmonSourceAdapter

REPO_ROOT = Path(__file__).resolve().parents[1]
INTEL = REPO_ROOT / "data" / "intel"
ADVISORIES = INTEL / "advisories"
ATTRIBUTIONS = INTEL / "advisory-attributions.json"
GOLDEN = REPO_ROOT / "data" / "telemetry-samples" / "otrf-compound" / "golden-records.jsonl"
PACK = (
    REPO_ROOT
    / "data"
    / "detection"
    / "sigma"
    / "r2026-07-01"
    / "generated"
    / "sigma-r2026-07-01-sigma_core++.rules.json"
)
#: SMSvcService.exe, from CISA MAR-10448362.c1 (Volt Typhoon).
ADVISORY_SHA256 = "99b80c5ac352081a64129772ed5e1543d94cad708ba2adc46dc4ab7a0bd563f1"


def _sysmon_1() -> dict[str, Any]:
    rows = (json.loads(line) for line in GOLDEN.read_text(encoding="utf-8").splitlines())
    return next(r["record"] for r in rows if r["golden_id"] == "wlb6-sysmon-1")


def _event_data(record: dict[str, Any]) -> dict[str, Any]:
    data: dict[str, Any] = (
        record["event_data"] if "event_data" in record else record["winlog"]["event_data"]
    )
    return data


def _with_hash(record: dict[str, Any], sha256: str) -> dict[str, Any]:
    """One labelled change: the image's SHA256 replaced by ``sha256``."""
    changed = copy.deepcopy(record)
    data = _event_data(changed)
    parts = [p for p in data["Hashes"].split(",") if not p.startswith("SHA256=")]
    data["Hashes"] = ",".join([*parts, f"SHA256={sha256.upper()}"])
    return changed


# ===========================================================================
# The pinned bundle and its reviewed attribution
# ===========================================================================


def test_real_bundle_loads_attributed_through_the_review() -> None:
    everything = load_indicator_set(ADVISORIES, ATTRIBUTIONS)
    mar = [i for i in everything.indicators if i.bundle_file.startswith("MAR-10448362")]
    assert {i.name for i in mar} == {
        "BrightmetricAgent.exe",
        "SMSvcService.exe",
        "eaef901b31b5835035b75302f94fee27288ce46971c6db6221ecbea9ba7ff9d0",
    }
    for indicator in mar:
        assert (indicator.actor_name, indicator.attack_group_id) == ("Volt Typhoon", "G1017")
        assert indicator.attribution_quote and "Volt Typhoon" in indicator.attribution_quote
        assert {k for k, _ in indicator.values} == {"md5", "sha1", "sha256", "sha512"}


def test_every_pinned_bundle_loads_with_its_reviewed_actor() -> None:
    """ADR-0013 Amendment A: seven bundles, each attributed only through its
    reviewed quote; what cannot be read exactly is counted, not guessed."""
    loaded = load_indicator_set(ADVISORIES, ATTRIBUTIONS)
    by_bundle: dict[str, set[tuple[str | None, str | None]]] = {}
    for indicator in loaded.indicators:
        by_bundle.setdefault(indicator.bundle_file, set()).add(
            (indicator.actor_name, indicator.attack_group_id)
        )
        assert indicator.attribution_quote
    assert by_bundle == {
        "MAR-10448362.c1.v1.CLEAR_stix2.json": {("Volt Typhoon", "G1017")},
        "AA23-144A.stix.json": {("Volt Typhoon", "G1017")},
        "AA23-347A.stix.json": {("APT29", "G0016")},
        "AA24-207A.stix.json": {("Andariel", "G0138")},
        "AA24-241A.stix.json": {("Fox Kitten", "G0117")},
        "AA24-249A.stix.json": {("Ember Bear (GRU Unit 29155)", "G1003")},
        "AA25-141A.stix.json": {("APT28 (GRU unit 26165)", "G0007")},
    }
    assert len(loaded.indicators) == 454
    # 13 e-mail addresses (no Observation carries one) and 2 malformed patterns
    assert loaded.unsupported_patterns == 15
    assert sum(1 for i in loaded.indicators if i.required_names) == 67


def test_a_quote_not_in_the_bundle_fails_closed(tmp_path: Path) -> None:
    review = json.loads(ATTRIBUTIONS.read_text(encoding="utf-8"))
    review["attributions"][0]["quote"] = "compromised by APT29."
    altered = tmp_path / "attributions.json"
    altered.write_text(json.dumps(review), encoding="utf-8")
    with pytest.raises(IndicatorError, match="quote is not in the report"):
        load_indicator_set(ADVISORIES, altered)


def test_a_bundle_that_differs_from_its_pin_fails_closed(tmp_path: Path) -> None:
    copied = tmp_path / "advisories"
    shutil.copytree(ADVISORIES, copied)
    bundle = next(p for p in sorted(copied.iterdir()) if p.name.endswith("stix2.json"))
    bundle.write_bytes(bundle.read_bytes() + b" ")
    with pytest.raises(IndicatorError, match="SHA-256"):
        load_indicator_set(copied, ATTRIBUTIONS)


@pytest.mark.parametrize(
    ("pattern", "expected"),
    [
        ("[ipv4-addr:value = '203.0.113.7']", ((("ip", "203.0.113.7"),), ())),
        ("[domain-name:value = 'Evil.Example.']", ((("domain", "evil.example"),), ())),
        ("[url:value = 'http://a/b?x=1 OR y']", ((("url", "http://a/b?x=1 OR y"),), ())),
        # 1.1: redundant parentheses, the unquoted MD5 key
        ("[(file:hashes.MD5 = 'AB')]", ((("md5", "ab"),), ())),
        (
            "[(file:hashes.MD5 = 'AB' OR file:hashes.'SHA-1' = 'CD')]",
            ((("md5", "ab"), ("sha1", "cd")), ()),
        ),
        # 1.1: hashes of one file joined by AND; size follows from the content
        (
            "[file:hashes.MD5 = 'AB' AND file:hashes.'SHA-256' = 'EF']",
            ((("md5", "ab"), ("sha256", "ef")), ()),
        ),
        ("[file:size = 9 AND (file:hashes.MD5 = 'AB')]", ((("md5", "ab"),), ())),
        # 1.1: a published name is kept as a condition
        (
            "[(file:name = 'T.EXE' OR file:name = 't.dll') AND file:size = 9"
            " AND file:hashes.MD5 = 'AB']",
            ((("md5", "ab"),), ("t.dll", "t.exe")),
        ),
        ("[file:name = 'x.exe']", None),
        ("[file:size = 9]", None),
        ("[file:name = 'a' OR 'b' AND file:hashes.MD5 = 'AB']", None),
        ("[file:hashes.MD5 = 'AB' AND directory:path = 'C:\\\\x']", None),
        ("[(file:name = 'a') AND (file:name = 'b') AND file:hashes.MD5 = 'AB']", None),
        ("[ipv4-addr:value = '203.0.113.7' AND file:hashes.MD5 = 'AB']", None),
        ("[(file:hashes.MD5 = 'AB']", None),
        ("[email-addr:value = 'a@b.example']", None),
        ("[ipv4-addr:value = '203.0.113.7' AND domain-name:value = 'a.example']", None),
        ("[ipv4-addr:value != '203.0.113.7']", None),
        ("[ipv4-addr:value = '203.0.113.7'] WITHIN 5 SECONDS", None),
        ("[ipv4-addr:value = '1.2.3.4'] OR [ipv4-addr:value = '5.6.7.8']", None),
        ("[process:name = 'x.exe']", None),
        ("[ipv4-addr:value = 'not-an-ip']", None),
    ],
)
def test_only_exact_equality_patterns_are_read(
    pattern: str, expected: tuple[tuple[tuple[str, str], ...], tuple[str, ...]] | None
) -> None:
    assert _parse_pattern(pattern) == expected


# ===========================================================================
# Matching
# ===========================================================================


def test_sysmon_process_hashes_are_parsed_exactly() -> None:
    (obs,) = SysmonSourceAdapter().to_observations(_sysmon_1())
    assert obs.process is not None
    assert obs.process.hashes == HashSet(
        md5="f225f37717c8d714b56cf21c7c1e9c34",
        sha1="121e6c3cf7af4ca30db43440f71c1510ec3ea261",
        sha256="e272d0e33299bca60479683eae0d9b5d880293c01b337d5759fee812ea631a39",
    )


def test_a_real_record_matches_only_with_the_advisory_hash() -> None:
    indicators = load_indicator_set(ADVISORIES, ATTRIBUTIONS)
    (plain,) = SysmonSourceAdapter().to_observations(_sysmon_1())
    assert match_observations(indicators, [plain]) == ()
    (changed,) = SysmonSourceAdapter().to_observations(_with_hash(_sysmon_1(), ADVISORY_SHA256))
    (match,) = match_observations(indicators, [changed])
    assert (match.indicator_name, match.kind, match.value) == (
        "SMSvcService.exe",
        "sha256",
        ADVISORY_SHA256,
    )
    assert (match.actor_name, match.attack_group_id) == ("Volt Typhoon", "G1017")
    # the record is from 2019; the indicator is valid from 2024 — flagged, not dropped
    assert match.within_validity is False


# ===========================================================================
# Context only: no attribution quantity changes
# ===========================================================================


def test_matches_are_annotations_and_change_no_attribution_quantity(tmp_path: Path) -> None:
    knowledge = load_attack_knowledge()
    pack = load_rule_pack(PACK, knowledge=knowledge)
    path = tmp_path / "rec.jsonl"
    # two labelled changes on the real record: an image a Sigma rule detects
    # (whoami /all, T1033) and the advisory's hash — so a unit exists to annotate
    record = _with_hash(_sysmon_1(), ADVISORY_SHA256)
    _event_data(record).update(
        Image="C:\\Windows\\System32\\whoami.exe",
        CommandLine="whoami /all",
        OriginalFileName="whoami.exe",
    )
    path.write_text(json.dumps(record) + "\n", encoding="utf-8")

    source = RecordingSource(
        recording_id="ioc-test",
        path=path,
        sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        declared_sources={"HR001.shire.com": ("sysmon",)},
    )
    analyses = []
    for indicators in (None, load_indicator_set(ADVISORIES, ATTRIBUTIONS)):
        client = FakeElasticClient()
        investigated = run_investigation(
            source,
            client=client,
            engine=DetectionEngine(rules=pack.rules),
            knowledge=knowledge,
            detection_pack_content_hash=pack.content_hash,
            indicators=indicators,
        )
        analyses.append(
            {u: dict(load_attribution_analysis(client, u) or {}) for u in investigated.units}
        )
    without, with_ = analyses
    assert without.keys() == with_.keys()
    assert with_  # the detected record forms a unit
    for unit, analysis in with_.items():
        matches = analysis.pop("indicator_matches")
        assert without[unit].pop("indicator_matches") == []
        assert analysis == without[unit]  # every attribution quantity identical
        assert matches and matches[0]["named_actor"] == "Volt Typhoon"


def test_indicator_set_is_frozen() -> None:
    indicators = load_indicator_set(ADVISORIES, ATTRIBUTIONS)
    with pytest.raises(dataclasses.FrozenInstanceError):
        indicators.unsupported_patterns = 1  # type: ignore[misc]


def test_a_published_file_name_is_part_of_the_match() -> None:
    """ADR-0013 Amendment A: where the advisory's pattern joins a hash with a
    file name, the observed image must carry that name. The content hash alone
    is not the published pattern."""
    indicators = load_indicator_set(ADVISORIES, ATTRIBUTIONS)
    named = next(
        i
        for i in indicators.indicators
        if i.required_names and any(kind == "sha256" for kind, _ in i.values)
    )
    sha256 = next(value for kind, value in named.values if kind == "sha256")

    def observed(image: str) -> tuple[str, ...]:
        record = _with_hash(_sysmon_1(), sha256)
        _event_data(record)["Image"] = image
        (observation,) = SysmonSourceAdapter().to_observations(record)
        return tuple(
            m.indicator_id
            for m in match_observations(indicators, [observation])
            if m.indicator_id == named.indicator_id
        )

    folder = "C:\\Users\\Public\\"
    assert observed(folder + named.required_names[0].upper()) != ()
    assert observed(folder + "renamed-copy.exe") == ()
