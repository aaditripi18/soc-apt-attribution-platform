"""ADR-0003 Amendment I: a low-level detection reaches the unit of its nearest
ancestor with Evidence through processes that matched no rule - and only a
low-level detection: unit boundaries of core Evidence never change."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from attribution_platform.attack_knowledge.loader import AttackKnowledge, load_attack_knowledge
from attribution_platform.correlation import correlate_structurally
from attribution_platform.correlation.structural import MAX_UNDETECTED_ANCESTORS

sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_enrich_tier import _engine, _items, _obs  # noqa: E402


@pytest.fixture(scope="module")
def knowledge() -> AttackKnowledge:
    return load_attack_knowledge()


def _members(items, result) -> set[str]:  # type: ignore[no-untyped-def]
    (group,) = result.groups
    return {
        e.provenance.source_observation_ids[0]
        for e, _ in items
        if e.evidence_id in group.member_evidence_ids
    }


def test_a_low_level_grandchild_joins_through_an_undetected_shell(
    tmp_path: Path, knowledge: AttackKnowledge
) -> None:
    engine = _engine(tmp_path, knowledge)
    implant = _obs("o-implant", "C:\\core.exe", "{IMPLANT}")
    shell = _obs("o-shell", "C:\\cmd.exe", "{SHELL}", parent="{IMPLANT}")  # matches no rule
    recon = _obs("o-recon", "C:\\low.exe", "{RECON}", parent="{SHELL}")
    items = _items(engine, knowledge, implant, shell, recon)
    assert {o.observation_id for _, o in items} == {"o-implant", "o-recon"}
    # without the shell's own record nothing proves the chain: no link
    assert len(correlate_structurally(items).groups) == 1
    assert _members(items, correlate_structurally(items)) == {"o-implant"}
    # with it, the low-level detection joins the implant's unit, and the link says how
    result = correlate_structurally(items, context_observations=[shell])
    assert _members(items, result) == {"o-implant", "o-recon"}
    (link,) = [link for link in result.links if "o-shell" in link.provenance.source_observation_ids]
    # an unhedged fact: the shell's own start record names its parent
    assert link.basis.uncertainty_note is None


def test_the_walk_stops_after_the_bound(tmp_path: Path, knowledge: AttackKnowledge) -> None:
    engine = _engine(tmp_path, knowledge)
    chain = [_obs("o-0", "C:\\core.exe", "{P0}")]
    hops = MAX_UNDETECTED_ANCESTORS + 1
    for i in range(1, hops + 1):
        chain.append(_obs(f"o-{i}", "C:\\cmd.exe", f"{{P{i}}}", parent=f"{{P{i - 1}}}"))
    chain.append(_obs("o-low", "C:\\low.exe", "{LOW}", parent=f"{{P{hops}}}"))
    items = _items(engine, knowledge, chain[0], chain[-1])
    result = correlate_structurally(items, context_observations=chain[1:-1])
    assert _members(items, result) == {"o-0"}  # too far: not linked


def test_core_evidence_is_never_linked_this_way(tmp_path: Path, knowledge: AttackKnowledge) -> None:
    engine = _engine(tmp_path, knowledge)
    parent = _obs("o-a", "C:\\core.exe", "{A}")
    shell = _obs("o-shell", "C:\\cmd.exe", "{SHELL}", parent="{A}")
    child = _obs("o-b", "C:\\core.exe", "{B}", parent="{SHELL}")
    items = _items(engine, knowledge, parent, child)
    result = correlate_structurally(items, context_observations=[shell])
    assert len(result.groups) == 2  # two core units stay two: boundaries unchanged


def test_attacker_discovery_from_the_implants_shell_is_counted(tmp_path: Path) -> None:
    """End to end on Sysmon records: an implant dumping LSASS (core), a shell it
    starts (no rule), and systeminfo started by that shell (low-level, reviewed
    to count once linked). System Information Discovery is counted; the same
    systeminfo started by an unrelated shell is context only."""
    import copy
    import json

    from attribution_platform.api.read_model import (
        get_investigation_activity,
        get_investigation_context,
    )
    from test_dossier import _investigate
    from test_indicators import _event_data, _sysmon_1

    base = _sysmon_1()

    def process(record_id: int, guid: str, parent: str, image: str, command: str) -> str:
        record = copy.deepcopy(base)
        record["record_number"] = str(record_id)  # one record each (the golden is flat)
        data = _event_data(record)
        data.update(
            ProcessGuid=guid,
            ParentProcessGuid=parent,
            Image=image,
            CommandLine=command,
            OriginalFileName=image.rsplit("\\", 1)[-1],
        )
        return json.dumps(record)

    bs = "\\"
    implant = bs.join(["C:", "Users", "u", "AppData", "Local", "Temp", "payload.exe"])
    cmd = bs.join(["C:", "Windows", "System32", "cmd.exe"])
    systeminfo = bs.join(["C:", "Windows", "System32", "systeminfo.exe"])
    dump = "procdump.exe -accepteula -ma lsass.exe d.dmp"
    lines = [
        process(9001, "{IMPLANT}", "{ROOT}", implant, dump),
        process(9002, "{SHELL}", "{IMPLANT}", cmd, "cmd.exe"),
        process(9003, "{RECON}", "{SHELL}", systeminfo, "systeminfo"),
        process(9004, "{OTHER}", "{ELSEWHERE}", systeminfo, "systeminfo"),
    ]
    client, investigation_id = _investigate(tmp_path, "chain.jsonl", "\n".join(lines) + "\n")
    counted = {
        e["attack_id"]
        for e in get_investigation_activity(client, investigation_id)["events"]
        if e["decision_feature"]
    }
    assert {"T1003.001", "T1082"} <= counted
    # the unrelated systeminfo stays context, outside every cluster
    context = get_investigation_context(client, investigation_id)["items"]
    assert [i["attack_id"] for i in context if i["label"] == "systeminfo.exe"] == ["T1082"]
