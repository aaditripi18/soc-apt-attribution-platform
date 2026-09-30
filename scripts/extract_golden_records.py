#!/usr/bin/env python3
"""Extract a small, fixed set of real records from the corpus telemetry cache
into a tracked golden file for always-on adapter tests.

The full recordings (~3.7 GB) live only in the git-ignored cache; the tests need
a handful of specific real records. Each record is selected by a deterministic
rule over one recording (first record matching it, in file order) and written
verbatim, with its source file, to
``data/telemetry-samples/otrf-compound/golden-records.jsonl``. Re-running on the
verified cache reproduces the file byte-for-byte. MIT-licensed data (see the
NOTICE beside it).

    python scripts/extract_golden_records.py
"""

from __future__ import annotations

import io
import json
import sys
import tarfile
import zipfile
from collections.abc import Callable, Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
CACHE = REPO_ROOT / "data" / "cache" / "otrf-compound"
OUT = REPO_ROOT / "data" / "telemetry-samples" / "otrf-compound" / "golden-records.jsonl"
EMPIRE = "windows/apt3/empire_apt3.tar.gz"
CALDERA = "windows/apt3/caldera_attack_evals_round1_day1_2019-10-20201108.tar.gz"
APT29_DAY1 = "apt29/day1/apt29_evals_day1_manual.zip"
APT29_DAY2 = "apt29/day2/apt29_evals_day2_manual.zip"

Record = dict[str, Any]


def _v6(channel: str, event_id: int) -> Callable[[Record], bool]:
    return lambda r: r.get("log_name") == channel and r.get("event_id") == event_id


def _wlb7(event_id: int) -> Callable[[Record], bool]:
    """A Winlogbeat 7 collector record of the (lower-case) Security channel."""
    return lambda r: str((r.get("winlog") or {}).get("channel", "")).lower() == "security" and (
        r["winlog"].get("event_id") == event_id
    )


def _nx(event_id: int) -> Callable[[Record], bool]:
    """A flat NXLog Security record carrying its exact EventTime."""
    return lambda r: (
        str(r.get("Channel", "")).lower() == "security"
        and int(r.get("EventID", -1)) == event_id
        and "EventTime" in r
    )


def _utc_gap_seconds(r: Record, event_data: Record) -> float:
    stamp = datetime.fromisoformat(r["@timestamp"].replace("Z", "+00:00"))
    return (
        stamp - datetime.fromisoformat(event_data["UtcTime"]).replace(tzinfo=UTC)
    ).total_seconds()


#: (golden id, recording, selection rule) — first matching record in file order.
SELECTIONS: tuple[tuple[str, str, Callable[[Record], bool]], ...] = (
    ("wlb6-sysmon-1", EMPIRE, _v6("Microsoft-Windows-Sysmon/Operational", 1)),
    ("wlb6-sysmon-10", EMPIRE, _v6("Microsoft-Windows-Sysmon/Operational", 10)),
    ("wlb6-sysmon-13", EMPIRE, _v6("Microsoft-Windows-Sysmon/Operational", 13)),
    (
        "wlb6-sysmon-3-late",
        EMPIRE,
        lambda r: _v6("Microsoft-Windows-Sysmon/Operational", 3)(r)
        and _utc_gap_seconds(r, r["event_data"]) > 3600,
    ),
    ("wlb6-sysmon-5", EMPIRE, _v6("Microsoft-Windows-Sysmon/Operational", 5)),
    ("wlb6-security-4624", EMPIRE, _v6("Security", 4624)),
    ("wlb6-security-4688", EMPIRE, _v6("Security", 4688)),
    ("wlb6-security-5145", EMPIRE, _v6("Security", 5145)),
    (
        "wlb6-powershell-4103",
        EMPIRE,
        lambda r: _v6("Microsoft-Windows-PowerShell/Operational", 4103)(r)
        and "Payload" in (r.get("event_data") or {}),
    ),
    (
        "wlb6-system-7",
        EMPIRE,
        lambda r: r.get("log_name") == "System" and r.get("event_id") == 7036,
    ),
    (
        "wlb7-sysmon-late",
        CALDERA,
        lambda r: (r.get("winlog") or {}).get("channel") == "Microsoft-Windows-Sysmon/Operational"
        and r["winlog"].get("event_id") in (1, 3, 7, 10, 11, 12, 13)
        and _utc_gap_seconds(r, r["winlog"]["event_data"]) > 1,
    ),
    (
        "wlb7-security-lower",
        CALDERA,
        lambda r: (r.get("winlog") or {}).get("channel") == "security"
        and r["winlog"].get("event_id") == 4663,
    ),
    (
        "nxlog-sysmon-12-nxlog-eventtype",
        APT29_DAY1,
        lambda r: r.get("Channel") == "Microsoft-Windows-Sysmon/Operational"
        and r.get("EventID") == 12
        and r.get("EventType") == "INFO"
        and "EventType: DeleteKey" in (r.get("Message") or ""),
    ),
    (
        "nxlog-security-lower",
        APT29_DAY1,
        lambda r: r.get("Channel") == "security" and r.get("EventID") == 4663,
    ),
    # Security batch B (ADR-0008): one real record per supported event.
    ("b-4611", CALDERA, _wlb7(4611)),
    ("b-4625", EMPIRE, _v6("Security", 4625)),
    ("b-4648", EMPIRE, _v6("Security", 4648)),
    ("b-4648-nxlog", APT29_DAY1, _nx(4648)),
    ("b-4657", APT29_DAY1, _nx(4657)),
    ("b-4661", CALDERA, _wlb7(4661)),
    ("b-4662", CALDERA, _wlb7(4662)),
    ("b-4672", CALDERA, _wlb7(4672)),
    ("b-4673", CALDERA, _wlb7(4673)),
    ("b-4674", CALDERA, _wlb7(4674)),
    ("b-4697", EMPIRE, _v6("Security", 4697)),
    ("b-4697-apt29", APT29_DAY1, lambda r: _nx(4697)(r) and r.get("ServiceName") == "javamtsup"),
    ("b-4698", CALDERA, _wlb7(4698)),
    ("b-4702", CALDERA, _wlb7(4702)),
    ("b-4720", APT29_DAY2, _nx(4720)),
    ("b-4722", APT29_DAY2, _nx(4722)),
    ("b-4724", APT29_DAY2, _nx(4724)),
    ("b-4728", APT29_DAY2, _nx(4728)),
    ("b-4732", APT29_DAY2, _nx(4732)),
    ("b-4738", APT29_DAY2, _nx(4738)),
    ("b-4768", CALDERA, _wlb7(4768)),
    ("b-4769", CALDERA, _wlb7(4769)),
    ("b-4771", EMPIRE, _v6("Security", 4771)),
    ("b-5379", APT29_DAY1, _nx(5379)),
    ("b-5441", APT29_DAY1, _nx(5441)),
    ("b-5447", APT29_DAY1, _nx(5447)),
)


def _records(path: Path) -> Iterator[Record]:
    if path.suffix == ".zip":
        with zipfile.ZipFile(path) as archive:
            (name,) = archive.namelist()
            with archive.open(name) as handle:
                for line in io.TextIOWrapper(handle, encoding="utf-8", errors="replace"):
                    if line.strip():
                        yield json.loads(line)
    else:
        with tarfile.open(path, "r:gz") as archive:
            for member in archive.getmembers():
                extracted = archive.extractfile(member) if member.isfile() else None
                if extracted is not None:
                    for line in io.TextIOWrapper(extracted, encoding="utf-8", errors="replace"):
                        if line.strip():
                            yield json.loads(line)


def main() -> int:
    by_recording: dict[str, list[tuple[str, Callable[[Record], bool]]]] = {}
    for golden_id, recording, rule in SELECTIONS:
        by_recording.setdefault(recording, []).append((golden_id, rule))
    found: dict[str, tuple[str, Record]] = {}
    for recording, wanted in by_recording.items():
        pending = list(wanted)
        for record in _records(CACHE / recording):
            for golden_id, rule in list(pending):
                try:
                    hit = rule(record)
                except (KeyError, TypeError, ValueError):
                    hit = False
                if hit:
                    found[golden_id] = (recording, record)
                    pending.remove((golden_id, rule))
            if not pending:
                break
        if pending:
            raise RuntimeError(f"{recording}: no record for {[g for g, _ in pending]}")
    with OUT.open("w", encoding="utf-8", newline="\n") as handle:
        for golden_id, _, _ in SELECTIONS:
            recording, record = found[golden_id]
            line = {"golden_id": golden_id, "recording": recording, "record": record}
            handle.write(json.dumps(line, sort_keys=True, ensure_ascii=False) + "\n")
    print(f"wrote {len(found)} records to {OUT.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
