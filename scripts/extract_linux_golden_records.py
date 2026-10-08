#!/usr/bin/env python3
"""Extract a small, fixed set of real Sysmon for Linux records from the
``splunk/attack_data`` cache into a tracked golden file (ADR-0010 D7).

Selection is deterministic: for every supported event ID, the first record in
the pinned logs taken in sorted path order; plus the first process start of
each Sandworm-attributed malware detonation (AcidRain, Cyclops Blink), and the
first process start whose command line spans several lines; and auditd records
(the first raw record of each type, an enriched one, and two refusal cases). Records
are written verbatim (the XML line), with their source path, to
``data/telemetry-samples/splunk-attack-data/golden-records.jsonl``. Re-running on
the verified cache reproduces the file byte-for-byte. Apache-2.0 data (see the
NOTICE beside it).

    python scripts/extract_linux_golden_records.py
"""

from __future__ import annotations

import json
import re
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from attribution_platform.replay.recording_pipeline import iter_recording_records  # noqa: E402

CACHE = REPO_ROOT / "data" / "cache" / "splunk-attack-data"
OUT = REPO_ROOT / "data" / "telemetry-samples" / "splunk-attack-data" / "golden-records.jsonl"
EVENT_IDS = (1, 3, 5, 11, 23)
MALWARE = ("acidrain", "cyclopsblink")
_EVENT_ID = re.compile(r"<EventID>(\d+)</EventID>")
_RAW_AUDIT = re.compile(r"type=(?P<type>[A-Z_]+) msg=audit\(\d+\.\d{3}:\d+\):")


def _raw(line: str, record_type: str) -> bool:
    """A raw audit.log record (epoch time) of ``record_type``."""
    match = _RAW_AUDIT.match(line)
    return match is not None and match["type"] == record_type


def _text_records(log: Path) -> Iterator[str]:
    """The text (XML event) records of a log, through the pipeline's own reader."""
    return (r for r in iter_recording_records(log) if isinstance(r, str))


def main() -> int:
    logs = sorted(CACHE.rglob("sysmon_linux*.log"), key=lambda p: p.relative_to(CACHE).as_posix())
    wanted: dict[str, tuple[str, int]] = {f"linux-sysmon-{i}": ("", i) for i in EVENT_IDS}
    wanted.update({f"linux-sysmon-1-{m}": (f"malware/{m}/", 1) for m in MALWARE})
    found: dict[str, tuple[str, str]] = {}
    for log in logs:
        source = log.relative_to(CACHE).as_posix()
        pending = [
            g for g, (prefix, _) in wanted.items() if g not in found and source.startswith(prefix)
        ]
        if not pending:
            continue
        # The pipeline's own reader: a multi-line XML event is one record.
        for record in _text_records(log):
            match = _EVENT_ID.search(record)
            if match is None:
                continue
            for golden_id in list(pending):
                if int(match[1]) == wanted[golden_id][1]:
                    found[golden_id] = (source, record)
                    pending.remove(golden_id)
            if not pending:
                break
    # The first event whose command line spans several lines (reassembly proof).
    multiline = "linux-sysmon-1-multiline"
    for log in logs:
        multiline_record: str | None = next(
            (r for r in _text_records(log) if "\n" in r and "<EventID>1</EventID>" in r),
            None,
        )
        if multiline_record is not None:
            found[multiline] = (log.relative_to(CACHE).as_posix(), multiline_record)
            wanted[multiline] = ("", 1)
            break
    # auditd (ADR-0010 D4): the first raw record of each type (raw lines only,
    # file order over sorted paths), one enriched SYSCALL, one ausearch -i
    # record and one post-processed record (both refused by the adapter).
    audit_rules: dict[str, Any] = {
        **{
            f"auditd-{t.lower()}": (lambda line, t=t: _raw(line, t))
            for t in ("SYSCALL", "EXECVE", "PATH", "PROCTITLE", "SERVICE_STOP", "ADD_USER")
        },
        "auditd-syscall-enriched": lambda line: _raw(line, "SYSCALL") and "\x1d" in line,
        "auditd-interpreted": lambda line: line.startswith("type=") and "msg=audit(0" in line,
        "auditd-bare-argument": lambda line: _raw(line, "EXECVE") and " a0=xclip " in line,
    }
    audit_logs = sorted(
        (p for p in CACHE.rglob("*.log") if "sysmon" not in p.name),
        key=lambda p: p.relative_to(CACHE).as_posix(),
    )
    for log in audit_logs:
        pending = [g for g in audit_rules if g not in found]
        if not pending:
            break
        with log.open(encoding="utf-8", errors="replace", newline="\n") as handle:
            for raw in handle:
                line = raw.rstrip("\r\n")
                for golden_id in list(pending):
                    if audit_rules[golden_id](line):
                        found[golden_id] = (log.relative_to(CACHE).as_posix(), line)
                        pending.remove(golden_id)
                if not pending:
                    break
    wanted.update({g: ("", 0) for g in audit_rules})
    missing = sorted(set(wanted) - set(found))
    if missing:
        raise RuntimeError(f"no record for {missing}")
    with OUT.open("w", encoding="utf-8", newline="\n") as handle:
        for golden_id in wanted:
            source, record = found[golden_id]
            row = {"golden_id": golden_id, "source": source, "record": record}
            handle.write(json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n")
    print(f"wrote {len(found)} records to {OUT.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
