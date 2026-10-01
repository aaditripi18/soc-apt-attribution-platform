#!/usr/bin/env python3
"""Extract a small, fixed set of real Sysmon for Linux records from the
``splunk/attack_data`` cache into a tracked golden file (ADR-0010 D7).

Selection is deterministic: for every supported event ID, the first record in
the pinned logs taken in sorted path order; plus the first process start of
each Sandworm-attributed malware detonation (AcidRain, Cyclops Blink), and the
first process start whose command line spans several lines. Records
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
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from attribution_platform.replay.recording_pipeline import iter_recording_records  # noqa: E402

CACHE = REPO_ROOT / "data" / "cache" / "splunk-attack-data"
OUT = REPO_ROOT / "data" / "telemetry-samples" / "splunk-attack-data" / "golden-records.jsonl"
EVENT_IDS = (1, 3, 5, 11, 23)
MALWARE = ("acidrain", "cyclopsblink")
_EVENT_ID = re.compile(r"<EventID>(\d+)</EventID>")


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
        for record in iter_recording_records(log):
            match = _EVENT_ID.search(record) if isinstance(record, str) else None
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
        record = next(
            (
                r
                for r in iter_recording_records(log)
                if isinstance(r, str) and "\n" in r and "<EventID>1</EventID>" in r
            ),
            None,
        )
        if record is not None:
            found[multiline] = (log.relative_to(CACHE).as_posix(), record)
            wanted[multiline] = ("", 1)
            break
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
