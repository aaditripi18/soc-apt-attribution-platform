#!/usr/bin/env python3
"""Extract a small, fixed set of real Zeek records from the OTRF cache into a
tracked golden file (ADR-0012 D7).

Deterministic: for each golden id, the first matching record in the file named
(JSON lines from the APT29 day-1 combined log; one TSV log from the LSASS
campaign 5 archive, with its header block, so the TSV reader is tested on a
real header). Records are written verbatim with their source to
``data/telemetry-samples/otrf-zeek/golden-records.jsonl``. Re-running on the
verified cache reproduces the file byte-for-byte. MIT data (see the NOTICE).

    python scripts/extract_zeek_golden_records.py
"""

from __future__ import annotations

import json
import sys
import zipfile
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
SAMPLES = REPO_ROOT / "data" / "telemetry-samples" / "otrf-zeek"
CACHE = REPO_ROOT / "data" / "cache" / "otrf-compound"
OUT = SAMPLES / "golden-records.jsonl"
COMBINED = CACHE / "apt29" / "day1" / "zeek" / "combined_zeek.log"
TSV_ARCHIVE = CACHE / "LSASS_campaign_05" / "metasploit_sharpdump_lsass_memory_dump_zeek_logs.zip"


def _stream(name: str, **values: Any) -> Callable[[Mapping[str, Any]], bool]:
    return lambda r: r.get("@stream") == name and all(r.get(k) == v for k, v in values.items())


#: golden id -> predicate over one JSON record of the APT29 day-1 combined log.
JSON_GOLDEN: Mapping[str, Callable[[Mapping[str, Any]], bool]] = {
    "zeek-json-conn": _stream("conn", proto="tcp", id_resp_p=445),
    "zeek-json-dns": _stream("dns", qtype_name="A"),
    "zeek-json-dce-rpc": _stream("dce_rpc", endpoint="drsuapi", operation="DRSCrackNames"),
    "zeek-json-kerberos": _stream("kerberos", request_type="TGS"),
    "zeek-json-smb-files": _stream("smb_files"),
    "zeek-json-http": _stream("http"),
    "zeek-json-ssl": _stream("ssl"),
    "zeek-json-files": _stream("files"),
    "zeek-json-x509": _stream("x509"),  # refused: not a traffic log read here
}
#: TSV logs taken whole (header block + first data line) from the LSASS archive.
TSV_LOGS = ("dns.log", "conn.log")


def main() -> int:
    found: dict[str, tuple[str, str]] = {}
    with COMBINED.open(encoding="utf-8") as handle:
        for raw in handle:
            line = raw.rstrip("\n")
            record = json.loads(line)
            for golden_id, predicate in JSON_GOLDEN.items():
                if golden_id not in found and predicate(record):
                    found[golden_id] = (COMBINED.relative_to(CACHE).as_posix(), line)
            if len(found) == len(JSON_GOLDEN):
                break
    with zipfile.ZipFile(TSV_ARCHIVE) as archive:
        for name in sorted(archive.namelist()):
            log = name.rsplit("/", 1)[-1]
            if log not in TSV_LOGS:
                continue
            lines = archive.read(name).decode("utf-8").splitlines()
            header = [line for line in lines if line.startswith("#")][:8]  # through #types
            first = next(line for line in lines if not line.startswith("#"))
            source = f"{TSV_ARCHIVE.relative_to(CACHE).as_posix()}!{name}"
            found[f"zeek-tsv-{log.removesuffix('.log')}"] = (source, "\n".join([*header, first]))
    expected = [*JSON_GOLDEN, *(f"zeek-tsv-{log.removesuffix('.log')}" for log in TSV_LOGS)]
    missing = sorted(set(expected) - set(found))
    if missing:
        raise RuntimeError(f"no record for {missing}")
    with OUT.open("w", encoding="utf-8", newline="\n") as handle:
        for golden_id in expected:
            source, record = found[golden_id]
            row = {"golden_id": golden_id, "source": source, "record": record}
            handle.write(json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n")
    print(f"wrote {len(found)} records to {OUT.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
