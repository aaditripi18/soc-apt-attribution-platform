#!/usr/bin/env python3
"""Export a read-only snapshot of a running read-model API for the hosted demo.

Every GET the analyst console makes for the investigations being served is
requested once and written, with its HTTP status and body exactly as the API
answered, to ``<out>/snapshot/<fnv1a32(path)>.json``. The console built in
snapshot mode (``VITE_SNAPSHOT=1``) reads these files instead of calling the API,
so the hosted pages show precisely what the platform produced - nothing is
recomputed, re-ranked or edited. Unit search with filters is answered in the
browser from the full unit list, with the API's exact-match semantics.

Three routes describe capabilities that need the local server; the snapshot
states that instead of copying the serving process's state: uploads and the
assistant are off, and there is no live session.

    python scripts/export_snapshot.py http://127.0.0.1:8000 frontend/dist-snapshot
"""

from __future__ import annotations

import json
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from attribution_platform.api.assistant import disabled as assistant_disabled
from attribution_platform.api.uploads import disabled as uploads_disabled

GLOBAL = (
    "/health",
    "/investigations",
    "/coverage",
    "/attack/techniques",
    "/attack/groups",
    "/validation",
    "/validation/measurements",
    "/units?limit=1000",
)
PER_INVESTIGATION = (
    "",
    "/units?limit=1000",
    "/dossier",
    "/assessment",
    "/profile-match",
    "/observables",
    "/activity",
    "/context",
    "/emulation",
)
NOT_SERVED_HERE = {
    "/uploads": uploads_disabled(),
    "/assistant": {**assistant_disabled(), "reason": "snapshot"},
    "/live": {"enabled": False},
}


def fnv1a32(text: str) -> str:
    """The file name of a path - the same function as the console's."""
    value = 0x811C9DC5
    for byte in text.encode("utf-8"):
        value = ((value ^ byte) * 0x01000193) & 0xFFFFFFFF
    return f"{value:08x}"


def encode(segment: str) -> str:
    """``encodeURIComponent``, as the console builds its paths."""
    return urllib.parse.quote(segment, safe="-_.!~*'()")


def fetch(base: str, path: str) -> tuple[int, Any]:
    try:
        with urllib.request.urlopen(base + "/api" + path, timeout=600) as response:  # noqa: S310
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read() or b"null")


def main(argv: list[str]) -> int:
    base, out = argv[0].rstrip("/"), Path(argv[1]) / "snapshot"
    out.mkdir(parents=True, exist_ok=True)
    written: dict[str, str] = {}

    def save(path: str, status: int, body: Any) -> None:
        name = fnv1a32(path)
        if name in written and written[name] != path:
            raise SystemExit(f"file-name collision: {path!r} and {written[name]!r}")
        written[name] = path
        (out / f"{name}.json").write_text(
            json.dumps({"path": path, "status": status, "body": body}, separators=(",", ":")),
            encoding="utf-8",
        )

    for path in GLOBAL:
        save(path, *fetch(base, path))
    for path, body in NOT_SERVED_HERE.items():
        save(path, 200, body)
    status, investigations = fetch(base, "/investigations")
    assert status == 200
    units = 0
    for summary in investigations:
        prefix = "/investigations/" + encode(summary["investigation_id"])
        for suffix in PER_INVESTIGATION:
            save(prefix + suffix, *fetch(base, prefix + suffix))
        _, record = fetch(base, prefix)
        for group_id in record["units"]:
            unit = "/units/" + encode(group_id)
            save(unit, *fetch(base, unit))
            save(unit + "/evidence", *fetch(base, unit + "/evidence"))
            units += 1
    size = sum(p.stat().st_size for p in out.glob("*.json"))
    print(
        f"{len(written)} responses, {len(investigations)} investigations, "
        f"{units} units, {size / 1e6:.1f} MB"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
