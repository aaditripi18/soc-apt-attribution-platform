#!/usr/bin/env python3
"""Reproducibility check: investigate one recording in fresh processes under
different Python hash seeds and require byte-identical results.

Python randomises string hashing per process (``PYTHONHASHSEED``), so any code
whose output depends on set / dict iteration order of strings gives different
results run to run — exactly the class of bug ADR-0003 revision H2.3 found on the
real APT29 recording. This check makes reproducibility a tested property: every
document the investigation persists (Observations, Evidence, links, units,
sequences, attribution analyses, guidance, indicator matches) is serialised
canonically and hashed; all seeds must agree.

    python scripts/check_reproducibility.py <recording id | path> [--seeds 0,1,2]

Exit 0 when every seed yields the same digest, 1 otherwise.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

_CHILD = """
import hashlib, json, sys
from attribution_platform.dataplane import FakeElasticClient
from attribution_platform.investigation.__main__ import investigate
client = FakeElasticClient()
investigate(sys.argv[1], client=client)
digest = hashlib.sha256()
for index in sorted(client._documents):
    for doc_id in sorted(client._documents[index]):
        digest.update(index.encode() + b"\\0" + doc_id.encode() + b"\\0")
        digest.update(json.dumps(client._documents[index][doc_id], sort_keys=True).encode())
print(json.dumps({"digest": digest.hexdigest(),
                  "documents": sum(len(d) for d in client._documents.values())}))
"""


def digest_under_seed(recording: str, seed: int) -> dict[str, object]:
    """The canonical digest of everything one investigation persists, computed
    in a fresh interpreter with ``PYTHONHASHSEED=seed``."""
    env = {**os.environ, "PYTHONHASHSEED": str(seed), "PYTHONPATH": str(REPO_ROOT / "src")}
    completed = subprocess.run(  # noqa: S603 - our own interpreter and code
        [sys.executable, "-c", _CHILD, recording],
        capture_output=True,
        text=True,
        env=env,
        cwd=REPO_ROOT,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(f"seed {seed} failed:\n{completed.stderr[-2000:]}")
    result: dict[str, object] = json.loads(completed.stdout.strip().splitlines()[-1])
    return result


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__)
        return 2
    seeds = [0, 1, 2]
    if "--seeds" in argv:
        seeds = [int(s) for s in argv[argv.index("--seeds") + 1].split(",")]
    results = {seed: digest_under_seed(argv[0], seed) for seed in seeds}
    for seed, result in results.items():
        print(f"seed {seed}: {result['digest']}  ({result['documents']} documents)")
    identical = len({r["digest"] for r in results.values()}) == 1
    print("reproducible" if identical else "NOT reproducible: results depend on the hash seed")
    return 0 if identical else 1


if __name__ == "__main__":
    _ = hashlib  # the child computes the digest; kept for readers of the parent
    sys.exit(main(sys.argv[1:]))
