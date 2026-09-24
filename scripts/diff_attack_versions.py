#!/usr/bin/env python3
"""Write the change report between two vendored ATT&CK releases (doc 11 §G).

    python scripts/diff_attack_versions.py \
        --from enterprise-attack-19.0 --to enterprise-attack-19.2

Writes ``changes-from-<old>.json`` and ``.md`` into the *new* release's
vendored directory. Offline and deterministic.
"""

from __future__ import annotations

import argparse
import json
import sys

from attribution_platform.attack_knowledge.diff import diff_attack_versions, render_attack_diff
from attribution_platform.attack_knowledge.loader import attack_artifact_dir, load_attack_knowledge


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--from", dest="old", required=True)
    parser.add_argument("--to", dest="new", required=True)
    args = parser.parse_args()

    diff = diff_attack_versions(load_attack_knowledge(args.old), load_attack_knowledge(args.new))
    out_dir = attack_artifact_dir(args.new)
    stem = f"changes-from-{args.old}"
    (out_dir / f"{stem}.json").write_text(
        json.dumps(diff, indent=1, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n"
    )
    (out_dir / f"{stem}.md").write_text(render_attack_diff(diff), encoding="utf-8", newline="\n")
    for kind, row in diff["kinds"].items():
        print(
            f"{kind}: {row['active_before']} -> {row['active_after']} "
            f"(+{len(row['added'])} / -{len(row['retired'])} / ~{len(row['modified'])})"
        )
    print(f"group profiles changed: {len(diff['group_profile_changes'])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
