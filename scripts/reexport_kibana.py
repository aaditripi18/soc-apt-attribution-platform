"""Re-write the Kibana chart documents of every investigation stored in the
configured Elasticsearch (ADR-0024) - after the export format changes, without
re-running the investigations. Environment: as ``--elasticsearch``."""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from attribution_platform.api.__main__ import elasticsearch_client_from_env  # noqa: E402
from attribution_platform.api.context import ApiContext, build_technique_catalogue  # noqa: E402
from attribution_platform.api.kibana_export import export_investigation  # noqa: E402
from attribution_platform.api.read_model import list_investigation_summaries  # noqa: E402
from attribution_platform.attack_knowledge.loader import load_attack_knowledge  # noqa: E402


def main() -> int:
    client = elasticsearch_client_from_env(dict(os.environ))
    if client is None:
        print("ELASTIC_PASSWORD must be set.", file=sys.stderr)
        return 1
    knowledge = load_attack_knowledge()
    context = ApiContext(knowledge=knowledge, techniques=build_technique_catalogue(knowledge))
    for summary in list_investigation_summaries(client):
        counts = export_investigation(client, context, str(summary["investigation_id"]))
        print(f"{summary['source_id']}: {counts}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
