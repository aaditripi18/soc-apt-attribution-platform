"""Manual entrypoint: run the read-model API against a real Elasticsearch.

Not exercised by the automated test suite (it needs a live cluster and calls
``serve_forever()``) — a small, optional convenience so a human can actually
try the two G0.10 endpoints once Docker/Elasticsearch (G0.7) is running,
satisfying doc 13 G0.10's acceptance criterion that the read model is
"serveable", not just unit-tested. Every environment variable defaults to
match ``docker-compose.yml``/``.env.example`` (G0.7).

    python -m attribution_platform.api

Environment variables:
  ELASTICSEARCH_URL      default "https://localhost:9200"
  ELASTIC_USERNAME       default "elastic"
  ELASTIC_PASSWORD       required (no default — refuses to start without it)
  ELASTICSEARCH_CA_CERT  optional path to the CA cert G0.7's ``setup``
                         container generates; omit only for a throwaway
                         experiment (see ElasticsearchHttpClient's own
                         ``verify_tls`` docs for why that is insecure)
  API_HOST               default "127.0.0.1"
  API_PORT               default "8000"
"""

from __future__ import annotations

import os
import sys

from attribution_platform.api.server import create_server
from attribution_platform.dataplane import ElasticsearchHttpClient


def main(env: dict[str, str] | None = None) -> int:
    env = env if env is not None else dict(os.environ)

    password = env.get("ELASTIC_PASSWORD")
    if not password:
        print("ELASTIC_PASSWORD must be set to run the read-model API.", file=sys.stderr)
        return 1

    client = ElasticsearchHttpClient(
        env.get("ELASTICSEARCH_URL", "https://localhost:9200"),
        username=env.get("ELASTIC_USERNAME", "elastic"),
        password=password,
        ca_cert_path=env.get("ELASTICSEARCH_CA_CERT"),
    )
    host = env.get("API_HOST", "127.0.0.1")
    port = int(env.get("API_PORT", "8000"))

    server = create_server(client, host=host, port=port)
    print(f"Serving the read-model API on http://{host}:{port} (Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
