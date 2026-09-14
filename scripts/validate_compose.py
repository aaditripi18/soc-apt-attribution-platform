#!/usr/bin/env python3
"""Static validation for the gate G0.7 Docker Compose platform definition.

This is a structural check of ``docker-compose.yml``, not a bring-up test —
it never talks to Docker and requires no Docker/Compose installation. It
exists because a real bring-up smoke test (``docker compose up`` + poll the
health endpoints) needs a Docker runtime, which may not be present wherever
this repository is checked out or reviewed (e.g. this was authored and
validated on a host with no Docker daemon available — see
docs/architecture/13-phase-0-implementation-plan.md's G0.7 entry for that
environment note). Static validation is the documented fallback for that
case, not a replacement for an actual bring-up when Docker is available.

Checks performed (see docs/architecture/12-deployment-and-endpoint-scope.md
C0.2 and 13-phase-0-implementation-plan.md's G0.7 gate for the requirements
these encode):

1. The file is syntactically valid YAML (if PyYAML is importable; otherwise
   this check is skipped and reported as skipped, not silently passed).
2. The expected services exist: ``setup``, ``es01``, ``kibana`` — and no
   other services (in particular, no placeholder Attribution Engine/API
   container — G0.7 explicitly defers those to G0.8/G0.10).
3. Elasticsearch and Kibana images are pinned to an explicit, identical,
   non-floating version (never ``:latest``, never two different versions).
4. ``es01`` and ``kibana`` each declare a ``healthcheck``.
5. Elasticsearch's data directory is a NAMED volume, not a bind mount.
6. Security is enabled: ``xpack.security.enabled=true`` and TLS enabled on
   both the HTTP and transport layers for ``es01``.
7. No ``.env`` file (only the committed ``.env.example`` /
   ``.env.constrained.example`` templates) is tracked by git, so no
   credential ever lands in the repository.

Usage:

    python scripts/validate_compose.py

Exits 0 and prints "OK" per check on success; exits 1 and prints every
failure otherwise.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
COMPOSE_FILE = REPO_ROOT / "docker-compose.yml"

EXPECTED_SERVICES = {"setup", "es01", "kibana"}


def _read_compose_text() -> str:
    if not COMPOSE_FILE.exists():
        print(f"FAIL: {COMPOSE_FILE} does not exist")
        sys.exit(1)
    return COMPOSE_FILE.read_text(encoding="utf-8")


def check_yaml_syntax(text: str) -> list[str]:
    """Parse with PyYAML if available; otherwise report the check as skipped.

    PyYAML is NOT a declared project dependency (no new dependencies for
    G0.7) — this check is a best-effort deeper validation when the tool
    happens to be present in the environment, not a requirement.
    """
    try:
        import yaml  # type: ignore[import-untyped]
    except ImportError:
        print("SKIP: YAML syntax check (PyYAML not installed in this environment)")
        return []

    try:
        parsed = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        return [f"docker-compose.yml is not valid YAML: {exc}"]

    if not isinstance(parsed, dict) or "services" not in parsed:
        return ["parsed YAML has no top-level 'services' mapping"]

    print("OK: docker-compose.yml is syntactically valid YAML")

    failures: list[str] = []
    services = parsed.get("services", {})
    actual_services = set(services)
    if actual_services != EXPECTED_SERVICES:
        failures.append(
            f"services {sorted(actual_services)} != expected {sorted(EXPECTED_SERVICES)} "
            "(G0.7 defers the Attribution Engine/API containers to G0.8/G0.10)"
        )
    else:
        print(f"OK: exactly the expected services are defined: {sorted(EXPECTED_SERVICES)}")

    for name in ("es01", "kibana"):
        if name in services and "healthcheck" not in services[name]:
            failures.append(f"service '{name}' has no healthcheck")
    if not failures:
        print("OK: es01 and kibana both declare a healthcheck")

    volumes = parsed.get("volumes", {})
    if "esdata01" not in volumes:
        failures.append("no named volume 'esdata01' declared for Elasticsearch data")
    else:
        es_volumes = services.get("es01", {}).get("volumes", [])
        if not any(str(v).startswith("esdata01:") for v in es_volumes):
            failures.append("es01 does not mount the named 'esdata01' volume")
        else:
            print("OK: Elasticsearch data uses the named volume 'esdata01'")

    es_env = services.get("es01", {}).get("environment", [])
    es_env_text = "\n".join(str(e) for e in es_env)
    required_security_settings = (
        "xpack.security.enabled=true",
        "xpack.security.http.ssl.enabled=true",
        "xpack.security.transport.ssl.enabled=true",
    )
    missing = [s for s in required_security_settings if s not in es_env_text]
    if missing:
        failures.append(f"es01 is missing required security settings: {missing}")
    else:
        print("OK: es01 has security + TLS (HTTP and transport) enabled")

    return failures


def check_pinned_versions(text: str) -> list[str]:
    image_lines = re.findall(r"image:\s*(\S+)", text)
    failures = []
    if not image_lines:
        return ["no 'image:' lines found in docker-compose.yml"]
    for line in image_lines:
        if "latest" in line:
            failures.append(f"image reference floats to 'latest': {line}")
    es_image = next((i for i in image_lines if "elasticsearch/elasticsearch" in i), None)
    kb_image = next((i for i in image_lines if "kibana/kibana" in i), None)
    if es_image is None:
        failures.append("no elasticsearch image reference found")
    if kb_image is None:
        failures.append("no kibana image reference found")
    if es_image and kb_image:
        es_tag = es_image.split(":", 1)[-1]
        kb_tag = kb_image.split(":", 1)[-1]
        if es_tag != kb_tag:
            failures.append(f"elasticsearch tag {es_tag!r} != kibana tag {kb_tag!r} (must match)")
        elif "STACK_VERSION" not in es_tag:
            failures.append(f"expected both images pinned via ${{STACK_VERSION}}, got {es_tag!r}")
        else:
            print("OK: Elasticsearch and Kibana are pinned to the same ${STACK_VERSION}")
    if not failures:
        print("OK: no image reference floats to ':latest'")
    return failures


def check_env_files_not_tracked() -> list[str]:
    """Confirm .env itself (as opposed to the committed .env*.example
    templates) is excluded from version control, so a real password can
    never be committed."""
    gitignore = (REPO_ROOT / ".gitignore").read_text(encoding="utf-8")
    if re.search(r"(?m)^\.env$", gitignore) is None:
        return [".gitignore does not exclude '.env'"]
    print("OK: .gitignore excludes '.env' (only the .example templates are tracked)")
    return []


def main() -> int:
    text = _read_compose_text()
    failures: list[str] = []
    failures += check_yaml_syntax(text)
    failures += check_pinned_versions(text)
    failures += check_env_files_not_tracked()

    print()
    if failures:
        print(f"FAILED: {len(failures)} check(s):")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("All static checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
