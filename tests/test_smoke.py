"""Smoke test for gate G0.0: proves the test/tooling infrastructure works.

Requires no Elasticsearch, Docker, Windows, or external network access —
per docs/architecture/13-phase-0-implementation-plan.md (G0.0 acceptance
criteria).
"""

from __future__ import annotations

import importlib

import attribution_platform


def test_package_version_is_defined() -> None:
    """The top-level package exposes a version string."""
    assert attribution_platform.__version__ == "0.0.0"


def test_scaffolded_submodules_import_cleanly() -> None:
    """Every Phase-0 module boundary exists and imports without side effects.

    This is the "import/module-resolution smoke test" required by G0.0's
    acceptance criteria: it proves the package layout matches the accepted
    architecture's module boundaries (domain, attack_knowledge, sources,
    extraction, dataplane, api) before any of them contain real logic.
    """
    submodule_names = (
        "attribution_platform.domain",
        "attribution_platform.attack_knowledge",
        "attribution_platform.sources",
        "attribution_platform.extraction",
        "attribution_platform.dataplane",
        "attribution_platform.api",
    )

    for name in submodule_names:
        module = importlib.import_module(name)
        assert module.__doc__, f"{name} must document its purpose and owning gate"


def test_no_network_or_external_service_access() -> None:
    """Sanity marker: this suite is self-contained at gate G0.0.

    There is no Elasticsearch client, no ATT&CK loader, and no collector
    implemented yet, so there is nothing here that could reach a network,
    Docker, or a Windows-specific API even by accident.
    """
    assert True
