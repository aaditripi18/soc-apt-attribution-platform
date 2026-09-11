# SOC APT Attribution Platform

A personal cybersecurity research and portfolio project: an end-to-end system that
analyzes security telemetry, maps evidence to MITRE ATT&CK techniques, correlates
related activity, reconstructs attack chains, and performs **explainable,
evidence-based APT attribution**. See [CLAUDE.md](CLAUDE.md) for the project's
governing principles.

## Project status

The project has completed research and architecture design and is in
**Phase 0 (foundation implementation)**. Repository scaffolding (G0.0), the
pinned ATT&CK v19.0 artifact (G0.1), and a deterministic runtime loader for
it (G0.2, implemented, awaiting review — not yet checkpointed) are in place;
there is no Elastic integration, no domain contracts, no API, and no
frontend yet.

- **Architecture (accepted):** [docs/architecture/](docs/architecture/README.md) —
  see ADR-0001 (Evidence-Graph Core), ADR-0002 (Attribution Scoring & Evidence
  Methodology), and the accepted Phase-0 gates C0.1 (ATT&CK v19.0 versioning) and
  C0.2 (deployment & endpoint scope).
- **Research:** [docs/research/](docs/research/README.md).
- **Implementation plan:** [docs/architecture/13-phase-0-implementation-plan.md](docs/architecture/13-phase-0-implementation-plan.md) —
  the gate-by-gate roadmap this repository structure follows.

## Repository structure

```
src/attribution_platform/
  domain/            core contracts (Observation, Evidence, TechniqueAssertion,
                      provenance) — source-agnostic; implemented in gate G0.3
  attack_knowledge/  pinned MITRE ATT&CK STIX loading & access — G0.1/G0.2
  sources/           telemetry-source adapters (Sysmon, Windows Event Logs,
                      synthetic/replay, ...) — G0.4
  extraction/        detection-match -> Observation boundary — G0.5
  dataplane/         Elasticsearch client & persistence — G0.7/G0.8
  api/               read-model API (serves data, computes nothing) — G0.10
tests/               pytest suite (no Elastic/Docker/Windows/network required)
fixtures/            hand-authored synthetic telemetry fixtures (added from G0.4)
data/attack/enterprise/v19.0/
                     vendored, hash-verified MITRE ATT&CK v19.0 STIX 2.1
                     bundle + acquisition manifest + attribution NOTICE — G0.1
docs/                research and architecture documentation
```

Every submodule's `__init__.py` docstring names the Phase-0 gate that
implements it. Nothing above `domain/` may depend on a specific telemetry
source, collector, or Elastic API — see
[docs/architecture/12-deployment-and-endpoint-scope.md](docs/architecture/12-deployment-and-endpoint-scope.md)
(§D.1/§D.2) for the enforced layering.

## Local development setup

Requires **Python 3.12** (matches `requires-python` in `pyproject.toml`).

```bash
python -m venv .venv
# Windows (PowerShell): .venv\Scripts\Activate.ps1
# Windows (Git Bash) / macOS / Linux:
source .venv/Scripts/activate   # or .venv/bin/activate on macOS/Linux

pip install -e ".[dev]"
```

This installs the package in editable mode plus the pinned dev toolchain:
[ruff](https://docs.astral.sh/ruff/) (formatting + linting), [mypy](https://mypy-lang.org/)
(type checking), and [pytest](https://docs.pytest.org/) (tests). No other
runtime dependencies exist at this stage (see the comment in `pyproject.toml`).

## Commands

| Task | Command |
|---|---|
| Format check | `ruff format --check .` |
| Format (apply) | `ruff format .` |
| Lint | `ruff check .` |
| Lint (autofix) | `ruff check --fix .` |
| Type check | `mypy` |
| Run tests | `pytest` |
| Run everything CI runs | `ruff format --check . && ruff check . && mypy && pytest` |

All of the above run **without** Elasticsearch, Docker, Windows-specific
APIs, or external network access at this gate — that is a deliberate,
tested property of Phase 0 (see `tests/test_smoke.py`).

> **Windows + Git Bash note:** the pip-installed `mypy`/`pytest`/`ruff`
> launcher scripts in `.venv/Scripts/` can occasionally fail in Git Bash with
> `Permission denied` (an MSYS/launcher quirk, not a project issue). If that
> happens, run the module form instead: `python -m mypy`, `python -m pytest`.
> PowerShell and CI (Linux) are unaffected.

## Continuous integration

[`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs on every push and
pull request: `ruff format --check`, `ruff check`, `mypy`, then `pytest`, on
`ubuntu-latest` with the pinned Python 3.12. CI runs on Linux even though the
primary development target is Windows 11 ([C0.2](docs/architecture/12-deployment-and-endpoint-scope.md)):
at this gate the codebase has no OS-specific logic, so the simplest portable
runner is used. Windows-specific behavior (the native endpoint collector)
arrives in gate G0.11 and will be verified separately, not by this CI job.

## MITRE ATT&CK® attribution

This project uses MITRE ATT&CK® data (Enterprise **v19.0**, pinned and
vendored under [`data/attack/enterprise/v19.0/`](data/attack/enterprise/v19.0/))
under the [ATT&CK Terms of Use](https://attack.mitre.org/resources/terms-of-use/).
MITRE ATT&CK and ATT&CK are registered trademarks of The MITRE Corporation.
See [`data/attack/enterprise/v19.0/NOTICE.md`](data/attack/enterprise/v19.0/NOTICE.md)
for the full attribution statement and acquisition record.

## Configuration

No environment configuration exists yet — there is nothing to connect to
(no Elasticsearch, no external services). A `.env.example` will be added
once a gate actually requires configuration (starting around G0.7/G0.8).
