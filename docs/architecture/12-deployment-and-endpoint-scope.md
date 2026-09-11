# 12 — Deployment Shape & Endpoint Scope (resolves C0.2)

**Status: C0.2 ACCEPTED (2026-09-11).** Resolves the final-review gate C0.2 — "owner confirms Windows-first
and deployment shape" — with the owner's explicit acceptance recorded in **§A.1 Owner acceptance**. No ADR
created or changed; no application code; no Elastic acquired or configured. Refines (does not alter)
[ADR-0001 D13/D14](adr/0001-evidence-graph-core-architecture.md) and sits under the boundaries in
[04](04-component-boundaries.md) and the data flow in [03](03-system-data-flow.md).

---

## A. C0.2 decision statement (recommended)

Adopt a **hybrid topology**: a **Windows 11 development host** running the **reproducible platform stack in
containers (Docker Compose via Docker Desktop/WSL2)** — Elasticsearch + Kibana + Attribution Engine + API +
render-only frontend — with **Windows endpoint telemetry collected by a *natively-installed* Windows
collector (not containerized)** that ships ECS-normalized events to the containerized Elasticsearch, and with
**synthetic/replayed telemetry entering through the same normalized ingestion path**. Linux endpoints are
**supported architecturally but are not a v1 deliverable**.

This matches the target shape the brief proposed, **with one decisive refinement**: the endpoint collector
must run on the **Windows host**, never inside WSL2 (see §C challenge and §F).

| Dimension | Decision |
|---|---|
| **Primary development environment** | Windows 11 host + Docker Desktop (WSL2 backend) |
| **Primary endpoint/telemetry target** | Windows endpoint (Sysmon + Windows Event Logs; optionally Elastic Defend) |
| **Platform deployment model** | Docker Compose, single-node, on the WSL2/Docker runtime |
| **Endpoint collector placement** | **Native on Windows** (Elastic Agent or Winlogbeat) — *not* in a container |
| **Supported secondary endpoint environments** | Linux endpoints **architecturally** (ECS is OS-agnostic); not shipped in v1 |
| **Production/deployment portability** | The container stack redeploys on Linux/servers unchanged; only the collector is OS-specific |
| **Telemetry-source coupling** | **None at the engine.** Sysmon is a *primary v1 source*, **not** a dependency of the evidence graph or attribution engine (see §D.1) |

**Explicit architectural requirement (owner-mandated):** the platform **must not be architecturally
Sysmon-only**. Sysmon is the richest *first* Windows source, but the Observation/Evidence model and the
Attribution Engine are **telemetry-source-agnostic** — any source that can be normalized to the ECS/domain
contract feeds the *same* pipeline. This is a core architectural property, detailed in **§D.1** and **§D.2**.

---

## A.1 Owner acceptance (2026-09-11)

The owner **explicitly accepted** the following decisions, closing C0.2. These supersede the "recommended /
pending confirmation" language elsewhere in this document (retained for the reasoning that produced them):

1. **Hybrid deployment — ACCEPTED.** Windows-native endpoint telemetry collectors; reproducible platform
   services via **Docker Compose** on the Windows 11 dev environment using Docker Desktop/WSL2 **or an
   equivalent Compose-compatible runtime**. **Elasticsearch, Kibana, Attribution Engine, API, and frontend
   are platform services and must not be forced into native Windows processes.**
2. **Windows-first endpoint scope — ACCEPTED.** Windows is the primary v1 endpoint/telemetry target. **Linux
   remains architecturally supported** through the source-agnostic Observation/Evidence boundary (§D.1/§D.2)
   but is **not a v1 endpoint implementation requirement**.
3. **Resource target — ACCEPTED.** Design and document around **≥16 GB host RAM** as the normal development
   target; **retain the 8 GB constrained/replay-oriented profile** (§I) as a documented fallback.
4. **Safety — ACCEPTED.** **Replay-first** evaluation is the normal path; **any live adversary
   emulation/generation occurs only in a disposable, isolated Windows VM, never on the development host**
   (§J).
5. **Runtime portability — ACCEPTED.** The architecture relies on **Docker Compose / container semantics**,
   **not** a permanent Docker Desktop lock-in; it must remain portable to an equivalent Compose-compatible
   runtime and to later Linux/server deployment (§H).
6. **Telemetry-source agnosticism — ACCEPTED (and not weakened).** Sysmon is a **primary v1 source, not an
   architectural dependency**; Windows Event Logs and future Windows/Linux/network/EDR/cloud/identity sources
   must enter through the **same normalized Observation/Evidence boundary**; **adding a source requires a
   source-specific ingestion/normalization adapter, not Attribution Engine changes** (§D.1/§D.2).

**Architectural-support vs v1-implementation-scope distinction (preserved):** items marked "architecturally
supported" (Linux endpoints; non-Sysmon/non-Windows sources) are **guaranteed by the architecture** — the
source-agnostic boundary and adapter model must accommodate them — but are **explicitly out of v1
implementation scope**. Acceptance of the architecture is **not** a commitment to implement those sources in
v1.

---

## B. Requirements

1. **Windows-first** SOC/endpoint investigation environment; realistic **Windows endpoint telemetry** is a
   first-class source.
2. **Elastic is the telemetry/data plane**; the **Attribution Engine** owns the evidence graph, correlation,
   attack-chain reconstruction, and explainable attribution; the **frontend is render-only**
   ([04](04-component-boundaries.md)).
3. **Reproducible and practical for local dev/demo** on a single machine; no paid Elastic tier
   ([ADR-0001 D14](adr/0001-evidence-graph-core-architecture.md)).
4. **Synthetic telemetry** must enter through the **same normalized ingestion path** as live telemetry (so
   validation/calibration are reproducible — [03](03-system-data-flow.md)).
5. **Containerize where it improves reproducibility**, but **do not** force components into containers where
   that makes endpoint telemetry unrealistic or difficult.
6. **Portability:** the same architecture must be redeployable elsewhere later.

---

## C. Deployment options considered

### Option 1 — Fully Windows-native (no containers)
- ES/Kibana via the Windows ZIP distribution; engine/API/frontend as native Windows processes; collector
  native.
- **Pro:** no WSL2 network boundary — a native Windows agent reaches ES on `localhost` trivially.
- **Con:** **least reproducible** — Elastic's first-class distribution is the **Linux container**; the
  Windows ZIP path is more fragile, harder to pin, and diverges from how the stack will run anywhere else.
  Fails requirement 3's reproducibility intent and portability (6). **Rejected as the platform model.**

### Option 2 — Everything in Docker Desktop/WSL2 (including the collector)
- Platform stack **and** the telemetry collector in containers.
- **Fatal flaw (verified):** **WSL2 has its own network stack and is effectively a separate Linux host**; a
  container in WSL2 **cannot read the Windows host's Event Log/Sysmon channels**. A containerized "Windows
  collector" would collect the *Linux VM's* telemetry, not Windows endpoint telemetry — defeating the whole
  Windows-first premise. **Rejected for the collector.** (The *platform stack* in containers is fine.)

### Option 3 — Hybrid: containerized platform + native Windows collector  ✅
- Platform stack (ES, Kibana, engine, API, frontend) in Docker Compose on WSL2/Docker Desktop; **collector
  native on Windows**, shipping to containerized ES over a reachable address.
- **Pro:** reproducible container stack **and** realistic Windows telemetry; portable (the container stack
  moves to Linux/servers unchanged); matches [ADR-0001 D14](adr/0001-evidence-graph-core-architecture.md).
- **Con:** must handle the **WSL2 network boundary** (collector → ES cannot use `localhost`; bind ES to a
  WSL2-reachable address / use `host.docker.internal` / port-mapping). A known, documentable one-time
  configuration — not a blocker.
- **Recommended.**

### Option 4 — Materially different alternatives (evaluated, not chosen now)
- **Dedicated Windows endpoint VM + Linux platform VM/host:** cleaner isolation (esp. for *generating* live
  attack telemetry safely), and the most production-like separation of endpoint vs platform OS. **Better for
  safety when running live emulation** — retained as the recommended path *if/when* we generate live
  adversary telemetry (see §J), but heavier than needed for day-one dev, so not the default.
- **Elastic Cloud / serverless:** rejected — cost + we standardized on free self-managed
  ([research audit](../research/10-research-audit.md)).

### Challenge to the suggested Docker Desktop/WSL2 shape (as instructed)
The brief's suggested shape is **endorsed for the platform stack**, with these honest caveats:
- **Resource weight (verified):** Elastic recommends **≥8 GB RAM**, and **16 GB is realistic** when running
  ES **and** Kibana together plus our engine; Docker Desktop needs a memory allocation (≥4 GB) and the WSL2
  VM a `.wslconfig` memory setting (≈8 GB). On an 8 GB laptop this is painful → see §I for a constrained
  profile and the "replay-only, Kibana-off" fallback.
- **Container runtime is not sacred:** we depend only on **Docker Compose semantics**, so Docker Desktop is
  **swappable** for **Podman/compose**, **Rancher Desktop**, or the **native Docker engine inside WSL2** if
  Docker Desktop licensing (free for personal/education/small use) or footprint is undesirable. The decision
  is "**Compose stack on a WSL2/Docker runtime**," not "Docker Desktop specifically."
- **Conclusion:** the WSL2/Docker Compose platform stack is appropriate; the only non-negotiable refinement
  is that the **endpoint collector stays native on Windows** (Option 3, not 2).

---

## D. Windows-first scope

- **Primary endpoint OS:** Windows. Primary telemetry: **Sysmon** (process/network/file/registry lineage) +
  **Windows Event Logs** (Security, System, PowerShell, WMI, etc.); optionally **Elastic Defend** for
  kernel-level ECS-mapped host telemetry.
- **Rationale:** richest labeled/attack telemetry and detection content is Windows/endpoint-centric
  ([research 07](../research/07-datasets-and-synthetic-telemetry.md)); aligns with
  [ADR-0001 D13](adr/0001-evidence-graph-core-architecture.md) (Windows/endpoint-first).
- **OS scope is a *detection-content* concern, not a *domain-model* concern:** the evidence graph,
  correlation, attack-chain, and attribution engine operate on the **ECS-normalized contract**, which is
  OS-agnostic. Windows-first therefore constrains *which detection content and datasets we start with*, not
  the architecture.

---

## D.1 Telemetry-source agnosticism (explicit architectural requirement)

**The platform MUST NOT be architecturally Sysmon-only.** This is a hard requirement, not a preference.

1. **Sysmon is a primary v1 Windows telemetry source, but it is NOT a dependency** of the evidence graph or
   the Attribution Engine. Removing Sysmon must never break the engine — it only reduces available Windows
   visibility.
2. **Windows Event Logs and other Windows telemetry sources must feed the *same* normalized
   observation/evidence pipeline** as Sysmon — they are peers, not fallbacks. No source is privileged in the
   domain model.
3. **The normalized `Observation`/`Evidence` model must not depend on Sysmon event IDs or Sysmon-specific
   field names.** Observations reference **ECS/domain fields** (process, user, command line, hashes, network,
   file, registry, etc.) and the ATT&CK techniques they support — never `winlog.event_id == 1`,
   `sysmon.*`, or any collector-native schema. Sysmon specifics live **only** in the source-specific
   normalization adapter, below the domain boundary.
4. **Architectural extension targets** (design must *accommodate* these; v1 need not implement them):
   - Windows Security/System Event Logs (non-Sysmon channels)
   - PowerShell script-block / module logging
   - Microsoft Defender / EDR-style telemetry
   - Linux `auditd` / `journald` / process / network telemetry
   - Network telemetry (e.g., **Zeek**, **Suricata**)
   - Cloud / identity telemetry (e.g., cloud audit logs, identity-provider sign-in/audit events)
5. **These are extension *targets*, not v1 requirements.** v1 ships Windows (Sysmon + Windows Event Logs);
   the list above documents where the seam must remain open — it is **not** a promise to build them, and
   Windows Event Logs are **not** the only intended future source.
6. **Adding a new telemetry source must primarily require a source-specific ingestion/normalization
   adapter** (source → ECS/domain contract) — **not** changes to the Attribution Engine, the evidence graph,
   correlation, attack-chain logic, or the scoring methodology. If adding a source forces engine changes, the
   boundary has been violated and must be corrected.
7. **Synthetic/replayed telemetry must enter through the same normalized observation path where practical**,
   so evaluation and calibration are **not coupled to Sysmon** (or to any single source). A dataset captured
   from Windows Event Logs, auditd, or Zeek must be evaluable through the identical downstream pipeline.

This requirement *strengthens*, and is consistent with, the existing statements that the engine "never knows
or cares" what the source was (§F) and that OS/source scope is a content concern, not a model concern (§D).

## D.2 Telemetry layering model (the six distinct layers)

Attribution reasoning is separated from data acquisition by a strict layering. Each layer has one job; the
**domain boundary** sits between *normalization* and *Observation*, and **nothing above it may reference a
source-native schema**.

| Layer | What it is | Example (v1) | Source-specific? |
|---|---|---|---|
| **1. Telemetry source** | The raw origin of security-relevant events | Sysmon, Windows Security log, PowerShell log, (later) auditd/Zeek/cloud | **Yes** |
| **2. Collector / agent** | The component that acquires source events and forwards them | Elastic Agent or Winlogbeat (native on Windows) | **Yes** |
| **3. Normalization / ECS mapping** | Maps source-native fields → the ECS/domain contract | Elastic ingest pipelines + our thin ECS→domain mapper ([04](04-component-boundaries.md)) | **Yes — this is the ONLY place source specifics live** |
| **── domain boundary ──** | *Below: source-aware. Above: source-agnostic.* | | |
| **4. `Observation`** | A detected fact over normalized events (entities, ECS fields, matched rule, timestamp) | "process X spawned Y on host H" | **No** |
| **5. `Evidence`** | An observation interpreted as bearing on attribution (behavioral/evidentiary/procedural/contextual) → ATT&CK technique assertions | "supports T1055 (with *why*)" | **No** |
| **6. Attribution Engine** | Evidence graph, correlation, attack-chain, ACH, two-axis confidence | ranked hypotheses + explanation | **No** |

**Consequences of the layering:**
- A new source touches **layers 1–3 only** (a new adapter); layers 4–6 are untouched (requirement §D.1.6).
- `Observation`/`Evidence` (layers 4–5) and everything above are defined purely in ECS/domain +
  ATT&CK terms (requirement §D.1.3).
- Synthetic data and live data are indistinguishable at layer 4 and above (requirement §D.1.7) — this is
  what makes evaluation source-agnostic and reproducible ([03](03-system-data-flow.md)).

---

## E. Recommended deployment topology

```
Windows 11 host
├── (native, NOT containerized)
│   └── Endpoint collector: Sysmon + Elastic Agent | Winlogbeat  ──ships ECS──┐
│       (reads Windows Event Log / Sysmon channels directly)                   │
│                                                                              ▼
└── Docker Desktop / WSL2  (Docker Compose, single-node)              [ Elasticsearch ]
        ├── Elasticsearch (single node, security on, modest heap)   ◄──────────┘   ▲
        ├── Kibana (raw-telemetry investigation; deep-link target)                 │
        ├── Attribution Engine (evidence graph, correlation, ACH)  ── reads ───────┘
        ├── API (read-model JSON)                                   (queries ES)
        └── Frontend (render-only; talks to API; deep-links Kibana)

Replay/synthetic path:  labeled dataset ──_bulk──► Elasticsearch  (same downstream pipeline)
```

Network note (the one real gotcha): the **native Windows collector → containerized Elasticsearch** hop
crosses the WSL2 boundary, so Elasticsearch must be bound to an address the Windows host can reach (mapped
port on the WSL2 VM / `host.docker.internal` / the WSL2 IP), **not** container-internal `localhost`. This is
documented once and scripted; it does not affect the replay path (which runs inside the compose network).

---

## F. Endpoint telemetry strategy

- **Collector runs natively on Windows** (decisive per §C). Two acceptable choices, decision deferrable to
  Phase 1:
  - **Elastic Agent + Windows/System integrations (+ optionally Elastic Defend/Fleet):** richest, ECS ingest
    pipelines for Sysmon/PowerShell/Defender/AppLocker out of the box; heavier; Fleet adds a management
    component.
  - **Winlogbeat:** lighter, simpler, ships Windows Event Logs (incl. Sysmon channel) to ES; less turnkey
    enrichment.
  - *Lean:* start with whichever gives the corpus techniques ECS-clean fastest; both keep normalization on
    Elastic's side ([04](04-component-boundaries.md)).
- **Sysmon** is installed on the Windows endpoint with a curated config (e.g., a community modular config) to
  produce high-fidelity process/network/file/registry events; the collector ships that channel.
- Everything lands as **ECS** in Elasticsearch → the extractor turns detections into `Observation`s → the
  normal pipeline. The engine never knows or cares that the source was Windows — **or that it was Sysmon**.
- **Sysmon is one source behind the layer-3 adapter (§D.2), not a dependency (§D.1).** Its event IDs and
  `sysmon.*`/`winlog.*` fields are mapped to ECS/domain at normalization and must not appear in
  `Observation`/`Evidence` or anywhere in the engine. A Windows deployment with Sysmon *disabled* still
  produces observations from Windows Security/PowerShell channels — reduced visibility, not a broken engine.
- **Adding another source = a new layer-1–3 adapter**, not an engine change (§D.1.6): e.g., later wiring
  PowerShell logging, Defender/EDR telemetry, or (secondary) Linux auditd/Zeek means writing/enabling that
  source's normalization to ECS/domain — the extractor, evidence graph, and attribution logic are untouched.

---

## G. Synthetic telemetry strategy

- Synthetic/replayed telemetry (`Security-Datasets`, EVTX fixtures, CALDERA/Atomic captures —
  [research 07](../research/07-datasets-and-synthetic-telemetry.md)) enters via **`_bulk` into the same
  Elasticsearch indices**, then flows through the **identical** detection → extraction → graph → attribution
  pipeline as live telemetry ([03](03-system-data-flow.md)).
- This is the **primary mode for tests, validation, and calibration** because it is deterministic and
  reproducible (pinned dataset content-hash + pinned ATT&CK v19.0); live Windows telemetry is for **realism
  and demo**.
- Because both modes converge immediately after ingestion, a result is reproducible regardless of whether it
  originated live or from replay — the replay path is OS-independent and needs no Windows at all (it can run
  in CI on Linux).
- **Evaluation is not coupled to Sysmon (§D.1.7):** a replayed dataset sourced from Windows Event Logs,
  `auditd`, Zeek, or any other supported source enters through the **same normalized observation path** and
  is scored identically. The golden/scenario corpus may therefore include non-Sysmon and non-Windows cases
  without any engine change — only the relevant layer-3 adapter must exist.

---

## H. Portability / reproducibility

- **Reproducibility:** the platform is a pinned Docker Compose stack; ATT&CK is pinned to v19.0
  ([11](11-attack-knowledge-versioning.md)); datasets are content-hashed; results carry the provenance
  manifest ([03](03-system-data-flow.md)). The **replay path reproduces results with no Windows dependency**
  (CI-friendly).
- **Portability:** the container stack redeploys unchanged on a Linux host/server or another workstation;
  only the **native collector** is OS-specific. Moving to a Linux endpoint later means swapping the collector
  and adding Linux detection content — no architectural change (ECS contract absorbs it).
- **Secondary endpoints (Linux):** supported **architecturally now, operationally later** — the normalized
  contract and engine are OS-agnostic; we simply don't ship Linux detection content/datasets in v1. This is
  the explicit answer to "should Linux be supported architecturally": **yes in the model, no as a v1
  deliverable.**

---

## I. Resource & operational considerations

- **RAM (verified):** ES ≥8 GB recommended; **16 GB host RAM is the comfortable target** with ES + Kibana +
  engine. On **8 GB**: use a **constrained profile** — small ES heap (~1–2 GB), single node, security on,
  ML/monitoring off, and **run Kibana only when needed** (or rely on the replay path with Kibana stopped).
- **Docker/WSL2:** allocate Docker Desktop ≥4 GB and set `.wslconfig` memory (≈8 GB); cap ES container
  memory explicitly.
- **Single-node, dev-grade:** no HA, no multi-node — matches [ADR-0001 D14](adr/0001-evidence-graph-core-architecture.md).
- **Runtime swappability:** Docker Desktop ↔ Rancher/Podman/native-WSL2-engine (§C), since we only use
  Compose.

## J. Security / isolation considerations

- **Elastic security ON even in dev** (auth + TLS); do not run an open ES on the WSL2 network boundary.
- **Live adversary emulation (CALDERA/Atomic) must NOT run on the primary dev host** — it executes real
  (benign-but-real) attack behaviors. Generating **live** attack telemetry requires a **disposable, isolated
  Windows VM/endpoint** (Option 4's endpoint VM). **Replaying** pre-recorded datasets on the host is safe;
  **generating** is not. This is the main safety line for this project.
- Treat vendored datasets/EVTX as **inert data**; never execute samples.
- The WSL2↔Windows exposure surface (the mapped ES port) should be bound minimally and authenticated.

## K. Explicit non-goals

- No multi-node/HA/production cluster; no cloud/serverless; no paid Elastic tier.
- No containerized Windows endpoint collector (architecturally wrong — §C).
- No Mobile/ICS ATT&CK domains; no Linux **detection content/datasets** in v1 (Linux stays
  architecture-only).
- No live adversary emulation on the primary dev host (§J).
- No production portability *hardening* now (portability is preserved by design, not engineered in v1).

## L. Open questions

**All C0.2-level decisions are now CLOSED** by the owner acceptance in §A.1 (hybrid shape, Windows-first /
Linux-architecture-only, resource target, safety rule, runtime portability, source-agnosticism). The
following remain purely **Phase-1 / operational** choices — none gates C0.2 or Phase 0:

- ✅ **Container-runtime latitude — resolved architecturally** (§A.1.5): the design targets Compose
  semantics, not Docker Desktop. The *specific* runtime pick (Docker Desktop vs Podman/Rancher/native WSL2
  engine) is an owner preference to make at setup — not an architectural constraint.
- ⏳ **Collector choice (Elastic Agent+Fleet vs Winlogbeat)** — Phase-1 operational; decided by which gets
  the corpus techniques ECS-clean with least overhead. *(Constrained by §D.1: whichever is chosen, source
  specifics stay in the layer-3 adapter.)*
- ⏳ **Dedicated Windows endpoint VM vs dev host** — only material when moving from *replay* to
  *live/generated* telemetry (§J); replay-first defers it. Not a C0.2 item.

## M. C0.2 acceptance criteria — ALL MET (2026-09-11)

C0.2 required the owner to confirm the following; **all five are now explicitly accepted (§A.1):**

1. ✅ **Hybrid topology** (containerized platform stack + **native Windows collector**), i.e. Option 3 over
   Options 1/2.
2. ✅ **Windows-first endpoint scope**, with **Linux architecture-only** (not a v1 deliverable).
3. ✅ **Host resources:** **≥16 GB RAM** normal target, with the **constrained 8 GB profile** (§I) retained
   as fallback.
4. ✅ **Live-emulation safety rule:** generation only on an isolated VM; the host uses **replay-first**.
5. ✅ **Container-runtime latitude:** "Compose on a WSL2/Docker(-compatible) runtime," specific runtime an
   owner preference.

Items in §L (collector choice, dedicated endpoint VM timing, runtime pick) may remain open at acceptance —
they are Phase-1/operational choices, not C0.2 blockers.

**Recorded architectural requirement (not an open decision):** telemetry-source agnosticism (§D.1/§D.2) is
now an **explicit, owner-mandated architectural requirement** — the platform is not Sysmon-only, and adding a
source is an adapter, not an engine change. This is a constraint the design must uphold from Phase 0 onward;
it is not something to re-confirm as a deployment choice.

---

## Source-agnosticity clarification — change log

Added on owner requirement: **the platform must not be architecturally Sysmon-only.**
- §A: added a "telemetry-source coupling = none at engine" row + an explicit architectural-requirement
  callout.
- **New §D.1** (Telemetry-source agnosticism): the seven required statements — Sysmon is a primary v1 source
  but not an engine dependency; Windows Event Logs and other sources are peers on the same pipeline;
  `Observation`/`Evidence` must not reference Sysmon event IDs/fields; the extension-target list (Windows
  Security/System logs, PowerShell logging, Defender/EDR, Linux auditd/journald, Zeek/Suricata,
  cloud/identity) as *targets not v1 requirements*; adding a source = an adapter, not an engine change;
  synthetic/replay uses the same normalized observation path.
- **New §D.2** (Telemetry layering model): the six explicit layers — **telemetry source → collector/agent →
  normalization/ECS mapping → Observation → Evidence → Attribution Engine** — with the domain boundary drawn
  between normalization and Observation (source specifics live *only* below it).
- §F and §G: reinforced non-dependency on Sysmon and source-agnostic evaluation.
- §M: recorded source-agnosticism as an accepted architectural requirement (not an open deployment decision).
- **Unchanged:** the hybrid deployment recommendation, resource guidance, isolation rules, and non-goals.

## C0.2 STATUS: ACCEPTED (2026-09-11)

All five owner confirmations are recorded and accepted (§A.1, §M): hybrid deployment (containerized platform
services + native Windows collector); Windows-first with Linux architecture-only for v1; ≥16 GB normal /
8 GB constrained profile; replay-first with live emulation only on an isolated VM; Compose/runtime
portability with no Docker Desktop lock-in. Telemetry-source agnosticism (§D.1/§D.2) is an accepted,
un-weakened architectural requirement. The architectural-support-vs-v1-scope distinction is preserved
(Linux/other sources are guaranteed by the architecture, out of v1 implementation scope).

Remaining items (§L) are **Phase-1/operational** (collector choice; dedicated endpoint VM timing; specific
container-runtime pick) and do **not** gate C0.2 or Phase 0.

*No ADR created or changed. No application code. No Elastic acquired/configured. No datasets acquired. ATT&CK
bundle not vendored. Phase 0 not started.*
