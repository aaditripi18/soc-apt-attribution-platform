# 06 — SOC Investigation Platforms & APT Attribution Tools/Research

Covers requested areas 16–17: open-source SOC investigation platforms, and open-source APT attribution
tools & research implementations.

> All verdicts are candidates for architectural review, not decisions.

---

## Summary opinion (design opinion)

**No existing open-source tool does explainable, evidence-based APT attribution** the way this project
intends. SOC platforms (TheHive/Cortex/Wazuh/Velociraptor/Shuffle) cover **case management, endpoint
DFIR, enrichment, and orchestration** — worth studying and selectively reusing, but they are **not**
attribution engines. The academic work has the right *ideas* (TTP-sequenced, kill-chain-ordered
attribution; explainability as an open gap) but ships as papers/prototypes, not production dependencies.
This confirms the opportunity: **combine mature substrate (Elastic + ATT&CK + Sigma + feeds) with our own
explainable attribution reasoning.**

---

## Open-source SOC investigation platforms

### Cortex (TheHive Project / StrangeBee)
- **What it does:** Observable **analysis/enrichment** engine — submit IPs/hashes/domains to hundreds of
  **analyzers**, get structured results.
- **License (fact):** **AGPLv3** (still open).
- **Verdict:** **Study / optional Integrate** as a ready-made **enrichment backend** ([04](04-threat-intel-and-ioc.md))
  — reuse analyzers instead of hand-writing feed clients.
- **Risks:** AGPL; pulls in the TheHive orbit (see license caution below).

### TheHive
- **What it does:** SOC **case management / incident response** collaboration.
- **License (fact — caution):** **TheHive 5 is commercially licensed** by StrangeBee — after a trial it
  goes **read-only without a paid license**. (Older TheHive 4 was AGPL but is EOL.)
- **Verdict:** **Avoid as a dependency.** Study its case/observable data model for our own investigation
  workspace ([frontend, later]); do not build on a tool that degrades to read-only.

### Wazuh
- **What it does:** Open **XDR/SIEM** — endpoint agents, detection ruleset, FIM, log analysis; ships its
  own **wazuh-indexer** (an **OpenSearch fork**, Apache-2.0) and dashboard.
- **License (fact):** Core **GPLv2**; indexer/dashboard on Apache-2.0 OpenSearch; no stated plan to
  commercialize.
- **Verdict:** **Study** (and possibly use as an **agent/telemetry source** in a lab). Overlaps Elastic;
  choosing both would be redundant. If we standardize on **Elastic**, Wazuh is mainly a **study reference
  and an alternative agent** — not a core dependency.
- **Risks:** Direct duplication of the Elastic backbone; running both is wasteful.

### Velociraptor
- **What it does:** Endpoint **DFIR / live hunting** at scale via its **VQL** query language; excellent
  for collecting rich host artifacts and triggered collections.
- **License (VERIFIED 2026-09):** **AGPL-3.0** (repo `Velocidex/velociraptor`, actively developed, frequent
  releases). (Earlier note about a Rapid7 acquisition is **not confirmed from the repo** — drop it as a
  claim; ownership is immaterial to the AGPL terms either way.)
- **Verdict:** **Study / optional Integrate** as a **high-fidelity host-evidence collector** feeding our
  observation layer in a lab; strong "traceable telemetry path" story.
- **Risks:** AGPL; agent deployment overhead; ownership/licensing continuity **(verify).**

### Shuffle (SOAR)
- **What it does:** Open-source **orchestration/automation** (workflows across Wazuh, VirusTotal, MISP,
  Slack, firewalls, etc.).
- **License (VERIFIED 2026-09):** **backend AGPL-3.0**; **workflows, apps, App SDK, docs, and spec are
  MIT** (so automation content we build/share is permissively licensed even though the engine is AGPL).
- **Verdict:** **Study / optional (later).** Useful if we ever want to orchestrate enrichment/response,
  but **not** on the attribution correctness path and not needed early.

### Adjacent: MITRE CALDERA (adversary emulation)
- **What it does:** Automated **adversary emulation** built on ATT&CK (C2 server, agents, ability plugins,
  emulation plans) — generates realistic attack activity.
- **License (fact):** **Apache-2.0** (now `apache/caldera`).
- **Verdict:** **Study / Integrate for data generation** — a controlled way to produce ATT&CK-labeled
  telemetry for validating our detection→technique→attribution pipeline ([07](07-datasets-and-synthetic-telemetry.md)).
- **Risks:** Running C2/emulation safely requires an isolated lab; treat as offline data generation only.

## APT attribution tools & research implementations

- **General finding:** open-source, production-grade, **explainable** APT attribution engines are
  essentially **absent**. What exists is (a) IOC/actor *knowledge* (ATT&CK, OpenCTI, MISP), (b) opaque or
  vendor attribution (Elastic Attack Discovery), and (c) **research prototypes**.

### Research worth studying (Study — method inspiration, not dependencies)
- **"A Comprehensive Survey of APT Attribution" (arXiv 2409.11415, 2024)** — the anchor reference.
  Key takeaways to bake into our design:
  - Attribution artifacts split into **evidentiary** (IOCs, C2 infra — *more manipulable*) vs
    **behavioral** (**TTPs — more robust**); **TTPs are the most-used feature (~28%)** in the literature.
  - Automated attribution leans on ML (Decision Trees / Random Forest common), but **explainability is a
    recognized gap** — some works add **LIME**. This validates our explainability-first stance.
- **"Chasing the Shadows / CAPTAIN" (arXiv 2409.16400, 2024)** — attribute via **TTP extraction** then
  **kill-chain TTP sequencing**; higher-order behavior is **harder to disguise** → better attribution
  basis. Directly supports our tactic-ordered attack-chain + TTP-weighted attribution design.
- **Provenance-graph line of work** — see [05](05-correlation-graph-attack-chain.md).

### Design implications (opinion)
1. **Weight behavioral (TTP) evidence above evidentiary (IOC) evidence**, and represent IOCs as
   *corroborating/contradicting*, never decisive.
2. **Explainability is the moat.** Every hypothesis must show supporting **and** contradicting evidence,
   discriminating-technique weighting, and residual uncertainty ([08](08-attribution-methodology-foundations.md)).
3. **Prefer deterministic, testable logic**; keep any ML strictly optional and interpretable.
4. **Support competing hypotheses** — never force a single actor label; model false-flag/aliasing risk
   explicitly.

---

## Open questions for architectural review

1. Which SOC components (if any) do we actually **run** vs. only **study**? (Leaning: Cortex *maybe* for
   enrichment; CALDERA + datasets for validation; **avoid TheHive 5**; Wazuh/Velociraptor as study/lab
   only if not redundant with Elastic.)
2. Do we implement a **from-scratch explainable attribution engine** (recommended, it's the point of the
   project) and use research only as inspiration?
3. What is our **evaluation methodology** to prove the engine works (labeled datasets, known-actor
   scenarios) — so we never regress into hard-coded/simulated results?

## Sources

- [Cortex](https://github.com/TheHive-Project/Cortex) · TheHive 5 licensing —
  [MISP vs OpenCTI / SOC stack notes](https://www.cosive.com/misp-vs-opencti) ·
  [Wazuh indexer (OpenSearch fork)](https://github.com/wazuh/wazuh-indexer)
- [apache/caldera](https://github.com/apache/caldera)
- [APT Attribution Survey (arXiv 2409.11415)](https://arxiv.org/abs/2409.11415) ·
  [Chasing the Shadows / CAPTAIN (arXiv 2409.16400)](https://arxiv.org/pdf/2409.16400)
