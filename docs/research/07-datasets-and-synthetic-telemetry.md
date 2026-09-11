# 07 — Datasets & Synthetic Telemetry

Covers requested area 18: security telemetry datasets and synthetic-data projects.

> All verdicts are candidates for architectural review, not decisions.

---

## Summary opinion (design opinion)

**Reproducible, ATT&CK-labeled data is the single most important enabler for avoiding the previous
version's failures.** Hard-coded/simulated results happen when there is no ground truth to validate
against. We should assemble a **small, versioned corpus** of ATT&CK-labeled telemetry (replayed datasets +
CALDERA-generated activity) and treat it as the **test/validation substrate** for every capability:
detection→technique mapping, correlation, attack-chain reconstruction, and attribution.

A useful distinction (fact): **Atomic Red Team / CALDERA generate activity**; **Mordor / OTRF
Security-Datasets capture the resulting telemetry**. We want both roles.

---

## Pre-recorded, ATT&CK-labeled telemetry (replay)

### OTRF **Security-Datasets** (formerly **Mordor**)
- **What it does:** Pre-recorded security events (JSON, sometimes PCAP) from simulated/real techniques,
  **categorized by platform, adversary group, and ATT&CK tactic/technique**; community-mapped to Sigma,
  Atomic Red Team, and hunting notebooks.
- **Maturity/Maintenance (VERIFIED 2026-09):** Established community resource (~815 commits, some open
  issues/PRs); like several OTRF repos its cadence has **slowed** — treat as a **stable corpus**, not a
  fast-moving project. Pin the datasets we use.
- **License (VERIFIED 2026-09 — corrected):** **MIT** (the `LICENSE` file is MIT; an earlier "GPL family"
  guess was wrong — a stray GPL-3.0 string appears elsewhere on the repo page but the license file is MIT).
- **Elastic/ATT&CK fit:** Excellent — replay into Elastic; labels align to ATT&CK.
- **Verdict:** **Integrate** as a core **validation corpus** (candidate). Pin the specific datasets we use.
- **Risks:** Coverage is uneven across techniques; maintenance cadence — **verify.**

### EVTX sample collections
- **`sbousseaden/EVTX-ATTACK-SAMPLES`** and **`mdecrevoisier/EVTX-to-MITRE-Attack` (270+ samples)** —
  Windows event-log (EVTX) samples mapped to ATT&CK tactics/techniques; good for measuring detection
  coverage and building technique-labeled fixtures.
- **License (VERIFIED 2026-09):** `sbousseaden/EVTX-ATTACK-SAMPLES` is **GPL-3.0** (has a `LICENSE.GPL`) —
  so it *is* licensed, but GPL copyleft applies; using the EVTX files as **local test fixtures** is fine,
  but bundling/redistributing them (or derivatives) inherits GPL obligations. `mdecrevoisier/EVTX-to-MITRE-Attack`
  license still **(verify per repo).**
- **Verdict:** **Study / Integrate as local read-only fixtures** (candidate); keep them out of any
  redistributed artifact unless the GPL obligation is acceptable.

## Activity generators (produce telemetry on demand)

### Atomic Red Team (Red Canary)
- **What it does:** Library of small, portable **tests mapped to ATT&CK** — reproducibly execute a
  technique to generate its telemetry.
- **License (fact):** **MIT** (permissive).
- **Verdict:** **Integrate for data generation** in an isolated lab (candidate) — cheap, precise,
  per-technique labeled telemetry.
- **Risks:** Executes real (benign) attack behaviors — **lab isolation required.**

### MITRE CALDERA
- See [06](06-soc-and-attribution-tools.md). **Apache-2.0.** Generates **multi-step, ATT&CK-sequenced**
  activity — ideal for exercising **attack-chain reconstruction and attribution**, not just single-technique
  detection. **Integrate for scenario generation** in a lab (candidate).

## Larger / academic datasets (Study)

- **Splunk `attack_data` / Boss of the SOC (BOTS)** — curated attack datasets/scenarios; **Study** and
  selectively replay **(verify license/usage terms).**
- **DARPA Transparent Computing (TC)** — host **provenance** datasets used widely in APT provenance
  research; **Study** if we pursue provenance-graph reconstruction ([05](05-correlation-graph-attack-chain.md)).
  Large and research-oriented.
- **CIC (UNB) / other academic network datasets** — mostly network-flow/IDS oriented; **Study** for
  network evidence, lower priority than host/ATT&CK-labeled telemetry.

---

## Proposed validation strategy (design opinion, for review)

1. **Golden corpus:** a pinned set of ATT&CK-labeled datasets (OTRF/Security-Datasets + a few EVTX
   fixtures) with known techniques → deterministic **ground truth** for detection→technique tests.
2. **Scenario corpus:** a handful of **CALDERA/Atomic** multi-step scenarios with known tactic ordering →
   ground truth for **attack-chain reconstruction**.
3. **Attribution scenarios:** scenarios emulating **known ATT&CK Groups' TTP sets** → evaluate whether the
   engine ranks the true actor highly *and explains why*, and whether it correctly expresses **uncertainty**
   and **competing hypotheses** when TTPs are ambiguous or point to multiple groups.
4. Everything **versioned and reproducible**; no capability is "done" until it passes against this corpus.
   This is the concrete guardrail against hard-coded/simulated results.

## Open questions for architectural review

1. What is the **minimum viable golden corpus** (which datasets, which techniques) for the first
   detection→technique milestone?
2. Do we build a small, **isolated lab** (VMs/containers + Elastic) to run Atomic/CALDERA, or rely purely
   on **replayed** pre-recorded datasets initially? (Leaning: replay first for zero-risk reproducibility;
   add a lab when we need scenarios not covered by existing data.)
3. Which sample repos clear the **license bar** for anything we might redistribute vs. use only locally?

## Sources

- [OTRF/Security-Datasets](https://github.com/OTRF/Security-Datasets) ·
  [mdecrevoisier/EVTX-to-MITRE-Attack](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack)
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) ·
  [apache/caldera](https://github.com/apache/caldera)
- [Splunk attack_data](https://github.com/splunk/attack_data)
