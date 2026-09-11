# 03 — Detection Engineering (Sigma & ecosystem)

Covers requested area 9: Sigma and the detection-engineering ecosystem.

> All verdicts are candidates for architectural review, not decisions.

---

## Summary opinion (design opinion)

Sigma is the most attractive **vendor-neutral, permissively-licensed** source of ATT&CK-tagged detection
logic. Its value to *this* project is less "run a SIEM" and more: a large corpus of
**observation → technique** mappings that feed our evidence layer, plus a conversion library that targets
Elastic. Elastic's own `detection-rules` are richer but **ELv2-licensed** ([01](01-elastic-stack.md)); Sigma
is the redistribution-safe complement.

---

## Sigma rule corpus (`SigmaHQ/sigma`)

- **What it does:** Generic YAML signature format for log-based detections; thousands of community rules,
  most tagged with **ATT&CK techniques**.
- **Maturity/Maintenance:** High; the de-facto open detection-content standard; actively maintained.
- **License (fact — important nuance):** The **rules** are under the **Detection Rule License (DRL)
  1.1** — very permissive (private/commercial use allowed with author attribution). This is **separate**
  from the tooling license below.
- **Reuse:** Each rule is an `observation pattern → ATT&CK technique` assertion with a stated log source —
  a direct feeder for our "which techniques does this telemetry support, and why" evidence edges.
- **Elastic fit:** Excellent via the backend below (compiles to Lucene/ES|QL/EQL/Kibana NDJSON).
- **ATT&CK fit:** Excellent (technique tags in rule metadata).
- **Duplicates Elastic?** Overlaps `detection-rules`, but with a **friendlier license** and
  cross-platform neutrality. Complementary.
- **Verdict:** **Integrate/Adapt** as a redistribution-safe detection-content and technique-mapping source
  (candidate).
- **Risks:** Rule *quality/noise* varies; DRL attribution obligation must be honored if we surface matches;
  log-source assumptions must be mapped onto our ECS/OTel fields.

## pySigma + backends (`SigmaHQ/pySigma`, `pySigma-backend-elasticsearch`)

- **What it does:** Modern Python library to parse/convert Sigma rules into target queries. The
  **Elasticsearch backend** (`LuceneBackend`) emits **Lucene, ES|QL (with correlations), EQL**, and
  **Kibana NDJSON**. `sigma-cli` is the CLI front-end.
- **Maturity:** Mature core; modular backend/pipeline design.
- **Maintenance (VERIFIED 2026-09 — a real but bounded risk):** Core pySigma is active. The Elasticsearch
  backend's latest release is **v2.1.1 (2024-08-10)** — it *does* ship features (EQL correlations, ES 9
  compat, ECS pipeline fixes), so it is **functional and reasonably current**, but the cadence is **slow
  (~13 months since last release as of this audit)** and the backend has previously requested additional
  maintainers. Verdict unchanged: usable, but keep it behind a boundary so a stall is survivable.
- **License (fact):** pySigma is **LGPL v2.1** (distinct from the rules' DRL). LGPL is generally fine for
  use as a library dependency; note the copyleft-on-modification obligation if we fork it.
- **Dependencies:** Python; per-backend/pipeline plugins.
- **Verdict:** **Integrate** for offline Sigma→Elastic conversion in a controlled pipeline (candidate);
  keep it behind an internal boundary so a stalled backend can be swapped.
- **Risks:** Backend maintenance; conversion fidelity (not every Sigma construct maps cleanly to every
  target — validate converted rules against known-true datasets, see [07](07-datasets-and-synthetic-telemetry.md)).

## Adjacent ecosystem (brief)

- **Elastic `detection-rules`** — richer Elastic-native content but ELv2; see [01](01-elastic-stack.md).
  Use Sigma when redistribution/neutrality matters, Elastic rules when maximizing Elastic-native coverage.
- **Threat Hunter Playbook / hunting notebooks (OTRF)** — analytic *methodology* and Jupyter-based
  hunts mapped to ATT&CK; **Study** for how to structure explainable analytics; not a runtime dependency.
- **LLM-assisted Sigma tooling** (e.g., AttackIQ SigmAIQ) — **Study only**; do not put nondeterministic
  rule generation on the correctness path (violates the "keep security logic deterministic/testable"
  principle).

---

## How this feeds attribution (design note)

Detection content (Sigma + Elastic rules) is an **evidence producer**, not the attribution engine. The
path we should model:

```
telemetry (ECS/OTel) → detection rule match → OBSERVATION
OBSERVATION --supports--> ATT&CK technique (with rule + matched fields as the "why")
techniques (weighted by discriminating power) --> candidate Groups/Campaigns  [attribution, doc 08]
```

Every technique assertion must carry its provenance (which rule, which fields matched, which events) so
the conclusion is **explainable** — directly countering the previous version's "unreliable mapping" and
"hard-coded results" failures.

---

## Open questions for architectural review

1. **Sigma vs. Elastic rules as primary content** — or both, with license-based separation (Sigma for
   anything we might redistribute, Elastic rules for internal coverage)?
2. Run detections **inside Elastic** (rules engine) or **convert Sigma and run offline over replayed
   datasets** for reproducible research? (Likely both: Elastic for live/lab, offline conversion for
   deterministic validation.)
3. How do we **measure and record rule reliability** (false-positive propensity) so evidence weight
   reflects rule quality rather than treating every match as equal?

## Sources

- [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) ·
  [Detection Rule License (DRL) 1.1](https://github.com/SigmaHQ/Detection-Rule-License)
- [SigmaHQ/pySigma](https://github.com/SigmaHQ/pySigma) ·
  [pySigma-backend-elasticsearch](https://github.com/SigmaHQ/pySigma-backend-elasticsearch)
- [Sigma backends overview](https://sigmahq.io/docs/digging-deeper/backends.html)
