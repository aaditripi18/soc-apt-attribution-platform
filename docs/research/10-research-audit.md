# 10 — Research Audit (Critical Review of docs 01–09)

**Date:** 2026-09-11 · **Scope:** a skeptical re-read of the reconnaissance in `docs/research/`, primary-
source re-verification of every `(verify)` item, and a hunt for over-reliance on popularity, Elastic
duplication, unnecessary complexity, and gaps. **No architecture decisions are made here.** Corrections
found during this audit were applied back into docs 01–09; this document records *why* and organizes the
findings.

Sections: **A. Verified findings · B. Findings requiring architectural validation · C. Findings that should
NOT be used · D. Potentially valuable opportunities · E. Remaining research questions**, then
**What we now know** / **What we still need to decide**.

---

## A. Verified findings (checked against primary sources this pass)

**Licenses / editions (corrected or confirmed):**

| Item | Verified fact | Change vs. round 1 |
|---|---|---|
| Elasticsearch/Kibana | AGPLv3 **+** SSPL 1.0 **+** ELv2 since 2024-08-29; clients Apache-2.0 | confirmed |
| **Elastic feature tiers** | **Detection engine + prebuilt rules = free/Basic**; **entity analytics, Attack Discovery, ML = Platinum+**; Platinum **not sold to new self-managed** customers | **resolved** (was `verify`) |
| `mitreattack-python` | **Apache-2.0**, active | confirmed (dropped `verify`) |
| `attack-stix-data` | MITRE copyright + **ATT&CK Terms of Use**; ships a *floating* latest bundle + *versioned* bundles | confirmed; **pin the versioned bundle** |
| `attackcti` (OTRF) | **BSD-3-Clause**; "Production/Stable" but **low recent activity** | confirmed (dropped `verify`) |
| pySigma ES backend | **LGPL-2.1**; last release **v2.1.1 (2024-08-10)**; slow but functional | corrected ("needs maintainers/mid-2024" → dated release) |
| OpenCTI | **CE Apache-2.0 / EE separate commercial license** | confirmed (dropped `verify`) |
| MISP | **AGPLv3** | confirmed |
| Cortex | **AGPLv3** | confirmed |
| TheHive 5 | **Commercial** (read-only without paid key) | confirmed |
| Wazuh | **GPLv2** core; indexer/dashboard = Apache-2.0 OpenSearch fork | confirmed |
| Velociraptor | **AGPL-3.0** (`Velocidex`), active | corrected — **Rapid7-acquisition claim was unverified and removed** |
| Shuffle | **backend AGPL-3.0 / apps+SDK+docs MIT** | confirmed + refined |
| CALDERA | **Apache-2.0** (`apache/caldera`) | confirmed |
| Atomic Red Team | **MIT** | confirmed |
| OTRF Security-Datasets (Mordor) | **MIT** (license file); stable/slowed cadence | **corrected** (was "GPL family") |
| `sbousseaden/EVTX-ATTACK-SAMPLES` | **GPL-3.0** (`LICENSE.GPL`) | **corrected** (was "maybe no license") |

**Technical facts confirmed:**
- ATT&CK is genuinely graph-shaped: `intrusion-set`/`malware`/`tool`/`campaign`/`attack-pattern` joined by
  `relationship` objects — safe basis for our evidence graph.
- Elastic natively does **EQL `sequence`** + **ES|QL** correlation and ships ATT&CK-tagged prebuilt rules
  on the **free** tier.
- **STIX 2.1 has a native `confidence` (0–100) property with normative mappings (OASIS Appendix A) to
  None/Low/Med/High, 0–10, Admiralty, WEP, and DNI scales**, implemented in `cti-python-stix2`
  (`stix2.confidence.scales`). This is a strong, standards-based anchor for our scoring output.

## B. Findings requiring architectural validation (true but needs a decision/test)

1. **Elastic paid-tier avoidance is now a design constraint, not a footnote.** Because entity analytics /
   Attack Discovery / ML are Platinum+ (and Platinum isn't sold to new self-managed users), the design
   should assume **Basic-tier primitives + our own engine**. Validate that no "minimum viable" feature
   secretly needs a paid capability. *(Turns a limitation into alignment with the project's goal.)*
2. **Schema decision is three-way, not two-way.** ECS vs. **OTel SemConv** (the merge target) vs. **OCSF**
   (LF/AWS/Splunk-backed). ECS is easiest on Elastic, but the internal mapping boundary must not assume ECS
   is the only contract. Decide the contract *and* how thin the mapping layer is.
3. **Graph store progression.** "NetworkX → Neo4j" understates the option space: **Kùzu/Memgraph** (embedded/
   fast, Cypher) are a middle path. Validate against *actual* query patterns (pathfinding, actor similarity)
   before committing.
4. **Sigma→Elastic conversion fidelity + backend longevity.** pySigma ES backend is functional but
   slow-cadence and LGPL. Validate (a) conversion fidelity on known-true datasets and (b) a fallback
   (STIX-shifter, or running Sigma natively where supported) so a stall is survivable.
5. **ATT&CK Group→technique data is presence, not frequency.** Our discriminating-technique weighting
   (doc 08) must be validated against labeled scenarios or it will over-attribute on common techniques.
6. **Confidence must be *calibrated*, not merely computed.** Two-axis (likelihood + confidence) output must
   be validated for calibration on the scenario corpus; STIX serialization must not silently collapse the
   two axes into one integer.

## C. Findings that should NOT be used (as-is)

1. **Do not treat Elastic Attack Discovery as our attribution engine.** It is Platinum+, LLM-based, and
   opaque — use only as an offline **baseline to beat on explainability**; never on our correctness path.
2. **Do not build on TheHive 5.** Commercial read-only-without-key; study its case/observable *model* only.
3. **Do not run Wazuh and Elastic as parallel backbones.** Direct duplication; pick one backbone (leaning
   Elastic for ATT&CK-native content) and treat the other as study/lab agent at most.
4. **Do not rely on the *floating* `attack-stix-data` bundle.** Reproducibility requires a **pinned
   versioned** bundle; the always-latest bundle silently changes ground truth.
5. **Do not redistribute GPL/ELv2 material as if permissive.** `EVTX-ATTACK-SAMPLES` (GPL-3.0) is fine as a
   *local fixture* but carries copyleft if bundled; `elastic/detection-rules` (ELv2) is fine for
   *internal* use but must be reviewed before any redistribution or hosted service.
6. **Do not treat IOC/malware matches as attribution.** Confirmed by the 2024 survey: IOCs/infrastructure
   are the most manipulable artifacts; malware is shared/sold. Behavioral TTP evidence must lead.
7. **Do not equate popularity with fitness (audit of round-1 reasoning).** Star counts were *not* the basis
   for any **Integrate** verdict, but two popular items were correctly *down*-weighted on technical grounds
   — TheHive (license) and Wazuh (duplication). Keep this discipline: OpenCTI and Neo4j are popular and
   capable yet remain **Study**, precisely because adopting them early risks making us "a thin UI on someone
   else's engine" — the previous version's failure mode.

## D. Potentially valuable opportunities (some newly surfaced)

1. **Explainable, deterministic, evidence-graph attribution is a genuine open niche.** The 2024 survey
   confirms explainability is a *recognized gap* and TTP/behavioral evidence is the most robust basis —
   exactly our thesis. No mature open-source tool fills this.
2. **STIX 2.1 confidence scales (new).** Serialize our two-axis score to a *standard* and reuse
   `stix2.confidence.scales` — credibility + interoperability + "not arbitrary numbers," cheaply.
3. **DeTT&CT (new).** Its data-source/visibility/detection **coverage scoring** against ATT&CK data
   components is a near-perfect fit for the **"what additional evidence would raise confidence"** feature
   and for grounding telemetry→technique **visibility**. Study/adapt the model; don't take a runtime dep.
4. **ACH × discriminating-technique weighting × ICD-203 two axes** as the scoring core — deterministic,
   testable, explainable, and now serializable to STIX. This *combination* is the differentiator.
5. **CALDERA + Atomic Red Team → labeled scenario corpus** (both permissive) gives us reproducible ground
   truth for detection, chain-reconstruction, and attribution — the concrete guard against hard-coded
   results.
6. **"Next-evidence / information-gain" guidance** (which observation would most change the ranking) is
   both an analyst feature and a strong portfolio differentiator; DeTT&CT-style coverage data feeds it.

## E. Remaining research questions (open after this audit)

1. **Schema contract:** ECS now, designed for OTel-merge, with OCSF not precluded — or commit differently?
   How thin can the mapping boundary be?
2. **Graph substrate:** embedded (NetworkX/Kùzu) first, server (Neo4j/Memgraph) later — decided by which
   concrete queries?
3. **Scoring spec:** exact formula for discriminating-technique weight (TF-IDF-like over Group×Technique?),
   how IOC corroboration and Diamond-axis coverage feed **likelihood** vs. **confidence**, and how both map
   to STIX `confidence` without losing the distinction. Needs a written, versioned spec + worked examples.
4. **Attribution ground truth & calibration:** which labeled scenarios (ATT&CK Group TTP sets, CALDERA
   emulation plans, provenance datasets like DARPA OpTC) constitute a fair, reproducible test — and how do
   we measure *calibration*, not just top-1 accuracy?
5. **Detection content strategy:** Sigma (permissive) vs. Elastic rules (ELv2) vs. both under a license
   split; and pySigma vs. STIX-shifter vs. native execution for conversion.
6. **`(verify)` items still open:** `mdecrevoisier/EVTX-to-MITRE-Attack` license; DeTT&CT / CAR / STIX-
   shifter / Kùzu exact licenses; Splunk `attack_data`/BOTS and DARPA TC/OpTC usage terms; per-Elastic-
   integration license for anything we actually deploy.
7. **Coverage gap check:** ICS/OT and cloud-control-plane telemetry were only lightly considered — decide
   whether the first milestone is deliberately **endpoint/Windows-centric** (where labeled data is richest)
   and note the scope explicitly.

---

## What we now know

- **Stand on Elastic for the data plane, cheaply.** The parts we need most — storage, ECS normalization,
  EQL/ES|QL correlation, and **ATT&CK-tagged prebuilt detection rules — are on the free tier.** The opaque,
  attribution-adjacent features (Attack Discovery, entity analytics, ML) are **paid and largely
  unavailable** to a new self-managed user, which *pushes us toward* building our own explainable engine —
  aligning cost reality with the project's whole point.
- **The knowledge and content layers are permissively available.** ATT&CK STIX 2.1 (ATT&CK Terms of Use) +
  `mitreattack-python` (Apache-2.0) + Sigma rules (DRL) + CALDERA/Atomic (Apache/MIT) + Security-Datasets
  (MIT) give us a legally clean, reproducible substrate — *if* we pin versions and respect the GPL/ELv2
  exceptions (`EVTX-ATTACK-SAMPLES`, `detection-rules`).
- **The differentiator is real and unfilled:** explainable, deterministic, evidence-graph-based APT
  attribution with **competing hypotheses (ACH)**, **discriminating-TTP weighting**, and a **two-axis
  confidence methodology (ICD-203)** that **serializes to STIX 2.1 confidence scales**. Recent 2024
  research explicitly names explainability as the gap and TTPs as the strongest basis.
- **Our round-1 verdicts survived scrutiny**, with corrected license facts and one removed unverified claim
  (Velociraptor/Rapid7). No **Integrate** verdict rested on popularity.

## What we still need to decide (architectural review, no code yet)

1. **Normalized event contract** — ECS vs. OTel-merge-ready vs. OCSF-aware; and the thickness of the mapping
   boundary.
2. **Graph substrate** — embedded first (NetworkX/Kùzu) vs. server (Neo4j/Memgraph), decided by real query
   needs; and whether we mirror OpenCTI's STIX-2.1 model.
3. **Detection-content + conversion strategy** — Sigma vs. Elastic rules (license split) and pySigma vs.
   STIX-shifter vs. native execution.
4. **The attribution scoring specification** — the exact, versioned, testable methodology (weighting,
   two-axis likelihood/confidence, STIX serialization) *before* any engine code.
5. **Validation & calibration corpus** — the minimum labeled golden + scenario sets and the metrics
   (including calibration) that let us call a capability "done."
6. **First milestone scope** — almost certainly **deterministic telemetry → observation → ATT&CK-technique
   mapping on Windows/endpoint data**, validated against labeled datasets, with attribution layered only
   after that foundation is proven.

## Sources (audit re-verification)

- [Elastic subscriptions](https://www.elastic.co/subscriptions) ·
  [mitreattack-python](https://github.com/mitre-attack/mitreattack-python) ·
  [attack-stix-data](https://github.com/mitre-attack/attack-stix-data) ·
  [ATTACK-Python-Client (attackcti)](https://github.com/OTRF/ATTACK-Python-Client)
- [pySigma-backend-elasticsearch releases](https://github.com/SigmaHQ/pySigma-backend-elasticsearch/releases) ·
  [OpenCTI](https://github.com/OpenCTI-Platform/opencti) ·
  [Velociraptor LICENSE](https://github.com/Velocidex/velociraptor/blob/master/LICENSE) ·
  [Shuffle](https://github.com/Shuffle/Shuffle)
- [OTRF/Security-Datasets LICENSE](https://github.com/OTRF/Security-Datasets/blob/master/LICENSE) ·
  [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES)
- [STIX 2.1 confidence scales (cti-python-stix2)](https://github.com/oasis-open/cti-python-stix2/blob/master/stix2/confidence/scales.py) ·
  [STIX 2.1 OASIS Standard](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html)
- [OCSF schema](https://github.com/ocsf/ocsf-schema) ·
  [DeTT&CT (Rabobank)](https://github.com/rabobank-cdc/DeTTECT)
