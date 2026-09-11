# 08 — Attribution Methodology Foundations

Grounds the project's central differentiator: **explainable, evidence-based attribution with a defensible
confidence methodology.** This document surveys the established analytic frameworks we should build on so
that confidence scores have a real methodology — never "arbitrary numbers displayed by the UI" (the
explicit failure of the previous version).

> This is a synthesis of established public frameworks plus design opinions. It is **not** a final scoring
> spec — it is input for architectural review.

---

## Frameworks to build on (facts)

### MITRE ATT&CK — the behavioral vocabulary
Structured tactics/techniques/sub-techniques with Group/Software/Campaign relationships
([02](02-mitre-attack.md)). Provides the **behavioral evidence language** and the actor baseline.

### Lockheed Martin Cyber Kill Chain (2011)
Seven stages — Reconnaissance, Weaponization, Delivery, Exploitation, Installation, Command & Control,
Actions on Objectives. Useful as a **phase ordering** for attack-chain reconstruction. Limitation:
perimeter/malware-centric; less suited to post-compromise lateral movement. The **Unified Kill Chain**
extends/merges kill-chain + ATT&CK for fuller coverage.

### Diamond Model of Intrusion Analysis (2013)
Every intrusion event has four linked features — **Adversary, Capability, Infrastructure, Victim** — with
attribution being an explicit focus. Complements ATT&CK: ATT&CK describes **behavior (Capability)**; the
Diamond Model frames how behavior, infrastructure, and victimology **jointly** support (or weaken) an
adversary hypothesis. **Design opinion:** model evidence along Diamond axes so attribution reasons over
*capability + infrastructure + victimology*, not TTPs alone.

### Analytic standards — ICD 203 (Analytic Standards)
The US IC standard for rigorous judgments. Two independent axes we should adopt directly:
- **Likelihood / estimative probability** — how probable the judgment is, using **Words of Estimative
  Probability** bound to numeric ranges (almost no chance 1–5% → very unlikely 5–20% → unlikely 20–45% →
  roughly even 45–55% → likely 55–80% → very likely 80–95% → almost certain 95–99%).
- **Confidence** — how strong the *evidentiary/analytic basis* is (high/moderate/low), independent of
  likelihood.

**This likelihood-vs-confidence separation is the single most important idea for our scoring.** A candidate
can be "roughly even chance, high confidence" (good evidence, genuinely ambiguous) or "likely, low
confidence" (suggestive but thin) — and the UI must show both, plus the reasoning.

### Source/information grading — Admiralty (NATO) System
A widely used two-part grade: **source reliability (A–F)** × **information credibility (1–6)**. **Design
opinion:** grade each enrichment/intel input this way so a hypothesis built on well-corroborated,
reliable sources is visibly distinguished from one resting on a single low-reliability feed.
**(verify exact NATO/STANAG lettering before codifying.)**

### STIX 2.1 native confidence scales (added in audit — important)
STIX 2.1 defines a **`confidence` property (integer 0–100)** on most objects, and **Appendix A of the
OASIS standard gives normative mappings** from that 0–100 value to five named scales: **None/Low/Medium/
High, a 0–10 scale, Admiralty Credibility, Words of Estimative Probability (WEP), and the DNI scale**
(e.g., confidence 70 ↔ Admiralty "2 – Probably True" ↔ WEP "Likely/Probable"). The OASIS
`cti-python-stix2` library ships a `stix2.confidence.scales` module that performs these conversions.
**Design consequence:** our confidence output can **serialize to a recognized standard** and reuse an
existing, tested scale-conversion implementation instead of inventing one — directly supporting the "not
arbitrary numbers" principle. **Caveat:** STIX collapses to a *single* confidence integer, whereas ICD-203
keeps **likelihood and confidence separate**; we should keep both axes internally and map to STIX
`confidence` only at the serialization boundary, documenting how (so we don't lose the distinction).

### Structured Analytic Techniques — Analysis of Competing Hypotheses (ACH)
Heuer's ACH: enumerate hypotheses, then score **evidence against each**, emphasizing **disconfirming**
evidence to reduce confirmation bias. **Design opinion:** ACH is the natural backbone for
"competing attribution hypotheses" — the engine maintains multiple actor hypotheses and ranks them by how
evidence **supports and contradicts** each, not by cumulative "points for the favorite."

---

## Evidence taxonomy (from the 2024 APT attribution survey — [06](06-soc-and-attribution-tools.md))

- **Behavioral artifacts (TTPs)** — most robust; hardest for an adversary to change at will. **Weight
  highest.**
- **Evidentiary artifacts (IOCs, C2 infrastructure)** — useful but **easily manipulated / shared / spoofed**.
  **Weight lower; treat as corroborating or contradicting, never decisive.**
- Malware-based attribution is fragile (tools are shared/sold/reused). **False-flag** operations and actor
  **aliasing** must be representable as explicit uncertainty/contradiction, not silently ignored.

---

## Proposed attribution principles (design opinions, for review)

1. **Two-axis output, always:** every hypothesis reports **likelihood** (WEP scale) *and* **confidence**
   (basis strength), never a single opaque number.
2. **Discriminating-technique weighting:** a technique's attribution weight scales with how **rare/
   actor-characteristic** it is across ATT&CK Groups. Ubiquitous techniques (e.g., command-line execution)
   contribute little; rare, group-characteristic TTP *combinations* contribute much. (Think TF-IDF-style
   discrimination over the Group×Technique matrix — deterministic and explainable.)
3. **Support and contradiction as first-class:** store and display evidence that **weakens** each
   candidate, per ACH.
4. **Full provenance chain:** observation → matched rule/fields → technique → candidate, every link
   inspectable. No conclusion without a traceable path (directly answers the previous version's failures).
5. **Explicit uncertainty + next-evidence:** report residual uncertainty and **what additional evidence
   would most change the result** (highest-information-gain observation). This is both an analyst feature
   and a strong portfolio differentiator.
6. **Deterministic and testable first:** the core scoring is reproducible given the same evidence + pinned
   ATT&CK version; any ML is optional, versioned, and interpretable (e.g., LIME-style explanations).
7. **Never assume a single answer:** default to a ranked hypothesis set; a confident single attribution is
   an *output condition* the evidence must earn, not a default.

---

## Open questions for architectural review

1. **Exact scoring model:** how do we combine per-technique discrimination weights, IOC corroboration, and
   Diamond-axis coverage into a **likelihood** — and separately into a **confidence** grade? (Needs a
   written, versioned spec + tests against the attribution scenarios in [07](07-datasets-and-synthetic-telemetry.md).)
2. **Confidence calibration:** how do we validate that "likely / high confidence" is actually right ~55–80%
   of the time on our scenario corpus (i.e., calibration, not just ranking accuracy)?
3. **Aliasing/false-flag modeling:** how do we encode alias equivalence and represent deliberate
   deception as a hypothesis rather than a mis-attribution?
4. Which frameworks are **codified into the engine** (ATT&CK + ACH + ICD-203 axes are the leading
   candidates) vs. used only as analyst-facing framing (Diamond, kill chain)?

## Sources

- [Diamond Model of Intrusion Analysis (overview)](https://www.eccouncil.org/cybersecurity-exchange/ethical-hacking/diamond-model-intrusion-analysis/) ·
  [Cyber Kill Chain vs Diamond vs ATT&CK](https://medium.com/cycraft/cycraft-classroom-mitre-att-ck-vs-cyber-kill-chain-vs-diamond-model-1cc8fa49a20f)
- [ICD 203 Analytic Standards (ODNI)](https://archive.dni.gov/files/documents/ICD/ICD-203.pdf) ·
  [Words of Estimative Probability & Analytic Confidence (CIS)](https://www.cisecurity.org/ms-isac/services/words-of-estimative-probability-analytic-confidences-and-structured-analytic-techniques)
- [APT Attribution Survey (arXiv 2409.11415)](https://arxiv.org/abs/2409.11415)
- [STIX 2.1 confidence scales (cti-python-stix2 `scales` module)](https://github.com/oasis-open/cti-python-stix2/blob/master/stix2/confidence/scales.py) ·
  [STIX 2.1 OASIS Standard (Appendix A confidence scales)](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html)
