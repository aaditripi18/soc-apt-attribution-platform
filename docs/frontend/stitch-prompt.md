# Google Stitch 2.0 prompt — SOC APT Attribution Platform frontend

Prepared 2026-10-09 from the implemented backend (read-model API, ADR-0009; collection guidance, ADR-0005
Amendment E; indicators, ADR-0013; dossier, ADR-0009 Amendment C). Every screen below maps to data the API
already serves — nothing is decorative or invented.

---

```
Design a desktop web app for professional SOC analysts: "SOC APT Attribution Platform". It explains how security telemetry leads to evidence-based APT attribution. It is an investigation tool, not a marketing dashboard: dense, precise, readable, calm. Dark theme by default (near-black slate background, one restrained accent colour such as teal, amber only for warnings), light theme variant. Monospace font for IDs, hashes, command lines and timestamps; clean sans-serif (e.g. Inter) for text. 8px spacing grid, tables with sticky headers, keyboard-friendly, WCAG AA contrast. No world maps, no glowing globes, no fake live attack counters, no gauges, no confidence percentages.

CORE RULE — the product deliberately shows NO likelihood, confidence score, probability, ranking or "most likely actor". Attribution is not yet calibrated, so every attribution screen carries a small persistent badge "UNCALIBRATED — explainable facts only" with a tooltip: "No calibration version exists yet, so no likelihood, confidence or ranking is shown. Values shown: g = share of active ATT&CK Groups using a technique, D = 1 − g." Candidate actors are always listed alphabetically.

Global layout: left sidebar navigation (Investigations, Units search, Detection coverage, About & provenance), top bar with breadcrumb, global search box (technique ID like T1059.001, host name, or actor name), and API health indicator dot ("backend reachable").

SCREEN 1 — Investigations. Table of investigations: source name (e.g. "otrf-apt29-day1"), source type (recording / fixture), ATT&CK version ("enterprise-attack-19.2"), evidence count, unit count, investigation ID (truncated monospace, copy button). Row click opens the investigation.

SCREEN 2 — Investigation detail. Header: source, SHA-256 (truncated + copy), ATT&CK version, detection pack hash, method versions (small chips). Summary strip: evidence count, unit count, time span. Main area: a horizontal TIMELINE of attribution units (each unit a bar from first-seen to last-seen, stacked by host), and below it a UNITS TABLE: first seen, last seen, hosts, number of steps, evidence count, ATT&CK technique chips (e.g. T1059.001, T1003.001), number of candidate actors. Filters: technique, host, candidate actor. Button "Open attribution dossier" (renders a Markdown report).

SCREEN 3 — Unit workspace (the heart of the app). Header: unit ID, time span, hosts, users, UNCALIBRATED badge. Tabs:
 (a) Overview — "What was observed": observation count, behavioural steps, structural links, and a plain-language summary.
 (b) Attack sequence — a left-to-right directed graph of behavioural steps ordered by time; nodes show time, process executable and technique chips; edges labelled by their structural basis: "same process", "parent → child", "injection", "same audit event". Show ties/gaps as dashed connectors. Clicking a node opens a side panel with the step's evidence.
 (c) Evidence — table: time (UTC), ATT&CK technique, content source chip (Sigma / Elastic), tier ("core" or "low-level (context)" as a muted pill), what was observed (host, user, process, command line or cloud action, data source). Expanding a row shows the full evidence claim text: the detection rule that matched (Sigma or Elastic, its rule id and a link to the exact rule), the exact field values it matched, and the ATT&CK mapping basis.
 (d) Techniques — observed ATT&CK techniques grouped by tactic (mini ATT&CK matrix: only observed cells filled), each cell showing technique ID, name, number of supporting evidence items, and rarity: "used by 4 of 176 Groups · D = 0.977" with a thin horizontal bar for D. Rarer techniques read as more distinctive.
 (e) Candidate actors — alphabetical list of ATT&CK Groups and Campaigns consistent with the evidence (e.g. "G0016 APT29", "C0024 SolarWinds Compromise"). Primary visual: a matrix with candidates as rows and observed techniques as columns; a filled cell means the actor's ATT&CK profile includes that technique; a count column "3 of 4 observed techniques" (a fact, not a score). Include a row "Unattributed baseline" with its support value. Expanding a candidate shows per-technique contributions (g, D, outcome).
 (f) What evidence would help — cards, one per question: technique ID and name, "77 of 169 candidates use it", a split bar showing users vs non-users, the rationale sentence ("observing it is consistent with those 77; finding it adequately absent contradicts them"), ATT&CK data components as chips (e.g. Process Creation, Command Execution), and a detectability tag: "Detectable here" with log source chips (windows/process_creation, aws/cloudtrail) or "Not detectable yet" with the blocking reason.
 (g) Indicator context — separated with a clear label "Context only — not part of attribution". Each match: matched value (hash/IP/domain, monospace), observation, indicator name, advisory (e.g. CISA MAR-10448362.c1), the actor the publisher names (e.g. "Volt Typhoon (G1017)") with the publisher's verbatim quote in a blockquote, and a validity badge: "inside" / "outside" the indicator's validity window.
 (h) Provenance — method versions, ATT&CK version, detection pack hash, source SHA-256, every ID copyable.

SCREEN 4 — Units search. Search across all investigations by technique, host, candidate actor, with a result table like Screen 2.

SCREEN 5 — Detection coverage. Explains what the platform can detect today: headline facts "Sigma 1,883 rules + Elastic 440 rules · 395 ATT&CK techniques covered · 314 of 498 group-used techniques covered · 163 of 176 groups with ≥ 2 covered techniques"; a small "coverage by content source" breakdown (Sigma 336 techniques, Elastic 271, 59 only by Elastic); a stacked bar of technique statuses (covered, telemetry gap, translation gap, no Sigma rule, not observable on supported platforms); a table of supported telemetry families (Windows: Sysmon, Security, PowerShell; Linux: Sysmon for Linux, auditd; Cloud/SaaS: Entra ID, Office 365, AWS CloudTrail, Azure Activity, Okta, GitHub, Kubernetes; Network: Zeek; macOS: Endpoint Security); and a ranked table of "top telemetry blockers".

SCREEN 6 — Attribution dossier viewer. A clean reading view of a long Markdown report with a sticky table of contents (per unit: 1 What was observed, 2 Evidence extracted, 3 Techniques supported and why, 4 Actors consistent with the evidence, 5 Uncertainty, 6 What evidence would help, 7 Indicator context), print / export button.

Also design: empty states ("No units — no detection matched this recording"), loading skeletons, error states (backend unreachable, 404 unit not found). Use realistic sample content: APT29 evaluation day 1, hosts SCRANTON and NASHUA, techniques T1059.001 PowerShell, T1003.001 LSASS Memory, T1021.002 SMB/Windows Admin Shares, candidate actors APT29, APT28, Turla, Lazarus Group, Volt Typhoon.
```
