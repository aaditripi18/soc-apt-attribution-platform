# ADR-0013 — Indicator (IOC) intelligence layer

- **Status:** ACCEPTED for D1–D2 (2026-10-09, owner instruction "finish all other tasks", recommended path:
  contextual only). D3 (scoring) is **not** adopted — matches stay contextual until validation data with real
  public infrastructure exists.
- **Builds on:** ADR-0002 / 0005 (attribution methodology: evidence-driven, ACH over ATT&CK features),
  ADR-0003 (contextual vs structural links), ADR-0012 (network telemetry — the infrastructure facts an IOC
  would match).

## Context — measured, not assumed

**What an indicator match is.** An IOC match says: *a value observed here (IP, domain, hash, certificate) was
reported by a third party in connection with an actor or malware family*. It is not an observation of behaviour;
it is a **label claim** made elsewhere, at another time. CLAUDE.md's attribution philosophy is "evidence-driven
rather than label-driven" — so how such a claim may enter attribution is a methodology decision, not plumbing.

**The corpus cannot validate it.** Every recording in calibration corpus v2 (APT29 days 1–2, APT3 CALDERA /
Empire, the seven LSASS campaigns) and every network log of ADR-0012 uses **private lab infrastructure**
(`10.0.0.0/8`, `192.168.0.0/16`, lab domains such as `dmevals.local`, lab-built payloads). No public indicator
feed can match them. An IOC layer built now would have **zero measurable effect** on the corpus and could only
be tested on records with an inserted indicator value.

**Candidate sources (checked 2026-10-08):**

| Source | Licence / access | Attribution in the data | Reproducible pin | Fit |
|---|---|---|---|---|
| abuse.ch ThreatFox | fair use; every export needs an account **Auth-Key**; IOCs **expire after 6 months** | malware family (+ tags) | no — rolling, expiring | ✗ for a pinned, reproducible pipeline |
| CISA / partner advisories (STIX) | US-government work (public domain); per-advisory files | **actor stated by the advisory** | yes — one file per advisory | ✓, but only some advisories publish STIX (e.g. AA24-057A on APT29 publishes **no** indicators) |
| MISP galaxies | CC0 / BSD | actor and malware **metadata, no IOCs** | yes | context only |
| ATT&CK (pinned v19.2) | Apache-2.0 | **no IOCs** by design | yes | — |

**How the engine could use it.** ATT&CK Software ↔ Group relationships are already in the knowledge base
(the importer accepts software tags after review, e.g. PsExec S0029). An indicator attributed to a *malware
family* maps cleanly onto that path (family → ATT&CK Software → Groups that use it). An indicator attributed
directly to an *actor* has no ATT&CK feature to attach to; scoring it would need a new evidence class in the ACH
matrix (an ADR-0005 amendment) with its own diagnosticity — and indicator diagnosticity is not one number:
hashes of bespoke tooling are near-unique, IPs are reused, rented and reassigned within weeks.

## Decisions (proposed)

**D1 — Recommended: contextual only.** An indicator match is recorded as a **contextual annotation** on the
Observation / unit (which value, which source document, which actor or family it names, the report date, the
indicator type) — shown to the analyst, **never** a structural link and **never** an ACH feature. It explains;
it does not score. This is consistent with ADR-0003's rule for shared infrastructure.

**D2 — Recommended source and form.** Per-advisory STIX 2.1 bundles from government advisories that publish
them, pinned by URL and SHA-256 like every other dataset; exact matching only (IP, domain, URL, file hash,
certificate fingerprint); indicator validity windows kept and shown (a 2023 indicator matched in 2026 is
labelled stale, not dropped silently). No rolling feeds.

**D3 — Owner decision.** Whether indicator matches may ever contribute to attribution **scores** (an ADR-0005
amendment: a separate, typed evidence class with stated diagnosticity per indicator type), or stay contextual
(D1) permanently. Recommendation: contextual now; revisit only with validation data that contains real public
infrastructure (none exists in the corpus).

## Consequences

- If D1–D2 are accepted: a small, testable component (STIX ingestion → exact match → contextual annotation),
  validated by golden tests on real advisory bundles with one inserted value; no change to any attribution result.
- Until decided, nothing is built: building an unvalidatable scoring path would contradict CLAUDE.md principles
  1–4 and 14.

## Alternatives rejected

- **Rolling commercial / community feeds** — not reproducible, licence-restricted, expiring.
- **Scoring indicators as ATT&CK-technique-like features now** — label-driven, unvalidated, and an IP's
  diagnosticity is not knowable from the feed alone.

## Record — implementation (2026-10-09)

- *Source:* CISA MAR-10448362.c1 STIX 2.1 bundle (published with joint advisory AA24-038A), TLP:CLEAR, marked
  for public release; 53,239 bytes, pinned by URL **and** SHA-256 (`scripts/acquire_advisory_indicators.py`,
  vendored under `data/intel/advisories/`). cisa.gov's CDN refuses Python's HTTP client (403 regardless of
  headers), so the script's `--from-file` mode vendors a copy fetched with an ordinary client — accepted only if
  its SHA-256 equals the pin; bot detection is never worked around. The manifest records how the bytes arrived.
- *Attribution:* the bundle carries no structured actor relationship; its report names the actor in prose. The
  reviewed `data/intel/advisory-attributions.json` maps the report to ATT&CK **Volt Typhoon (G1017)** with the
  naming sentence quoted verbatim, and **loading fails closed if the quote is not in the pinned bundle**. The
  review also records the claim's scope (files from one compromised environment — not files unique to the actor).
- *Patterns:* only one observation expression of `=` comparisons joined by `OR` on file hashes, IPv4 / IPv6,
  domain names and URLs; `AND`, other operators, qualifiers, multiple expressions and other paths are refused and
  counted. The bundle's 3 indicators (MD5 / SHA-1 / SHA-256 / SHA-512 each) load with 0 unsupported.
- *Observation side:* Sysmon process creation now records the image hashes (`process.hashes`), parsed exactly
  from Sysmon's documented `ALGO=HEX,…` form (`-`, Sysmon's "no value" written by Sysmon for Linux, is absent;
  IMPHASH is not a file digest and is not kept; malformed values fail closed). Matched values: process and file
  hashes, Zeek file hashes, network IPs, DNS / Zeek query names, TLS server names, HTTP hosts.
- *Output:* `indicator_matches` on each unit's attribution analysis (`attribution-analysis/3`; investigation
  1.3): the value, the observation, the indicator, the advisory, the named actor with its ATT&CK id and quote,
  and whether the observation falls inside the indicator's validity window (a stale match is flagged, not
  dropped).
- *Proof of D1:* `tests/test_indicators.py` runs the same real record (an advisory hash and a detected image as
  two labelled changes) with and without the indicator set: the match appears, and **every attribution quantity
  in the analysis is identical**. The corpus contains only lab-built tooling and private infrastructure, so no
  match is expected there (ADR context).

## Amendment A (2026-10-11) — six more advisory bundles, and the patterns they use

**Why:** the owner requires that the platform name the responsible Group wherever evidence allows (see ADR-0018
Amendment B). Advisory indicators are the second kind of evidence that can point at one Group, and one bundle was
too little.

**Sources added.** Six CISA joint-advisory STIX 2.1 bundles, each published as TLP:CLEAR with its advisory, pinned
by URL and SHA-256 and vendored (`data/intel/advisories/`, short file names: the published names exceed Windows
path limits; the manifest keeps the published URL). All were fetched with an ordinary client and accepted only on
their pinned hash (`--from-file`, as before).

| Bundle | Publisher's actor (quoted in the review) | ATT&CK Group | Indicators read |
|---|---|---|---|
| AA23-144A | "state-sponsored cyber actor known as Volt Typhoon" | Volt Typhoon G1017 | 9 file hashes |
| AA23-347A | SVR, "also known as … (APT 29), the Dukes, CozyBear" | APT29 G0016 | 33 (hashes, 3 addresses, a domain, a URL) |
| AA24-207A | "known publicly as Andariel, Onyx Sleet …" | Andariel G0138 | 124 file hashes |
| AA24-241A | "Pioneer Kitten, Fox Kitten, UNC757 …" | Fox Kitten G0117 | 12 addresses and domains |
| AA24-249A | GRU "161st Specialist Training Center (Unit 29155)" | Ember Bear G1003 | 208 (mostly file hashes) |
| AA25-141A | GRU "85th GTsSS, military unit 26165" | APT28 G0007 | 65 addresses |

Two attributions go through a unit rather than a vendor name: the publishers name GRU Unit 29155 and unit 26165.
ATT&CK records Ember Bear as linked to Unit 29155 (citing this advisory) and APT28 as unit 26165; the review states
this in each entry's `scope`, and AA24-249A's own caveat that vendor names may not map one to one. Every entry's
quote is checked against the pinned bundle at load, as before.

**Patterns (matching 1.1).** Most file indicators in these bundles are not plain `OR` lists. Read exactly:

- redundant parentheses around a comparison or an `OR` group, and the unquoted `file:hashes.MD5` key;
- file-hash comparisons joined by `AND` with `file:name` and `file:size`. Equality of a hash identifies the
  file's content, which fixes its size and its other hashes, so those conjuncts add nothing an Observation could
  contradict. **The name does not follow from the content**: where a pattern states a name, the observed file or
  process image must carry one of the published names (case-insensitive) or there is no match — a renamed copy is
  a miss, by design.

Still refused and counted: `AND` between anything else, a name or size without a hash, `directory:path`,
`email-addr` (no Observation carries one), and malformed patterns. Of 469 indicators in the seven bundles, 454 load
(67 with a name condition) and 15 are refused (13 e-mail addresses, 2 malformed).

**What a match means — unchanged.** D1 holds: a match is a contextual annotation and the verdict it can produce is
`third_party_lead` (ADR-0017) — "an advisory names this actor for a value seen here" — never a technique feature,
never a score. The review's `scope` says what each bundle's indicators are: many hashes are builds of public tools
the actor used, and published addresses are often shared or compromised infrastructure, so a match outside the
indicator's validity window is flagged (`within_validity: false`) and should be read as weak.

**Checks.** `tests/test_indicators.py`: all seven bundles load with exactly their reviewed actor; every supported
and refused pattern shape; a published file name is required where the pattern states one (same hash, other name:
no match). The known-answer checks (`data/validation/known-answer-checks.json`) were regenerated with this set.
