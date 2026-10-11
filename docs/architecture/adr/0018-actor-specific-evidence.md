# ADR-0018 — Actor-specific evidence: the only evidence that may name a Group

- **Status:** ACCEPTED (2026-10-11, owner instruction: "go ahead with step 2" — group-specific evidence, after the
  honest verdict of ADR-0017).
- **Builds on:** ADR-0017 (no verdict names an actor on technique overlap; naming one needs evidence that
  discriminates), ADR-0007 D3 amendment (a Sigma software tag counts only when a per-rule review accepts it),
  ADR-0013 (indicators), ADR-0005 record 2026-10-11, CLAUDE.md ("never hard-code attribution results"; "every
  important attribution conclusion must be explainable"; "prefer authoritative sources").

## Context — measured

- **Techniques do not separate actors** (ADR-0005 record, ADR-0017): on the known-answer recordings the emulated
  actor is at position 14–121 under every ordering of technique overlap.
- **Tooling does, in ATT&CK's own data:** of 607 software entries used by an active Group, 503 are recorded for
  exactly one Group, and 128 of 176 Groups have at least one. But ATT&CK holds no signatures for them, the
  emulation recordings use stand-in tooling, and Sigma's software tags were already found unreliable (ADR-0007).
- **What exists as structured, signature-level content:** the pinned SigmaHQ release has 49 rules tagged with an
  ATT&CK Group id (52 tags, 26 Groups) — mostly `rules-emerging-threats`, written from published reporting on one
  actor's operation, and not part of the Core++ package the platform imports. Reading all of them: a minority
  match literal artefacts of one Group's tooling (a service name, a staging path, a hash, a payload fragment); the
  majority put a Group tag on a generic technique or a public framework — for example the default persistence task
  of Empire / PowerSploit tagged APT3, or the public CMSTP UAC bypass tagged MuddyWater. Trusting the tag would
  manufacture false attributions.

## Decisions

### D1 — A Group tag counts only when a per-rule review accepts it

`data/detection/sigma/<release>/actor-tag-review.json` holds one decision **with a written reason** for every
`(rule, attack.gNNNN)` in the pinned archive. Accepted only when **every branch** of the rule's detection logic
matches a literal artefact published for that Group's own tooling or operation — something unrelated software or
another actor would not plausibly produce — and the source supports the Group named. One generic branch rejects
the rule. A miss is acceptable; a false lead is not. Result: 14 tags accepted, 38 rejected.

The importer fails closed: a Group tag without a decision, a decision without a reason, or a decision for a rule
not in the archive stops the import.

### D2 — A separately pinned archive and a separate pack

`scripts/build_sigma_actor_archive.py` builds `sigma_actor_specific.zip` (49 rules, reproducible, with a manifest)
offline from the release's own `sigma_all_rules.zip`, whose pinned SHA-256 it checks.
`detection_content/sigma_actor_import.py` translates accepted rules with the same exact translation as every other
Sigma rule and writes the pack `sigma-<release>-actor-specific` (rule ids `sigma-actor:<sigma id>:NNN`). A rule maps
to **its reviewed Group only**; its technique tags are not mapped here. The Core++ / enrich pack is untouched and
byte-identical; the coverage report stays a report about techniques and does not include this pack.

Usable on ingested telemetry: 9 of the 14 accepted rules (8 whole, 1 in part; 26 engine rules), for 8 Groups —
Equation, Lazarus Group, Lotus Blossom, MuddyWater, Mustang Panda, OilRig, Turla, ZIRCONIUM. The other 5 need the
Windows System log or firewall records, which are not ingested, or a field the adapter does not carry (file
hashes on process creation).

### D3 — The Evidence references the Group

A match yields ordinary Evidence whose `attack_ref` is the Group (`object_type: intrusion-set`), with the rule, the
matched values and the review's reason in its claim. It is core Evidence, so it forms or joins a unit like any
other detection. It is **not** a technique: it is never a decision feature, never in a unit's technique ids, never
in the candidate comparison (the comparison already skips non-technique features; the unit summary and the
frontend now filter by object type). The unit analysis lists it in `actor_specific_evidence`
(`attribution-analysis/5`).

### D4 — The assessment may name a Group, as a lead

`Verdict.ACTOR_SPECIFIC_EVIDENCE` (ADR-0017's vocabulary gains its fourth value). The statement names the Group,
says how many matches of how many rules, that it is a lead to verify, that it is not a calibrated conclusion, and
that anyone holding the same tooling or copying its artefacts would produce it. Leads to different Groups single
none out. It applies with or without technique decision features, and the technique facts are still stated beside
it. Advisory indicator leads (ADR-0013) remain a separate, weaker kind: a publisher's claim about an indicator.

### D5 — Every decision is visible

Detection Coverage lists every reviewed rule with its Group, decision, reason and whether it is usable here. An
actor-specific Evidence row shows why its rule counts as specific.

## Validation — what is and is not established

- **No false lead on real telemetry:** the pack was run over all 11 pinned recordings (two APT29 days, two APT3
  runs, seven credential-dumping tool tests; 1,132,553 observations): **0 firings**. None of them contains the
  tooling of the 8 Groups, so 0 is the correct answer, and the known-answer checks (`GET /validation`) now record
  how many verdicts named an actor and how many named a wrong one.
- **The path from artefact to lead works:** a recording carrying one accepted rule's published artefact yields the
  Evidence, the unit entry, the verdict and the dossier line; the same activity without the artefact yields none
  (`tests/test_actor_specific_evidence.py`).
- **Not established:** that these rules fire on the real malware, and how often a firing is the named Group. No
  public recording contains these artefacts, so recall and precision on real intrusions are unmeasured; precision
  rests on the upstream rule and the review. That is why the verdict is a lead and not a conclusion, and why
  `calibration_status` stays `uncalibrated`.

## Limits and next sources

Nine usable rules for eight Groups is a narrow base, and several artefacts are years old. The mechanism — pinned
source, per-rule review with reasons, exact translation, Group-referenced Evidence, a lead verdict — is what future
content plugs into: further Sigma releases, more government advisory indicator bundles (ADR-0013), and ATT&CK
software identification once a signature source for it passes the same review. Ingesting the Windows System log
would make 3 more accepted rules usable.
