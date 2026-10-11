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

## Amendment B (2026-10-11) — more candidates, the same bar

**Why:** the owner requires that the platform name the responsible Group wherever the evidence allows. The route
that can do so correctly is the one this ADR opened — evidence specific to one Group — and 9 usable rules for 8
Groups was too narrow a base. Group *tags* were exhausted (D1 reviewed all of them).

**What changes — only how candidates are found.** SigmaHQ files rules written from reporting on one actor or one
malware family under a directory named after it, often without a Group tag, and tags some rules with ATT&CK
software. `detection_content/actor_association.py` derives the candidate Groups of every rule in the release
archive mechanically from the pinned ATT&CK version:

| Basis | A rule is a candidate for a Group when… |
|---|---|
| `group_tag` | it carries `attack.gNNNN` (D1, unchanged) |
| `directory_alias` | its `rules-emerging-threats/<year>/TA|Malware/<name>/` directory name contains a name or alias of exactly one active Group |
| `directory_software` | that directory name contains a name or alias of one software entry that exactly one active Group is recorded using |
| `software_tag` | it carries `attack.sNNNN` for such a software entry |

Aliases and software-to-Group links are read from ATT&CK (for example *Forest Blizzard* → APT28, *Diamond Sleet* →
Lazarus Group, *Kapeka* → Sandworm Team); nothing is mapped by hand. An ambiguous name (two Groups, two software
entries) yields no candidate.

**What does not change.** A candidate is not evidence. Every `(rule, Group)` pair needs a decision with a written
reason in `actor-tag-review.json` (now `actor-tag-review/2`, with the basis recorded), the importer fails closed
on a missing one, and the bar is D1's: every branch a literal artefact of that Group's own tooling or operation,
and the Group supported. "ATT&CK records this software for one Group" is a statement about ATT&CK's records, not
about the world, so the review rejects commodity malware (Emotet, Ursnif, Pikabot, SocGholish, jRAT),
ransomware-as-a-service (Conti, BlackByte), self-propagating worms (WannaCry, NotPetya), commercial tools, rules
that detect an exploit any actor can reuse, compromised legitimate domains, and every rule with one generic branch.

**Result.**

| | Before | After |
|---|---|---|
| Rules in the archive (candidates) | 49 | 138 |
| `(rule, Group)` decisions | 52 | 141 |
| Accepted | 14 | 41 |
| Rules usable on ingested telemetry | 9 | 32 (30 whole, 2 in part) |
| Groups with a usable rule | 8 | 15 |

The 15: APT28, APT29, APT32, APT33, Andariel, Equation, Lazarus Group, Lotus Blossom, MuddyWater, Mustang Panda,
OilRig, Sandworm Team, TeamPCP, Turla, ZIRCONIUM. Nine accepted rules are not usable yet: six need a log source the
platform does not ingest (Windows System log service installs — four rules; a DNS-server log; a firewall log), one
needs proxy logs, and two cannot be translated exactly.

**Checks added.**

- `tests/test_actor_rule_known_answers.py`: for **every** generated rule, an event carrying exactly the artefact the
  rule looks for — built from the rule's own conditions and put through the real source adapter — makes that rule
  fire and name its Group, and the same event with neutral values makes no actor rule fire. Two Linux rule branches
  are listed as not exercised (Sysmon-for-Linux input), by name, in the test.
- `scripts/measure_actor_rule_firings.py` → `data/validation/actor-rule-firings.json`: the false-lead measurement of
  the Validation section, now reproducible and re-run for the larger pack (result below).
- Detection Coverage gains "Groups this platform can name": the Groups with a usable accepted rule, out of all
  active Groups, and for each reviewed rule the basis of its association.

**Measured (2026-10-11).** `actor-rule-firings.json`: 100 generated rules over the 11 pinned recordings, 1,146,524
observations — **1 firing**: the CosmicDuke service name (`javamtsup`, Security 4697) in `otrf-apt29-day1`. That
recording is the public emulation of APT29, whose plan installs a service under the name published for APT29's own
malware, so the rule fired on exactly the artefact it was written for and the investigation's verdict is now
`actor_specific_evidence`: a lead to APT29, the recording's known answer. The other ten recordings — a second APT29
day in which that step does not occur, two APT3 emulations (no accepted APT3 content exists) and seven tool tests —
fire nothing. Known-answer checks: verdicts naming an actor 1 of 4, naming a wrong actor 0.

This is the limit stated in D4 seen from the other side: an emulation that copies a Group's published artefact
produces that Group's lead. The lead is correct about the artefact and says so; it is not proof of who ran it.

**Still not established** (unchanged from Validation): that these rules fire on the real malware in the field, and
how often a firing is the named Group. The known-answer events prove the path from artefact to lead, not field
recall. 161 of 176 active Groups have no such content; for them the verdict stays "no actor can be singled out".
