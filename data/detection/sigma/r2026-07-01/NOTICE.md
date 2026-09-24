# NOTICE — SigmaHQ detection rules (Detection Rule License 1.1)

`sigma_core++.zip` in this directory is an unmodified release asset of the
[SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) project, release
[`r2026-07-01`](https://github.com/SigmaHQ/sigma/releases/tag/r2026-07-01)
(SHA-256 recorded in `manifest.json`).

The rules are licensed under the **Detection Rule License (DRL) 1.1**:
<https://github.com/SigmaHQ/Detection-Rule-License>. Copyright remains with
each rule's authors, as named in each rule's `author` field.

`generated/` contains rules **derived** from those rules by this project's
build-time importer (`src/attribution_platform/detection_content/`, ADR-0007).
As DRL 1.1 requires, the derived material keeps:

- **Author attribution** — every generated rule's technique mapping
  (`mapping_basis`) names the original Sigma rule id, title and author, and
  that text is carried into every Evidence claim produced when the rule
  matches.
- **A link to the rule** — the import report lists each source rule's path and
  a `rule_url` pinned to this release tag; each generated rule's
  `rule_source` is `sigma:<original rule id>`.
- **This license notice** — this file, referenced from the generated pack's
  `provenance.license` field.

The derived rules are translations, not copies: conditions are rewritten into
this project's predicate language and some rule branches are omitted where they
cannot be translated exactly (see the import report). They carry no warranty,
as the DRL states.
