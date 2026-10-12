# ADR-0022 — Attack chain, observables, an analyst assistant, and a front page that states the purpose

- **Status:** ACCEPTED (2026-10-12, owner instruction: the site must present itself as an APT attribution platform
  for an analyst — technique identification, ATT&CK mapping, attack chains, IOCs, attribution — show everything
  that leads to its answer, show nothing fake, keep past investigations on their own page, and include an AI
  assistant that knows the investigation, answers questions and can summarise).
- **Builds on:** ADR-0019 (activity route), ADR-0021 (profile match, response), ADR-0013 (advisory indicators),
  ADR-0020 (the guards of the one input route), CLAUDE.md ("never fabricate cybersecurity functionality").

## Decisions

### D1 — The attack chain is the order of observation, and says so

The Attack chain tab draws one stage per ATT&CK tactic with detections, **ordered by when that tactic was first
observed** (ties in matrix order), with the techniques of each stage in the order they were first seen. It is
derived in the browser from the existing activity route (`derive.ts::attackChain`, unit-tested).

It does not claim that one stage caused the next: the page states that the order is the order of first
observation and that causality — which process started which — is shown inside each activity cluster's sequence
(ADR-0004), which is built from process lineage. The tab lists those clusters in time order with a link to each
sequence, so the tactic-level chain and the exact process chain are one click apart. A technique ATT&CK files
under several tactics appears in each of those stages, as on the matrix.

### D2 — Observables: values the events state, never a verdict

`GET /investigations/<id>/observables` lists every file hash (process image and file), destination address and
queried domain stated by an Observation that grounds Evidence in a unit, with what it was seen with, the hosts,
units and techniques, how often and when, and — where the value equals an indicator of a pinned advisory
(ADR-0013) — that advisory and the actor it names. Addresses are labelled internal or external by the standard
library's own classification.

Calling these "indicators of compromise" without qualification would be false: a detection that fires on a system
binary lists that binary's hash. The page therefore says they are values from detected activity and candidates to
verify, marks a value as known-bad only where an advisory matches, and reminds the reader to check a hash against
their own baseline. No reputation is invented. A CSV export is generated in the browser from the served rows.

### D3 — An assistant grounded in a digest of stored results

`POST /api/assistant` takes `{investigation_id, messages}` and returns a generated answer.

- **What the model receives.** A digest built by `api/assistant.py::build_digest` from the stored records the pages
  show: source, counts, hosts, time range, observed techniques with counts and first-seen times, the attack chain,
  the verdict's statement and reasons, identified Groups and the evidence for them, the closest behavioural
  profiles and clusters with overlap, observables, mitigations, and the ran-versus-detected outcomes where present.
  **Not the logs**: no raw event and no command line is in it (tested).
- **What it is told.** To answer only from the digest; to say when the digest lacks the answer and name the page
  that has it; never to call a Group responsible unless the digest lists it as identified; to describe overlap as
  similarity, not probability; not to call an observable malicious without an advisory match; to mark general
  ATT&CK knowledge as general; not to give attack instructions. The prompt is versioned (`assistant/1`) and tested
  for these rules.
- **What that guarantees, and what it does not.** The digest bounds what the assistant *knows*; instructions do
  not bound what a language model *says* with certainty. So the panel states that answers are generated and can
  be wrong, and every fact it can cite is on a page the analyst can open. The assistant is a way to read the
  results, not a source of results: nothing it says is stored or fed back into any analysis.
- **Conversation.** The browser keeps the conversation (per investigation, for the tab's session) and sends it with
  each question, so follow-ups have context; the server keeps no transcript. Messages must alternate user /
  assistant, at most 40 of at most 4,000 characters; no client-supplied system message is accepted.
- **Off by default.** The assistant exists only if the operator set `ANTHROPIC_API_KEY` in the environment of the
  serving command (model from `ATTRIBUTION_ASSISTANT_MODEL`, default `claude-opus-5-5`). Without a key
  `GET /api/assistant` reports `enabled: false`, the panel says so, and **nothing is sent anywhere**. With a key, a
  question sends the digest and the conversation to the model provider's API — the panel says this next to the
  input. The key is used only as the request header: it is in no response, log line or error (tested), and a
  provider error is reported by status code alone.
- **Callers.** As for uploads (ADR-0020): loopback only, same origin only, declared length required, body at most
  256 KiB. Called over HTTPS with the standard library; no SDK dependency is added.

### D4 — A front page for the purpose; investigations on their own page

The root page states what the platform does for an analyst, the five steps of an analysis, and what each log
source yields, with the entry point (Analyze logs) first. Its figures — detectable techniques, rules, Groups
profiled, Groups identifiable — are read from the coverage report and the Group catalogue, not typed in. Past
investigations are not advertised there: they are on the Investigations page.

Investigation tabs, in the order an analyst works: Overview, Attack chain, ATT&CK matrix, Timeline, Indicators,
Attribution, Response, Detection validation.

## Consequences

- With no API key the platform is unchanged apart from a panel that says the assistant is not enabled.
- Using the assistant sends a summary of results to a third party. That is the operator's decision, made by
  setting the key; the digest's contents are fixed by code and documented here.
- The assistant cannot answer questions about raw events (exact command lines, full paths); it is instructed to
  point to the Evidence tab instead.
- Observables are limited to what the adapters keep: hashes need hash logging in the source, addresses and
  domains need network and DNS events.

## Checks

`tests/test_assistant_and_observables.py`: observables of a real record (value, context, techniques, advisory
match, no judgement keys, ordering); the digest of a real investigation (techniques, chain order, identified
Groups, no command line, no likelihood wording); the request sent to the provider (system prompt rules, digest,
conversation, key only in the header); malformed conversations refused; provider failures reported without their
body or the key; no key, no service; the HTTP route and its refusals; a server without a key. Frontend:
`derive.test.ts` (attack-chain ordering).

## Amendment A — the assistant's model runs on this machine (2026-10-12, owner instruction)

The owner asked for a free model served by Ollama instead of a paid provider API. This replaces the
"Off by default" and "Callers" provider details of D3; the digest, the rules, the conversation handling and the
route guards are unchanged.

- **Where the model runs.** A model served by [Ollama](https://ollama.com) on the same machine
  (`POST /api/chat`, not streamed). The address comes from `ATTRIBUTION_ASSISTANT_URL` (default
  `http://127.0.0.1:11434`) and **must be an http loopback address**: any other address is refused when the
  service is built (tested), so a question cannot leave the machine. There is no key and no account.
- **Model.** `ATTRIBUTION_ASSISTANT_MODEL`, default `llama3.1:8b`. The model is not shipped with the platform;
  the operator installs Ollama and pulls it.
- **Availability is reported, not assumed.** `GET /api/assistant` asks Ollama which models it has and answers
  `enabled` with a `reason` when it is not: `not_running`, `model_missing`, or `off` (`--no-assistant`). The panel
  shows the matching instruction.
- **Context window.** Ollama's default window is smaller than a digest (measured on the reference recordings:
  18,000–39,000 characters), and a prompt that does not fit is silently truncated — which would cut facts out
  from under the rules. Each request therefore asks for a window sized to it (characters / 3 plus the reply,
  rounded up to 4,096, between 8,192 and 32,768 tokens; tested). The digest is now rendered as compact JSON to
  cut its length by about a quarter.
- **Cost of the change, stated.** A small local model follows the grounding rules less reliably than a large
  hosted one and is slower: on a CPU the first answer about a large investigation can take minutes (later
  questions reuse the read prompt). The panel's notice that answers are generated and must be checked against
  the evidence therefore matters more, not less. Nothing the assistant says is stored or used by any analysis.
- **Version.** `assistant/2`.

- **First real answers (2026-10-12).** With `llama3.1:8b` on the owner's laptop (CPU only), two questions about the
  smallest reference investigation were answered from the digest: the summary matched the stored results and the
  model declined to name a group, as instructed. Each answer took two to four minutes, and the summary listed hashes
  of ordinary system programs as indicators without saying they are only candidates to verify.
- **Identification and advisory leads are separate (`assistant/3`, 2026-10-12).** The digest listed a group named by an
  advisory indicator under `identified_groups`, beside groups identified by their own tooling. They are now two lists,
  and the model is told to report an advisory match as a lead to verify and never as an identification.
