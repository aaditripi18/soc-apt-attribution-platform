# ADR-0011 — Cloud telemetry (ADR-0008 Wave 2, second format family)

- **Status:** ACCEPTED (2026-10-06, owner delegation on the recommended Wave 2 order: Linux → cloud → network +
  IOC layer → macOS). Data downloaded with owner approval (D7).
- **Builds on:** ADR-0008 (acceptance standard D2, one authoritative source per kind D3, record shapes D4, domain
  additions D5), ADR-0007 (Sigma import, field map, false-coverage guards), ADR-0010 D2 (product / OS scope),
  ADR-0003 (correlation; Amendments B, E, F, G), ADR-0005 / 0006 (attribution and calibration are format-agnostic).

## Context — measured, not assumed

Against the pinned Sigma release (`r2026-07-01`, Core++), cloud logsources would add **34 ATT&CK technique ids**
with no imported rule today, **27 of them used by active Groups** — the largest remaining format gain. Their users
are the actors for whom cloud is the battlefield: APT29 (11 of the 27), Scattered Spider (10), LAPSUS$ (10),
Storm-0501 (9), APT28, ShinyHunters, HAFNIUM, Volt Typhoon, TeamTNT.

| Sigma logsource | Rules | New ids | Fields read (most frequent) |
|---|---|---|---|
| `aws/cloudtrail` | 37 | 11 | `eventSource`, `eventName`, `userAgent`, `errorCode`, `userIdentity.arn` |
| `azure/auditlogs` | 38 | 5 | `properties.message`, `Category`, `OperationName`, `Status`, `ActivityDisplayName` |
| `azure/activitylogs` | 23 | 6 | `operationName`, `CategoryValue`, `ResourceProviderValue`, `ResourceId` |
| `azure/signinlogs` | 20 | 3 | `ResultType`, `ResultDescription`, `Status`, `AuthenticationRequirement` |
| `azure/riskdetection`, `azure/pim` | 26 | 3 | `riskEventType` |
| `m365/*` | 16 | 6 | `eventSource`, `eventName`, `status`, `Operation`, `Workload` |
| `okta/okta` | 9 | 5 | `eventType`, `displayMessage`, `actor.alternateId` |
| `github/audit`, `bitbucket/audit` | 21 | 10 | `action`, `auditType.*` |
| `gcp/*`, `kubernetes/*` | 19 | 9 | `gcp.audit.method_name`, `protoPayload.*`, `verb`, `objectRef.*` |

**Real data** (`splunk/attack_data` at `a28608b5`, Apache-2.0, 243 recordings + 194 descriptors, 74.1 MB, every
file verified against the commit): each recording is labelled by ATT&CK technique in its descriptor. The records
come in these shapes —

| Shape | Recordings |
|---|---|
| AWS CloudTrail native JSON (one event per line) | ~49 |
| Amazon Security Lake **OCSF** (a different normalized schema) | ~33 |
| Entra ID audit / sign-in — Azure Monitor diagnostic export (`category`, `operationName`, `properties`) | ~37 |
| Office 365 Management Activity API — unified audit log (`Operation`, `Workload`, `Actor`) | ~32 |
| Okta System Log | ~15 |
| Entra sign-ins via Microsoft Graph, Azure activity log, GitHub, Google Workspace, Kubernetes audit | ~31 |
| Splunk search exports (`preview` / `result` wrappers — not source records) | 6 |

## Decisions

**D1 — Order.** *Batch A:* Entra ID (audit and sign-in, diagnostic export) and Office 365 (Management Activity) —
the APT29 / Scattered Spider / LAPSUS$ / Storm-0501 surface. *Batch B:* AWS CloudTrail (native). *Batch C:* Okta,
GitHub, Google Workspace, Kubernetes audit, Azure activity log. *Not now:* Amazon Security Lake OCSF (a second
normalized schema for the same events — a record shape to add later, ADR-0008 D4) and Splunk search exports
(refused: they are query results, not source records).

**D2 — Exact, per-source fields; no cross-provider guessing.** Sigma's cloud rules use each provider's native
field names, and the Azure rules are written against the **Log Analytics / Sentinel table layout** (`ResultType`,
`OperationName`, `ActivityDisplayName`), while the downloaded Entra data is the **diagnostic export** layout
(`operationName`, `properties.resultType`, …). A Sigma field is mapped only where a documented, exact
correspondence between the two layouts exists (Microsoft's own schema documentation); anything else is a telemetry
gap reported per rule, never approximated. Each source keeps its native values in its own entity group (D3);
ECS-aligned fields (`user`, `network.source.ip`, `user_agent`, `event.action`, `event.outcome`, `cloud.*`) are
filled only where the value means the same thing.

**D3 — Domain additions.** A `cloud` group (ECS `cloud.provider`, `cloud.account.id`, `cloud.region`,
`cloud.service.name`) and, per provider, a source group holding the native fields Sigma reads (e.g. `aws_cloudtrail`:
`event_source`, `event_name`, `error_code`, `user_identity_type` / `arn`, request parameters Sigma reads;
`entra`: `category`, `operation_name`, `result_type`, `result_description`, `status`, `activity_display_name`,
`authentication_requirement`, `risk_event_type`; `o365`: `workload`, `operation`, `result_status`, `application_id`,
`object_id`; `okta`: `event_type`, `display_message`, `outcome`). `user_agent` (ECS `user_agent.original`).
Values are kept exactly as logged.

**D4 — Cloud is its own platform scope.** Cloud Observations have no host. Every cloud adapter sets
`cloud.provider`; cloud logsources are scoped by `event.dataset` (Elastic's dataset names, e.g.
`azure.signinlogs`, `azure.auditlogs`, `o365.audit`, `aws.cloudtrail`, `okta.system`); and the endpoint product
scopes (ADR-0010 D2) gain a negated `cloud.provider exists`, so no Windows or Linux rule can fire on a cloud
event (today a host-less event would pass the Windows "not Linux / macOS" condition) — proven on all the real
cloud data, as the OS scope was.

**D5 — Event time.** Each provider's own event time field, which is UTC and zoned in all observed shapes
(`eventTime`, `time`, `CreationTime`, `published`); a value without a zone is refused, never assumed UTC.

**D6 — Correlation.** Cloud events have no processes. The decision follows ADR-0003's test exactly: an identity
(user, service principal, IAM role) or a sign-in session is a **container** for many actions → contextual, never
group-forming (§6–8). A provider-asserted identifier of **one operation instance** — e.g. a request or correlation
id that the provider documents as identifying a single operation whose records are split across several log
entries — would be structural, like `SAME_AUDIT_EVENT`; each candidate is decided per provider with real-data
evidence in its batch (an ADR-0003 amendment), not assumed here. Until then cloud Evidence forms single-Evidence
units (Amendment F), with identity / IP / session as contextual links.

**D7 — Data.** As above; downloaded with owner approval (2026-10-06) by `scripts/acquire_linux_telemetry.py --set
cloud` (commit-pinned, every file verified against its git blob id or LFS pointer), cache git-ignored, tracked
selection and manifest under `data/telemetry-samples/splunk-attack-data-cloud/`, a small golden-record file per
batch with the Apache-2.0 notice.

**D8 — Validation per ADR-0008 D2,** plus: detection measured against each dataset's own ATT&CK label (resolved
through ATT&CK's `revoked-by`, as for Linux), the product-scope parity check of D4 on all real cloud data, and a
statement of what cannot be measured honestly — these datasets are short, single-technique simulations, so they
validate parsing and rules, not attribution of a cloud intrusion.

## Consequences

- Up to 27 group-used techniques become detectable (measured after each batch, not claimed now); cloud-heavy
  actors (APT29, Scattered Spider, LAPSUS$, Storm-0501) gain the evidence that distinguishes them.
- Cloud attribution will mostly rest on single-event evidence until an operation-instance link is proven per
  provider (D6) — recorded honestly as a limit, not papered over.
- The endpoint product scopes change once more (D4): every endpoint rule's hash changes, and stored artifacts are
  regenerated with the new pack, as for ADR-0010 D2.

## Alternatives rejected

- **Normalizing every provider to one generic "cloud audit" schema.** Loses the exact native values Sigma matches
  and invents equivalences between providers.
- **Treating sign-in sessions or identities as structural.** Violates ADR-0003 §6: a session or identity is a
  container for unrelated actions.
- **Consuming the OCSF Security Lake records first.** A second normalization layer over the same events; the
  native CloudTrail records are the authoritative source and Sigma's rules are written against them.
