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

## Amendments (implementation, 2026-10-06)

**A1 — D4, the endpoint exclusion uses the cloud account, not the provider.** Elastic's own Office 365 pipeline
sets no `cloud.provider`, and the O365 records state none, so none is invented. Every cloud adapter instead sets
the tenant / organization / account the record belongs to (`cloud.account_id`: Entra `tenantId`, O365
`OrganizationId`, CloudTrail `recipientAccountId` — a fact in every record). Endpoint products (`windows`,
`linux`) carry a negated `cloud.account_id exists`; `azure` rules require `cloud.provider = azure`, `aws` rules
`cloud.provider = aws`, `m365` rules a cloud account. (The field path is the Observation's own
`cloud.account_id`, the ECS `cloud.account.id`.)

**A2 — D5, documented UTC.** O365 `CreationTime` is written without a zone, and Microsoft's common schema defines
it as UTC. A zone stated by the source's documentation is not an assumption: the value is read as UTC, the
documentation is cited in the adapter, and a `CreationTime` that carries a zone keeps it. An undocumented
zone-less value is still refused (e.g. Entra `RiskyUsers` `time = "4/26/2023 6:58:15 PM"`).

**A3 — Event time per Entra category,** from the field Microsoft documents for the event, not the export's
`time`: sign-ins `properties.createdDateTime` (sign-in initiated), audit `properties.activityDateTime`, risk
detections `properties.activityDateTime` (when the risky activity happened, not when it was detected).

## Record — batch A: Entra ID and Office 365 (2026-10-06)

- *Adapters:* `sources/entra.py` (Azure Monitor diagnostic export; sign-in, non-interactive, service-principal
  and managed-identity sign-ins → `azure.signinlogs`; audit → `azure.auditlogs`; user / service-principal risk
  events → `azure.identity_protection`) and `sources/o365.py` (Management Activity API → `o365.audit`). Other Entra
  categories (Graph activity, risky-user state, …) have no Sigma logsource and are refused, counted. Domain groups
  `cloud`, `user_agent`, `entra`, `o365` (`observation/1` extended, persistence and mapping wired). Records are
  recognised by their own schema in the pipeline (`ENTRA_CHANNEL`, `O365_CHANNEL`), never by guess.
- *Field map `sigma-field-map/12`:* the Azure rules use Log Analytics column names; the export carries the same
  values under its own names (one diagnostic setting feeds both destinations). Mapped one-to-one only:
  sign-ins `ResultType`, `ResultDescription`, `AuthenticationRequirement`, `RiskState`, `ResourceDisplayName`,
  `AppId`, `HomeTenantId`, `ResourceTenantId`, `conditionalAccessStatus`, `DeviceDetail.isCompliant`,
  `userAgent`; audit `OperationName` / `operationName`, `Category` (the audit record's own category),
  `ActivityDisplayName`, `LoggedByService`, `properties.result`; risk `riskEventType`; O365 `Operation`,
  `Workload`, `ResultStatus`, `ObjectId`, `ApplicationId`, `Directionality`, `DeliveryAction`.
  **Gaps, by reason:** `properties.message` (23 audit rules, 2 sign-in rules) is in no Microsoft schema and is not
  mapped by SigmaHQ's own Kusto backend (`pySigma-backend-kusto` `azuremonitor/mappings.py`), so its intended
  column is undocumented; `Status` in sign-in rules is a JSON object compared to a string; `TargetResources` /
  `InitiatedBy` are arrays / objects; `m365/threat_management`, `m365/exchange` read `eventSource` / `eventName` /
  `status`, which are not Management Activity fields; `RequestType` is an `ExtendedProperties` entry;
  `azure/pim` and `azure/activitylogs` have no source in the data.
- *Real data (`scripts/report_cloud_telemetry.py`):* Entra **579** unique Observations (refused: 39 Graph
  activity, 2 risky-user state records); O365 **1,413** (refused: 2 records with `CreationTime …17:08:65`, an
  impossible time). **Only `azure` rules fire on Entra and only `m365` rules on O365** (D4 parity). Documented-
  label recall: Entra **6 / 40** labelled datasets, O365 **2 / 50**. The misses are content gaps, checked one by
  one: the AzureHound dataset is Graph-activity only; the federation dataset logs `Set domain authentication`
  where the rule expects `Set federation settings on domain`; the role-assignment rules need `TargetResources`;
  the O365 alert rules read fields the API does not have; most labelled datasets are behaviours Sigma has no
  single-event rule for (password spray, high-volume access, consent grants).

## Record — batch B: AWS CloudTrail (2026-10-06)

- *Adapter:* `sources/cloudtrail.py`, native records only (`class_uid` marks OCSF, not read — D1).
  `eventTime` must carry a zone. `aws_cloudtrail` group: CloudTrail's own fields plus the nested values Sigma
  reads (`additionalEventData.MFAUsed`, `responseElements.ConsoleLogin`, `requestParameters.attribute` /
  `enable`, `responseElements.publiclyAccessible`, `…pendingModifiedValues.masterUserPassword`).
  `sourceIPAddress` keeps CloudTrail's meaning — **in the data 21,422 of 43,152 records carry
  `eks.amazonaws.com` there** — and is copied to `network.source.ip` only when it is an IP address.
  `event.outcome`: `failure` for an `errorCode`, else a sign-in's own `ConsoleLogin` result (a failed console
  login has no `errorCode`), else absent.
- *Field map:* `aws/cloudtrail` uses CloudTrail's paths as-is (`eventSource`, `eventName`, `eventType`,
  `errorCode`, `errorMessage`, `sourceIPAddress`, `userAgent`, `userIdentity.type` / `.arn`, and the nested values
  above). Gaps: `requestParameters` matched as a whole (substring over a JSON object), container-definition
  commands (an array inside an array), `status` (not a CloudTrail field); a field-reference and a regular
  expression stay translation gaps.
- *Real data:* **21,690** unique Observations from 43,152 records, none refused; **only `aws` rules fire**;
  documented-label recall **9 / 40** labelled datasets.

## Record — batch C: Azure Activity, Okta, GitHub, Kubernetes (2026-10-06)

- *Adapters:* `sources/azure_activity.py` (Activity Log, Azure Monitor REST form; `.value` of each localizable
  object = the Log Analytics `AzureActivity` columns), `sources/okta.py` (System Log), `sources/github_audit.py`
  (enterprise / organization audit-log export; `@timestamp` epoch milliseconds, exact integer arithmetic),
  `sources/kubernetes_audit.py` (`audit.k8s.io/v1` events; id = `auditID` + `stage`; event time
  `requestReceivedTimestamp`). Shared exact readers moved to `sources/json_values.py` (the batch A/B adapters
  now use them too; doing so caught Entra's `callerIpAddress` being copied to `network.source.ip` unchecked —
  it is now copied only when it is an IP address).
- *Scope (A1 refined):* Okta, GitHub and Kubernetes events name **no** cloud account (an Okta System Log event
  carries no org id; a Kubernetes audit event no cluster id), so none is invented: they set no `cloud` group,
  their product scope is empty and their dataset scope (`okta.system`, `github.audit`,
  `kubernetes.audit_logs`) is the whole scope. No endpoint rule can match them: endpoint logsources require an
  `event.category` / Windows dataset these adapters never set — proven on every real record (each golden record
  fires at most its own product).
- *Field map:* `okta/okta` (`eventType`, `legacyEventType`, `displayMessage`, `actor.alternateId`,
  `outcome.result` / `.reason`, `securityContext.isProxy`, `debugContext.debugData.behaviors` /
  `.logOnlySecurityData`), `github/audit` (`action`), `kubernetes/{audit,application}` (`verb`, `requestURI`,
  `userAgent`, `responseStatus.code`, `objectRef.*`), `azure/activitylogs` (`operationName` /
  `OperationNameValue`, `CategoryValue`, `ResourceProviderValue`, `ResourceId`, `properties.message` — which
  this schema does carry). Gaps: Okta `target.displayName` (an array of objects), a top-level `apiGroup`
  (not a Kubernetes audit field), regular-expression and keyword rules (translation gaps).
- *Real data:* Azure Activity 17, Okta 98, GitHub 16, Kubernetes 12 unique Observations, **none refused**; each
  source fires only its own product. Documented-label recall: Okta **1 / 16**; Azure Activity 0 / 3 (all three
  datasets are Automation runbook operations, for which Sigma has no rule); Kubernetes 0 / 6 (scanning, cron
  jobs, daemonsets — no matching single-event rule); GitHub not measurable — its datasets ship **no YAML
  descriptor** at the pinned commit, the technique appears only in the directory path, and labels are taken
  from descriptors only. Detection on these sources is therefore proven by golden tests on real records with
  one labelled change (Key Vault delete, pod in `kube-system`, `exec`, proxied Okta session).
- *Not now (D1 refined):* **Google Workspace and GCP.** Sigma's `gcp/google_workspace.*` rules read the Cloud
  Logging export form (`protoPayload.*`, `eventService: admin.googleapis.com`); the available data is the Admin
  SDK Reports API form (`kind: admin#reports#activity`, `events[].name`). No exact correspondence is documented
  between the two, and no GCP audit records are in the data — both wait for matching data. Bitbucket: no data.

## Result — batches A–C

Pack imported rules 1,715 → **1,825** (+110: Azure / M365 38, CloudTrail 31, Activity / Okta / GitHub /
Kubernetes 41), ATT&CK ids with an imported rule 310 → **336**, nothing lost. Active techniques covered 302 →
**328**; **group-used techniques covered 252 → 273 of 498**; Groups with ≥ 5 covered 144 → 145, ≥ 10 covered
109 → 111. As D8 states, these datasets are short single-technique simulations: they validate parsing, scoping
and rules — not attribution of a cloud intrusion. D6 is unchanged: cloud Evidence forms single-Evidence units
with user and identity as contextual links. A Kubernetes `auditID` (shared by one request's stage events) is a
provider-asserted operation-instance identifier of the kind D6 anticipates; it is not adopted as a structural
link yet because the data holds one stage per request (no two Observations to link) — recorded for when it does.
