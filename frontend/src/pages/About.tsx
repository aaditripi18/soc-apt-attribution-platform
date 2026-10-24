import type { ReactNode } from "react";
import { TrackRecordLine, VERDICT_LABEL } from "../components/Assessment";
import { Badge, Card, CardHeader, ErrorState, Id, PageHeader, PageSkeleton, Td, Th } from "../components/ui";
import {
  paths,
  useApi,
  type Coverage,
  type KnownAnswerCase,
  type Measurements,
  type TechniqueCatalogue,
  type UnseenReport,
  type Validation,
} from "../lib/api";
import { integer } from "../lib/format";
import { links } from "../lib/router";

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="grid grid-cols-[14rem_1fr] items-center gap-4 border-b border-outline-variant/40 px-4 py-2 last:border-b-0">
      <dt className="text-body-md text-on-surface-variant">{label}</dt>
      <dd className="min-w-0 break-all font-mono text-code-md text-on-surface">{children}</dd>
    </div>
  );
}

const STAGES: { name: string; text: string }[] = [
  {
    name: "Telemetry",
    text: "A recording (Sysmon, Windows Security, PowerShell, Zeek, cloud audit logs) is read by a source adapter into ECS-aligned Observations. Each keeps a reference to the raw event it came from.",
  },
  {
    name: "Detection",
    text: "Pinned Sigma and Elastic rules, translated exactly, are evaluated on every Observation. A match produces Evidence: one rule, one observation, one ATT&CK technique, with the matched values and the mapping basis in its claim. A few Elastic rules count several events: a threshold rule detects only when enough matching events fall close enough together to be counted under any rule schedule, and a first-time-seen rule only when the logs themselves cover the history it compares against.",
  },
  {
    name: "Correlation",
    text: "Evidence is joined into attribution units only by structural links — same process, parent/child lineage, injection, same audit event. A shared host or user alone never joins two things.",
  },
  {
    name: "Sequence",
    text: "Within a unit, steps are ordered where lineage or timestamps resolve the order, and left explicitly unordered where they do not.",
  },
  {
    name: "Comparison",
    text: "The techniques supported by core Evidence are compared with every ATT&CK Group and Campaign profile. For each technique, g is the share of active Groups recorded using it and D = 1 − g.",
  },
  {
    name: "Explanation",
    text: "The result is a set of facts: which candidates’ profiles include which observed techniques, what would tell them apart, and which advisory indicators coincide. Groups are ordered by behavioural overlap, and identified only on evidence specific to them.",
  },
];

function positions(item: KnownAnswerCase): string {
  const seen = item.orderings.map((o) => o.known_actor_position).filter((p): p is number => p !== null);
  if (seen.length === 0) return "—";
  const groups = Math.max(...item.orderings.map((o) => o.groups_ordered));
  return `${Math.min(...seen)}–${Math.max(...seen)} of about ${groups}`;
}

function KnownAnswerChecks({ validation }: { validation: Validation }) {
  return (
    <Card padded={false}>
      <CardHeader
        title="Validation on known cases"
        hint="Recordings of emulated intrusions and tool tests where the answer is known in advance: what the platform concluded, and where the true group fell when ordered by overlap alone."
      />
      <p className="border-b border-outline-variant/70 px-4 py-3 text-body-lg text-on-surface-variant">
        The platform identified a group in {validation.summary.verdicts_naming_an_actor} of these{" "}
        {validation.summary.cases} cases and a wrong one in {validation.summary.verdicts_naming_a_wrong_actor}.{" "}
        <TrackRecordLine validation={validation} /> This is the measured reason identification relies on group-specific
        evidence and overlap is presented as similarity.
      </p>
      <div className="overflow-x-auto">
        <table className="w-full border-collapse text-body-md">
          <thead>
            <tr>
              <Th>Recording</Th>
              <Th>Known answer</Th>
              <Th>Platform conclusion</Th>
              <Th>Its techniques observed</Th>
              <Th>Its position by overlap alone</Th>
              <Th>Top of the overlap order</Th>
            </tr>
          </thead>
          <tbody>
            {validation.cases.map((item) => {
              const named = [...new Set(item.orderings.map((o) => o.would_name).filter((n): n is string => !!n))].sort();
              return (
                <tr key={item.investigation_id}>
                  <Td className="font-medium text-on-surface">
                    <span title={item.known_basis}>{item.source_id}</span>
                  </Td>
                  <Td>
                    {item.known_actor ? (
                      <span className="text-on-surface">
                        {item.known_actor.name} <span className="font-mono text-code-sm text-outline">{item.known_actor.attack_id}</span>
                      </span>
                    ) : (
                      <span className="text-on-surface-variant">no actor (tool test)</span>
                    )}
                  </Td>
                  <Td>
                    <Badge tone={item.verdict === "actor_specific_evidence" ? "primary" : "muted"}>{VERDICT_LABEL[item.verdict]}</Badge>
                  </Td>
                  <Td className="font-mono text-code-md">
                    {item.known_actor
                      ? `${item.known_actor_techniques_observed} of ${item.observed_techniques} (profile ${item.known_actor_profile_techniques})`
                      : "—"}
                  </Td>
                  <Td className="font-mono text-code-md">{positions(item)}</Td>
                  <Td className="max-w-md text-on-surface-variant">{named.join(", ") || "—"}</Td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      <p className="border-t border-outline-variant/70 px-4 py-2.5 font-mono text-code-sm text-outline">
        {validation.summary.orderings_measured} orderings measured · {validation.pinned.attack_kb_version}
      </p>
    </Card>
  );
}

function percent(part: number, whole: number): string {
  return whole ? `${Math.round((100 * part) / whole)}%` : "—";
}

function UnseenRow({ label, report, note }: { label: string; report: UnseenReport; note: string }) {
  const s = report.summary;
  const found = s.found_exactly + s.found_as_parent_or_sub;
  return (
    <tr className="align-top">
      <Td>
        <div className="text-on-surface">{label}</div>
        <div className="mt-0.5 max-w-sm text-body-sm text-on-surface-variant">{note}</div>
      </Td>
      <Td className="font-mono text-code-md">
        {integer(report.recordings_investigated)} of {integer(report.recordings_selected)}
      </Td>
      <Td className="font-mono text-code-md">
        {integer(found)} of {integer(s.authors_techniques)} ({percent(found, s.authors_techniques)})
        <div className="text-code-sm text-outline">{integer(s.missed_but_shown)} more shown, not counted</div>
      </Td>
      <Td className="font-mono text-code-md">{integer(s.counted_but_not_listed_by_authors)}</Td>
      <Td className="font-mono text-code-md">{integer(s.recordings_naming_an_actor)}</Td>
    </tr>
  );
}

/** ADR-0025 Amendment E and ADR-0027: counted techniques against what the dataset
 * authors themselves list as performed - the platform's recall, as measured. */
function TechniqueMeasurements({ measurements }: { measurements: Measurements }) {
  const truth = measurements.technique_ground_truth;
  const first = measurements.unseen_first_run;
  const unseen = measurements.unseen;
  const splunkBaseline = measurements.unseen_splunk_baseline;
  const splunkImproved = measurements.unseen_splunk_improved;
  return (
    <Card padded={false}>
      <CardHeader
        title="Measured against the dataset authors’ own technique lists"
        hint="What the platform counted, compared with what the people who recorded the data say they performed. “Found” includes a parent or sub-technique of the listed one; techniques counted but not listed are not errors by that fact — the authors list the procedure, not everything on the host."
      />
      <table className="w-full">
        <thead>
          <tr>
            <Th>Test</Th>
            <Th>Recordings read</Th>
            <Th>Authors’ techniques counted</Th>
            <Th>Counted, not listed</Th>
            <Th>Naming an actor</Th>
          </tr>
        </thead>
        <tbody>
          {truth && (
            <tr className="align-top">
              <Td>
                <div className="text-on-surface">LSASS credential-dumping tool runs</div>
                <div className="mt-0.5 max-w-sm text-body-sm text-on-surface-variant">
                  Seven single-tool recordings, all used during development{truth.snapshot ? ` · ${truth.snapshot}` : ""}.
                </div>
              </Td>
              <Td className="font-mono text-code-md">7</Td>
              <Td className="font-mono text-code-md">
                {integer(truth.all.found_exactly + truth.all.found_as_parent_or_sub)} of {integer(truth.all.authors_techniques_in_recordings)} (
                {percent(truth.all.found_exactly + truth.all.found_as_parent_or_sub, truth.all.authors_techniques_in_recordings)})
              </Td>
              <Td className="font-mono text-code-md">{integer(truth.all.counted_but_not_listed_by_authors)}</Td>
              <Td className="font-mono text-code-md">—</Td>
            </tr>
          )}
          {first && (
            <UnseenRow
              label="Unseen test — first run, as pre-registered"
              report={first}
              note="105 recordings never used before, run once on a frozen build. The intake refused 44 (Security-only domain controllers, archive metadata) — reported, then fixed. Figures as first measured, with the authors’ pre-v19 technique ids unresolved; resolved through the pinned ATT&CK version they are 32 of 65 (ADR-0027)."
            />
          )}
          {unseen && (
            <UnseenRow
              label="Unseen test — after the fixes it exposed"
              report={unseen}
              note="The same recordings, now development data: intake and store faults fixed, and the rules they showed reviewed."
            />
          )}
          {splunkBaseline && (
            <UnseenRow
              label="Second unseen test — baseline"
              report={splunkBaseline}
              note="169 Splunk attack_data Windows Sysmon recordings, another lab and export, selected and registered before any content was read; run on the registration commit (ADR-0029)."
            />
          )}
          {splunkImproved && (
            <UnseenRow
              label="Second unseen test — after the changes made since"
              report={splunkImproved}
              note="The same recordings on the build frozen after the Event Log rules and Elastic sequence rules: no change in recall. 14 labels are techniques no Group is recorded using and can never be counted; on the other 150, 73 (49%)."
            />
          )}
        </tbody>
      </table>
    </Card>
  );
}

export function AboutPage() {
  const coverage = useApi<Coverage>(paths.coverage());
  const catalogue = useApi<TechniqueCatalogue>(paths.techniques());
  const validation = useApi<Validation>(paths.validation());
  const measurements = useApi<Measurements>(paths.measurements());

  if (coverage.state === "error") return <ErrorState failure={coverage.error} onRetry={coverage.reload} />;
  if (catalogue.state === "error") return <ErrorState failure={catalogue.error} onRetry={catalogue.reload} />;
  if (coverage.state !== "ready" || catalogue.state !== "ready") return <PageSkeleton />;

  const provenance = coverage.data.provenance;
  const sigma = provenance.sigma_import;
  const elastic = provenance.elastic_import;
  const streams = Array.isArray(elastic.data_streams) ? (elastic.data_streams as string[]) : [];
  return (
    <>
      <PageHeader
        eyebrow="Methodology"
        title="How detection and attribution work"
        description="Every result on this platform traces to a log event, a detection rule and a MITRE ATT&CK record you can open. This page explains how techniques are detected, how threat groups are matched, and how the method was validated."
      />
      <div className="space-y-6">
        <Card padded={false}>
          <CardHeader title="Attribution in two tiers" hint="What the platform can say about who is behind an intrusion, and on what basis." />
          <div className="grid grid-cols-1 gap-px bg-outline-variant/40 xl:grid-cols-2">
            <div className="bg-surface-low p-4">
              <Badge tone="primary">Identification</Badge>
              <h3 className="mt-2 text-headline-sm text-on-surface">Group-specific evidence</h3>
              <p className="mt-1.5 text-body-md text-on-surface-variant">
                A group is identified when the logs contain something only that group is known for: an artefact of its
                own tooling (a service name, file path, hash or payload string from published reporting), or an indicator
                a government advisory attributes to it. Every such rule was reviewed individually, and rules that also
                match generic activity, public tools or commodity malware were rejected. The{" "}
                <a href={links.actors({ evidence: "specific" })} className="text-primary hover:underline">
                  Threat Actors
                </a>{" "}
                page lists the groups this covers.
              </p>
            </div>
            <div className="bg-surface-low p-4">
              <Badge tone="tertiary">Behavioural profiling</Badge>
              <h3 className="mt-2 text-headline-sm text-on-surface">Overlap with group profiles</h3>
              <p className="mt-1.5 text-body-md text-on-surface-variant">
                For every tracked group, the platform measures how much of the observed behaviour its public ATT&amp;CK
                profile contains. Each observed technique is weighted by its rarity — one minus the share of groups
                recorded using it — so a technique nearly everyone uses counts for little and a rare one for a lot.
              </p>
              <p className="mt-2 rounded-sm border border-outline-variant/70 bg-surface-lowest px-3 py-2 font-mono text-code-md text-on-surface">
                overlap = Σ weight(observed ∩ profile) ÷ Σ weight(observed)
              </p>
              <p className="mt-2 text-body-md text-on-surface-variant">
                Groups with identical matches form a cluster: the evidence cannot separate them. Overlap measures
                similarity to a public profile. It is not the probability that a group is responsible — techniques are
                shared between groups, and well-documented groups overlap with almost anything — which is why
                identification rests on the first tier.
              </p>
            </div>
          </div>
        </Card>

        {validation.state === "ready" && <KnownAnswerChecks validation={validation.data} />}
        {measurements.state === "ready" && <TechniqueMeasurements measurements={measurements.data} />}

        <Card padded={false}>
          <CardHeader title="From logs to attribution" hint="Each stage is deterministic and keeps what it produced." />
          <ol className="grid grid-cols-1 gap-px bg-outline-variant/40 md:grid-cols-2 xl:grid-cols-3">
            {STAGES.map((stage, i) => (
              <li key={stage.name} className="bg-surface-low p-4">
                <div className="flex items-center gap-2">
                  <span className="flex h-6 w-6 items-center justify-center rounded-sm border border-primary/40 bg-primary/10 font-mono text-code-sm text-primary">
                    {i + 1}
                  </span>
                  <h3 className="text-headline-sm text-on-surface">{stage.name}</h3>
                </div>
                <p className="mt-2 text-body-md text-on-surface-variant">{stage.text}</p>
              </li>
            ))}
          </ol>
        </Card>

        <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
          <Card padded={false}>
            <CardHeader title="ATT&CK knowledge" hint="Pinned and hashed; every investigation records the version it used." />
            <dl>
              <Row label="Knowledge base">{provenance.attack_kb_version}</Row>
              <Row label="STIX bundle SHA-256">
                <Id value={provenance.attack_kb_sha256} />
              </Row>
              <Row label="Active techniques">{integer(catalogue.data.techniques.length)}</Row>
              <Row label="Active Groups">{integer(catalogue.data.active_groups)}</Row>
              <Row label="Tactics">{integer(catalogue.data.tactics.length)}</Row>
            </dl>
          </Card>
          <Card padded={false}>
            <CardHeader title="Sigma detection content" />
            <dl>
              <Row label="Release">{String(sigma.sigma_release ?? "—")}</Row>
              <Row label="Archive">{String(sigma.sigma_archive ?? "—")}</Row>
              <Row label="Archive SHA-256">
                <Id value={String(sigma.sigma_archive_sha256 ?? "")} />
              </Row>
              <Row label="Importer">{String(sigma.importer ?? "—")}</Row>
              <Row label="Field map">{String(sigma.field_map_version ?? "—")}</Row>
              <Row label="pySigma">{String(sigma.pysigma_version ?? "—")}</Row>
              <Row label="License">{String(sigma.license ?? "—")}</Row>
            </dl>
          </Card>
          <Card padded={false}>
            <CardHeader title="Elastic detection content" />
            <dl>
              <Row label="Source">{String(elastic.source ?? "—")}</Row>
              <Row label="Commit">
                <Id value={String(elastic.source_commit ?? "")} />
              </Row>
              <Row label="Integrations commit">
                <Id value={String(elastic.integrations_commit ?? "")} />
              </Row>
              <Row label="Importer">{String(elastic.importer ?? "—")}</Row>
              <Row label="Field map">{String(elastic.field_map_version ?? "—")}</Row>
              <Row label="ECS">{String(elastic.ecs_version ?? "—")}</Row>
              <Row label="Data streams">{streams.join(", ") || "—"}</Row>
              <Row label="License">{String(elastic.license ?? "—")}</Row>
            </dl>
          </Card>
          <Card padded={false} className="xl:col-span-2">
            <CardHeader title="Rule packs in use" hint="An investigation records the hash of the exact pack set it ran." />
            <dl>
              {provenance.rule_packs.map((pack) => (
                <Row key={pack.pack_id} label={pack.pack_id}>
                  <Id value={pack.content_hash} />
                </Row>
              ))}
            </dl>
          </Card>
        </div>
        <p className="text-body-md text-on-surface-variant">
          What the content can and cannot see is on{" "}
          <a href={links.coverage()} className="text-primary hover:underline">
            Technique Coverage
          </a>
          . The written explanation of an investigation is its{" "}
          <a href={links.dossier()} className="text-primary hover:underline">
            report
          </a>
          .
        </p>
      </div>
    </>
  );
}
