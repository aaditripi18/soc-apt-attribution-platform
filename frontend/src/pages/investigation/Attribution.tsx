import { Fingerprint, Quote, ShieldAlert, Users } from "lucide-react";
import { useMemo, useState } from "react";
import {
  AttackId,
  Badge,
  Button,
  Card,
  CardHeader,
  EmptyState,
  ErrorState,
  PageSkeleton,
  Stat,
  Td,
  Th,
  cx,
} from "../../components/ui";
import { paths, useApi, type Assessment, type ProfileMatch, type ProfileMatchRecord } from "../../lib/api";
import { integer, plural } from "../../lib/format";
import { links } from "../../lib/router";

const TOP = 15;
const MATRIX_ROWS = 12;

export const percent = (value: number): string => `${Math.round(value * 100)}%`;

function OverlapBar({ value, strong = false }: { value: number; strong?: boolean }) {
  return (
    <div className="flex items-center gap-2">
      <div className="h-1.5 w-28 overflow-hidden rounded-full bg-surface-highest">
        <div
          className={cx("h-full rounded-full", strong ? "bg-primary" : "bg-secondary-container")}
          style={{ width: `${Math.max(2, value * 100)}%` }}
        />
      </div>
      <span className="w-10 text-right font-mono text-code-md tabular-nums text-on-surface">{percent(value)}</span>
    </div>
  );
}

/** The headline: a Group named on specific evidence, or the closest behavioural cluster. */
export function AttributionHeadline({ assessment, match }: { assessment: Assessment; match: ProfileMatchRecord }) {
  const named = [...new Set([...assessment.actor_leads, ...assessment.indicator_leads].map((l) => l.actor_name))];
  const specific = assessment.actor_leads.length > 0;
  const first = match.clusters[0];
  if (named.length > 0) {
    return (
      <div className="flex gap-4">
        <span className="flex h-11 w-11 shrink-0 items-center justify-center rounded-md border border-primary/40 bg-primary/10 text-primary">
          <Fingerprint size={22} />
        </span>
        <div className="min-w-0">
          <div className="label">{specific ? "Identified by group-specific evidence" : "Named by an advisory indicator"}</div>
          <div className="mt-0.5 text-headline-lg text-on-surface">{named.join(" · ")}</div>
          <p className="mt-1.5 max-w-3xl text-body-md text-on-surface-variant">{assessment.statement}</p>
        </div>
      </div>
    );
  }
  if (!first) {
    return (
      <div className="flex gap-4">
        <span className="flex h-11 w-11 shrink-0 items-center justify-center rounded-md border border-outline-variant bg-surface-high text-on-surface-variant">
          <ShieldAlert size={22} />
        </span>
        <div>
          <div className="label">Attribution</div>
          <div className="mt-0.5 text-headline-lg text-on-surface">No comparable behaviour</div>
          <p className="mt-1.5 max-w-3xl text-body-md text-on-surface-variant">{assessment.statement}</p>
        </div>
      </div>
    );
  }
  return (
    <div className="flex gap-4">
      <span className="flex h-11 w-11 shrink-0 items-center justify-center rounded-md border border-tertiary-dim/40 bg-tertiary-dim/10 text-tertiary">
        <Users size={22} />
      </span>
      <div className="min-w-0">
        <div className="label">Closest behavioural profile</div>
        <div className="mt-0.5 text-headline-lg text-on-surface">
          {first.member_names.slice(0, 3).join(" · ")}
          {first.member_names.length > 3 && (
            <span className="text-on-surface-variant"> +{first.member_names.length - 3} more</span>
          )}
        </div>
        <p className="mt-1.5 max-w-3xl text-body-md text-on-surface-variant">
          {percent(first.overlap)} behavioural overlap
          {first.member_ids.length > 1
            ? `, shared by ${first.member_ids.length} groups that this evidence cannot tell apart.`
            : "."}{" "}
          {integer(match.matches.length)} groups and campaigns match at least one observed
          technique; none is identified by evidence specific to it.
        </p>
      </div>
    </div>
  );
}

function Leads({ assessment }: { assessment: Assessment }) {
  if (assessment.actor_leads.length + assessment.indicator_leads.length === 0) return null;
  return (
    <Card padded={false}>
      <CardHeader
        title="Group-specific evidence"
        hint="Artefacts tied to one group: its own tooling, or indicators a government advisory attributes to it. This is what identifies a group; behavioural overlap alone does not."
      />
      <div className="space-y-3 p-4">
        {assessment.actor_leads.map((lead) => (
          <div key={lead.evidence_id} className="rounded-sm border border-primary/40 bg-primary/5 p-3">
            <div className="flex flex-wrap items-center gap-2 text-body-md">
              <Badge tone="primary">Tooling artefact</Badge>
              <span className="font-semibold text-on-surface">{lead.actor_name}</span>
              {lead.actor_attack_id && <AttackId id={lead.actor_attack_id} tone="muted" />}
              <a href={links.unit(lead.group_id, "evidence")} className="text-label-md text-primary hover:underline">
                View evidence
              </a>
            </div>
            <p className="mt-1.5 break-words font-mono text-code-sm leading-relaxed text-on-surface-variant">{lead.claim}</p>
          </div>
        ))}
        {assessment.indicator_leads.map((lead) => (
          <div key={`${lead.value}::${lead.group_id}`} className="rounded-sm border border-tertiary-dim/40 bg-tertiary-dim/5 p-3">
            <div className="flex flex-wrap items-center gap-2 text-body-md">
              <Badge tone="tertiary">Advisory indicator</Badge>
              <span className="font-semibold text-on-surface">{lead.actor_name}</span>
              {lead.actor_attack_id && <AttackId id={lead.actor_attack_id} tone="muted" />}
              {lead.within_validity === false && <Badge tone="warning">outside its validity window</Badge>}
            </div>
            <p className="mt-1.5 text-body-md text-on-surface-variant">
              An observed {lead.kind} equals indicator <span className="text-on-surface">{lead.indicator_name}</span> in{" "}
              {lead.report_name ?? "a published advisory"}.{" "}
              <a href={links.unit(lead.group_id, "indicators")} className="text-primary hover:underline">
                View evidence
              </a>
            </p>
            {lead.attribution_quote && (
              <blockquote className="mt-2 flex gap-2 border-l-2 border-outline-variant pl-3 text-body-md italic text-on-surface-variant">
                <Quote size={13} className="mt-1 shrink-0 text-outline" />
                <span>{lead.attribution_quote}</span>
              </blockquote>
            )}
          </div>
        ))}
      </div>
    </Card>
  );
}

function NamedBadge({ match }: { match: ProfileMatch }) {
  if (match.named_by === null) return null;
  return (
    <Badge tone={match.named_by === "actor_specific" ? "primary" : "tertiary"}>
      {match.named_by === "actor_specific" ? "specific evidence" : "advisory indicator"}
    </Badge>
  );
}

export function AttributionTab({ investigationId }: { investigationId: string }) {
  const assessment = useApi<Assessment>(paths.assessment(investigationId));
  const profile = useApi<ProfileMatchRecord>(paths.profileMatch(investigationId));
  const [all, setAll] = useState(false);
  const labelOf = useMemo(
    () => new Map(profile.state === "ready" ? profile.data.clusters.map((c) => [c.cluster_id, c.label]) : []),
    [profile.state, profile.data],
  );

  if (assessment.state === "loading" || profile.state === "loading") return <PageSkeleton rows={6} />;
  if (assessment.state === "error") return <ErrorState failure={assessment.error} onRetry={assessment.reload} />;
  if (profile.state === "error") return <ErrorState failure={profile.error} onRetry={profile.reload} />;
  const a = assessment.data;
  const match = profile.data;
  const observed = match.observed;

  if (observed.length === 0 && a.actor_leads.length + a.indicator_leads.length === 0) {
    return (
      <EmptyState title="No behaviour to compare">
        <p>{a.statement}</p>
      </EmptyState>
    );
  }
  const rows = all ? match.matches : match.matches.slice(0, TOP);
  const matrix = match.matches.slice(0, MATRIX_ROWS);
  const full = match.matches.filter((m) => m.overlap === 1).length;

  return (
    <div className="space-y-6">
      <Card>
        <AttributionHeadline assessment={a} match={match} />
      </Card>

      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <Stat label="Observed techniques" value={integer(observed.length)} sub="compared with group profiles" accent />
        <Stat label="Matching groups" value={integer(match.matches.length)} sub={`of ${integer(match.active_groups)} tracked groups, plus campaigns`} />
        <Stat label="Behavioural clusters" value={integer(match.clusters.length)} sub="sets of groups this evidence cannot separate" />
        <Stat label="Full overlap" value={integer(full)} sub="profiles containing every observed technique" />
      </div>

      <Leads assessment={a} />

      {match.matches.length > 0 && (
        <>
          <Card padded={false}>
            <CardHeader
              title="Closest behavioural profiles"
              hint="Groups ordered by how much of the observed behaviour their public ATT&CK profile contains. Rare techniques count for more than common ones. Overlap is a measure of similarity, not of responsibility."
              right={
                <a href={links.about()} className="text-label-md text-primary hover:underline">
                  How overlap is calculated
                </a>
              }
            />
            <div className="overflow-x-auto">
              <table className="w-full border-collapse text-body-md">
                <thead>
                  <tr>
                    <Th align="right">#</Th>
                    <Th>Group</Th>
                    <Th>Behavioural overlap</Th>
                    <Th align="right">Techniques matched</Th>
                    <Th align="right">Share of its profile</Th>
                    <Th>Cluster</Th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((row, index) => (
                    <tr key={row.stix_id} className="hover:bg-surface" data-candidate={row.candidate_id}>
                      <Td align="right" className="font-mono tabular-nums text-on-surface-variant">
                        {index + 1}
                      </Td>
                      <Td>
                        <span className="flex flex-wrap items-center gap-2">
                          <a
                            href={row.kind === "group" ? links.actor(row.candidate_id) : undefined}
                            className={cx("text-on-surface", row.kind === "group" && "hover:text-primary hover:underline")}
                          >
                            {row.name}
                          </a>
                          <AttackId id={row.candidate_id} tone="muted" />
                          {row.kind === "campaign" && <Badge tone="muted">campaign</Badge>}
                          <NamedBadge match={row} />
                        </span>
                      </Td>
                      <Td>
                        <OverlapBar value={row.overlap} strong={row.named_by !== null} />
                      </Td>
                      <Td align="right" className="font-mono tabular-nums">
                        {row.matched} of {observed.length}
                      </Td>
                      <Td align="right" className="font-mono tabular-nums text-on-surface-variant">
                        {row.matched} of {integer(row.profile_techniques)}
                      </Td>
                      <Td className="whitespace-nowrap font-mono text-code-sm text-on-surface-variant">
                        {labelOf.get(row.cluster_id) ?? "—"}
                      </Td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {match.matches.length > TOP && (
              <div className="border-t border-outline-variant/70 px-4 py-2.5">
                <Button variant="ghost" onClick={() => setAll((value) => !value)}>
                  {all ? `Show the top ${TOP}` : `Show all ${integer(match.matches.length)}`}
                </Button>
              </div>
            )}
          </Card>

          <Card padded={false}>
            <CardHeader
              title="Behavioural clusters"
              hint="Groups whose profiles contain exactly the same observed techniques. Within a cluster, more evidence is needed to tell the members apart."
            />
            <div className="grid grid-cols-1 gap-3 p-4 xl:grid-cols-2">
              {match.clusters.slice(0, 6).map((cluster) => (
                <div key={cluster.cluster_id} className="rounded-sm border border-outline-variant/70 bg-surface-lowest p-3" data-cluster={cluster.label}>
                  <div className="flex items-center justify-between gap-3">
                    <span className="text-headline-sm text-on-surface">{cluster.label}</span>
                    <OverlapBar value={cluster.overlap} />
                  </div>
                  <div className="mt-2 flex flex-wrap gap-1">
                    {cluster.matched_technique_ids.map((id) => (
                      <AttackId key={id} id={id} />
                    ))}
                  </div>
                  <div className="mt-2 text-body-sm text-on-surface-variant">
                    <span className="text-on-surface">{plural(cluster.member_ids.length, "member")}:</span>{" "}
                    {cluster.member_names.slice(0, 12).join(", ")}
                    {cluster.member_names.length > 12 && ` and ${cluster.member_names.length - 12} more`}
                  </div>
                </div>
              ))}
            </div>
            {match.clusters.length > 6 && (
              <p className="border-t border-outline-variant/70 px-4 py-2.5 text-body-sm text-on-surface-variant">
                The {match.clusters.length - 6} remaining clusters have lower overlap; every group's cluster is in the table above.
              </p>
            )}
          </Card>

          <Card padded={false}>
            <CardHeader
              title="Technique overlap matrix"
              hint={`Which observed techniques each of the ${matrix.length} closest profiles contains. The weight under a technique is how rare it is across groups (higher counts for more).`}
            />
            <div className="overflow-x-auto p-4">
              <table className="border-collapse text-body-md">
                <thead>
                  <tr>
                    <th className="sticky left-0 z-10 bg-surface-low pr-4 text-left" />
                    {observed.map((technique) => (
                      <th key={technique.technique_id} className="px-1 pb-2 align-bottom">
                        <div className="flex w-16 flex-col items-center gap-1" title={`${technique.technique_name} — used by ${technique.groups_using} of ${match.active_groups} groups`}>
                          <AttackId id={technique.technique_id} />
                          <span className="font-mono text-code-sm text-outline">{technique.weight.toFixed(2)}</span>
                        </div>
                      </th>
                    ))}
                    <th className="pl-4 text-left align-bottom">
                      <span className="label">Overlap</span>
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {matrix.map((row) => (
                    <tr key={row.stix_id}>
                      <td className="sticky left-0 z-10 max-w-56 truncate bg-surface-low py-1 pr-4 text-on-surface" title={row.name}>
                        {row.name}
                      </td>
                      {observed.map((technique) => {
                        const hit = row.matched_technique_ids.includes(technique.technique_id);
                        return (
                          <td key={technique.technique_id} className="px-1 py-1">
                            <div
                              aria-label={`${row.name} ${hit ? "uses" : "is not recorded using"} ${technique.technique_id}`}
                              className={cx(
                                "mx-auto h-6 w-14 rounded-sm border",
                                hit ? "border-primary/60 bg-primary/30" : "border-outline-variant/40 bg-transparent",
                              )}
                            />
                          </td>
                        );
                      })}
                      <td className="py-1 pl-4 font-mono text-code-md tabular-nums text-on-surface">{percent(row.overlap)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>
        </>
      )}
    </div>
  );
}
