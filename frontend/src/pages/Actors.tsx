import { Fingerprint, Search } from "lucide-react";
import { useMemo, useState } from "react";
import {
  AttackId,
  Badge,
  Card,
  CardHeader,
  ErrorState,
  ExternalA,
  NotFoundState,
  PageHeader,
  PageSkeleton,
  Segmented,
  Stat,
  Td,
  TextInput,
  Th,
} from "../components/ui";
import { paths, useApi, type ActorProfile, type GroupCatalogue, type TechniqueCatalogue } from "../lib/api";
import { useCrumbs } from "../lib/crumbs";
import { indexTechniques } from "../lib/derive";
import { attackUrl, integer, plural } from "../lib/format";
import { links, navigate } from "../lib/router";

type Filter = "all" | "specific";

const hasSpecific = (group: ActorProfile): boolean => group.actor_rules.length + group.advisories.length > 0;

function Identification({ group }: { group: ActorProfile }) {
  if (!hasSpecific(group)) return <Badge tone="muted">behaviour profile</Badge>;
  return (
    <span className="flex flex-wrap gap-1">
      {group.actor_rules.length > 0 && <Badge tone="primary">{plural(group.actor_rules.length, "tooling rule")}</Badge>}
      {group.advisories.length > 0 && <Badge tone="tertiary">{plural(group.advisories.length, "advisory")}</Badge>}
    </span>
  );
}

export function ActorsPage({ query }: { query: URLSearchParams }) {
  const groups = useApi<GroupCatalogue>(paths.groups());
  const [text, setText] = useState("");
  const [filter, setFilter] = useState<Filter>(query.get("evidence") === "specific" ? "specific" : "all");
  const rows = useMemo(() => {
    if (groups.state !== "ready") return [];
    const needle = text.trim().toLowerCase();
    return groups.data.groups.filter(
      (group) =>
        (filter === "all" || hasSpecific(group)) &&
        (needle === "" ||
          group.name.toLowerCase().includes(needle) ||
          group.attack_id.toLowerCase() === needle ||
          group.aliases.some((alias) => alias.toLowerCase().includes(needle)) ||
          group.software.some((item) => item.name.toLowerCase().includes(needle)) ||
          group.technique_ids.some((id) => id.toLowerCase() === needle)),
    );
  }, [groups.state, groups.data, text, filter]);

  if (groups.state === "error") return <ErrorState failure={groups.error} onRetry={groups.reload} />;
  if (groups.state !== "ready") return <PageSkeleton />;
  const data = groups.data;
  return (
    <>
      <PageHeader
        eyebrow="Threat intelligence"
        title="Threat Actors"
        description="Every intrusion set tracked in MITRE ATT&CK, with its known techniques and software. Each is matched against observed behaviour; groups marked with tooling rules or advisories can also be identified by evidence specific to them."
      />
      <div className="mb-6 grid grid-cols-2 gap-4 lg:grid-cols-3">
        <Stat label="Groups tracked" value={integer(data.active_groups)} sub={data.attack_kb_version} accent />
        <Stat label="Identifiable by specific evidence" value={integer(data.groups_with_specific_evidence)} sub="tooling artefacts or advisory indicators" />
        <Stat label="Matched by behaviour" value={integer(data.active_groups)} sub="all groups are scored by technique overlap" />
      </div>
      <Card padded={false}>
        <CardHeader
          title="Group catalogue"
          hint={`${integer(rows.length)} of ${integer(data.groups.length)} groups`}
          right={
            <>
              <Segmented<Filter>
                ariaLabel="Groups shown"
                value={filter}
                onChange={setFilter}
                options={[
                  { value: "all", label: "All" },
                  { value: "specific", label: "Specific evidence" },
                ]}
              />
              <TextInput value={text} onChange={setText} placeholder="Name, alias, software, T1059…" icon={<Search size={14} />} className="w-64" />
            </>
          }
        />
        <div className="overflow-x-auto">
          <table className="w-full border-collapse text-body-md">
            <thead>
              <tr>
                <Th>Group</Th>
                <Th>Also known as</Th>
                <Th align="right">Techniques</Th>
                <Th align="right">Software</Th>
                <Th>Identification</Th>
              </tr>
            </thead>
            <tbody>
              {rows.map((group) => (
                <tr
                  key={group.attack_id}
                  onClick={() => navigate(links.actor(group.attack_id))}
                  className="cursor-pointer hover:bg-surface"
                  data-group={group.attack_id}
                >
                  <Td>
                    <span className="flex items-center gap-2">
                      <a href={links.actor(group.attack_id)} className="font-medium text-on-surface hover:text-primary">
                        {group.name}
                      </a>
                      <span className="font-mono text-code-sm text-outline">{group.attack_id}</span>
                    </span>
                  </Td>
                  <Td className="max-w-md truncate text-on-surface-variant">
                    {group.aliases.slice(0, 4).join(", ") || "—"}
                    {group.aliases.length > 4 && ` +${group.aliases.length - 4}`}
                  </Td>
                  <Td align="right" className="font-mono tabular-nums">
                    {integer(group.technique_ids.length)}
                  </Td>
                  <Td align="right" className="font-mono tabular-nums">
                    {integer(group.software.length)}
                  </Td>
                  <Td>
                    <Identification group={group} />
                  </Td>
                </tr>
              ))}
              {rows.length === 0 && (
                <tr>
                  <Td colSpan={5} className="py-8 text-center text-on-surface-variant">
                    No group matches this search.
                  </Td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </Card>
    </>
  );
}

export function ActorPage({ id }: { id: string }) {
  const groups = useApi<GroupCatalogue>(paths.groups());
  const catalogue = useApi<TechniqueCatalogue>(paths.techniques());
  const group = groups.state === "ready" ? groups.data.groups.find((g) => g.attack_id === id) : undefined;
  useCrumbs([{ label: "Threat Actors", href: links.actors() }, { label: group?.name ?? id }]);
  const index = useMemo(
    () => (catalogue.state === "ready" ? indexTechniques(catalogue.data) : null),
    [catalogue.state, catalogue.data],
  );

  if (groups.state === "error") return <ErrorState failure={groups.error} onRetry={groups.reload} />;
  if (groups.state !== "ready" || !index) return <PageSkeleton />;
  if (!group) {
    return (
      <NotFoundState title="No such group">
        <p className="font-mono text-code-md">{id}</p>
      </NotFoundState>
    );
  }
  const byTactic = index.tacticOrder
    .map((tactic) => ({
      tactic,
      name: index.tacticName.get(tactic) ?? tactic,
      techniques: group.technique_ids.filter((t) => index.byAttackId.get(t)?.tactics.includes(tactic)),
    }))
    .filter((column) => column.techniques.length > 0);
  const url = attackUrl(group.attack_id);
  return (
    <>
      <PageHeader
        eyebrow={`Threat actor · ${group.attack_id}`}
        title={group.name}
        description={group.description}
        right={url ? <ExternalA href={url}>MITRE ATT&CK</ExternalA> : undefined}
      />
      <div className="mb-6 grid grid-cols-2 gap-4 lg:grid-cols-4">
        <Stat label="Techniques" value={integer(group.technique_ids.length)} sub="recorded in its ATT&CK profile" accent />
        <Stat label="Software" value={integer(group.software.length)} sub="malware and tools it is recorded using" />
        <Stat label="Tooling rules" value={integer(group.actor_rules.length)} sub="detections specific to this group" />
        <Stat label="Advisories" value={integer(group.advisories.length)} sub="published indicator sets attributed to it" />
      </div>
      <div className="space-y-6">
        {group.aliases.length > 0 && (
          <Card>
            <div className="label mb-2">Also known as</div>
            <div className="flex flex-wrap gap-1.5">
              {group.aliases.map((alias) => (
                <Badge key={alias} tone="neutral" className="normal-case tracking-normal">
                  {alias}
                </Badge>
              ))}
            </div>
          </Card>
        )}

        <Card padded={false}>
          <CardHeader
            title="How this group can be identified"
            hint={
              hasSpecific(group)
                ? "Evidence specific to this group is available: a match identifies it directly."
                : "No group-specific artefacts are available for this group. It is matched by behavioural overlap with its technique profile."
            }
          />
          {hasSpecific(group) ? (
            <ul className="divide-y divide-outline-variant/50">
              {group.actor_rules.map((rule) => (
                <li key={rule.title} className="flex gap-3 px-4 py-3">
                  <Fingerprint size={16} className="mt-0.5 shrink-0 text-primary" />
                  <div className="min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      <Badge tone="primary">tooling rule</Badge>
                      {rule.url ? <ExternalA href={rule.url}>{rule.title}</ExternalA> : <span className="text-on-surface">{rule.title}</span>}
                    </div>
                    <p className="mt-1 text-body-md text-on-surface-variant">{rule.reason}</p>
                  </div>
                </li>
              ))}
              {group.advisories.map((advisory) => (
                <li key={advisory.report_name} className="flex gap-3 px-4 py-3">
                  <Fingerprint size={16} className="mt-0.5 shrink-0 text-tertiary" />
                  <div className="min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      <Badge tone="tertiary">advisory indicators</Badge>
                      <span className="text-on-surface">{advisory.report_name}</span>
                    </div>
                    <p className="mt-1 text-body-md text-on-surface-variant">Published by {advisory.publisher}.</p>
                  </div>
                </li>
              ))}
            </ul>
          ) : (
            <p className="px-4 py-4 text-body-md text-on-surface-variant">
              When activity overlaps this profile it appears among the closest behavioural profiles of an investigation,
              together with the other groups the same evidence fits.
            </p>
          )}
        </Card>

        <Card padded={false}>
          <CardHeader title="Technique profile" hint="The techniques ATT&CK records for this group, by tactic." />
          <div className="overflow-x-auto px-4 py-4">
            <div className="flex min-w-max gap-2">
              {byTactic.map((column) => (
                <div key={column.tactic} className="w-40 shrink-0">
                  <div className="mb-2 rounded-sm border border-outline-variant bg-surface-high px-2 py-1.5">
                    <div className="text-label-md leading-tight text-on-surface">{column.name}</div>
                    <div className="font-mono text-code-sm text-outline">{column.techniques.length}</div>
                  </div>
                  <div className="space-y-1">
                    {column.techniques.map((technique) => (
                      <a
                        key={technique}
                        href={links.units({ technique })}
                        title={`${index.byAttackId.get(technique)?.name ?? ""} — find investigations where it was observed`}
                        className="block rounded-sm border border-outline-variant/60 bg-surface px-2 py-1 hover:border-primary/50"
                      >
                        <div className="font-mono text-code-sm text-on-surface">{technique}</div>
                        <div className="truncate text-body-sm text-on-surface-variant">{index.byAttackId.get(technique)?.name ?? ""}</div>
                      </a>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </Card>

        {group.software.length > 0 && (
          <Card padded={false}>
            <CardHeader title="Software" hint="Malware and tools ATT&CK records this group using." />
            <div className="flex flex-wrap gap-1.5 p-4">
              {group.software.map((item) => (
                <span key={item.attack_id} className="inline-flex items-center gap-2 rounded-sm border border-outline-variant bg-surface px-2 py-1 text-body-sm">
                  <span className="text-on-surface">{item.name}</span>
                  <AttackId id={item.attack_id} tone="muted" />
                </span>
              ))}
            </div>
          </Card>
        )}
      </div>
    </>
  );
}
