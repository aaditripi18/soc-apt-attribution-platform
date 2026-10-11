import { ArrowRight, Crosshair, FileUp, Fingerprint, Radar, ShieldCheck, Users } from "lucide-react";
import type { ReactNode } from "react";
import { Badge, Button, Card, CardHeader, ErrorState, PageHeader, PageSkeleton, Stat, Td, Th } from "../components/ui";
import {
  paths,
  useApi,
  type Assessment,
  type Coverage,
  type GroupCatalogue,
  type InvestigationSummary,
  type ProfileMatchRecord,
} from "../lib/api";
import { integer } from "../lib/format";
import { links, navigate } from "../lib/router";
import { percent } from "./investigation/Attribution";

/** The attribution outcome of one investigation, in one line. */
function Outcome({ id }: { id: string }) {
  const assessment = useApi<Assessment>(paths.assessment(id));
  const profile = useApi<ProfileMatchRecord>(paths.profileMatch(id));
  if (assessment.state !== "ready" || profile.state !== "ready") {
    return <span className="text-outline">—</span>;
  }
  const leads = [...assessment.data.actor_leads, ...assessment.data.indicator_leads];
  if (leads.length > 0) {
    const names = [...new Set(leads.map((lead) => lead.actor_name))];
    return (
      <span className="flex flex-wrap items-center gap-2">
        <Badge tone="primary">identified</Badge>
        <span className="text-on-surface">{names.join(", ")}</span>
      </span>
    );
  }
  const cluster = profile.data.clusters[0];
  if (!cluster) return <span className="text-on-surface-variant">no comparable behaviour</span>;
  return (
    <span className="flex flex-wrap items-center gap-2">
      <Badge tone="tertiary">{percent(cluster.overlap)} overlap</Badge>
      <span className="text-on-surface-variant">
        {cluster.member_names.slice(0, 2).join(", ")}
        {cluster.member_names.length > 2 && ` +${cluster.member_names.length - 2}`}
      </span>
    </span>
  );
}

function Capability({ icon, title, value, text, href }: { icon: ReactNode; title: string; value: string; text: string; href: string }) {
  return (
    <a href={href} className="group block rounded-md border border-outline-variant/70 bg-surface-low p-4 transition-colors hover:border-primary/50">
      <div className="flex items-center justify-between">
        <span className="flex h-9 w-9 items-center justify-center rounded-md border border-primary/30 bg-primary/10 text-primary">{icon}</span>
        <ArrowRight size={15} className="text-outline transition-colors group-hover:text-primary" />
      </div>
      <div className="mt-3 font-mono text-headline-lg tabular-nums text-on-surface">{value}</div>
      <div className="mt-0.5 text-headline-sm text-on-surface">{title}</div>
      <p className="mt-1 text-body-sm text-on-surface-variant">{text}</p>
    </a>
  );
}

export function DashboardPage() {
  const investigations = useApi<InvestigationSummary[]>(paths.investigations());
  const coverage = useApi<Coverage>(paths.coverage());
  const groups = useApi<GroupCatalogue>(paths.groups());

  if (investigations.state === "error") return <ErrorState failure={investigations.error} onRetry={investigations.reload} />;
  if (investigations.state !== "ready") return <PageSkeleton />;
  const all = investigations.data;
  const summary = coverage.state === "ready" ? coverage.data.summary : null;
  const catalogue = groups.state === "ready" ? groups.data : null;
  const rules =
    coverage.state === "ready"
      ? [coverage.data.content.sigma, coverage.data.content.elastic].reduce(
          (n, source) => n + source.summary.by_status.imported + source.summary.by_status.partial,
          0,
        )
      : null;

  return (
    <>
      <PageHeader
        eyebrow="Threat detection & attribution"
        title="Overview"
        description="Turn raw security logs into detected ATT&CK techniques, a reconstructed attack chain, the threat groups the behaviour matches, and the mitigations that address it."
        right={
          <Button href={links.upload()} variant="primary">
            <FileUp size={14} />
            Analyze logs
          </Button>
        }
      />

      <div className="mb-6 grid grid-cols-2 gap-4 xl:grid-cols-4">
        <Stat label="Investigations" value={integer(all.length)} accent />
        <Stat label="Detections" value={integer(all.reduce((n, i) => n + i.evidence, 0))} sub="evidence items across investigations" />
        <Stat label="Activity clusters" value={integer(all.reduce((n, i) => n + i.units, 0))} sub="linked chains of related events" />
        <Stat label="Threat groups tracked" value={catalogue ? integer(catalogue.active_groups) : "—"} sub="MITRE ATT&CK intrusion sets" />
      </div>

      <div className="mb-6 grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
        <Capability
          icon={<Crosshair size={18} />}
          title="Technique detection"
          value={summary ? `${summary.techniques_by_status.covered} / ${summary.active_techniques}` : "—"}
          text={`ATT&CK techniques with detection content${rules ? `, from ${integer(rules)} translated Sigma and Elastic rules` : ""}.`}
          href={links.coverage()}
        />
        <Capability
          icon={<Fingerprint size={18} />}
          title="Group identification"
          value={catalogue ? integer(catalogue.groups_with_specific_evidence) : "—"}
          text="Groups identifiable by their own tooling artefacts or published advisory indicators."
          href={links.actors({ evidence: "specific" })}
        />
        <Capability
          icon={<Users size={18} />}
          title="Behavioural profiling"
          value={catalogue ? integer(catalogue.active_groups) : "—"}
          text="Every tracked group's profile is compared with observed behaviour and scored by overlap."
          href={links.actors()}
        />
        <Capability
          icon={<ShieldCheck size={18} />}
          title="Response guidance"
          value="ATT&CK"
          text="Mitigations for the techniques observed, prioritised by how many they address."
          href={all[0] ? links.investigation(all[0].investigation_id, "response") : links.upload()}
        />
      </div>

      <Card padded={false}>
        <CardHeader
          title="Investigations"
          hint="Each analysed log source, with its attribution outcome."
          right={
            <Button href={links.investigations()} variant="ghost">
              View all
            </Button>
          }
        />
        {all.length === 0 ? (
          <div className="flex flex-col items-center gap-3 px-6 py-12 text-center">
            <Radar size={26} className="text-on-surface-variant" />
            <div className="text-body-lg text-on-surface">No investigations yet</div>
            <p className="max-w-md text-body-md text-on-surface-variant">
              Upload a log archive to detect techniques, reconstruct the attack chain and match it against threat group
              profiles.
            </p>
            <Button href={links.upload()} variant="primary">
              <FileUp size={14} />
              Analyze logs
            </Button>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full border-collapse text-body-md">
              <thead>
                <tr>
                  <Th>Source</Th>
                  <Th>Attribution</Th>
                  <Th align="right">Detections</Th>
                  <Th align="right">Activity clusters</Th>
                  <Th />
                </tr>
              </thead>
              <tbody>
                {all.slice(0, 10).map((item) => (
                  <tr
                    key={item.investigation_id}
                    onClick={() => navigate(links.investigation(item.investigation_id))}
                    className="cursor-pointer hover:bg-surface"
                  >
                    <Td className="font-medium text-on-surface">{item.source_id}</Td>
                    <Td>
                      <Outcome id={item.investigation_id} />
                    </Td>
                    <Td align="right" className="font-mono tabular-nums">
                      {integer(item.evidence)}
                    </Td>
                    <Td align="right" className="font-mono tabular-nums">
                      {integer(item.units)}
                    </Td>
                    <Td align="right">
                      <a href={links.investigation(item.investigation_id, "attribution")} className="text-label-md text-primary hover:underline">
                        Attribution
                      </a>
                    </Td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </>
  );
}
