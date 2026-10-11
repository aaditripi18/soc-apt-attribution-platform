import type { ReactNode } from "react";
import { Badge, Card, CardHeader, ErrorState, Id, PageHeader, PageSkeleton } from "../components/ui";
import { paths, useApi, useHealth, type Coverage, type TechniqueCatalogue } from "../lib/api";
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
    text: "Pinned Sigma and Elastic rules, translated exactly, are evaluated on every Observation. A match produces Evidence: one rule, one observation, one ATT&CK technique, with the matched values and the mapping basis in its claim.",
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
    text: "The result is a set of facts: which candidates’ profiles include which observed techniques, what would tell them apart, and which advisory indicators coincide. Nothing is ranked.",
  },
];

export function AboutPage() {
  const coverage = useApi<Coverage>(paths.coverage());
  const catalogue = useApi<TechniqueCatalogue>(paths.techniques());
  const { health } = useHealth(60000);

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
        eyebrow="About & provenance"
        title="How this console reaches its statements"
        description="A research platform for evidence-based, explainable APT attribution. This console is a reader: it shows what the engine stored, and every number on every page traces to a record you can open."
      />
      <div className="space-y-6">
        <Card className="border-warning/30 bg-warning/5">
          <div className="flex flex-wrap items-center gap-3">
            <Badge tone="warning">Uncalibrated — explainable facts only</Badge>
            <h2 className="text-headline-md text-on-surface">Why there is no “most likely actor”</h2>
          </div>
          <p className="mt-3 max-w-4xl text-body-lg text-on-surface-variant">
            A likelihood or confidence is only honest if it has been checked against cases where the answer is known. No
            calibration version exists for this platform, so it emits none: no likelihood, no confidence band, no verdict and
            no ranking. Candidates are always listed alphabetically. What you get instead is the evidence itself — what was
            observed, which techniques it supports and why, which ATT&amp;CK profiles include those techniques, and what
            additional evidence would separate them. Overlap with a Group’s published profile is not attribution: techniques
            are shared, copied and under-reported.
          </p>
        </Card>

        <Card padded={false}>
          <CardHeader title="From telemetry to explanation" hint="Each stage is deterministic and stores what it produced." />
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
            <CardHeader title="This session" hint="What is answering this page." />
            <dl>
              <Row label="API">{health?.api ?? "—"}</Row>
              <Row label="Record store">{health?.backend ?? "—"}</Row>
              <Row label="Access">read-only; every mutation method is refused</Row>
              <Row label="Coverage report">{coverage.data.report_version}</Row>
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
            Detection Coverage
          </a>
          . The written explanation of an investigation is its{" "}
          <a href={links.dossier()} className="text-primary hover:underline">
            Attribution Dossier
          </a>
          .
        </p>
      </div>
    </>
  );
}
