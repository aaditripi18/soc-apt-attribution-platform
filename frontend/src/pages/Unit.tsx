import { useMemo } from "react";
import {
  ErrorState,
  Field,
  Id,
  PageHeader,
  PageSkeleton,
  UncalibratedBadge,
  cx,
} from "../components/ui";
import {
  paths,
  useApi,
  type Investigation,
  type TechniqueCatalogue,
  type Unit,
  type UnitEvidence,
} from "../lib/api";
import { useCrumbs } from "../lib/crumbs";
import {
  candidateRows,
  indexTechniques,
  isContextEvidence,
  unitTechniques,
  type CandidateRow,
  type TechniqueIndex,
  type UnitTechnique,
} from "../lib/derive";
import { duration, integer, shortId, utcDateTime } from "../lib/format";
import { links } from "../lib/router";
import { CandidatesTab } from "./unit/Candidates";
import { EvidenceTab } from "./unit/EvidenceTab";
import { GuidanceTab } from "./unit/Guidance";
import { IndicatorsTab } from "./unit/Indicators";
import { OverviewTab } from "./unit/Overview";
import { ProvenanceTab } from "./unit/Provenance";
import { SequenceTab } from "./unit/Sequence";
import { TechniquesTab } from "./unit/Techniques";

/** Everything the unit tabs read: stored records and joins of them. */
export interface UnitData {
  unit: Unit;
  evidence: UnitEvidence;
  index: TechniqueIndex;
  techniques: UnitTechnique[];
  candidates: CandidateRow[];
  investigation: Investigation | null;
  hosts: string[];
  firstSeen: string | null;
  lastSeen: string | null;
  coreEvidence: number;
  contextEvidence: number;
}

const TABS = [
  { key: "overview", label: "Overview" },
  { key: "sequence", label: "Attack sequence" },
  { key: "evidence", label: "Evidence" },
  { key: "techniques", label: "Techniques" },
  { key: "candidates", label: "Candidate actors" },
  { key: "guidance", label: "What evidence would help" },
  { key: "indicators", label: "Indicator context" },
  { key: "provenance", label: "Provenance" },
] as const;

type TabKey = (typeof TABS)[number]["key"];

function count(tab: TabKey, data: UnitData): number | null {
  const analysis = data.unit.attribution_analysis;
  switch (tab) {
    case "sequence":
      return data.unit.sequence.steps.length;
    case "evidence":
      return data.evidence.evidence.length;
    case "techniques":
      return data.techniques.length;
    case "candidates":
      return analysis.candidates.length;
    case "guidance":
      return analysis.collection_guidance?.questions.length ?? 0;
    case "indicators":
      return analysis.indicator_matches.length;
    default:
      return null;
  }
}

export function UnitPage({ id, tab, query }: { id: string; tab: string | undefined; query: URLSearchParams }) {
  const unit = useApi<Unit>(paths.unit(id));
  const evidence = useApi<UnitEvidence>(paths.unitEvidence(id));
  const catalogue = useApi<TechniqueCatalogue>(paths.techniques());
  const investigationId = unit.state === "ready" ? unit.data.attribution_analysis.investigation_id : null;
  const investigation = useApi<Investigation>(investigationId ? paths.investigation(investigationId) : null);

  const data = useMemo((): UnitData | null => {
    if (unit.state !== "ready" || evidence.state !== "ready" || catalogue.state !== "ready") return null;
    const index = indexTechniques(catalogue.data);
    const observations = Object.values(evidence.data.observations);
    const times = observations.map((o) => o.timestamp).sort();
    return {
      unit: unit.data,
      evidence: evidence.data,
      index,
      techniques: unitTechniques(unit.data.attribution_analysis, evidence.data.evidence, index),
      candidates: candidateRows(unit.data.attribution_analysis),
      investigation: investigation.state === "ready" ? investigation.data : null,
      hosts: [...new Set(observations.map((o) => o.host?.name ?? o.host?.id ?? "").filter(Boolean))].sort(),
      firstSeen: times[0] ?? null,
      lastSeen: times[times.length - 1] ?? null,
      coreEvidence: evidence.data.evidence.filter((e) => !isContextEvidence(e)).length,
      contextEvidence: evidence.data.evidence.filter(isContextEvidence).length,
    };
  }, [unit.state, unit.data, evidence.state, evidence.data, catalogue.state, catalogue.data, investigation.state, investigation.data]);

  const source = data?.investigation?.source_id;
  useCrumbs([
    { label: "Investigations", href: links.investigations() },
    ...(investigationId
      ? [{ label: source ?? shortId(investigationId, 8), href: links.investigation(investigationId) }]
      : []),
    { label: `Unit ${shortId(id, 8).replace("corr-group::", "")}` },
  ]);

  for (const resource of [unit, evidence, catalogue]) {
    if (resource.state === "error") {
      return <ErrorState failure={resource.error} onRetry={resource.reload} />;
    }
  }
  if (!data) return <PageSkeleton rows={8} />;

  const active: TabKey = TABS.some((t) => t.key === tab) ? (tab as TabKey) : "overview";
  const analysis = data.unit.attribution_analysis;
  return (
    <>
      <PageHeader
        eyebrow="Attribution unit"
        title={
          <span className="flex flex-wrap items-center gap-x-3 gap-y-1">
            <span>{data.hosts.join(", ") || "Unit"}</span>
            <span className="font-mono text-headline-md font-normal text-on-surface-variant">
              {utcDateTime(data.firstSeen)}
            </span>
          </span>
        }
        right={<UncalibratedBadge />}
      >
        <div className="mt-4 grid grid-cols-2 gap-x-8 gap-y-4 rounded-md border border-outline-variant/70 bg-surface-low p-4 lg:grid-cols-4 xl:grid-cols-6">
          <Field label="Unit id">
            <Id value={id} display={shortId(id, 12)} />
          </Field>
          <Field label="Recording">
            {investigationId ? (
              <a href={links.investigation(investigationId)} className="text-primary hover:underline">
                {source ?? shortId(investigationId, 10)}
              </a>
            ) : (
              "—"
            )}
          </Field>
          <Field label="Observed over">
            <span className="font-mono text-code-md">{duration(data.firstSeen, data.lastSeen)}</span>
          </Field>
          <Field label="Evidence">
            <span className="font-mono text-code-md">
              {integer(data.coreEvidence)} core · {integer(data.contextEvidence)} context
            </span>
          </Field>
          <Field label="Decision features">
            <span className="font-mono text-code-md">
              {integer(analysis.observed_feature_technique_ids.length)} technique
              {analysis.observed_feature_technique_ids.length === 1 ? "" : "s"}
            </span>
          </Field>
          <Field label="Candidates">
            <span className="font-mono text-code-md">{integer(analysis.candidates.length)} (A–Z)</span>
          </Field>
        </div>
      </PageHeader>

      <div
        role="tablist"
        aria-label="Unit views"
        className="no-print sticky top-14 z-10 -mx-6 mb-6 flex gap-1 overflow-x-auto border-b border-outline-variant/70 bg-background/95 px-6 backdrop-blur"
      >
        {TABS.map((item) => {
          const n = count(item.key, data);
          const selected = item.key === active;
          return (
            <a
              key={item.key}
              role="tab"
              aria-selected={selected}
              href={links.unit(id, item.key === "overview" ? undefined : item.key)}
              className={cx(
                "-mb-px flex h-10 shrink-0 items-center gap-2 border-b-2 px-3 text-label-md transition-colors",
                selected
                  ? "border-primary text-primary"
                  : "border-transparent text-on-surface-variant hover:text-on-surface",
              )}
            >
              {item.label}
              {n !== null && (
                <span
                  className={cx(
                    "rounded-sm px-1 font-mono text-code-sm",
                    selected ? "bg-primary/15" : "bg-surface-high text-outline",
                  )}
                >
                  {integer(n)}
                </span>
              )}
            </a>
          );
        })}
      </div>

      {active === "overview" && <OverviewTab data={data} unitId={id} />}
      {active === "sequence" && <SequenceTab data={data} unitId={id} />}
      {active === "evidence" && <EvidenceTab data={data} query={query} />}
      {active === "techniques" && <TechniquesTab data={data} unitId={id} />}
      {active === "candidates" && <CandidatesTab data={data} />}
      {active === "guidance" && <GuidanceTab data={data} />}
      {active === "indicators" && <IndicatorsTab data={data} />}
      {active === "provenance" && <ProvenanceTab data={data} unitId={id} />}
    </>
  );
}
