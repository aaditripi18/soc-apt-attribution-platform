import { CircleCheck, CircleSlash } from "lucide-react";
import { useState } from "react";
import { AttackId, Badge, Card, Disclosure, EmptyState, StackedBar } from "../../components/ui";
import type { CollectionQuestion, CoverageStatus } from "../../lib/api";
import { COVERAGE_LABEL, COVERAGE_MEANING } from "../../lib/derive";
import { integer, plural } from "../../lib/format";
import type { UnitData } from "../Unit";

function Detectability({ question }: { question: CollectionQuestion }) {
  const status = question.platform_detection_status as CoverageStatus | null;
  if (status === "covered") {
    return (
      <div className="rounded-sm border border-primary/30 bg-primary/5 p-3">
        <div className="flex items-center gap-2 text-label-md text-primary">
          <CircleCheck size={14} />
          Detectable here
        </div>
        <p className="mt-1 text-body-sm text-on-surface-variant">
          The pinned detection content has a rule for it on{" "}
          {question.platform_logsources.length > 0 ? "these log sources:" : "an ingested log source."}
        </p>
        {question.platform_logsources.length > 0 && (
          <div className="mt-1.5 flex flex-wrap gap-1">
            {question.platform_logsources.map((source) => (
              <Badge key={source} tone="muted" className="normal-case tracking-normal">
                {source}
              </Badge>
            ))}
          </div>
        )}
      </div>
    );
  }
  return (
    <div className="rounded-sm border border-warning/30 bg-warning/5 p-3">
      <div className="flex items-center gap-2 text-label-md text-warning">
        <CircleSlash size={14} />
        Not detectable yet
        {status && <span className="font-normal text-on-surface-variant">— {COVERAGE_LABEL[status] ?? status}</span>}
      </div>
      <p className="mt-1 text-body-sm text-on-surface-variant">
        {status ? (COVERAGE_MEANING[status] ?? "") : "The coverage report has no entry for this technique."}
      </p>
      {question.platform_blocked_by.length > 0 && (
        <>
          <div className="label mt-2">Blocked by</div>
          <div className="mt-1 flex flex-wrap gap-1">
            {question.platform_blocked_by.map((blocker) => (
              <Badge key={blocker} tone="muted" className="normal-case tracking-normal">
                {blocker}
              </Badge>
            ))}
          </div>
        </>
      )}
    </div>
  );
}

function QuestionCard({ question, names }: { question: CollectionQuestion; names: Map<string, string> }) {
  const [open, setOpen] = useState(false);
  const using = question.candidates_using.length;
  const total = question.candidates_total;
  const users = question.candidates_using.map((id) => names.get(id) ?? id).sort((a, b) => a.localeCompare(b));
  return (
    <Card className="flex flex-col gap-3">
      <div>
        <AttackId id={question.technique_id} />
        <h3 className="mt-2 text-headline-md text-on-surface">{question.technique_name}</h3>
      </div>
      <div>
        <div className="mb-1.5 flex items-baseline justify-between gap-3 text-body-md">
          <span className="text-on-surface">
            <span className="font-mono font-semibold">{integer(using)}</span> of{" "}
            <span className="font-mono">{integer(total)}</span> candidates are recorded using it
          </span>
          <span className="shrink-0 font-mono text-code-sm text-on-surface-variant" title="min(k, n − k): candidates the answer would set apart">
            split {integer(question.split)}
          </span>
        </div>
        <StackedBar
          height={8}
          segments={[
            { key: "use", label: "Recorded using it", value: using, color: "var(--color-primary-container)" },
            { key: "not", label: "Not recorded using it", value: total - using, color: "var(--color-outline-variant)" },
          ]}
        />
      </div>
      <p className="text-body-md text-on-surface-variant">{question.rationale}</p>
      {question.data_components.length > 0 && (
        <div>
          <div className="label mb-1">ATT&amp;CK data components to collect</div>
          <div className="flex flex-wrap gap-1">
            {question.data_components.map((component) => (
              <Badge key={component} tone="tertiary" className="normal-case tracking-normal">
                {component}
              </Badge>
            ))}
          </div>
        </div>
      )}
      <Detectability question={question} />
      <button
        type="button"
        onClick={() => setOpen((value) => !value)}
        aria-expanded={open}
        className="mt-auto flex items-center gap-1.5 text-label-md text-on-surface-variant hover:text-on-surface"
      >
        <Disclosure open={open} />
        {plural(using, "candidate")} recorded using it (A–Z)
      </button>
      {open && <p className="text-body-sm leading-relaxed text-on-surface-variant">{users.join(" · ")}</p>}
    </Card>
  );
}

export function GuidanceTab({ data }: { data: UnitData }) {
  const analysis = data.unit.attribution_analysis;
  const guidance = analysis.collection_guidance;
  const names = new Map(analysis.candidates.map((c) => [c.candidate_id, c.name]));
  if (!guidance || guidance.questions.length === 0) {
    return (
      <EmptyState title="No unobserved technique separates these candidates">
        <p>
          {analysis.candidates.length < 2
            ? "With fewer than two candidates there is nothing to tell apart."
            : "Every technique that some candidates use and others do not is already observed, or none exists in ATT&CK."}
        </p>
      </EmptyState>
    );
  }
  return (
    <div className="space-y-4">
      <p className="max-w-4xl text-body-md text-on-surface-variant">
        Techniques <span className="text-on-surface">not observed in this unit</span> that some candidates are recorded using
        and others are not. Looking for one — and finding or not finding it — would set candidates apart. Shown in the stored
        order: by how many candidates the answer would separate, then by whether this platform can detect it.{" "}
        <span className="font-mono text-code-sm text-outline">
          {integer(guidance.questions.length)} kept of {integer(guidance.questions_considered)} considered · method{" "}
          {guidance.method_version}
        </span>
      </p>
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2 2xl:grid-cols-3">
        {guidance.questions.map((question) => (
          <QuestionCard key={question.technique_stix_id} question={question} names={names} />
        ))}
      </div>
    </div>
  );
}
