import {
  AttackId,
  Badge,
  Card,
  CardHeader,
  Command,
  EmptyState,
  ErrorState,
  Field,
  Id,
  PageSkeleton,
  Stat,
  StackedBar,
  Td,
  Th,
} from "../../components/ui";
import { paths, useApi, type EmulationComparison, type StepOutcome } from "../../lib/api";
import { integer, plural, shortHash, shortId, titleCase, utcClock, utcDateTime } from "../../lib/format";
import { links } from "../../lib/router";

const OUTCOMES: StepOutcome[] = [
  "technique_detected_in_step",
  "step_activity_detected",
  "technique_detected_elsewhere",
  "not_detected",
];

const LABEL: Record<StepOutcome, string> = {
  technique_detected_in_step: "Technique detected in the step",
  step_activity_detected: "Step seen, other technique",
  technique_detected_elsewhere: "Technique seen elsewhere",
  not_detected: "Not detected",
};

const MEANING: Record<StepOutcome, string> = {
  technique_detected_in_step:
    "Evidence for the technique the report names is grounded in the step's own process, inside its time window.",
  step_activity_detected:
    "The step's own process produced Evidence, but for other techniques than the one the report names.",
  technique_detected_elsewhere:
    "Nothing from the step's own process, but the investigation holds Evidence for the technique from other activity. It cannot be tied to this step.",
  not_detected: "No Evidence from the step's process and none for its technique anywhere in the investigation.",
};

const TONE = {
  technique_detected_in_step: "primary",
  step_activity_detected: "tertiary",
  technique_detected_elsewhere: "warning",
  not_detected: "error",
} as const;

const COLOR: Record<StepOutcome, string> = {
  technique_detected_in_step: "var(--color-primary)",
  step_activity_detected: "var(--color-tertiary-dim)",
  technique_detected_elsewhere: "var(--color-warning)",
  not_detected: "var(--color-error)",
};

export function EmulationTab({ investigationId }: { investigationId: string }) {
  const comparison = useApi<EmulationComparison>(paths.emulation(investigationId));
  if (comparison.state === "loading") return <PageSkeleton rows={5} />;
  if (comparison.state === "error") {
    if (comparison.error.kind !== "not_found") {
      return <ErrorState failure={comparison.error} onRetry={comparison.reload} />;
    }
    return (
      <EmptyState title="No emulation report was given for this recording">
        <p>
          When a recording comes from a lab run, the emulation tool's own report says what was executed. Given that
          report, the platform sets each step beside the Evidence it extracted — it measures detection against a
          known answer instead of asserting it.
        </p>
        <p>The comparison is made when the investigation is run (a MITRE CALDERA operation report is supported):</p>
        <Command>
          python -m attribution_platform.investigation recording.zip --emulation-report report.json --serve
        </Command>
        <p>Only step names, techniques, hosts, times and process ids are read from the report. Its command text is never read.</p>
      </EmptyState>
    );
  }

  const data = comparison.data;
  const total = data.steps.length;
  const withOwn = data.steps.filter((s) => s.step_evidence > 0).length;
  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <Stat label="Steps in the report" value={integer(total)} sub={data.profile_name ?? data.operation_name} />
        <Stat
          label="Technique detected in its step"
          value={`${data.outcome_counts.technique_detected_in_step} of ${total}`}
          accent
        />
        <Stat label="Steps with any Evidence" value={`${withOwn} of ${total}`} sub="from the step's own process" />
        <Stat
          label="Techniques with Evidence"
          value={`${data.distinct_techniques_with_evidence} of ${data.distinct_techniques}`}
          sub="distinct techniques named by the report, anywhere in the investigation"
        />
      </div>

      <Card>
        <div className="grid grid-cols-2 gap-x-8 gap-y-4 lg:grid-cols-5">
          <Field label="Emulation tool">{data.tool}</Field>
          <Field label="Operation">{data.operation_name || "—"}</Field>
          <Field label="Started (UTC)">
            <span className="font-mono text-code-md">{utcDateTime(data.started_at)}</span>
          </Field>
          <Field label="Finished (UTC)">
            <span className="font-mono text-code-md">{utcDateTime(data.finished_at)}</span>
          </Field>
          <Field label="Report SHA-256">
            <Id value={data.report_sha256} display={shortHash(data.report_sha256, 16)} />
          </Field>
        </div>
        <div className="mt-4">
          <StackedBar
            segments={OUTCOMES.map((outcome) => ({
              key: outcome,
              label: LABEL[outcome],
              value: data.outcome_counts[outcome] ?? 0,
              color: COLOR[outcome],
            }))}
          />
        </div>
        <ul className="mt-4 grid gap-x-8 gap-y-3 text-body-sm text-on-surface-variant md:grid-cols-2">
          {OUTCOMES.map((outcome) => (
            <li key={outcome} className="flex items-start gap-3">
              <Badge tone={TONE[outcome]} className="mt-0.5">
                {data.outcome_counts[outcome] ?? 0}
              </Badge>
              <span>
                <span className="text-on-surface">{LABEL[outcome]}.</span> {MEANING[outcome]}
              </span>
            </li>
          ))}
        </ul>
      </Card>

      <Card padded={false}>
        <CardHeader
          title="What ran, beside what was found"
          hint={`The left half is the tool's report; the right half is what the platform extracted from the recording alone. A step's own Evidence is matched by process id (or parent process id), host and time window ± ${data.window_slack_seconds} s.`}
        />
        <div className="overflow-x-auto">
          <table className="w-full border-collapse text-body-md">
            <thead>
              <tr>
                <Th align="right">#</Th>
                <Th>Issued (UTC)</Th>
                <Th>Step</Th>
                <Th>Technique named</Th>
                <Th>Lab result</Th>
                <Th>Outcome</Th>
                <Th>Found in the step's process</Th>
                <Th align="right">Technique anywhere</Th>
              </tr>
            </thead>
            <tbody>
              {data.steps.map((step) => (
                <tr key={step.order} className="align-top hover:bg-surface" data-outcome={step.outcome}>
                  <Td align="right" className="font-mono tabular-nums text-on-surface-variant">
                    {step.order}
                  </Td>
                  <Td className="whitespace-nowrap font-mono text-code-md">{utcClock(step.issued_at)}</Td>
                  <Td>
                    <div className="text-on-surface">{step.name}</div>
                    <div className="font-mono text-code-sm text-outline">
                      {[step.host, step.pid !== null ? `pid ${step.pid}` : null].filter(Boolean).join(" · ") || "—"}
                    </div>
                  </Td>
                  <Td>
                    {step.technique_id ? (
                      <div className="flex flex-wrap items-center gap-2">
                        <AttackId id={step.technique_id} />
                        <span className="text-on-surface-variant">{step.technique_name}</span>
                      </div>
                    ) : (
                      "—"
                    )}
                    {step.tactic && (
                      <div className="mt-0.5 text-body-sm text-outline">{titleCase(step.tactic.replace(/-/g, " "))}</div>
                    )}
                  </Td>
                  <Td>
                    <Badge tone={step.status === "success" ? "neutral" : "muted"}>{step.status}</Badge>
                  </Td>
                  <Td>
                    <Badge tone={TONE[step.outcome]} title={MEANING[step.outcome]}>
                      {LABEL[step.outcome]}
                    </Badge>
                  </Td>
                  <Td>
                    {step.step_evidence === 0 ? (
                      <span className="text-outline">nothing</span>
                    ) : (
                      <div className="space-y-1.5">
                        <div className="font-mono text-code-md">{plural(step.step_evidence, "evidence item")}</div>
                        <div className="flex flex-wrap gap-1">
                          {step.step_technique_ids.map((id) => (
                            <AttackId key={id} id={id} tone={id === step.technique_id ? "primary" : "tertiary"} />
                          ))}
                        </div>
                        <div className="flex flex-wrap gap-x-3">
                          {step.step_unit_ids.length === 0 && (
                            <span className="text-body-sm text-outline">low-level Evidence, in no unit</span>
                          )}
                          {step.step_unit_ids.map((unit) => (
                            <a
                              key={unit}
                              href={links.unit(unit, "evidence")}
                              title={unit}
                              className="font-mono text-code-sm text-primary hover:underline"
                            >
                              unit {shortId(unit, 8).replace("corr-group::", "")}
                            </a>
                          ))}
                        </div>
                      </div>
                    )}
                  </Td>
                  <Td align="right" className="whitespace-nowrap font-mono text-code-md tabular-nums">
                    {step.technique_evidence_core + step.technique_evidence_context === 0 ? (
                      <span className="text-outline">none</span>
                    ) : (
                      <>
                        {integer(step.technique_evidence_core)} core
                        <span className="text-on-surface-variant"> · {integer(step.technique_evidence_context)} context</span>
                      </>
                    )}
                  </Td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>

      <p className="max-w-4xl text-body-md text-on-surface-variant">
        This compares detection with a known answer; it says nothing about who ran the activity. A step that failed in
        the lab can still be detected (the attempt is behaviour), and a step that ran can leave nothing a pinned rule
        matches. One run on one host is an example, not a detection rate. Method {data.method_version},{" "}
        {data.schema_version}. The report's command text and output are never read, stored or shown.
      </p>
    </div>
  );
}
