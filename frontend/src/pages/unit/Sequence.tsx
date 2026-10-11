import { ArrowRight } from "lucide-react";
import { useMemo, useState } from "react";
import { AttackId, Badge, Button, Card, CardHeader, Id, Segmented, Td, Th, cx } from "../../components/ui";
import type { BehavioralStep, Evidence, Observation, SequenceEdge } from "../../lib/api";
import { isContextEvidence, isTechniqueEvidence, layoutSequence, ruleOf } from "../../lib/derive";
import { integer, parseTime, plural, shortHash, titleCase, utcClock, utcDateTime } from "../../lib/format";
import { href } from "../../lib/router";
import type { UnitData } from "../Unit";
import { OriginBadge, TierBadge } from "./EvidenceTab";

const W = 236;
const H = 78;
const GAP_X = 72;
const GAP_Y = 16;
const PAD = 20;
/** Beyond this a drawing is a hairball; the time-ordered list is used instead. */
const MAX_GRAPH_STEPS = 60;
const MAX_GRAPH_LINES = 400;
const LIST_PAGE = 200;
const MAX_ORDERING_SHOWN = 12;

const BASIS_COLOR: Record<string, string> = {
  process_lineage: "var(--color-primary-container)",
  temporal_same_entity: "var(--color-tertiary-container)",
};
const BASIS_LABEL: Record<string, string> = {
  process_lineage: "Process lineage — parent started child",
  temporal_same_entity: "Time order within the same process or entity",
};

/** What the stored ordering basis says about an edge's timestamps. */
function edgeCaveat(edge: SequenceEdge): string {
  if (edge.basis.timestamp_agreement === false) {
    return " — the later step's event carries an earlier timestamp; lineage decides the order";
  }
  return edge.basis.precision_uncertain ? " — timestamp precision uncertain" : "";
}

function stepLabel(observation: Observation | undefined): string {
  if (!observation) return "observation not in read model";
  const process = observation.process;
  if (process?.name) return process.name;
  if (process?.executable) return process.executable.split(/[\\/]/).pop() ?? process.executable;
  return observation.event?.action ?? observation.raw_reference?.source_type ?? "event";
}

interface StepView {
  step: BehavioralStep;
  observation: Observation | undefined;
  evidence: Evidence[];
  techniqueIds: string[];
  contextOnly: boolean;
  time: number;
}

function Inspector({
  view,
  data,
  steps,
  incoming,
  outgoing,
  gaps,
  unitId,
  onSelect,
}: {
  view: StepView;
  data: UnitData;
  steps: Map<string, StepView>;
  incoming: SequenceEdge[];
  outgoing: SequenceEdge[];
  gaps: number;
  unitId: string;
  onSelect: (stepId: string) => void;
}) {
  const { step, observation, evidence } = view;
  const process = observation?.process;
  const row = (label: string, value: string | number | null | undefined) =>
    value === null || value === undefined || value === "" ? null : (
      <div className="grid grid-cols-[5.5rem_1fr] gap-2">
        <dt className="font-mono text-code-sm text-outline">{label}</dt>
        <dd className="min-w-0 break-all font-mono text-code-sm text-on-surface">{value}</dd>
      </div>
    );
  const link = (edge: SequenceEdge, other: string, direction: string) => (
    <li key={edge.edge_id}>
      <button
        type="button"
        onClick={() => onSelect(other)}
        title={`${BASIS_LABEL[edge.basis.basis_kind] ?? edge.basis.basis_kind}${edgeCaveat(edge)}`}
        className="flex w-full items-center gap-2 rounded-sm px-1.5 py-1 text-left hover:bg-surface-high"
      >
        <span
          className="h-2 w-2 shrink-0 rounded-full"
          style={{ background: BASIS_COLOR[edge.basis.basis_kind] ?? "var(--color-outline)" }}
        />
        <span className="min-w-0 flex-1 truncate text-body-sm text-on-surface-variant">
          {direction} {stepLabel(steps.get(other)?.observation)}
        </span>
        <span className="shrink-0 font-mono text-code-sm text-outline">
          {titleCase(edge.basis.basis_kind)}
          {edge.basis.timestamp_agreement === false && " · timestamps disagree"}
        </span>
      </button>
    </li>
  );
  const ordering = [
    ...incoming.map((edge) => link(edge, edge.from_step_id, "after")),
    ...outgoing.map((edge) => link(edge, edge.to_step_id, "before")),
  ];
  return (
    <Card padded={false} className="xl:sticky xl:top-28 xl:max-h-[calc(100vh-8rem)] xl:overflow-y-auto">
      <CardHeader title="Step" hint={utcDateTime(observation?.timestamp, true)} />
      <div className="space-y-4 p-4">
        <dl className="space-y-1">
          {row("host", observation?.host?.name ?? observation?.host?.id)}
          {row("user", [observation?.user?.domain, observation?.user?.name].filter(Boolean).join("\\"))}
          {row("action", observation?.event?.action)}
          {row("process", process?.executable)}
          {row("command", process?.command_line)}
          {row("pid", process?.pid)}
          {row("parent", process?.parent_executable)}
          {row("parent cmd", process?.parent_command_line)}
          {row("source", observation?.raw_reference?.source_type)}
        </dl>
        <div>
          <div className="label mb-1.5">{plural(evidence.length, "Evidence item")} at this step</div>
          <ul className="space-y-1.5">
            {evidence.map((item) => {
              const rule = ruleOf(item, data.evidence.rules);
              return (
                <li key={item.evidence_id} className="rounded-sm border border-outline-variant/60 bg-surface-lowest p-2">
                  <div className="flex flex-wrap items-center gap-1.5">
                    {item.attack_ref?.external_id && <AttackId id={item.attack_ref.external_id} />}
                    <TierBadge evidence={item} />
                    {rule && <OriginBadge origin={rule.origin} />}
                  </div>
                  <div className="mt-1 text-body-sm text-on-surface-variant">{rule?.title ?? item.provenance.method}</div>
                </li>
              );
            })}
          </ul>
          <a
            href={href(["units", unitId, "evidence"])}
            className="mt-2 inline-flex items-center gap-1 text-label-md text-primary hover:underline"
          >
            Open in Evidence
            <ArrowRight size={12} />
          </a>
        </div>
        {(ordering.length > 0 || gaps > 0) && (
          <div>
            <div className="label mb-1">
              Ordering — after {integer(incoming.length)}, before {integer(outgoing.length)}
              {gaps > 0 && `, order unresolved with ${integer(gaps)}`}
            </div>
            <ul>{ordering.slice(0, MAX_ORDERING_SHOWN)}</ul>
            {ordering.length > MAX_ORDERING_SHOWN && (
              <p className="px-1.5 pt-1 text-body-sm text-outline">
                … and {integer(ordering.length - MAX_ORDERING_SHOWN)} more ordered steps
              </p>
            )}
          </div>
        )}
        <div className="border-t border-outline-variant/40 pt-3">
          <div className="label mb-1">Observation id</div>
          <Id value={step.observation_id} display={shortHash(step.observation_id, 40)} />
        </div>
      </div>
    </Card>
  );
}

function StepTechniques({ view, max }: { view: StepView; max: number }) {
  return (
    <span className="flex items-center gap-1 overflow-hidden">
      {view.techniqueIds.slice(0, max).map((id) => (
        <Badge key={id} tone={view.contextOnly ? "muted" : "tertiary"} className="normal-case tracking-normal">
          {id}
        </Badge>
      ))}
      {view.techniqueIds.length > max && (
        <span className="font-mono text-code-sm text-outline">+{view.techniqueIds.length - max}</span>
      )}
      {view.techniqueIds.length === 0 && <span className="font-mono text-code-sm text-outline">unmapped</span>}
    </span>
  );
}

function Graph({
  data,
  views,
  selected,
  onSelect,
}: {
  data: UnitData;
  views: Map<string, StepView>;
  selected: string | null;
  onSelect: (stepId: string) => void;
}) {
  const { sequence } = data.unit;
  const model = useMemo(() => {
    const layout = layoutSequence(sequence, (stepId) => views.get(stepId)?.time ?? 0);
    return {
      at: new Map(
        layout.steps.map((p) => [p.stepId, { x: PAD + p.layer * (W + GAP_X), y: PAD + p.row * (H + GAP_Y) }]),
      ),
      width: PAD * 2 + Math.max(layout.layers, 1) * (W + GAP_X) - GAP_X,
      height: PAD * 2 + Math.max(layout.rows, 1) * (H + GAP_Y) - GAP_Y,
    };
  }, [sequence, views]);
  const touches = (a: string, b: string) => a === selected || b === selected;
  return (
    <div className="max-h-[72vh] overflow-auto bg-surface-lowest">
      <div className="relative" style={{ width: model.width, height: model.height }}>
        <svg width={model.width} height={model.height} className="absolute inset-0" aria-hidden="true">
          <defs>
            {Object.entries(BASIS_COLOR).map(([kind, color]) => (
              <marker key={kind} id={`arrow-${kind}`} viewBox="0 0 8 8" refX="7" refY="4" markerWidth="7" markerHeight="7" orient="auto">
                <path d="M0,0 L8,4 L0,8 z" fill={color} />
              </marker>
            ))}
          </defs>
          {sequence.gaps.map((gap) => {
            const a = model.at.get(gap.step_id_a);
            const b = model.at.get(gap.step_id_b);
            if (!a || !b) return null;
            return (
              <line
                key={gap.gap_id}
                x1={a.x + W / 2}
                y1={a.y + H / 2}
                x2={b.x + W / 2}
                y2={b.y + H / 2}
                stroke="var(--color-outline)"
                strokeWidth={1}
                strokeDasharray="3 5"
                opacity={selected === null || touches(gap.step_id_a, gap.step_id_b) ? 0.8 : 0.3}
              >
                <title>{`Order unresolved: ${titleCase(gap.reason)}`}</title>
              </line>
            );
          })}
          {sequence.edges.map((edge) => {
            const a = model.at.get(edge.from_step_id);
            const b = model.at.get(edge.to_step_id);
            if (!a || !b) return null;
            const x1 = a.x + W;
            const y1 = a.y + H / 2;
            const x2 = b.x - 2;
            const y2 = b.y + H / 2;
            const bend = Math.max(GAP_X / 2, Math.abs(x2 - x1) / 2);
            const kind = edge.basis.basis_kind;
            const lit = touches(edge.from_step_id, edge.to_step_id);
            return (
              <path
                key={edge.edge_id}
                d={`M${x1},${y1} C${x1 + bend},${y1} ${x2 - bend},${y2} ${x2},${y2}`}
                fill="none"
                stroke={BASIS_COLOR[kind] ?? "var(--color-outline)"}
                strokeWidth={lit ? 2 : 1.25}
                strokeDasharray={
                  edge.basis.precision_uncertain || edge.basis.timestamp_agreement === false ? "6 3" : undefined
                }
                opacity={selected === null || lit ? 0.95 : 0.25}
                markerEnd={`url(#arrow-${kind in BASIS_COLOR ? kind : "process_lineage"})`}
              >
                <title>{`${BASIS_LABEL[kind] ?? kind}${edgeCaveat(edge)}`}</title>
              </path>
            );
          })}
        </svg>
        {sequence.steps.map((step) => {
          const position = model.at.get(step.step_id);
          const view = views.get(step.step_id);
          if (!position || !view) return null;
          const active = step.step_id === selected;
          return (
            <button
              key={step.step_id}
              type="button"
              onClick={() => onSelect(step.step_id)}
              aria-pressed={active}
              style={{ left: position.x, top: position.y, width: W, height: H }}
              className={cx(
                "absolute flex flex-col justify-between rounded-md border bg-surface-low px-2.5 py-2 text-left transition-colors",
                active
                  ? "border-primary shadow-[0_0_0_1px_var(--color-primary)]"
                  : view.contextOnly
                    ? "border-outline-variant/70 hover:border-outline"
                    : "border-outline-variant hover:border-primary/60",
              )}
            >
              <span className="flex items-center justify-between gap-2">
                <span className="font-mono text-code-sm text-on-surface-variant">
                  {utcClock(view.observation?.timestamp, true)}
                </span>
                {view.contextOnly ? (
                  <Badge tone="muted">context</Badge>
                ) : (
                  <span className="font-mono text-code-sm text-outline">{view.evidence.length} ev</span>
                )}
              </span>
              <span
                className="truncate font-mono text-code-md text-on-surface"
                title={view.observation?.process?.command_line ?? stepLabel(view.observation)}
              >
                {stepLabel(view.observation)}
              </span>
              <StepTechniques view={view} max={3} />
            </button>
          );
        })}
      </div>
    </div>
  );
}

function StepList({
  ordered,
  selected,
  onSelect,
}: {
  ordered: StepView[];
  selected: string | null;
  onSelect: (stepId: string) => void;
}) {
  const [limit, setLimit] = useState(LIST_PAGE);
  return (
    <>
      <div className="max-h-[72vh] overflow-auto">
        <table className="w-full border-collapse text-body-md">
          <thead>
            <tr>
              <Th className="whitespace-nowrap">Time (UTC)</Th>
              <Th>Step</Th>
              <Th>Techniques</Th>
              <Th align="right">Evidence</Th>
            </tr>
          </thead>
          <tbody>
            {ordered.slice(0, limit).map((view) => {
              const active = view.step.step_id === selected;
              return (
                <tr
                  key={view.step.step_id}
                  data-step
                  onClick={() => onSelect(view.step.step_id)}
                  aria-selected={active}
                  className={cx("cursor-pointer hover:bg-surface", active && "bg-primary/5")}
                >
                  <Td
                    className={cx(
                      "whitespace-nowrap border-l-2 font-mono text-code-md",
                      active ? "border-l-primary" : "border-l-transparent",
                    )}
                  >
                    {utcClock(view.observation?.timestamp, true)}
                  </Td>
                  <Td className="max-w-md">
                    <span className="block truncate font-mono text-code-md text-on-surface">
                      {stepLabel(view.observation)}
                    </span>
                    {view.observation?.process?.command_line && (
                      <span
                        className="block truncate font-mono text-code-sm text-on-surface-variant"
                        title={view.observation.process.command_line}
                      >
                        {view.observation.process.command_line}
                      </span>
                    )}
                  </Td>
                  <Td>
                    <StepTechniques view={view} max={4} />
                  </Td>
                  <Td align="right" className="whitespace-nowrap font-mono tabular-nums">
                    {view.evidence.length}
                    {view.contextOnly && <span className="ml-1.5 text-outline">context</span>}
                  </Td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      {ordered.length > limit && (
        <div className="flex items-center justify-between border-t border-outline-variant/70 px-4 py-3">
          <span className="text-body-sm text-on-surface-variant">
            Showing {integer(limit)} of {integer(ordered.length)} steps
          </span>
          <Button onClick={() => setLimit((n) => n + LIST_PAGE)}>Show more</Button>
        </div>
      )}
    </>
  );
}

export function SequenceTab({ data, unitId }: { data: UnitData; unitId: string }) {
  const { sequence } = data.unit;
  const { observations } = data.evidence;

  const model = useMemo(() => {
    const evidenceById = new Map(data.evidence.evidence.map((e) => [e.evidence_id, e]));
    const views = new Map<string, StepView>();
    for (const step of sequence.steps) {
      const observation = observations[step.observation_id];
      const evidence = step.evidence_ids.map((id) => evidenceById.get(id)).filter((e): e is Evidence => !!e);
      views.set(step.step_id, {
        step,
        observation,
        evidence,
        techniqueIds: [
          ...new Set(
            evidence
              .filter(isTechniqueEvidence)
              .map((e) => e.attack_ref.external_id)
              .filter((id): id is string => !!id),
          ),
        ],
        contextOnly: evidence.length > 0 && evidence.every(isContextEvidence),
        time: parseTime(observation?.timestamp)?.getTime() ?? 0,
      });
    }
    const incoming = new Map<string, SequenceEdge[]>();
    const outgoing = new Map<string, SequenceEdge[]>();
    const push = (map: Map<string, SequenceEdge[]>, key: string, edge: SequenceEdge) => {
      const list = map.get(key);
      if (list) list.push(edge);
      else map.set(key, [edge]);
    };
    for (const edge of sequence.edges) {
      push(incoming, edge.to_step_id, edge);
      push(outgoing, edge.from_step_id, edge);
    }
    const gapCount = new Map<string, number>();
    for (const gap of sequence.gaps) {
      gapCount.set(gap.step_id_a, (gapCount.get(gap.step_id_a) ?? 0) + 1);
      gapCount.set(gap.step_id_b, (gapCount.get(gap.step_id_b) ?? 0) + 1);
    }
    const ordered = [...views.values()].sort(
      (a, b) => a.time - b.time || a.step.step_id.localeCompare(b.step.step_id),
    );
    return { views, incoming, outgoing, gapCount, ordered };
  }, [sequence, observations, data.evidence.evidence]);

  const drawable =
    sequence.steps.length <= MAX_GRAPH_STEPS && sequence.edges.length + sequence.gaps.length <= MAX_GRAPH_LINES;
  const [mode, setMode] = useState<"graph" | "list">(drawable ? "graph" : "list");
  const [selected, setSelected] = useState<string | null>(model.ordered[0]?.step.step_id ?? null);

  const lineage = sequence.edges.filter((e) => e.basis.basis_kind === "process_lineage").length;
  const disagree = sequence.edges.filter((e) => e.basis.timestamp_agreement === false).length;
  const current = selected ? model.views.get(selected) : undefined;

  return (
    <div className="grid grid-cols-1 gap-6 xl:grid-cols-[1fr_22rem]">
      <Card padded={false} className="min-w-0">
        <CardHeader
          title="Behavioural sequence"
          hint={
            <>
              {plural(sequence.steps.length, "step")} · {integer(lineage)} lineage and{" "}
              {integer(sequence.edges.length - lineage)} time-order edges ·{" "}
              {plural(sequence.gaps.length, "unresolved order", "unresolved orders")}
              {disagree > 0 && (
                <>
                  {" "}
                  · {integer(disagree)} lineage edge{disagree === 1 ? "" : "s"} against timestamp order
                </>
              )}
            </>
          }
          right={
            drawable && (
              <Segmented
                ariaLabel="Sequence view"
                value={mode}
                onChange={setMode}
                options={[
                  { value: "graph", label: "Graph" },
                  { value: "list", label: "Steps in time order" },
                ]}
              />
            )
          }
        />
        {!drawable && (
          <p className="border-b border-outline-variant/70 bg-surface px-4 py-2.5 text-body-sm text-on-surface-variant">
            This sequence has {integer(sequence.edges.length)} ordering edges and {integer(sequence.gaps.length)} unresolved
            orders between {integer(sequence.steps.length)} steps — a drawing would not be readable, so the steps are listed
            in time order. Select a step to see what the stored ordering says about it.
          </p>
        )}
        {mode === "graph" && drawable ? (
          <>
            <div className="flex flex-wrap items-center gap-x-4 gap-y-1 border-b border-outline-variant/70 px-4 py-2 text-body-sm text-on-surface-variant">
              {Object.entries(BASIS_LABEL).map(([kind, label]) => (
                <span key={kind} className="flex items-center gap-1.5">
                  <span className="h-0.5 w-5" style={{ background: BASIS_COLOR[kind] }} />
                  {label}
                </span>
              ))}
              <span className="flex items-center gap-1.5">
                <span className="h-0 w-5 border-t border-dashed border-outline" />
                Linked, order unresolved
              </span>
              <span>Left to right is resolved order only.</span>
            </div>
            <Graph data={data} views={model.views} selected={selected} onSelect={setSelected} />
          </>
        ) : (
          <StepList ordered={model.ordered} selected={selected} onSelect={setSelected} />
        )}
      </Card>
      {current ? (
        <Inspector
          view={current}
          data={data}
          steps={model.views}
          unitId={unitId}
          incoming={model.incoming.get(current.step.step_id) ?? []}
          outgoing={model.outgoing.get(current.step.step_id) ?? []}
          gaps={model.gapCount.get(current.step.step_id) ?? 0}
          onSelect={setSelected}
        />
      ) : (
        <Card>
          <p className="text-body-md text-on-surface-variant">Select a step to see what was observed.</p>
        </Card>
      )}
    </div>
  );
}
