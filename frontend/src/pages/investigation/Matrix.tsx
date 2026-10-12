import { useMemo, useState } from "react";
import { Card, CardHeader, EmptyState, Segmented, Select, Stat, cx } from "../../components/ui";
import type { Activity } from "../../lib/api";
import {
  matrixFromActivity,
  type ActivityRole,
  type MatrixTechnique,
  type TechniqueIndex,
} from "../../lib/derive";
import { attackUrl, integer, plural } from "../../lib/format";
import { links } from "../../lib/router";

export const ROLE_LABEL: Record<ActivityRole, string> = {
  actor: "Actor-specific",
  feature: "Decision feature",
  unmatched: "No candidate uses it",
  declared: "Declared by the rule only",
  context: "Context only",
};

export const ROLE_MEANING: Record<ActivityRole, string> = {
  actor: "Evidence from a rule its author tied to one named Group (ADR-0018).",
  feature: "Core Evidence for a technique at least one Group or Campaign uses: it enters the comparison.",
  unmatched: "Core Evidence for a technique no Group or Campaign is recorded using: observed, but it compares nothing.",
  declared:
    "The rule that fired lists this technique among several alternatives and the match does not say which. Shown for review; not counted when comparing with group profiles.",
  context: "Low-level Evidence only (common administrative behaviour): shown for context, never compared.",
};

const CELL: Record<ActivityRole, string> = {
  actor: "border-tertiary-dim/60 bg-tertiary-dim/15 hover:bg-tertiary-dim/25",
  feature: "border-primary/60 bg-primary/15 hover:bg-primary/25",
  unmatched: "border-warning/50 bg-warning/10 hover:bg-warning/20",
  declared: "border-dashed border-outline bg-surface-low hover:bg-surface-high",
  context: "border-outline-variant bg-surface hover:bg-surface-high",
};

const SWATCH: Record<ActivityRole, string> = {
  actor: "bg-tertiary-dim",
  feature: "bg-primary",
  unmatched: "bg-warning",
  declared: "bg-outline-variant",
  context: "bg-outline",
};

export function RoleLegend({ roles }: { roles: ActivityRole[] }) {
  return (
    <ul className="flex flex-wrap gap-x-6 gap-y-2 text-body-sm text-on-surface-variant">
      {roles.map((role) => (
        <li key={role} className="flex max-w-md items-start gap-2">
          <span className={cx("mt-1 h-2.5 w-2.5 shrink-0 rounded-sm", SWATCH[role])} aria-hidden />
          <span>
            <span className="text-on-surface">{ROLE_LABEL[role]}.</span> {ROLE_MEANING[role]}
          </span>
        </li>
      ))}
    </ul>
  );
}

function Cell({ technique, investigationId }: { technique: MatrixTechnique; investigationId: string }) {
  const sub = technique.attackId.includes(".");
  return (
    <a
      href={links.units({ investigation: investigationId, technique: technique.attackId })}
      title={`${technique.attackId} ${technique.name} — ${ROLE_LABEL[technique.role]} · ${plural(technique.evidence, "evidence item")} in ${plural(technique.units, "unit")}. Opens the units.`}
      className={cx("block rounded-sm border px-2 py-1.5 transition-colors", CELL[technique.role], sub && "ml-3")}
    >
      <div className="flex items-baseline justify-between gap-2">
        <span className="font-mono text-code-md text-on-surface">{technique.attackId}</span>
        <span className="shrink-0 font-mono text-code-sm text-on-surface-variant">
          {integer(technique.evidence)}
          <span className="text-outline"> / {integer(technique.units)}u</span>
        </span>
      </div>
      <div className="mt-0.5 text-body-sm leading-snug text-on-surface-variant">{technique.name || "—"}</div>
    </a>
  );
}

/** Evidence outside every unit is not part of the activity views; say how much that is. */
export function OutsideUnits({ activity }: { activity: Activity }) {
  const n = activity.evidence_outside_units ?? 0;
  if (n === 0) return null;
  return (
    <>
      {" "}
      {integer(n)} low-level Evidence {n === 1 ? "item is" : "items are"} in no unit and not included.
    </>
  );
}

type Show = "all" | "core";

export function MatrixTab({
  activity,
  index,
  investigationId,
}: {
  activity: Activity;
  index: TechniqueIndex;
  investigationId: string;
}) {
  const [host, setHost] = useState("");
  const [show, setShow] = useState<Show>("all");
  const hosts = useMemo(
    () => [...new Set(activity.events.map((e) => e.host ?? "").filter(Boolean))].sort(),
    [activity.events],
  );
  const columns = useMemo(() => {
    const events = activity.events.filter((e) => host === "" || e.host === host);
    const all = matrixFromActivity(events, index);
    return show === "all"
      ? all
      : all.map((c) => ({ ...c, techniques: c.techniques.filter((t) => t.role !== "context") }));
  }, [activity.events, index, host, show]);

  const distinct = new Map(columns.flatMap((c) => c.techniques).map((t) => [t.attackId, t]));
  const count = (role: ActivityRole) => [...distinct.values()].filter((t) => t.role === role).length;
  const tacticsSeen = columns.filter((c) => c.tactic !== "" && c.techniques.length > 0).length;
  const tactics = columns.filter((c) => c.tactic !== "").length;

  if (activity.events.length === 0) {
    return <EmptyState title="No Evidence in any unit, so there is no technique to place" />;
  }
  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <Stat label="Techniques observed" value={integer(distinct.size)} sub="techniques and sub-techniques with Evidence" accent />
        <Stat label="Tactics with Evidence" value={`${tacticsSeen} of ${tactics}`} sub="ATT&CK Enterprise tactics" />
        <Stat label="Decision features" value={integer(count("feature"))} sub="enter the comparison" />
        <Stat
          label="Not compared"
          value={integer(count("unmatched") + count("context"))}
          sub={`${integer(count("unmatched"))} no candidate uses · ${integer(count("context"))} context only`}
        />
      </div>
      <Card padded={false}>
        <CardHeader
          title="ATT&CK matrix of what was observed"
          hint={
            <>
              Tactics in ATT&CK order; each cell is a technique with Evidence in at least one unit. The numbers are
              Evidence items / units. A technique listed under several tactics appears under each — the recording
              does not say which one the activity served.
              <OutsideUnits activity={activity} />
            </>
          }
          right={
            <>
              <Segmented<Show>
                ariaLabel="Evidence tier"
                value={show}
                onChange={setShow}
                options={[
                  { value: "all", label: "All" },
                  { value: "core", label: "Core only" },
                ]}
              />
              {hosts.length > 1 && (
                <Select
                  ariaLabel="Host"
                  value={host}
                  onChange={setHost}
                  options={[{ value: "", label: "All hosts" }, ...hosts.map((h) => ({ value: h, label: h }))]}
                />
              )}
            </>
          }
        />
        <div className="overflow-x-auto px-4 py-4">
          <div className="flex min-w-max gap-2">
            {columns.map((column) => (
              <div key={column.tactic || "none"} className="w-44 shrink-0" data-tactic={column.tactic}>
                <div
                  className={cx(
                    "mb-2 flex h-12 flex-col justify-center rounded-sm border px-2",
                    column.techniques.length > 0
                      ? "border-outline-variant bg-surface-high"
                      : "border-outline-variant/40 bg-transparent",
                  )}
                >
                  <div
                    className={cx(
                      "text-label-md leading-tight",
                      column.techniques.length > 0 ? "text-on-surface" : "text-outline",
                    )}
                  >
                    {column.name}
                  </div>
                  <div className="font-mono text-code-sm text-outline">
                    {column.techniques.length > 0 ? plural(column.techniques.length, "technique") : "nothing observed"}
                  </div>
                </div>
                <div className="space-y-1.5">
                  {column.techniques.map((technique) => (
                    <Cell key={technique.attackId} technique={technique} investigationId={investigationId} />
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
        <div className="border-t border-outline-variant/70 px-4 py-3">
          <RoleLegend roles={["feature", "unmatched", "context"]} />
        </div>
      </Card>
      <p className="max-w-4xl text-body-md text-on-surface-variant">
        An empty column means no pinned rule matched this recording for that tactic. It does not mean the tactic did
        not happen:{" "}
        <a href={links.coverage()} className="text-primary hover:underline">
          Detection Coverage
        </a>{" "}
        shows what the pinned content can and cannot see. Technique pages:{" "}
        <a
          href={attackUrl("T1059") ?? "#"}
          target="_blank"
          rel="noreferrer noopener"
          className="text-primary hover:underline"
        >
          attack.mitre.org
        </a>
        .
      </p>
    </div>
  );
}
