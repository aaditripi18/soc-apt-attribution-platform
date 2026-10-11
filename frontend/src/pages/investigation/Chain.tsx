import { GitBranch } from "lucide-react";
import { useMemo, useState } from "react";
import { Badge, Card, CardHeader, EmptyState, Select, Stat, cx } from "../../components/ui";
import type { Activity, UnitSummary } from "../../lib/api";
import { attackChain, type ActivityRole, type TechniqueIndex } from "../../lib/derive";
import { duration, durationMs, integer, plural, shortId, utcClock, utcDate, utcDateTime } from "../../lib/format";
import { links } from "../../lib/router";
import { ROLE_LABEL } from "./Matrix";

const CHIP: Record<ActivityRole, string> = {
  actor: "border-tertiary-dim/60 bg-tertiary-dim/15",
  feature: "border-primary/60 bg-primary/15",
  unmatched: "border-warning/50 bg-warning/10",
  context: "border-outline-variant bg-surface",
};

const iso = (ms: number) => new Date(ms).toISOString();

/** The intrusion as a chain: tactics in the order they were first observed. */
export function ChainTab({
  activity,
  index,
  units,
  investigationId,
}: {
  activity: Activity;
  index: TechniqueIndex;
  units: UnitSummary[];
  investigationId: string;
}) {
  const [host, setHost] = useState("");
  const hosts = useMemo(
    () => [...new Set(activity.events.map((e) => e.host ?? "").filter(Boolean))].sort(),
    [activity.events],
  );
  const chain = useMemo(
    () => attackChain(activity.events.filter((e) => host === "" || e.host === host), index),
    [activity.events, index, host],
  );
  const ordered = useMemo(
    () =>
      [...units]
        .filter((u) => host === "" || u.host_names.includes(host.toLowerCase()) || u.host_names.includes(host))
        .sort((a, b) => a.first_seen.localeCompare(b.first_seen)),
    [units, host],
  );

  if (chain.length === 0) {
    return <EmptyState title="No detected technique with a time and a tactic, so there is no chain to draw" />;
  }
  const first = chain[0]?.firstSeen ?? 0;
  const last = Math.max(...chain.map((stage) => stage.lastSeen));
  const techniques = new Set(chain.flatMap((stage) => stage.techniques.map((t) => t.attackId))).size;
  const sameDay = utcDate(iso(first)) === utcDate(iso(last));
  const stamp = (ms: number) => (sameDay ? utcClock(iso(ms)) : utcDateTime(iso(ms)));

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <Stat label="Stages" value={integer(chain.length)} sub="ATT&CK tactics with detections" accent />
        <Stat label="Techniques" value={integer(techniques)} sub="distinct techniques in the chain" />
        <Stat label="Duration" value={<span className="text-headline-lg">{durationMs(last - first)}</span>} sub={`from ${utcDateTime(iso(first))}`} />
        <Stat label="Activity clusters" value={integer(ordered.length)} sub="linked process chains behind it" />
      </div>

      <Card padded={false}>
        <CardHeader
          title="Attack chain"
          hint="Each stage is an ATT&CK tactic, placed in the order it was first observed in the logs. Open a technique to see the events behind it."
          right={
            hosts.length > 1 ? (
              <Select
                ariaLabel="Host"
                value={host}
                onChange={setHost}
                options={[{ value: "", label: "All hosts" }, ...hosts.map((h) => ({ value: h, label: h }))]}
              />
            ) : undefined
          }
        />
        <ol className="px-4 py-4">
          {chain.map((stage, position) => (
            <li key={stage.tactic} data-stage={stage.tactic}>
              <div className="grid grid-cols-[2.5rem_1fr] gap-x-4">
                <div className="flex flex-col items-center">
                  <span className="flex h-9 w-9 items-center justify-center rounded-md border border-primary/50 bg-primary/10 font-mono text-code-md text-primary">
                    {position + 1}
                  </span>
                  {position < chain.length - 1 && <span className="my-1 w-px flex-1 bg-outline-variant" />}
                </div>
                <div className={cx("min-w-0", position < chain.length - 1 && "pb-5")}>
                  <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
                    <h3 className="text-headline-md text-on-surface">{stage.name}</h3>
                    <span className="font-mono text-code-md text-on-surface-variant">
                      first seen {stamp(stage.firstSeen)}
                      {stage.lastSeen > stage.firstSeen && ` · active ${durationMs(stage.lastSeen - stage.firstSeen)}`}
                    </span>
                    <span className="font-mono text-code-sm text-outline">
                      {plural(stage.evidence, "detection")} · {stage.hosts.join(", ") || "no host"}
                    </span>
                  </div>
                  <div className="mt-2 flex flex-wrap gap-2">
                    {stage.techniques.map((technique) => (
                      <a
                        key={technique.attackId}
                        href={links.units({ investigation: investigationId, technique: technique.attackId })}
                        title={`${ROLE_LABEL[technique.role]} · first seen ${utcDateTime(iso(technique.firstSeen))}`}
                        className={cx("rounded-sm border px-2 py-1.5 transition-colors hover:brightness-125", CHIP[technique.role])}
                      >
                        <div className="flex items-baseline gap-2">
                          <span className="font-mono text-code-md text-on-surface">{technique.attackId}</span>
                          <span className="font-mono text-code-sm text-on-surface-variant">×{technique.evidence}</span>
                        </div>
                        <div className="text-body-sm text-on-surface-variant">{technique.name || "—"}</div>
                      </a>
                    ))}
                  </div>
                </div>
              </div>
            </li>
          ))}
        </ol>
        <p className="border-t border-outline-variant/70 px-4 py-2.5 text-body-sm text-on-surface-variant">
          The order is the order of first observation. Which process started which is shown, exactly, inside each
          activity cluster below.
        </p>
      </Card>

      <Card padded={false}>
        <CardHeader
          title="Process chains behind it"
          hint="Each activity cluster is a set of events linked by process lineage. Its sequence view shows the parent-to-child chain step by step."
        />
        <ul className="divide-y divide-outline-variant/50">
          {ordered.slice(0, 40).map((unit) => (
            <li key={unit.group_id} className="flex flex-wrap items-center gap-x-4 gap-y-2 px-4 py-3">
              <GitBranch size={15} className="shrink-0 text-on-surface-variant" />
              <span className="w-44 shrink-0 font-mono text-code-md text-on-surface">
                {utcDateTime(unit.first_seen)}
                <span className="block text-code-sm text-outline">{duration(unit.first_seen, unit.last_seen)}</span>
              </span>
              <span className="w-40 shrink-0 truncate font-mono text-code-md text-on-surface-variant">
                {unit.host_names.join(", ") || "—"}
              </span>
              <span className="flex min-w-0 flex-1 flex-wrap gap-1">
                {unit.technique_ids.slice(0, 8).map((id) => (
                  <Badge key={id} tone="tertiary" className="normal-case tracking-normal">
                    {id}
                  </Badge>
                ))}
                {unit.technique_ids.length > 8 && (
                  <span className="font-mono text-code-sm text-on-surface-variant">+{unit.technique_ids.length - 8}</span>
                )}
              </span>
              <span className="shrink-0 font-mono text-code-sm text-outline">
                {plural(unit.steps, "step")} · {plural(unit.evidence, "detection")}
              </span>
              <a href={links.unit(unit.group_id, "sequence")} className="shrink-0 text-label-md text-primary hover:underline" title={unit.group_id}>
                Open sequence {shortId(unit.group_id, 6).replace("corr-group::", "")}
              </a>
            </li>
          ))}
        </ul>
        {ordered.length > 40 && (
          <p className="border-t border-outline-variant/70 px-4 py-2.5 text-body-sm text-on-surface-variant">
            Showing the first 40 of {integer(ordered.length)} clusters; the Overview tab lists all of them.
          </p>
        )}
      </Card>
    </div>
  );
}
