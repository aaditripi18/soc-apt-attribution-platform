import { X } from "lucide-react";
import { useMemo, useState } from "react";
import { AttackId, Badge, Button, Card, CardHeader, EmptyState, Select, Td, Th, cx } from "../../components/ui";
import type { Activity, ActivityEvent } from "../../lib/api";
import {
  activityRole,
  timelineFromActivity,
  type ActivityBin,
  type ActivityRole,
  type TechniqueIndex,
} from "../../lib/derive";
import { durationMs, integer, plural, shortId, utcClock, utcDate, utcDateTime } from "../../lib/format";
import { links } from "../../lib/router";
import { OutsideUnits, ROLE_LABEL, RoleLegend } from "./Matrix";

const MARK: Record<ActivityRole, string> = {
  actor: "bg-tertiary-dim",
  feature: "bg-primary",
  unmatched: "bg-warning",
  declared: "bg-outline-variant",
  context: "bg-outline",
};

const TONE = { actor: "tertiary", feature: "primary", unmatched: "warning", declared: "muted", context: "muted" } as const;

/** Rows of a selected interval shown at once; the rest is reachable through the units. */
const MAX_ROWS = 200;

const iso = (ms: number) => new Date(ms).toISOString();

function byTime(a: ActivityEvent, b: ActivityEvent): number {
  return (a.time ?? "").localeCompare(b.time ?? "") || a.evidence_id.localeCompare(b.evidence_id);
}

export function ActivityTimelineTab({ activity, index }: { activity: Activity; index: TechniqueIndex }) {
  const [host, setHost] = useState("");
  const [selected, setSelected] = useState<{ lane: string; bin: number } | null>(null);
  const hosts = useMemo(
    () => [...new Set(activity.events.map((e) => e.host ?? "").filter(Boolean))].sort(),
    [activity.events],
  );
  const timeline = useMemo(
    () => timelineFromActivity(activity.events.filter((e) => host === "" || e.host === host), index),
    [activity.events, index, host],
  );

  if (!timeline) {
    return <EmptyState title="No Evidence with a time and an ATT&CK tactic, so there is nothing to draw" />;
  }
  const span = Math.max(timeline.end - timeline.start, 1);
  const width = span / timeline.binCount;
  const ticks = [0, 0.25, 0.5, 0.75, 1].map((f) => iso(timeline.start + span * f));
  const sameDay = utcDate(ticks[0]) === utcDate(ticks[4]);
  const lane = selected ? timeline.lanes.find((l) => l.key === selected.lane) : undefined;
  const bin: ActivityBin | undefined = selected ? lane?.bins.find((b) => b.index === selected.bin) : undefined;
  const rows = bin ? [...bin.events].sort(byTime) : [];
  const roles = (["actor", "feature", "unmatched", "context"] as ActivityRole[]).filter((role) =>
    timeline.lanes.some((l) => l.bins.some((b) => b.events.some((e) => activityRole(e) === role))),
  );

  return (
    <div className="space-y-6">
      <Card padded={false}>
        <CardHeader
          title="Evidence over time, by ATT&CK tactic"
          hint={
            <>
              {utcDateTime(iso(timeline.start))} → {utcDateTime(iso(timeline.end))} · {durationMs(span)} ·{" "}
              {integer(timeline.drawn)} Evidence items of all units, in {timeline.binCount} intervals of{" "}
              {durationMs(Math.max(1, Math.round(width)))}. A mark is coloured by the strongest role in its interval
              and grows with the number of items. Select a mark to list them.
              {timeline.undrawn > 0 && (
                <> {integer(timeline.undrawn)} items have no technique with a tactic and are not drawn.</>
              )}
              {host === "" && <OutsideUnits activity={activity} />}
            </>
          }
          right={
            hosts.length > 1 ? (
              <Select
                ariaLabel="Host"
                value={host}
                onChange={(value) => {
                  setHost(value);
                  setSelected(null);
                }}
                options={[{ value: "", label: "All hosts" }, ...hosts.map((h) => ({ value: h, label: h }))]}
              />
            ) : undefined
          }
        />
        <div className="px-4 py-4">
          <div className="grid grid-cols-[13rem_1fr] gap-x-3">
            <div />
            <div className="relative mb-2 h-4">
              {ticks.map((tick, i) => (
                <span
                  key={i}
                  style={{ left: `${i * 25}%` }}
                  className={cx(
                    "absolute top-0 font-mono text-code-sm text-outline",
                    i === 0 ? "" : i === 4 ? "-translate-x-full" : "-translate-x-1/2",
                  )}
                >
                  {sameDay ? utcClock(tick) : `${utcDate(tick).slice(5)} ${utcClock(tick).slice(0, 5)}`}
                </span>
              ))}
            </div>
            {timeline.lanes.map((item) => (
              <div key={item.key} className="contents" data-lane={item.key}>
                <div className="flex h-9 items-center justify-between gap-2 border-t border-outline-variant/40 pr-1">
                  <span className="truncate text-label-md text-on-surface" title={item.name}>
                    {item.name}
                  </span>
                  <span className="shrink-0 font-mono text-code-sm text-outline">{integer(item.evidence)}</span>
                </div>
                <div className="relative h-9 border-t border-outline-variant/40 bg-surface-lowest/60">
                  {item.bins.map((b) => {
                    const active = selected?.lane === item.key && selected.bin === b.index;
                    const height = Math.min(28, 8 + Math.round(Math.log2(b.events.length) * 4));
                    const from = iso(timeline.start + b.index * width);
                    return (
                      <button
                        key={b.index}
                        type="button"
                        onClick={() => setSelected(active ? null : { lane: item.key, bin: b.index })}
                        aria-pressed={active}
                        aria-label={`${item.name}, ${utcDateTime(from)}: ${plural(b.events.length, "evidence item")}`}
                        title={`${utcDateTime(from)} · ${plural(b.events.length, "evidence item")} · ${ROLE_LABEL[b.role]}`}
                        style={{
                          left: `${(b.index / timeline.binCount) * 100}%`,
                          width: `max(5px, ${100 / timeline.binCount}%)`,
                          height,
                          top: (36 - height) / 2,
                        }}
                        className={cx(
                          "absolute rounded-[1px] hover:z-10 hover:brightness-125",
                          MARK[b.role],
                          active ? "z-10 outline outline-2 outline-offset-1 outline-on-surface" : "opacity-80",
                        )}
                      />
                    );
                  })}
                </div>
              </div>
            ))}
          </div>
        </div>
        <div className="border-t border-outline-variant/70 px-4 py-3">
          <RoleLegend roles={roles} />
        </div>
      </Card>

      {bin && lane ? (
        <Card padded={false}>
          <CardHeader
            title={`${lane.name} · ${utcDateTime(iso(timeline.start + bin.index * width))}`}
            hint={`${plural(bin.events.length, "evidence item")} in this ${durationMs(Math.max(1, Math.round(width)))} interval${
              rows.length > MAX_ROWS ? ` · the first ${MAX_ROWS} shown; open a unit for all of it` : ""
            }`}
            right={
              <Button variant="ghost" onClick={() => setSelected(null)}>
                <X size={13} />
                Close
              </Button>
            }
          />
          <div className="overflow-x-auto">
            <table className="w-full border-collapse text-body-md">
              <thead>
                <tr>
                  <Th>Time (UTC)</Th>
                  <Th>Host</Th>
                  <Th>Observed</Th>
                  <Th>Mapped to</Th>
                  <Th>Role</Th>
                  <Th>Unit</Th>
                </tr>
              </thead>
              <tbody>
                {rows.slice(0, MAX_ROWS).map((event) => {
                  const role = activityRole(event);
                  return (
                    <tr key={event.evidence_id} className="hover:bg-surface">
                      <Td className="whitespace-nowrap font-mono text-code-md">{utcClock(event.time, true)}</Td>
                      <Td className="font-mono text-code-md">{event.host ?? "—"}</Td>
                      <Td className="font-mono text-code-md">{event.label ?? "—"}</Td>
                      <Td>
                        {event.attack_id ? (
                          <span className="flex items-center gap-2">
                            <AttackId id={event.attack_id} />
                            <span className="text-on-surface-variant">
                              {index.byAttackId.get(event.attack_id)?.name ?? ""}
                            </span>
                          </span>
                        ) : (
                          "—"
                        )}
                      </Td>
                      <Td>{role ? <Badge tone={TONE[role]}>{ROLE_LABEL[role]}</Badge> : "—"}</Td>
                      <Td>
                        <a
                          href={links.unit(event.group_id, "evidence")}
                          className="whitespace-nowrap font-mono text-code-sm text-primary hover:underline"
                          title={event.group_id}
                        >
                          {shortId(event.group_id, 8).replace("corr-group::", "")}
                        </a>
                      </Td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </Card>
      ) : (
        <p className="text-body-md text-on-surface-variant">
          Select a mark to list the Evidence in that interval. The order of tactics is ATT&CK's, not a claim about the
          order in which the activity happened — the horizontal axis is the only time here.
        </p>
      )}
    </div>
  );
}
