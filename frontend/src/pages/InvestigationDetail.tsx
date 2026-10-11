import { FileText, Search, X } from "lucide-react";
import { useMemo, useState } from "react";
import {
  AttackId,
  Button,
  Card,
  CardHeader,
  EmptyState,
  ErrorState,
  Field,
  Id,
  PageHeader,
  PageSkeleton,
  Select,
  Stat,
  Td,
  TextInput,
  Th,
  cx,
} from "../components/ui";
import {
  paths,
  useApi,
  type Activity,
  type Assessment,
  type Investigation,
  type ProfileMatchRecord,
  type TechniqueCatalogue,
  type UnitSearch,
  type UnitSummary,
} from "../lib/api";
import { buildTimeline, indexTechniques } from "../lib/derive";
import {
  duration,
  durationMs,
  integer,
  parseTime,
  plural,
  shortHash,
  shortId,
  utcClock,
  utcDate,
  utcDateTime,
} from "../lib/format";
import { links, navigate } from "../lib/router";
import { ActivityTimelineTab } from "./investigation/ActivityTimeline";
import { AttributionHeadline, AttributionTab } from "./investigation/Attribution";
import { EmulationTab } from "./investigation/Emulation";
import { MatrixTab } from "./investigation/Matrix";
import { ResponseTab } from "./investigation/Response";

const TABS = [
  { key: "overview", label: "Overview" },
  { key: "attribution", label: "Attribution" },
  { key: "matrix", label: "ATT&CK matrix" },
  { key: "timeline", label: "Timeline" },
  { key: "response", label: "Response" },
  { key: "emulation", label: "Detection validation" },
] as const;

type TabKey = (typeof TABS)[number]["key"];

/** The attribution outcome in brief, with the way into its detail. */
function AttributionSummary({ id }: { id: string }) {
  const assessment = useApi<Assessment>(paths.assessment(id));
  const profile = useApi<ProfileMatchRecord>(paths.profileMatch(id));
  if (assessment.state !== "ready" || profile.state !== "ready") return null;
  return (
    <Card>
      <div className="flex flex-wrap items-start justify-between gap-4">
        <AttributionHeadline assessment={assessment.data} match={profile.data} />
        <div className="flex shrink-0 gap-2">
          <Button href={links.investigation(id, "attribution")} variant="primary">
            Attribution detail
          </Button>
          <Button href={links.investigation(id, "response")}>Response</Button>
        </div>
      </div>
    </Card>
  );
}

/** The matrix and the timeline are two drawings of one read: the investigation's activity. */
function ActivityView({ id, view }: { id: string; view: "matrix" | "timeline" }) {
  const activity = useApi<Activity>(paths.activity(id));
  const catalogue = useApi<TechniqueCatalogue>(paths.techniques());
  const index = useMemo(
    () => (catalogue.state === "ready" ? indexTechniques(catalogue.data) : null),
    [catalogue.state, catalogue.data],
  );
  if (activity.state === "error") return <ErrorState failure={activity.error} onRetry={activity.reload} />;
  if (catalogue.state === "error") return <ErrorState failure={catalogue.error} onRetry={catalogue.reload} />;
  if (activity.state !== "ready" || !index) return <PageSkeleton rows={5} />;
  return view === "matrix" ? (
    <MatrixTab activity={activity.data} index={index} investigationId={id} />
  ) : (
    <ActivityTimelineTab activity={activity.data} index={index} />
  );
}

const MAX_CHIPS = 5;

export function TechniqueChips({ ids, max = MAX_CHIPS }: { ids: string[]; max?: number }) {
  const shown = ids.slice(0, max);
  return (
    <span className="flex flex-wrap items-center gap-1">
      {shown.map((id) => (
        <AttackId key={id} id={id} />
      ))}
      {ids.length > shown.length && (
        <span
          title={ids.slice(max).join(", ")}
          className="font-mono text-code-sm text-on-surface-variant"
        >
          +{ids.length - shown.length}
        </span>
      )}
      {ids.length === 0 && <span className="text-outline">—</span>}
    </span>
  );
}

function Timeline({ units, onOpen }: { units: UnitSummary[]; onOpen: (id: string) => void }) {
  const timeline = useMemo(() => buildTimeline(units), [units]);
  if (!timeline) return null;
  const span = Math.max(timeline.end - timeline.start, 1);
  const ticks = [0, 0.25, 0.5, 0.75, 1].map((f) => new Date(timeline.start + span * f).toISOString());
  const sameDay = utcDate(ticks[0]) === utcDate(ticks[4]);
  return (
    <Card padded={false}>
      <CardHeader
        title="Timeline by host"
        hint={`${utcDateTime(new Date(timeline.start).toISOString())} → ${utcDateTime(
          new Date(timeline.end).toISOString(),
        )} · ${durationMs(timeline.end - timeline.start)} · one bar per attribution unit, first to last observation`}
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
          {timeline.lanes.map((lane) => (
            <div key={lane.host} className="contents">
              <div className="flex h-9 items-center justify-between gap-2 border-t border-outline-variant/40 pr-1">
                <span className="truncate font-mono text-code-md text-on-surface" title={lane.host}>
                  {lane.host}
                </span>
                <span className="shrink-0 font-mono text-code-sm text-outline">{lane.units.length}</span>
              </div>
              <div className="relative h-9 border-t border-outline-variant/40 bg-surface-lowest/60">
                {lane.units.map((unit) => {
                  const start = parseTime(unit.first_seen)?.getTime() ?? timeline.start;
                  const end = parseTime(unit.last_seen)?.getTime() ?? start;
                  return (
                    <button
                      key={unit.group_id}
                      type="button"
                      onClick={() => onOpen(unit.group_id)}
                      title={`${utcDateTime(unit.first_seen)} · ${duration(unit.first_seen, unit.last_seen)} · ${plural(unit.evidence, "evidence item")} · ${unit.technique_ids.join(", ") || "no technique"}`}
                      style={{
                        left: `${((start - timeline.start) / span) * 100}%`,
                        width: `max(6px, ${((end - start) / span) * 100}%)`,
                      }}
                      className="absolute top-2 h-5 rounded-sm border border-primary/70 bg-primary/30 hover:z-10 hover:bg-primary/70"
                      aria-label={`Unit ${shortId(unit.group_id)}`}
                    />
                  );
                })}
              </div>
            </div>
          ))}
        </div>
      </div>
    </Card>
  );
}

export function InvestigationDetailPage({ id, tab }: { id: string; tab?: string }) {
  const investigation = useApi<Investigation>(paths.investigation(id));
  const search = useApi<UnitSearch>(paths.investigationUnits(id));
  const [host, setHost] = useState("");
  const [technique, setTechnique] = useState("");
  const [text, setText] = useState("");

  const units = search.state === "ready" ? search.data.units : [];
  const hosts = useMemo(() => [...new Set(units.flatMap((u) => u.host_names))].sort(), [units]);
  const techniques = useMemo(() => [...new Set(units.flatMap((u) => u.technique_ids))].sort(), [units]);
  const filtered = useMemo(() => {
    const needle = text.trim().toLowerCase();
    return units.filter(
      (u) =>
        (host === "" || u.host_names.includes(host)) &&
        (technique === "" || u.technique_ids.includes(technique)) &&
        (needle === "" ||
          u.group_id.toLowerCase().includes(needle) ||
          u.candidate_ids.some((c) => c.toLowerCase() === needle) ||
          u.technique_ids.some((t) => t.toLowerCase().startsWith(needle))),
    );
  }, [units, host, technique, text]);

  if (investigation.state === "loading" || search.state === "loading") return <PageSkeleton />;
  if (investigation.state === "error") {
    return <ErrorState failure={investigation.error} onRetry={investigation.reload} />;
  }
  if (search.state === "error") return <ErrorState failure={search.error} onRetry={search.reload} />;

  const record = investigation.data;
  const found = search.data;
  const active: TabKey = TABS.some((t) => t.key === tab) ? (tab as TabKey) : "overview";
  const filtering = host !== "" || technique !== "" || text.trim() !== "";
  const times = units.flatMap((u) => [u.first_seen, u.last_seen]).sort();
  return (
    <>
      <PageHeader
        eyebrow={`Investigation · ${record.source_kind}`}
        title={record.source_id}
        right={
          <>
            <Button href={links.dossier(record.investigation_id)} variant="primary">
              <FileText size={14} />
              Full report
            </Button>
          </>
        }
      >
        <div className="mt-4 grid grid-cols-1 gap-x-8 gap-y-4 rounded-md border border-outline-variant/70 bg-surface-low p-4 md:grid-cols-2 xl:grid-cols-3">
          <Field label="Investigation id">
            <Id value={record.investigation_id} display={shortId(record.investigation_id, 18)} />
          </Field>
          <Field label="Source SHA-256">
            <Id value={record.source_sha256} display={shortHash(record.source_sha256, 20)} />
          </Field>
          <Field label="ATT&CK knowledge base">
            <span className="font-mono text-code-md">{record.attack_kb_version}</span>
          </Field>
        </div>
      </PageHeader>

      <div
        role="tablist"
        aria-label="Investigation views"
        className="no-print sticky top-14 z-10 -mx-6 mb-6 flex gap-1 overflow-x-auto border-b border-outline-variant/70 bg-background/95 px-6 backdrop-blur"
      >
        {TABS.map((item) => {
          const selected = item.key === active;
          return (
            <a
              key={item.key}
              role="tab"
              aria-selected={selected}
              href={links.investigation(id, item.key === "overview" ? undefined : item.key)}
              className={cx(
                "-mb-px flex h-10 shrink-0 items-center border-b-2 px-3 text-label-md transition-colors",
                selected
                  ? "border-primary text-primary"
                  : "border-transparent text-on-surface-variant hover:text-on-surface",
              )}
            >
              {item.label}
            </a>
          );
        })}
      </div>

      {(active === "matrix" || active === "timeline") && <ActivityView id={id} view={active} />}
      {active === "emulation" && <EmulationTab investigationId={id} />}
      {active === "attribution" && <AttributionTab investigationId={id} />}
      {active === "response" && <ResponseTab investigationId={id} />}
      {active === "overview" && renderOverview()}
    </>
  );

  function renderOverview() {
    return (
      <>
        <div className="mb-6 grid grid-cols-2 gap-4 lg:grid-cols-3 xl:grid-cols-6">
          <Stat label="Observations" value={integer(record.observations_persisted)} sub="persisted (matched by a rule)" />
          <Stat
            label="Evidence"
            value={integer(record.evidence)}
            sub={`${integer(record.evidence_in_units)} in units · ${integer(record.evidence_outside_units)} low-level, in no unit`}
          />
          <Stat label="Units" value={integer(record.units.length)} accent />
          <Stat label="Hosts" value={integer(hosts.length)} />
          <Stat label="Techniques" value={integer(techniques.length)} sub="observed, incl. parents" />
          <Stat
            label="Time span"
            value={<span className="text-headline-lg">{times.length ? duration(times[0], times[times.length - 1]) : "—"}</span>}
            sub={times.length ? `from ${utcDateTime(times[0])}` : undefined}
          />
        </div>

        {units.length === 0 ? (
          <EmptyState title="No detections in this log source">
            <p>
              The engine read the source and no pinned rule fired on it, so there is no Evidence, no
              unit and nothing to attribute. That is a result, not an error.
            </p>
            <p>
              <a href={links.coverage()} className="text-primary hover:underline">
                Detection Coverage
              </a>{" "}
              shows which techniques the pinned content can see on which log sources.
            </p>
          </EmptyState>
        ) : (
          <div className="space-y-6">
            <AttributionSummary id={record.investigation_id} />
            {record.evidence_outside_units > 0 && (
              <p className="max-w-4xl text-body-md text-on-surface-variant">
                <span className="text-on-surface">{integer(record.evidence_outside_units)} low-level Evidence items are in no unit.</span>{" "}
                They come from enrich-tier rules (common administrative behaviour) and have no structural link to core
                Evidence, so they neither form a unit nor add a technique to any comparison (ADR-0003 Amendment H). Units below
                account for the other {integer(record.evidence_in_units)}.
              </p>
            )}
            <Timeline units={filtered} onOpen={(unitId) => navigate(links.unit(unitId))} />
            <Card padded={false}>
              <CardHeader
                title="Attribution units"
                hint={
                  <>
                    {filtering
                      ? `${integer(filtered.length)} of ${integer(units.length)} units`
                      : plural(units.length, "unit")}{" "}
                    · ordered by first observation
                    {found.truncated && (
                      <span className="text-warning">
                        {" "}
                        · the API returned only the first {integer(found.limit)}
                      </span>
                    )}
                  </>
                }
                right={
                  <>
                    <Select
                      ariaLabel="Host"
                      value={host}
                      onChange={setHost}
                      options={[{ value: "", label: "All hosts" }, ...hosts.map((h) => ({ value: h, label: h }))]}
                    />
                    <Select
                      ariaLabel="Technique"
                      value={technique}
                      onChange={setTechnique}
                      options={[
                        { value: "", label: "All techniques" },
                        ...techniques.map((t) => ({ value: t, label: t })),
                      ]}
                    />
                    <TextInput
                      value={text}
                      onChange={setText}
                      placeholder="Unit id, G0016, T1059…"
                      icon={<Search size={14} />}
                      className="w-52"
                      mono
                    />
                    {filtering && (
                      <Button
                        variant="ghost"
                        onClick={() => {
                          setHost("");
                          setTechnique("");
                          setText("");
                        }}
                      >
                        <X size={13} />
                        Clear
                      </Button>
                    )}
                  </>
                }
              />
              <div className="overflow-x-auto">
                <table className="w-full border-collapse text-body-md">
                  <thead>
                    <tr>
                      <Th>First observation (UTC)</Th>
                      <Th>Duration</Th>
                      <Th>Host</Th>
                      <Th>Techniques observed</Th>
                      <Th align="right">Candidates</Th>
                      <Th align="right">Evidence</Th>
                      <Th align="right">Steps</Th>
                      <Th>Unit</Th>
                    </tr>
                  </thead>
                  <tbody>
                    {filtered.map((unit) => (
                      <tr
                        key={unit.group_id}
                        onClick={() => navigate(links.unit(unit.group_id))}
                        className="cursor-pointer hover:bg-surface"
                      >
                        <Td className="whitespace-nowrap font-mono text-code-md">
                          <span className="text-on-surface-variant">{utcDate(unit.first_seen)}</span>{" "}
                          {utcClock(unit.first_seen, true)}
                        </Td>
                        <Td className="whitespace-nowrap font-mono text-code-md text-on-surface-variant">
                          {duration(unit.first_seen, unit.last_seen)}
                        </Td>
                        <Td className="font-mono text-code-md">{unit.host_names.join(", ") || "—"}</Td>
                        <Td>
                          <TechniqueChips ids={unit.technique_ids} />
                        </Td>
                        <Td align="right" className="font-mono tabular-nums">
                          {integer(unit.candidate_ids.length)}
                        </Td>
                        <Td align="right" className="font-mono tabular-nums">
                          {integer(unit.evidence)}
                        </Td>
                        <Td align="right" className="font-mono tabular-nums">
                          {integer(unit.steps)}
                        </Td>
                        <Td>
                          <a
                            href={links.unit(unit.group_id)}
                            className="whitespace-nowrap font-mono text-code-sm text-primary hover:underline"
                            title={unit.group_id}
                          >
                            {shortId(unit.group_id, 8).replace("corr-group::", "")}
                          </a>
                        </Td>
                      </tr>
                    ))}
                    {filtered.length === 0 && (
                      <tr>
                        <Td colSpan={8} className="py-8 text-center text-on-surface-variant">
                          No unit matches these filters.
                        </Td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </Card>
          </div>
        )}
      </>
    );
  }
}
