import { ArrowRight, Search, X } from "lucide-react";
import { useEffect, useMemo, useState, type FormEvent } from "react";
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
  Select,
  TableSkeleton,
  Td,
  TextInput,
  Th,
  cx,
} from "../components/ui";
import { paths, useApi, type InvestigationSummary, type UnitSearch, type UnitSummary } from "../lib/api";
import { duration, integer, plural, shortId, utcClock, utcDate, utcDateTime } from "../lib/format";
import { links, navigate } from "../lib/router";
import { TechniqueChips } from "./InvestigationDetail";

const FILTERS = ["investigation", "technique", "host", "candidate"] as const;
type FilterName = (typeof FILTERS)[number];
type Filters = Record<FilterName, string>;

const TECHNIQUE = /^T\d{4}(\.\d{3})?$/;
const CANDIDATE = /^[GC]\d{4}$/;

function read(query: URLSearchParams): Filters {
  return {
    investigation: query.get("investigation") ?? "",
    technique: query.get("technique") ?? "",
    host: query.get("host") ?? "",
    candidate: query.get("candidate") ?? "",
  };
}

/** What the API would refuse, said before asking it. */
function problems(filters: Filters): Partial<Record<FilterName, string>> {
  const found: Partial<Record<FilterName, string>> = {};
  if (filters.technique && !TECHNIQUE.test(filters.technique)) found.technique = "Like T1059 or T1059.001";
  if (filters.candidate && !CANDIDATE.test(filters.candidate)) found.candidate = "Like G0016 or C0024";
  return found;
}

function Selected({ unit, source }: { unit: UnitSummary; source: string | undefined }) {
  return (
    <Card padded={false} className="order-first 2xl:sticky 2xl:top-20 2xl:order-none">
      <CardHeader title="Selected unit" hint={utcDateTime(unit.first_seen, true)} />
      <div className="space-y-4 p-4">
        <Field label="Unit id">
          <Id value={unit.group_id} display={shortId(unit.group_id, 14)} />
        </Field>
        <Field label="Recording">
          <a href={links.investigation(unit.investigation_id)} className="text-primary hover:underline">
            {source ?? shortId(unit.investigation_id, 10)}
          </a>
        </Field>
        <div className="grid grid-cols-3 gap-3">
          <Field label="Evidence">
            <span className="font-mono text-headline-md">{integer(unit.evidence)}</span>
          </Field>
          <Field label="Steps">
            <span className="font-mono text-headline-md">{integer(unit.steps)}</span>
          </Field>
          <Field label="Duration">
            <span className="font-mono text-code-md">{duration(unit.first_seen, unit.last_seen)}</span>
          </Field>
        </div>
        <Field label="Hosts">
          <span className="font-mono text-code-md">{unit.host_names.join(", ") || "—"}</span>
        </Field>
        <Field label={`Techniques observed (${unit.technique_ids.length}, incl. parent techniques)`}>
          <TechniqueChips ids={unit.technique_ids} max={40} />
        </Field>
        <Field label={`Candidates (${unit.candidate_ids.length}) — by ATT&CK id, not by likelihood`}>
          <div className="flex max-h-40 flex-wrap gap-1 overflow-y-auto">
            {unit.candidate_ids.map((id) => (
              <AttackId key={id} id={id} tone="muted" />
            ))}
            {unit.candidate_ids.length === 0 && <span className="text-outline">—</span>}
          </div>
        </Field>
        <Button href={links.unit(unit.group_id)} variant="primary">
          Open unit workspace
          <ArrowRight size={14} />
        </Button>
      </div>
    </Card>
  );
}

export function UnitsSearchPage({ query }: { query: URLSearchParams }) {
  const applied = useMemo(() => read(query), [query]);
  const [draft, setDraft] = useState<Filters>(applied);
  const [selected, setSelected] = useState<string | null>(null);
  useEffect(() => setDraft(applied), [applied]);

  const investigations = useApi<InvestigationSummary[]>(paths.investigations());
  const invalid = problems(applied);
  const valid = Object.keys(invalid).length === 0;
  const search = useApi<UnitSearch>(valid ? paths.units({ ...applied, limit: "500" }) : null);
  const sources = useMemo(
    () => new Map((investigations.data ?? []).map((i) => [i.investigation_id, i.source_id])),
    [investigations.data],
  );

  const submit = (event: FormEvent) => {
    event.preventDefault();
    navigate(
      links.units({
        investigation: draft.investigation,
        technique: draft.technique.trim().toUpperCase(),
        host: draft.host.trim().toLowerCase(),
        candidate: draft.candidate.trim().toUpperCase(),
      }),
    );
  };
  const set = (name: FilterName) => (value: string) => setDraft((current) => ({ ...current, [name]: value }));
  const active = FILTERS.filter((name) => applied[name] !== "");
  const draftProblems = problems({
    ...draft,
    technique: draft.technique.trim().toUpperCase(),
    candidate: draft.candidate.trim().toUpperCase(),
  });
  const units = search.state === "ready" ? search.data.units : [];
  const current = units.find((u) => u.group_id === selected) ?? null;

  return (
    <>
      <PageHeader
        title="Units search"
        description="Find attribution units across every investigation by exact technique, host or candidate. Filters combine with AND and are answered by the API, not in the browser."
      />
      <Card className="mb-6">
        <form onSubmit={submit} className="grid grid-cols-1 items-end gap-4 md:grid-cols-2 xl:grid-cols-[1.4fr_1fr_1fr_1fr_auto]">
          <Field label="Investigation">
            <Select
              ariaLabel="Investigation"
              value={draft.investigation}
              onChange={set("investigation")}
              className="w-full"
              options={[
                { value: "", label: "All investigations" },
                ...(investigations.data ?? []).map((i) => ({ value: i.investigation_id, label: i.source_id })),
              ]}
            />
          </Field>
          <Field label="Technique observed">
            <TextInput value={draft.technique} onChange={set("technique")} placeholder="T1003.001" mono className={cx(draftProblems.technique && "border-error")} />
            {draftProblems.technique && <p className="mt-1 text-body-sm text-error">{draftProblems.technique}</p>}
          </Field>
          <Field label="Host (exact name)">
            <TextInput value={draft.host} onChange={set("host")} placeholder="ws01.example.local" mono />
          </Field>
          <Field label="Candidate">
            <TextInput value={draft.candidate} onChange={set("candidate")} placeholder="G0016" mono className={cx(draftProblems.candidate && "border-error")} />
            {draftProblems.candidate && <p className="mt-1 text-body-sm text-error">{draftProblems.candidate}</p>}
          </Field>
          <div className="flex gap-2">
            <button
              type="submit"
              disabled={Object.keys(draftProblems).length > 0}
              className="inline-flex h-8 items-center gap-1.5 rounded-sm border border-primary-container bg-primary-container px-3 text-label-md text-on-primary hover:bg-primary disabled:pointer-events-none disabled:opacity-40"
            >
              <Search size={14} />
              Search
            </button>
            {active.length > 0 && (
              <Button variant="ghost" onClick={() => navigate(links.units())}>
                <X size={13} />
                Clear
              </Button>
            )}
          </div>
        </form>
      </Card>

      {!valid ? (
        <EmptyState title="These filters are not valid">
          <p>{Object.entries(invalid).map(([name, message]) => `${name}: ${message}`).join(" · ")}</p>
        </EmptyState>
      ) : search.state === "loading" ? (
        <TableSkeleton rows={8} />
      ) : search.state === "error" ? (
        <ErrorState failure={search.error} onRetry={search.reload} />
      ) : units.length === 0 ? (
        <EmptyState title={active.length > 0 ? "No unit matches every filter" : "No units in the read model"}>
          <p>
            {active.length > 0
              ? "Matching is exact: a technique filter matches the observed technique or its parent; a host filter needs the full lower-cased host name."
              : "Run an investigation to create units."}
          </p>
        </EmptyState>
      ) : (
        <div className="grid grid-cols-1 gap-6 2xl:grid-cols-[1fr_22rem]">
          <Card padded={false} className="min-w-0">
            <CardHeader
              title="Results"
              hint={
                <>
                  {plural(units.length, "unit")}
                  {active.length > 0 && <> matching {active.map((name) => `${name} = ${name === "investigation" ? (sources.get(applied[name]) ?? shortId(applied[name], 8)) : applied[name]}`).join(" AND ")}</>}{" "}
                  · ordered by first observation
                  {search.data.truncated && <span className="text-warning"> · only the first {integer(search.data.limit)} are returned</span>}
                </>
              }
            />
            <div className="overflow-x-auto">
              <table className="w-full border-collapse text-body-md">
                <thead>
                  <tr>
                    <Th className="whitespace-nowrap">First observation (UTC)</Th>
                    <Th>Recording</Th>
                    <Th>Host</Th>
                    <Th>Techniques observed</Th>
                    <Th align="right">Candidates</Th>
                    <Th align="right">Evidence</Th>
                  </tr>
                </thead>
                <tbody>
                  {units.map((unit) => (
                    <tr
                      key={unit.group_id}
                      onClick={() => setSelected(unit.group_id)}
                      onDoubleClick={() => navigate(links.unit(unit.group_id))}
                      aria-selected={unit.group_id === selected}
                      className={cx("cursor-pointer hover:bg-surface", unit.group_id === selected && "bg-primary/5")}
                    >
                      <Td className={cx("whitespace-nowrap border-l-2 font-mono text-code-md", unit.group_id === selected ? "border-l-primary" : "border-l-transparent")}>
                        <span className="text-on-surface-variant">{utcDate(unit.first_seen)}</span> {utcClock(unit.first_seen)}
                      </Td>
                      <Td className="max-w-48 truncate">{sources.get(unit.investigation_id) ?? shortId(unit.investigation_id, 8)}</Td>
                      <Td className="font-mono text-code-md">{unit.host_names.join(", ") || "—"}</Td>
                      <Td className="min-w-64">
                        <TechniqueChips ids={unit.technique_ids} max={4} />
                      </Td>
                      <Td align="right" className="font-mono tabular-nums">
                        {integer(unit.candidate_ids.length)}
                      </Td>
                      <Td align="right" className="font-mono tabular-nums">
                        {integer(unit.evidence)}
                      </Td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>
          {current ? (
            <Selected unit={current} source={sources.get(current.investigation_id)} />
          ) : (
            <Card className="order-first h-fit 2xl:sticky 2xl:top-20 2xl:order-none">
              <p className="text-body-md text-on-surface-variant">
                Select a row to see the unit’s stored summary. Double-click a row to open its workspace.
              </p>
            </Card>
          )}
        </div>
      )}
    </>
  );
}
