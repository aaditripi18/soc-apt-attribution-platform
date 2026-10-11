import { Download, Search } from "lucide-react";
import { useMemo, useState } from "react";
import {
  AttackId,
  Badge,
  Button,
  Card,
  CardHeader,
  CopyButton,
  EmptyState,
  ErrorState,
  PageSkeleton,
  Segmented,
  Stat,
  Td,
  TextInput,
  Th,
} from "../../components/ui";
import { paths, useApi, type Observable, type Observables } from "../../lib/api";
import { integer, plural, shortId, utcDateTime } from "../../lib/format";
import { links } from "../../lib/router";

const KIND_LABEL: Record<Observable["kind"], string> = {
  sha256: "SHA-256",
  sha1: "SHA-1",
  md5: "MD5",
  ip: "IP address",
  domain: "Domain",
};

type Filter = "all" | "hash" | "network" | "advisory";

const isHash = (o: Observable) => o.kind === "sha256" || o.kind === "sha1" || o.kind === "md5";

function csv(rows: Observable[]): string {
  const cell = (value: string) => `"${value.replace(/"/g, '""')}"`;
  const lines = rows.map((o) =>
    [
      o.kind,
      o.value,
      o.scope ?? "",
      o.context.join("; "),
      o.technique_ids.join(" "),
      String(o.observations),
      o.first_seen,
      o.last_seen,
      o.advisory ? `${o.advisory.report_name ?? ""} (${o.advisory.named_actor ?? ""})` : "",
    ]
      .map(cell)
      .join(","),
  );
  return ["kind,value,scope,of,techniques,times_seen,first_seen,last_seen,advisory", ...lines].join("\n");
}

/** Values taken from the events behind the detections: what an analyst pivots on. */
export function IndicatorsTab({ investigationId, source }: { investigationId: string; source: string }) {
  const result = useApi<Observables>(paths.observables(investigationId));
  const [filter, setFilter] = useState<Filter>("all");
  const [text, setText] = useState("");
  const rows = useMemo(() => {
    if (result.state !== "ready") return [];
    const needle = text.trim().toLowerCase();
    return result.data.observables.filter(
      (o) =>
        (filter === "all" ||
          (filter === "hash" && isHash(o)) ||
          (filter === "network" && !isHash(o)) ||
          (filter === "advisory" && o.advisory !== null)) &&
        (needle === "" ||
          o.value.includes(needle) ||
          o.context.some((c) => c.toLowerCase().includes(needle)) ||
          o.technique_ids.some((t) => t.toLowerCase() === needle)),
    );
  }, [result.state, result.data, filter, text]);

  if (result.state === "loading") return <PageSkeleton rows={5} />;
  if (result.state === "error") return <ErrorState failure={result.error} onRetry={result.reload} />;
  const data = result.data;
  if (data.observables.length === 0) {
    return (
      <EmptyState title="No indicators in the detected activity">
        <p>
          The events behind the detections carry no file hash, network address or domain. Hashes need process or file
          hashing enabled in the log source; addresses and domains need network and DNS events.
        </p>
      </EmptyState>
    );
  }
  const hashes = data.counts.sha256 + data.counts.sha1 + data.counts.md5;
  const external = data.observables.filter((o) => o.kind === "ip" && o.scope === "external").length;

  const download = () => {
    const url = URL.createObjectURL(new Blob([csv(rows)], { type: "text/csv" }));
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `${source.replace(/[^A-Za-z0-9._-]+/g, "_")}-indicators.csv`;
    anchor.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <Stat label="Indicators" value={integer(data.observables.length)} sub="distinct values in detected activity" accent />
        <Stat label="File hashes" value={integer(hashes)} sub="of process images and files" />
        <Stat label="Network" value={integer(data.counts.ip + data.counts.domain)} sub={`${integer(external)} external addresses · ${integer(data.counts.domain)} domains`} />
        <Stat label="Advisory matches" value={integer(data.advisory_matches)} sub="equal to a published indicator" />
      </div>

      <Card padded={false}>
        <CardHeader
          title="Indicators of compromise"
          hint="Values stated by the events that triggered detections. They are candidates to verify and hunt on: a value is known-bad only where it matches a published advisory."
          right={
            <>
              <Segmented<Filter>
                ariaLabel="Indicator type"
                value={filter}
                onChange={setFilter}
                options={[
                  { value: "all", label: "All", count: data.observables.length },
                  { value: "hash", label: "Hashes", count: hashes },
                  { value: "network", label: "Network", count: data.counts.ip + data.counts.domain },
                  { value: "advisory", label: "Advisory", count: data.advisory_matches },
                ]}
              />
              <TextInput value={text} onChange={setText} placeholder="Value, file, T1059…" icon={<Search size={14} />} className="w-52" mono />
              <Button onClick={download} title="Download the listed indicators as CSV">
                <Download size={13} />
                CSV
              </Button>
            </>
          }
        />
        <div className="overflow-x-auto">
          <table className="w-full border-collapse text-body-md">
            <thead>
              <tr>
                <Th>Type</Th>
                <Th>Value</Th>
                <Th>Seen with</Th>
                <Th>Techniques</Th>
                <Th align="right">Times seen</Th>
                <Th>First seen (UTC)</Th>
                <Th>Evidence</Th>
              </tr>
            </thead>
            <tbody>
              {rows.map((o) => (
                <tr key={`${o.kind}:${o.value}`} className="align-top hover:bg-surface" data-indicator={o.kind}>
                  <Td className="whitespace-nowrap">
                    <Badge tone="neutral" className="normal-case tracking-normal">
                      {KIND_LABEL[o.kind]}
                    </Badge>
                    {o.scope && <span className="ml-2 text-body-sm text-outline">{o.scope}</span>}
                  </Td>
                  <Td>
                    <span className="flex items-start gap-2">
                      <span className="break-all font-mono text-code-md text-on-surface">{o.value}</span>
                      <CopyButton value={o.value} />
                    </span>
                    {o.advisory && (
                      <div className="mt-1 flex flex-wrap items-center gap-2 text-body-sm">
                        <Badge tone="primary">advisory match</Badge>
                        <span className="text-on-surface-variant">
                          {o.advisory.report_name ?? "published advisory"}
                          {o.advisory.named_actor && ` · attributed to ${o.advisory.named_actor}`}
                          {o.advisory.within_validity === false && " · outside the indicator's validity window"}
                        </span>
                      </div>
                    )}
                  </Td>
                  <Td className="max-w-xs break-words font-mono text-code-sm text-on-surface-variant">
                    {o.context.join(", ") || "—"}
                    {o.hosts.length > 0 && <div className="text-outline">{o.hosts.join(", ")}</div>}
                  </Td>
                  <Td>
                    <span className="flex flex-wrap gap-1">
                      {o.technique_ids.slice(0, 6).map((id) => (
                        <AttackId key={id} id={id} />
                      ))}
                      {o.technique_ids.length > 6 && (
                        <span className="font-mono text-code-sm text-on-surface-variant">+{o.technique_ids.length - 6}</span>
                      )}
                      {o.technique_ids.length === 0 && <span className="text-outline">—</span>}
                    </span>
                  </Td>
                  <Td align="right" className="font-mono tabular-nums">
                    {integer(o.observations)}
                  </Td>
                  <Td className="whitespace-nowrap font-mono text-code-md text-on-surface-variant">{utcDateTime(o.first_seen)}</Td>
                  <Td>
                    <span className="flex flex-col gap-0.5">
                      {o.unit_ids.slice(0, 3).map((unit) => (
                        <a key={unit} href={links.unit(unit, "evidence")} title={unit} className="whitespace-nowrap font-mono text-code-sm text-primary hover:underline">
                          {shortId(unit, 8).replace("corr-group::", "")}
                        </a>
                      ))}
                      {o.unit_ids.length > 3 && <span className="text-body-sm text-outline">+{o.unit_ids.length - 3} more</span>}
                    </span>
                  </Td>
                </tr>
              ))}
              {rows.length === 0 && (
                <tr>
                  <Td colSpan={7} className="py-8 text-center text-on-surface-variant">
                    No indicator matches this filter.
                  </Td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
        <p className="border-t border-outline-variant/70 px-4 py-2.5 text-body-sm text-on-surface-variant">
          {plural(rows.length, "indicator")} listed. System binaries appear here too when a detection fired on them;
          check a hash against your own baseline before blocking it.
        </p>
      </Card>
    </div>
  );
}
