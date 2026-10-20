import { useEffect, useState } from "react";
import { VERDICT_LABEL } from "../components/Assessment";
import {
  AttackId,
  Badge,
  Button,
  Card,
  CardHeader,
  EmptyState,
  ErrorState,
  Id,
  PageHeader,
  PageSkeleton,
  Td,
  Th,
} from "../components/ui";
import { ApiFailure, paths, request, type LiveCycle, type LiveStatus } from "../lib/api";
import { integer, shortHash, utcDateTime } from "../lib/format";
import { links } from "../lib/router";

const POLL_MS = 5000;

const STATE_TONE = {
  analysed: "primary",
  unchanged: "muted",
  empty: "muted",
  refused: "warning",
  failed: "error",
} as const;

const STATE_MEANING: Record<LiveCycle["state"], string> = {
  analysed: "The window changed: its snapshot was investigated with the same pipeline as a recording.",
  unchanged: "Nothing new arrived: the window's snapshot equals the previous one, so it was not re-analysed.",
  empty: "No records in the window yet.",
  refused: "The intake check did not accept the window's snapshot.",
  failed: "The investigation of the snapshot stopped with an error; the next cycle tries again.",
};

function verdict(value: string): string {
  return (VERDICT_LABEL as Record<string, string>)[value] ?? value;
}

function Changes({ cycle }: { cycle: LiveCycle }) {
  const changes = cycle.changes;
  if (!changes) return <span className="text-outline">—</span>;
  if (changes.first_cycle) return <span className="text-on-surface-variant">first analysed cycle</span>;
  const added = changes.techniques_newly_counted ?? [];
  const left = changes.techniques_no_longer_in_window ?? [];
  const nothing =
    added.length === 0 &&
    left.length === 0 &&
    !changes.verdict &&
    !(changes.named_actors_added ?? []).length &&
    !(changes.named_actors_removed ?? []).length;
  return (
    <div className="space-y-1">
      {added.length > 0 && (
        <div className="flex flex-wrap items-center gap-1">
          <span className="text-body-sm text-on-surface-variant">newly counted</span>
          {added.map((id) => (
            <AttackId key={id} id={id} />
          ))}
        </div>
      )}
      {left.length > 0 && (
        <div className="flex flex-wrap items-center gap-1">
          <span className="text-body-sm text-on-surface-variant">left the window</span>
          {left.map((id) => (
            <AttackId key={id} id={id} tone="neutral" />
          ))}
        </div>
      )}
      {changes.verdict && (
        <div className="text-body-sm">
          verdict {verdict(changes.verdict[0])} → <span className="font-semibold">{verdict(changes.verdict[1])}</span>
        </div>
      )}
      {(changes.named_actors_added ?? []).length > 0 && (
        <div className="text-body-sm text-warning">identified: {(changes.named_actors_added ?? []).join(", ")}</div>
      )}
      {(changes.named_actors_removed ?? []).length > 0 && (
        <div className="text-body-sm">no longer identified: {(changes.named_actors_removed ?? []).join(", ")}</div>
      )}
      {nothing && <span className="text-on-surface-variant">same techniques, units {changes.units?.join(" → ")}</span>}
    </div>
  );
}

function CycleRow({ cycle }: { cycle: LiveCycle }) {
  return (
    <tr className="align-top">
      <Td className="whitespace-nowrap font-mono text-code-md">
        #{cycle.cycle}
        <div className="text-code-sm text-outline">{utcDateTime(cycle.at)}</div>
      </Td>
      <Td>
        <Badge tone={STATE_TONE[cycle.state]}>{cycle.state}</Badge>
        <div className="mt-1 max-w-xs text-body-sm text-on-surface-variant">{STATE_MEANING[cycle.state]}</div>
        {(cycle.problems ?? []).map((problem) => (
          <div key={problem} className="mt-1 max-w-xs text-body-sm text-warning">
            {problem}
          </div>
        ))}
      </Td>
      <Td className="font-mono text-code-md">
        {cycle.snapshot_lines !== undefined ? `${integer(cycle.snapshot_lines)} lines` : "—"}
        {cycle.snapshot_sha256 && (
          <div className="mt-0.5">
            <Id value={cycle.snapshot_sha256} display={`sha256 ${shortHash(cycle.snapshot_sha256, 12)}`} />
          </div>
        )}
      </Td>
      <Td className="whitespace-nowrap font-mono text-code-md">{cycle.seconds.toFixed(1)} s</Td>
      <Td>
        {cycle.investigation_id ? (
          <a className="text-primary hover:underline" href={links.investigation(cycle.investigation_id)}>
            {integer(cycle.evidence ?? 0)} evidence · {integer(cycle.units ?? 0)} units
          </a>
        ) : (
          <span className="text-outline">—</span>
        )}
        {cycle.summary && (
          <div className="mt-1 text-body-sm text-on-surface-variant">
            {verdict(cycle.summary.verdict)} · {cycle.summary.counted_techniques.length} techniques counted
          </div>
        )}
      </Td>
      <Td>
        <Changes cycle={cycle} />
      </Td>
    </tr>
  );
}

export function LivePage() {
  const [status, setStatus] = useState<LiveStatus | null>(null);
  const [failure, setFailure] = useState<ApiFailure | null>(null);
  const [showQuiet, setShowQuiet] = useState(false);

  useEffect(() => {
    let active = true;
    const poll = () =>
      request<LiveStatus>(paths.live()).then(
        (data) => {
          if (!active) return;
          setStatus(data);
          setFailure(null);
        },
        (error: unknown) => active && setFailure(error instanceof ApiFailure ? error : new ApiFailure("server", String(error), paths.live(), null)),
      );
    void poll();
    const timer = window.setInterval(poll, POLL_MS);
    return () => {
      active = false;
      window.clearInterval(timer);
    };
  }, []);

  const header = (
    <PageHeader
      eyebrow="Operations"
      title="Live Monitoring"
      description="Telemetry followed as it arrives (log files, or Elasticsearch data streams). Every cycle freezes the recent window into a hashed snapshot and investigates it with the same pipeline as an uploaded recording, so each live result can be re-run exactly. What changed is a comparison of two stored investigations — no separate alerting logic."
    />
  );
  if (failure && !status) return <>{header}<ErrorState failure={failure} /></>;
  if (!status) return <>{header}<PageSkeleton rows={4} /></>;
  if (!status.enabled) {
    return (
      <>
        {header}
        <EmptyState title="This server is not running a live session">
          <p>Start one from the command line; the console then shows its cycles here.</p>
          <pre className="mt-2 overflow-x-auto rounded-sm bg-surface-lowest p-2 text-left font-mono text-code-sm">
            {"python -m attribution_platform.live --name lab --follow sysmon.jsonl --serve\n"}
            {'python -m attribution_platform.live --name lab --elasticsearch-index "logs-windows.sysmon_operational-*" --serve'}
          </pre>
        </EmptyState>
      </>
    );
  }
  const latest = status.cycles.find((cycle) => cycle.state === "analysed");
  const quiet = status.cycles.filter((cycle) => cycle.state === "unchanged" || cycle.state === "empty");
  const shown = showQuiet
    ? status.cycles
    : status.cycles.filter((cycle, index) => index === 0 || !quiet.includes(cycle));
  return (
    <>
      {header}
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        <Card padded={false} className="xl:col-span-1">
          <CardHeader title={`Session “${status.name}”`} hint={`Window: the last ${status.window_hours} h · ${status.investigations_retained} investigations retained`} />
          <table className="w-full">
            <thead>
              <tr>
                <Th>Source</Th>
                <Th>Read</Th>
              </tr>
            </thead>
            <tbody>
              {status.sources.map((source) => (
                <tr key={source.source} className="align-top">
                  <Td className="break-all font-mono text-code-sm">{source.source}</Td>
                  <Td className="whitespace-nowrap font-mono text-code-sm">
                    {integer(source.read_so_far)}{" "}
                    {source.source.startsWith("elasticsearch:") ? "documents" : "bytes"}
                    {source.dropped_partial_lines + source.undecodable_lines > 0 && (
                      <div className="text-warning">
                        {source.dropped_partial_lines} partial · {source.undecodable_lines} undecodable lines
                      </div>
                    )}
                  </Td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
        <Card className="xl:col-span-2">
          <div className="label mb-1.5">Latest analysed window</div>
          {latest?.summary ? (
            <div className="space-y-2">
              <div className="text-headline-sm">{verdict(latest.summary.verdict)}</div>
              <div className="flex flex-wrap gap-1">
                {latest.summary.counted_techniques.map((id) => (
                  <AttackId key={id} id={id} />
                ))}
              </div>
              {latest.investigation_id && (
                <a className="text-primary hover:underline" href={links.investigation(latest.investigation_id)}>
                  Open the investigation of cycle #{latest.cycle}
                </a>
              )}
            </div>
          ) : (
            <p className="text-on-surface-variant">No window has been analysed yet.</p>
          )}
        </Card>
      </div>
      <Card padded={false} className="mt-4">
        <CardHeader
          title="Cycles"
          hint={`Newest first · refreshed every ${POLL_MS / 1000} s`}
          right={
            quiet.length > 0 && (
              <Button variant="ghost" onClick={() => setShowQuiet((value) => !value)}>
                {showQuiet ? "Hide" : "Show"} {quiet.length} cycle{quiet.length === 1 ? "" : "s"} with nothing new
              </Button>
            )
          }
        />
        {status.cycles.length === 0 ? (
          <p className="p-4 text-on-surface-variant">No cycle has run yet.</p>
        ) : (
          <table className="w-full">
            <thead>
              <tr>
                <Th>Cycle</Th>
                <Th>State</Th>
                <Th>Snapshot</Th>
                <Th>Took</Th>
                <Th>Investigation</Th>
                <Th>What changed</Th>
              </tr>
            </thead>
            <tbody>
              {shown.map((cycle) => (
                <CycleRow key={cycle.cycle} cycle={cycle} />
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </>
  );
}
