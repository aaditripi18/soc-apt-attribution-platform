import { FileUp, UploadCloud } from "lucide-react";
import { useCallback, useEffect, useRef, useState } from "react";
import {
  Badge,
  Button,
  Card,
  CardHeader,
  Command,
  EmptyState,
  ErrorState,
  Id,
  PageHeader,
  PageSkeleton,
  Td,
  Th,
  cx,
} from "../components/ui";
import {
  ApiFailure,
  invalidate,
  paths,
  request,
  uploadRecording,
  type UploadJob,
  type UploadState,
  type Uploads,
} from "../lib/api";
import { integer, shortHash, utcDateTime } from "../lib/format";
import { links } from "../lib/router";

const ACTIVE: UploadState[] = ["queued", "checking", "analysing"];
const POLL_MS = 2000;

const STATE_LABEL: Record<UploadState, string> = {
  queued: "Queued",
  checking: "Checking the recording",
  analysing: "Investigating",
  done: "Done",
  refused: "Refused",
  failed: "Failed",
};

const STATE_TONE = {
  queued: "muted",
  checking: "tertiary",
  analysing: "tertiary",
  done: "primary",
  refused: "warning",
  failed: "error",
} as const;

const STATE_MEANING: Record<UploadState, string> = {
  queued: "Waiting for the investigation before it. One recording is investigated at a time.",
  checking: "The intake check is reading every record: is this a log format the platform models?",
  analysing:
    "Every record is run against the pinned detection rules, then correlated and compared. This takes minutes, not seconds.",
  done: "Stored. The investigation is in the console like any other.",
  refused: "The intake check did not accept the file. Nothing was investigated.",
  failed: "The investigation stopped with an error. Nothing was stored.",
};

function megabytes(bytes: number): string {
  return bytes >= 1 << 20 ? `${(bytes / (1 << 20)).toFixed(1)} MB` : `${Math.max(1, Math.round(bytes / 1024))} KB`;
}

function elapsed(job: UploadJob, now: number): string {
  if (!job.started_at) return "—";
  const end = job.finished_at ? Date.parse(job.finished_at) : now;
  const seconds = Math.max(0, Math.round((end - Date.parse(job.started_at)) / 1000));
  return seconds < 60 ? `${seconds} s` : `${Math.floor(seconds / 60)} min ${String(seconds % 60).padStart(2, "0")} s`;
}

function JobRow({ job, now }: { job: UploadJob; now: number }) {
  const active = ACTIVE.includes(job.state);
  return (
    <tr className="align-top" data-state={job.state}>
      <Td>
        <div className="font-mono text-code-md text-on-surface">{job.file_name}</div>
        <div className="mt-0.5 font-mono text-code-sm text-outline">
          {megabytes(job.size_bytes)} · received {utcDateTime(job.received_at)}
        </div>
        <div className="mt-0.5">
          <Id value={job.sha256} display={`sha256 ${shortHash(job.sha256, 16)}`} />
        </div>
      </Td>
      <Td>
        <Badge tone={STATE_TONE[job.state]}>
          {active && <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-current" aria-hidden />}
          {STATE_LABEL[job.state]}
        </Badge>
        <div className="mt-1.5 max-w-md text-body-sm text-on-surface-variant">{STATE_MEANING[job.state]}</div>
        {job.problems.map((problem) => (
          <div key={problem} className="mt-1.5 max-w-md text-body-sm text-warning">
            {problem}
          </div>
        ))}
        {job.warnings.map((warning) => (
          <div key={warning} className="mt-1.5 max-w-md text-body-sm text-on-surface-variant">
            Note: {warning}
          </div>
        ))}
      </Td>
      <Td className="whitespace-nowrap font-mono text-code-md">{elapsed(job, now)}</Td>
      <Td className="font-mono text-code-md">
        {job.records === null ? (
          <span className="text-outline">—</span>
        ) : (
          <>
            <div>{integer(job.records)} records</div>
            {Object.entries(job.converted_by_source).map(([source, count]) => (
              <div key={source} className="text-code-sm text-on-surface-variant">
                {source} {integer(count)}
              </div>
            ))}
            {(job.refused_records ?? 0) > 0 && (
              <div className="text-code-sm text-outline">{integer(job.refused_records ?? 0)} not modelled</div>
            )}
          </>
        )}
      </Td>
      <Td>
        {job.state === "done" && job.investigation_id ? (
          <div className="space-y-1.5">
            <div className="font-mono text-code-md">
              {integer(job.evidence ?? 0)} evidence · {integer(job.units ?? 0)} units
            </div>
            <Button href={links.investigation(job.investigation_id)} variant="primary">
              Open investigation
            </Button>
          </div>
        ) : (
          <span className="text-outline">—</span>
        )}
      </Td>
    </tr>
  );
}

export function UploadPage() {
  const [uploads, setUploads] = useState<Uploads | null>(null);
  const [failure, setFailure] = useState<ApiFailure | null>(null);
  const [sending, setSending] = useState<{ name: string; fraction: number } | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [over, setOver] = useState(false);
  const [now, setNow] = useState(() => Date.now());
  const input = useRef<HTMLInputElement>(null);
  const finished = useRef(new Set<string>());

  const refresh = useCallback(async () => {
    try {
      const next = await request<Uploads>(paths.uploads());
      // A newly finished investigation must show up on the pages that list them.
      for (const job of next.jobs) {
        if (job.state === "done" && !finished.current.has(job.job_id)) {
          finished.current.add(job.job_id);
          invalidate("/investigations");
          invalidate("/units");
        }
      }
      setUploads(next);
      setFailure(null);
    } catch (error) {
      if (error instanceof ApiFailure) setFailure(error);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const working = uploads?.jobs.some((job) => ACTIVE.includes(job.state)) ?? false;
  useEffect(() => {
    if (!working) return;
    const timer = window.setInterval(() => {
      setNow(Date.now());
      void refresh();
    }, POLL_MS);
    return () => window.clearInterval(timer);
  }, [working, refresh]);

  const send = useCallback(
    async (file: File | undefined) => {
      if (!file || !uploads || sending) return;
      setMessage(null);
      const lower = file.name.toLowerCase();
      if (!uploads.supported_suffixes.some((suffix) => lower.endsWith(suffix))) {
        setMessage(`${file.name} is not a recording archive (${uploads.supported_suffixes.join(", ")}).`);
        return;
      }
      if (file.size > uploads.max_bytes) {
        setMessage(`${file.name} is ${megabytes(file.size)}; the limit is ${megabytes(uploads.max_bytes)}.`);
        return;
      }
      setSending({ name: file.name, fraction: 0 });
      try {
        await uploadRecording(file, (fraction) => setSending({ name: file.name, fraction }));
      } catch (error) {
        setMessage(error instanceof Error ? error.message : String(error));
      }
      setSending(null);
      setNow(Date.now());
      await refresh();
    },
    [uploads, sending, refresh],
  );

  if (failure && !uploads) return <ErrorState failure={failure} onRetry={() => void refresh()} />;
  if (!uploads) return <PageSkeleton rows={4} />;

  return (
    <>
      <PageHeader
        eyebrow="New investigation"
        title="Upload a recording"
        description="Give the platform a log archive. It runs the same intake check and the same investigation as the command line, and the result opens in this console. The file stays on this machine."
      />

      {!uploads.enabled ? (
        <EmptyState title="Uploading is switched off on this server">
          <p>Start the console with its upload service (the default of the serving command):</p>
          <Command>python -m attribution_platform.investigation --serve</Command>
        </EmptyState>
      ) : (
        <div className="space-y-6">
          <div
            onDragOver={(event) => {
              event.preventDefault();
              setOver(true);
            }}
            onDragLeave={() => setOver(false)}
            onDrop={(event) => {
              event.preventDefault();
              setOver(false);
              void send(event.dataTransfer.files[0]);
            }}
            className={cx(
              "flex flex-col items-center gap-3 rounded-md border border-dashed px-6 py-10 text-center transition-colors",
              over ? "border-primary bg-primary/10" : "border-outline-variant bg-surface-low",
            )}
          >
            <UploadCloud size={28} className="text-on-surface-variant" aria-hidden />
            {sending ? (
              <div className="w-full max-w-md">
                <div className="font-mono text-code-md text-on-surface">Sending {sending.name}</div>
                <div
                  className="mt-2 h-1.5 overflow-hidden rounded-full bg-surface-highest"
                  role="progressbar"
                  aria-valuenow={Math.round(sending.fraction * 100)}
                  aria-valuemin={0}
                  aria-valuemax={100}
                >
                  <div className="h-full bg-primary" style={{ width: `${sending.fraction * 100}%` }} />
                </div>
              </div>
            ) : (
              <>
                <div className="text-body-lg text-on-surface">Drop a recording here, or choose a file</div>
                <div className="max-w-xl text-body-sm text-on-surface-variant">
                  {uploads.supported_suffixes.join(" · ")} of JSON-lines logs, up to {megabytes(uploads.max_bytes)}.
                  Windows (Sysmon, Security, PowerShell) is the strongest format; Linux, macOS, cloud and network
                  logs are read with less detection content behind them.
                </div>
                <Button variant="primary" onClick={() => input.current?.click()}>
                  <FileUp size={14} />
                  Choose a file
                </Button>
              </>
            )}
            <input
              ref={input}
              type="file"
              className="hidden"
              aria-label="Recording archive"
              accept={uploads.supported_suffixes.join(",")}
              onChange={(event) => {
                void send(event.target.files?.[0]);
                event.target.value = "";
              }}
            />
          </div>
          {message && (
            <p role="alert" className="text-body-md text-warning">
              {message}
            </p>
          )}

          <Card padded={false}>
            <CardHeader
              title="Uploads in this session"
              hint="One recording is investigated at a time, in the order received. Uploading the same file again returns its existing result."
            />
            {uploads.jobs.length === 0 ? (
              <p className="px-4 py-8 text-center text-body-md text-on-surface-variant">Nothing has been uploaded yet.</p>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full border-collapse text-body-md">
                  <thead>
                    <tr>
                      <Th>File</Th>
                      <Th>Status</Th>
                      <Th>Elapsed</Th>
                      <Th>Intake check</Th>
                      <Th>Result</Th>
                    </tr>
                  </thead>
                  <tbody>
                    {uploads.jobs.map((job) => (
                      <JobRow key={job.job_id} job={job} now={now} />
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Card>

          <Card>
            <h2 className="text-headline-sm text-on-surface">What you get, and what you do not</h2>
            <ul className="mt-3 max-w-4xl list-disc space-y-2 pl-5 text-body-md text-on-surface-variant">
              <li>
                <span className="text-on-surface">ATT&CK techniques with the evidence behind each</span> — the rule that
                fired, the raw event it fired on, the attack sequence, a matrix and a timeline.
              </li>
              <li>
                <span className="text-on-surface">The actors consistent with that evidence, and a verdict with reasons.</span>{" "}
                The platform names a Group only on evidence specific to that Group. Shared techniques alone do not single
                one out, so most recordings end in "no actor can be singled out" with the candidates listed.
              </li>
              <li>
                <span className="text-on-surface">No confidence percentage.</span> None is shown because no calibration
                exists; a number here would be invented.
              </li>
              <li>
                An investigation typically takes a few minutes and up to about twenty for a large recording. You can
                leave this page; the upload keeps running while the server does.
              </li>
            </ul>
          </Card>
        </div>
      )}
    </>
  );
}
