import { ArrowRight, FileText, Search } from "lucide-react";
import { useMemo, useState } from "react";
import {
  Badge,
  Card,
  CardHeader,
  Command,
  EmptyState,
  ErrorState,
  Id,
  PageHeader,
  PageSkeleton,
  Stat,
  Td,
  TextInput,
  Th,
} from "../components/ui";
import { paths, useApi, type InvestigationSummary } from "../lib/api";
import { integer, shortId } from "../lib/format";
import { links, navigate } from "../lib/router";

export function InvestigationsPage() {
  const list = useApi<InvestigationSummary[]>(paths.investigations());
  const [text, setText] = useState("");

  const rows = useMemo(() => {
    if (list.state !== "ready") return [];
    const needle = text.trim().toLowerCase();
    return list.data.filter(
      (item) =>
        needle === "" ||
        item.source_id.toLowerCase().includes(needle) ||
        item.investigation_id.toLowerCase().includes(needle),
    );
  }, [list.state, list.data, text]);

  if (list.state === "loading") return <PageSkeleton />;
  if (list.state === "error") return <ErrorState failure={list.error} onRetry={list.reload} />;

  const all = list.data;
  return (
    <>
      <PageHeader
        title="Investigations"
        description="One investigation is one engine run over one telemetry source. Each breaks down into attribution units: groups of Evidence joined by structural links (same process, lineage, injection, same audit event)."
      />
      <div className="mb-6 grid grid-cols-3 gap-4">
        <Stat label="Investigations" value={integer(all.length)} accent />
        <Stat label="Attribution units" value={integer(all.reduce((n, i) => n + i.units, 0))} />
        <Stat
          label="Evidence items"
          value={integer(all.reduce((n, i) => n + i.evidence, 0))}
          sub={`${integer(all.reduce((n, i) => n + i.evidence_in_units, 0))} in units · the rest is low-level context in no unit`}
        />
      </div>

      {all.length === 0 ? (
        <EmptyState title="No investigations in the read model">
          <p>
            Nothing has been investigated in this session. Run a recording through the engine; the
            server keeps serving it afterwards.
          </p>
          <Command>python -m attribution_platform.investigation otrf-apt3-empire --serve</Command>
        </EmptyState>
      ) : (
        <Card padded={false}>
          <CardHeader
            title="All investigations"
            hint="Sorted by investigation id, as the API returns them."
            right={
              <TextInput
                value={text}
                onChange={setText}
                placeholder="Filter by source or id"
                icon={<Search size={14} />}
                className="w-64"
              />
            }
          />
          <div className="overflow-x-auto">
            <table className="w-full border-collapse text-body-md">
              <thead>
                <tr>
                  <Th>Source</Th>
                  <Th>Kind</Th>
                  <Th>Investigation id</Th>
                  <Th>ATT&amp;CK</Th>
                  <Th align="right">Evidence</Th>
                  <Th align="right">Units</Th>
                  <Th />
                </tr>
              </thead>
              <tbody>
                {rows.map((item) => (
                  <tr
                    key={item.investigation_id}
                    onClick={() => navigate(links.investigation(item.investigation_id))}
                    className="cursor-pointer hover:bg-surface"
                  >
                    <Td>
                      <a
                        href={links.investigation(item.investigation_id)}
                        className="font-medium text-on-surface hover:text-primary"
                      >
                        {item.source_id}
                      </a>
                    </Td>
                    <Td>
                      <Badge tone="muted">{item.source_kind}</Badge>
                    </Td>
                    <Td>
                      <Id value={item.investigation_id} display={shortId(item.investigation_id, 16)} />
                    </Td>
                    <Td className="font-mono text-code-md text-on-surface-variant">
                      {item.attack_kb_version}
                    </Td>
                    <Td align="right" className="font-mono tabular-nums">
                      {integer(item.evidence)}
                    </Td>
                    <Td align="right" className="font-mono tabular-nums">
                      {integer(item.units)}
                    </Td>
                    <Td align="right">
                      <span className="inline-flex items-center gap-3">
                        <a
                          href={links.dossier(item.investigation_id)}
                          onClick={(event) => event.stopPropagation()}
                          title="Open the attribution dossier"
                          className="inline-flex items-center gap-1 text-label-md text-on-surface-variant hover:text-primary"
                        >
                          <FileText size={13} />
                          Dossier
                        </a>
                        <ArrowRight size={14} className="text-outline" />
                      </span>
                    </Td>
                  </tr>
                ))}
                {rows.length === 0 && (
                  <tr>
                    <Td colSpan={7} className="py-8 text-center text-on-surface-variant">
                      No investigation matches “{text}”.
                    </Td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </Card>
      )}
    </>
  );
}
