import { Badge, Card, CardHeader, Td, Th } from "../../components/ui";
import { paths, useApi, type ContextEvidence } from "../../lib/api";
import { integer, utcDateTime } from "../../lib/format";

const SHOWN = 60;

/**
 * Low-level detections that belong to no activity cluster (ADR-0026 Amendment B):
 * shown as context so nothing detected is hidden, and never compared with group
 * profiles. Network events land here: they carry no process identity, so they
 * cannot be linked to a host's process chain.
 */
export function ContextPanel({ id }: { id: string }) {
  const context = useApi<ContextEvidence>(paths.context(id));
  if (context.state !== "ready" || context.data.items.length === 0) return null;
  const { items } = context.data;
  return (
    <Card padded={false} data-context-evidence>
      <CardHeader
        title="Context outside the activity clusters"
        hint="Low-level detections with no link to a cluster's process chain - network events among them. Shown for review; they are never compared with group profiles."
      />
      <div className="overflow-x-auto">
        <table className="w-full border-collapse text-body-md">
          <thead>
            <tr>
              <Th>Time (UTC)</Th>
              <Th>Host</Th>
              <Th>What was seen</Th>
              <Th>Technique</Th>
              <Th>Network</Th>
              <Th>Rule</Th>
            </tr>
          </thead>
          <tbody>
            {items.slice(0, SHOWN).map((item) => (
              <tr key={item.evidence_id} className="border-t border-outline-variant/50">
                <Td className="whitespace-nowrap font-mono text-code-md">{item.time ? utcDateTime(item.time) : "-"}</Td>
                <Td className="font-mono text-code-md">{item.host ?? "-"}</Td>
                <Td>
                  {item.label ?? "-"}
                  {item.file_type && <span className="ml-2 font-mono text-code-sm text-on-surface-variant">{item.file_type}</span>}
                </Td>
                <Td>{item.attack_id ? <Badge tone="muted">{item.attack_id}</Badge> : "-"}</Td>
                <Td className="whitespace-nowrap font-mono text-code-sm text-on-surface-variant">
                  {item.from || item.to ? `${item.from ?? "?"} -> ${item.to ?? "?"}` : "-"}
                </Td>
                <Td className="font-mono text-code-sm text-on-surface-variant">{item.rule_source}</Td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {items.length > SHOWN && (
        <p className="border-t border-outline-variant/70 px-4 py-2.5 text-body-sm text-on-surface-variant">
          Showing the first {SHOWN} of {integer(items.length)}.
        </p>
      )}
    </Card>
  );
}
