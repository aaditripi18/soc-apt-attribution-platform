import { Braces } from "lucide-react";
import type { ReactNode } from "react";
import { Badge, Card, CardHeader, Id } from "../../components/ui";
import { integer } from "../../lib/format";
import { links } from "../../lib/router";
import type { UnitData } from "../Unit";

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="grid grid-cols-[13rem_1fr] items-center gap-4 border-b border-outline-variant/40 px-4 py-2 last:border-b-0">
      <dt className="text-body-md text-on-surface-variant">{label}</dt>
      <dd className="min-w-0 font-mono text-code-md text-on-surface">{children}</dd>
    </div>
  );
}

/** A stored provenance object, field by field. */
function flatten(value: unknown, prefix = ""): [string, string][] {
  if (value === null || value === undefined) return [];
  if (Array.isArray(value)) {
    if (value.length === 0) return [];
    if (value.every((v) => typeof v !== "object" || v === null)) return [[prefix, value.join(", ")]];
    return value.flatMap((v, i) => flatten(v, `${prefix}[${i}]`));
  }
  if (typeof value === "object") {
    return Object.entries(value).flatMap(([key, inner]) => flatten(inner, prefix ? `${prefix}.${key}` : key));
  }
  return [[prefix, String(value)]];
}

function Raw({ path, label }: { path: string; label: string }) {
  return (
    <a
      href={`/api${path}`}
      target="_blank"
      rel="noreferrer"
      className="flex items-center justify-between gap-3 border-b border-outline-variant/40 px-4 py-2 font-mono text-code-md text-primary last:border-b-0 hover:bg-surface"
    >
      <span className="flex min-w-0 items-center gap-2">
        <Braces size={13} className="shrink-0" />
        <span className="truncate">GET /api{path.length > 70 ? `${path.slice(0, 70)}…` : path}</span>
      </span>
      <span className="shrink-0 font-sans text-body-sm text-on-surface-variant">{label}</span>
    </a>
  );
}

export function ProvenanceTab({ data, unitId }: { data: UnitData; unitId: string }) {
  const { unit, investigation } = data;
  const analysis = unit.attribution_analysis;
  const encoded = encodeURIComponent(unitId);
  return (
    <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
      <Card padded={false}>
        <CardHeader title="Investigation" hint="The engine run this unit belongs to, and everything pinned it ran against." />
        <dl>
          <Row label="Investigation id">
            <span className="flex min-w-0 items-center gap-2">
              <Id value={analysis.investigation_id} />
              <a href={links.investigation(analysis.investigation_id)} className="shrink-0 font-sans text-label-md text-primary hover:underline">
                open
              </a>
            </span>
          </Row>
          {investigation ? (
            <>
              <Row label="Source">{investigation.source_id} ({investigation.source_kind})</Row>
              <Row label="Source SHA-256">
                <Id value={investigation.source_sha256} />
              </Row>
              <Row label="ATT&CK knowledge base">{investigation.attack_kb_version}</Row>
              <Row label="Detection pack set hash">
                <Id value={investigation.detection_pack_content_hash} />
              </Row>
              {Object.entries(investigation.method_versions).map(([name, version]) => (
                <Row key={name} label={`Method · ${name}`}>
                  {version}
                </Row>
              ))}
              <Row label="Record schema">{investigation.schema_version}</Row>
            </>
          ) : (
            <Row label="Investigation record">not loaded</Row>
          )}
        </dl>
      </Card>

      <Card padded={false}>
        <CardHeader title="Attribution analysis" />
        <dl>
          <Row label="ATT&CK knowledge base">{analysis.attack_kb_version}</Row>
          <Row label="Comparison">
            {analysis.comparison_status === "computed" ? (
              "computed"
            ) : (
              <Badge tone="warning">{analysis.comparison_status.replace(/_/g, " ")}</Badge>
            )}
          </Row>
          <Row label="Profile floor">{analysis.min_profile_floor}</Row>
          <Row label="Guidance method">{analysis.collection_guidance?.method_version ?? "—"}</Row>
          <Row label="Record schema">{analysis.schema_version}</Row>
        </dl>
      </Card>

      <Card padded={false}>
        <CardHeader title="Correlation group" hint="What was joined into this unit, and by which method." />
        <dl>
          <Row label="Group id">
            <Id value={unit.group.group_id} />
          </Row>
          <Row label="Evidence members">{integer(unit.group.member_evidence_ids.length)}</Row>
          <Row label="Observation members">{integer(unit.group.member_observation_ids.length)}</Row>
          <Row label="Structural links">{integer(unit.group.structural_link_ids.length)} (join the unit)</Row>
          <Row label="Contextual links">{integer(unit.group.contextual_link_ids.length)} (annotate only)</Row>
          {flatten(unit.group.provenance).map(([field, value]) => (
            <Row key={field} label={`Provenance · ${field}`}>
              <span className="break-all">{value}</span>
            </Row>
          ))}
          <Row label="Record schema">{unit.group.schema_version}</Row>
        </dl>
      </Card>

      <Card padded={false}>
        <CardHeader title="Behavioural sequence" hint="The ordered view of the group’s members." />
        <dl>
          <Row label="Sequence id">
            <Id value={unit.sequence.sequence_id} />
          </Row>
          <Row label="Steps">{integer(unit.sequence.steps.length)}</Row>
          <Row label="Ordered edges">{integer(unit.sequence.edges.length)}</Row>
          <Row label="Unresolved orders">{integer(unit.sequence.gaps.length)}</Row>
          <Row label="Parallel groups">{integer(unit.sequence.parallel_groups.length)}</Row>
          {flatten(unit.sequence.provenance).map(([field, value]) => (
            <Row key={field} label={`Provenance · ${field}`}>
              <span className="break-all">{value}</span>
            </Row>
          ))}
          <Row label="Record schema">{unit.sequence.schema_version}</Row>
        </dl>
      </Card>

      <Card padded={false} className="xl:col-span-2">
        <CardHeader title="Stored records" hint="Everything on this page is rendered from these read-only API responses." />
        <div>
          <Raw path={`/units/${encoded}`} label="group, sequence, attribution analysis" />
          <Raw path={`/units/${encoded}/evidence`} label="evidence, observations, rules" />
          <Raw path={`/investigations/${encodeURIComponent(analysis.investigation_id)}`} label="investigation record" />
          <Raw path="/attack/techniques" label="ATT&CK technique catalogue" />
        </div>
      </Card>
    </div>
  );
}
