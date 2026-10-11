import { Braces, Search, X } from "lucide-react";
import { useMemo, useState } from "react";
import {
  AttackId,
  Badge,
  Button,
  Card,
  CardHeader,
  Disclosure,
  EmptyState,
  ExternalA,
  Id,
  Segmented,
  Select,
  Td,
  TextInput,
  Th,
  cx,
} from "../../components/ui";
import type { Evidence, Observation, RuleInfo } from "../../lib/api";
import {
  describeObservation,
  isActorEvidence,
  isContextEvidence,
  isTechniqueEvidence,
  observationFacets,
  ruleOf,
} from "../../lib/derive";
import { integer, shortHash, utcClock, utcDate } from "../../lib/format";
import type { UnitData } from "../Unit";

const PAGE = 100;

export function TierBadge({ evidence }: { evidence: Evidence }) {
  if (isActorEvidence(evidence)) {
    return (
      <Badge tone="warning" title="The rule is specific to one Group's own tooling (reviewed). A lead; not part of the technique comparison.">
        Actor-specific
      </Badge>
    );
  }
  return isContextEvidence(evidence) ? (
    <Badge tone="muted" title="Low-level (enrich-tier) content: context, adds no attribution feature.">
      Context
    </Badge>
  ) : (
    <Badge tone="primary" title="Core detection content: its technique is a decision feature.">
      Core
    </Badge>
  );
}

export function OriginBadge({ origin }: { origin: string }) {
  return (
    <Badge tone={origin === "elastic" ? "tertiary" : "neutral"} title={origin === "elastic" ? "Elastic prebuilt detection rule" : "SigmaHQ rule"}>
      {origin}
    </Badge>
  );
}

export function ObservationFacets({ observation }: { observation: Observation }) {
  const facets = useMemo(() => observationFacets(observation), [observation]);
  return (
    <div className="columns-1 gap-3 lg:columns-2">
      {facets.map(({ facet, rows }) => (
        <div key={facet} className="mb-3 break-inside-avoid overflow-hidden rounded-sm border border-outline-variant/60 bg-surface-lowest">
          <div className="label border-b border-outline-variant/60 bg-surface-low px-2.5 py-1.5">{facet}</div>
          <dl className="divide-y divide-outline-variant/30">
            {rows.map((row) => (
              <div key={row.field} className="grid grid-cols-[11rem_1fr] gap-3 px-2.5 py-1.5">
                <dt className="truncate font-mono text-code-sm text-outline" title={row.field}>
                  {row.field}
                </dt>
                <dd className="min-w-0 break-all font-mono text-code-sm text-on-surface">{row.value}</dd>
              </div>
            ))}
          </dl>
        </div>
      ))}
    </div>
  );
}

function Detail({
  evidence,
  observation,
  rule,
}: {
  evidence: Evidence;
  observation: Observation | undefined;
  rule: RuleInfo | null;
}) {
  return (
    <div className="space-y-4 bg-surface-lowest/60 px-4 py-4 pl-10">
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <div>
          <div className="label mb-1.5">Detection rule</div>
          <div className="space-y-1.5 rounded-sm border border-outline-variant/60 bg-surface-lowest p-3 text-body-md">
            {rule ? (
              <>
                <div className="flex flex-wrap items-center gap-2">
                  <OriginBadge origin={rule.origin} />
                  {rule.url ? (
                    <ExternalA href={rule.url}>{rule.title ?? rule.source_id}</ExternalA>
                  ) : (
                    <span>{rule.title ?? rule.source_id}</span>
                  )}
                </div>
                <div className="flex flex-wrap gap-x-4 gap-y-1 font-mono text-code-sm text-on-surface-variant">
                  <span>tier {rule.content_tier}</span>
                  <span title={rule.translation === "partial" ? "Some branches of the upstream rule could not be translated; the translated branches are exact." : "The whole upstream rule was translated."}>
                    translation {rule.translation}
                  </span>
                  {rule.logsources.length > 0 && <span>log source {rule.logsources.join(", ")}</span>}
                </div>
                {(rule.actor_tags ?? []).map((tag) => (
                  <p key={tag.tag} className="rounded-sm border border-warning/30 bg-warning/5 p-2 text-body-sm text-on-surface-variant">
                    <span className="font-semibold text-on-surface">
                      Why this rule counts as specific to {tag.group_name} ({tag.group_id}):
                    </span>{" "}
                    {tag.reason}
                  </p>
                ))}
              </>
            ) : (
              <p className="text-on-surface-variant">This rule is not listed in the pinned import reports.</p>
            )}
            <dl className="grid grid-cols-[8rem_1fr] gap-x-3 gap-y-1 border-t border-outline-variant/40 pt-2 font-mono text-code-sm">
              <dt className="text-outline">engine rule</dt>
              <dd className="break-all text-on-surface">{evidence.provenance.method}</dd>
              <dt className="text-outline">rule version</dt>
              <dd className="text-on-surface">{evidence.provenance.method_version}</dd>
              <dt className="text-outline">pack hash</dt>
              <dd>
                {evidence.provenance.method_content_hash ? (
                  <Id value={evidence.provenance.method_content_hash} display={shortHash(evidence.provenance.method_content_hash, 24)} />
                ) : (
                  "—"
                )}
              </dd>
            </dl>
          </div>
        </div>
        <div>
          <div className="label mb-1.5">Claim — what matched, and the mapping basis</div>
          <p className="rounded-sm border border-outline-variant/60 bg-surface-lowest p-3 font-mono text-code-sm leading-relaxed text-on-surface-variant break-words">
            {evidence.claim}
          </p>
        </div>
      </div>

      <div>
        <div className="label mb-1.5">Observation — every recorded field</div>
        {observation ? (
          <ObservationFacets observation={observation} />
        ) : (
          <p className="text-body-md text-on-surface-variant">The grounding observation is not in the read model.</p>
        )}
      </div>

      <div className="flex flex-wrap items-center gap-x-6 gap-y-2 border-t border-outline-variant/40 pt-3">
        <span className="flex min-w-0 items-center gap-2">
          <span className="label">Evidence id</span>
          <Id value={evidence.evidence_id} display={shortHash(evidence.evidence_id, 48)} />
        </span>
        {observation && (
          <span className="flex min-w-0 items-center gap-2">
            <span className="label">Observation id</span>
            <Id value={observation.observation_id} display={shortHash(observation.observation_id, 48)} />
          </span>
        )}
        <a
          href={`/api/evidence/${encodeURIComponent(evidence.evidence_id)}`}
          target="_blank"
          rel="noreferrer"
          className="inline-flex items-center gap-1 text-label-md text-primary hover:underline"
        >
          <Braces size={12} />
          Stored JSON
        </a>
      </div>
    </div>
  );
}

export function EvidenceTab({ data, query }: { data: UnitData; query: URLSearchParams }) {
  const { evidence, observations, rules } = data.evidence;
  const [tier, setTier] = useState<"all" | "core" | "context">("all");
  const [origin, setOrigin] = useState("");
  const [technique, setTechnique] = useState(query.get("technique") ?? "");
  const [text, setText] = useState("");
  const [open, setOpen] = useState<Set<string>>(new Set());
  const [limit, setLimit] = useState(PAGE);

  const techniqueIds = useMemo(
    () =>
      [
        ...new Set(
          evidence
            .filter(isTechniqueEvidence)
            .map((e) => e.attack_ref.external_id)
            .filter((id): id is string => !!id),
        ),
      ].sort(),
    [evidence],
  );
  const origins = useMemo(() => [...new Set(Object.values(rules).map((r) => r.origin))].sort(), [rules]);

  const rows = useMemo(() => {
    const needle = text.trim().toLowerCase();
    return evidence.filter((item) => {
      if (tier === "core" && isContextEvidence(item)) return false;
      if (tier === "context" && !isContextEvidence(item)) return false;
      const rule = ruleOf(item, rules);
      if (origin !== "" && rule?.origin !== origin) return false;
      if (technique !== "" && item.attack_ref?.external_id !== technique) return false;
      if (needle === "") return true;
      const observation = observations[item.provenance.source_observation_ids[0] ?? ""];
      return (
        (rule?.title ?? "").toLowerCase().includes(needle) ||
        item.claim.toLowerCase().includes(needle) ||
        describeObservation(observation).toLowerCase().includes(needle)
      );
    });
  }, [evidence, observations, rules, tier, origin, technique, text]);

  if (evidence.length === 0) {
    return <EmptyState title="This unit has no stored Evidence" />;
  }
  const filtering = tier !== "all" || origin !== "" || technique !== "" || text.trim() !== "";
  const toggle = (id: string) =>
    setOpen((current) => {
      const next = new Set(current);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });

  return (
    <Card padded={false}>
      <CardHeader
        title="Evidence"
        hint={`${filtering ? `${integer(rows.length)} of ` : ""}${integer(evidence.length)} items · one detection rule matching one observation, mapped to one technique · in time order`}
        right={
          <>
            <Segmented
              ariaLabel="Content tier"
              value={tier}
              onChange={(value) => {
                setTier(value);
                setLimit(PAGE);
              }}
              options={[
                { value: "all", label: "All", count: evidence.length },
                { value: "core", label: "Core", count: data.coreEvidence },
                { value: "context", label: "Context", count: data.contextEvidence },
              ]}
            />
            {origins.length > 1 && (
              <Select
                ariaLabel="Rule source"
                value={origin}
                onChange={setOrigin}
                options={[{ value: "", label: "Sigma + Elastic" }, ...origins.map((o) => ({ value: o, label: o }))]}
              />
            )}
            <Select
              ariaLabel="Technique"
              value={technique}
              onChange={setTechnique}
              options={[{ value: "", label: "All techniques" }, ...techniqueIds.map((t) => ({ value: t, label: t }))]}
            />
            <TextInput value={text} onChange={setText} placeholder="Rule, command line, claim…" icon={<Search size={14} />} className="w-56" />
            {filtering && (
              <Button
                variant="ghost"
                onClick={() => {
                  setTier("all");
                  setOrigin("");
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
        <table className="w-full table-fixed border-collapse text-body-md">
          <colgroup>
            <col className="w-8" />
            <col className="w-44" />
            <col className="w-28" />
            <col className="w-24" />
            <col className="w-[28%]" />
            <col />
          </colgroup>
          <thead>
            <tr>
              <Th />
              <Th>Time (UTC)</Th>
              <Th>Maps to</Th>
              <Th>Tier</Th>
              <Th>Rule</Th>
              <Th>Observed</Th>
            </tr>
          </thead>
          <tbody>
            {rows.slice(0, limit).map((item) => {
              const observation = observations[item.provenance.source_observation_ids[0] ?? ""];
              const rule = ruleOf(item, rules);
              const expanded = open.has(item.evidence_id);
              return [
                <tr
                  key={item.evidence_id}
                  onClick={() => toggle(item.evidence_id)}
                  aria-expanded={expanded}
                  className={cx("cursor-pointer hover:bg-surface", expanded && "bg-surface")}
                >
                  <Td className="pr-0">
                    <Disclosure open={expanded} />
                  </Td>
                  <Td className="whitespace-nowrap font-mono text-code-md">
                    <span className="text-on-surface-variant">{utcDate(item.time_span?.start)}</span>{" "}
                    {utcClock(item.time_span?.start, true)}
                  </Td>
                  <Td>
                    {item.attack_ref?.external_id ? (
                      <AttackId id={item.attack_ref.external_id} tone={isActorEvidence(item) ? "warning" : "tertiary"} />
                    ) : (
                      <span className="text-outline">unmapped</span>
                    )}
                  </Td>
                  <Td>
                    <TierBadge evidence={item} />
                  </Td>
                  <Td>
                    <span className="flex min-w-0 items-center gap-2">
                      {rule && <OriginBadge origin={rule.origin} />}
                      <span className="truncate" title={rule?.title ?? item.provenance.method}>
                        {rule?.title ?? item.provenance.method}
                      </span>
                    </span>
                  </Td>
                  <Td>
                    <span className="block truncate font-mono text-code-md text-on-surface-variant" title={describeObservation(observation)}>
                      {describeObservation(observation)}
                    </span>
                  </Td>
                </tr>,
                expanded && (
                  <tr key={`${item.evidence_id}::detail`}>
                    <td colSpan={6} className="border-b border-outline-variant/40 p-0">
                      <Detail evidence={item} observation={observation} rule={rule} />
                    </td>
                  </tr>
                ),
              ];
            })}
            {rows.length === 0 && (
              <tr>
                <Td colSpan={6} className="py-8 text-center text-on-surface-variant">
                  No Evidence matches these filters.
                </Td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      {rows.length > limit && (
        <div className="flex items-center justify-between border-t border-outline-variant/70 px-4 py-3">
          <span className="text-body-sm text-on-surface-variant">
            Showing {integer(limit)} of {integer(rows.length)}
          </span>
          <Button onClick={() => setLimit((n) => n + PAGE)}>Show {Math.min(PAGE, rows.length - limit)} more</Button>
        </div>
      )}
    </Card>
  );
}
