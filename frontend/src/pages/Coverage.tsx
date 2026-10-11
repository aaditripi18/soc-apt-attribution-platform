import { Search } from "lucide-react";
import { useMemo, useState } from "react";
import {
  AttackId,
  Badge,
  Button,
  Card,
  CardHeader,
  ErrorState,
  PageHeader,
  PageSkeleton,
  Segmented,
  Select,
  StackedBar,
  Stat,
  Td,
  TextInput,
  Th,
  cx,
  type Segment,
} from "../components/ui";
import {
  paths,
  useApi,
  type ContentSource,
  type Coverage,
  type CoverageStatus,
  type TechniqueCatalogue,
} from "../lib/api";
import {
  COVERAGE_LABEL,
  COVERAGE_MEANING,
  COVERAGE_STATUSES,
  coverageByTactic,
  indexTechniques,
} from "../lib/derive";
import { integer, shortHash } from "../lib/format";

const STATUS_COLOR: Record<CoverageStatus, string> = {
  covered: "var(--color-primary-container)",
  telemetry_gap: "var(--color-warning)",
  translation_gap: "var(--color-tertiary-container)",
  no_sigma_rule: "var(--color-outline)",
  not_observable_on_supported_platforms: "var(--color-surface-highest)",
};

const PAGE = 60;

function segments(counts: Record<CoverageStatus, number>): Segment[] {
  return COVERAGE_STATUSES.map((status) => ({
    key: status,
    label: COVERAGE_LABEL[status],
    value: counts[status] ?? 0,
    color: STATUS_COLOR[status],
  }));
}

function StatusDot({ status }: { status: CoverageStatus }) {
  return <span className="inline-block h-2.5 w-2.5 shrink-0 rounded-sm" style={{ background: STATUS_COLOR[status] }} />;
}

function Source({ name, source, version }: { name: string; source: ContentSource; version: string }) {
  const { by_status: by } = source.summary;
  const total = by.imported + by.partial + by.rejected;
  return (
    <Card padded={false}>
      <CardHeader title={name} hint={version} right={<span className="font-mono text-code-md text-on-surface-variant">{integer(total)} upstream rules</span>} />
      <div className="space-y-4 p-4">
        <StackedBar
          segments={[
            { key: "imported", label: "Translated whole", value: by.imported, color: "var(--color-primary-container)" },
            { key: "partial", label: "Translated in part", value: by.partial, color: "var(--color-secondary-container)" },
            { key: "rejected", label: "Not offered", value: by.rejected, color: "var(--color-surface-highest)" },
          ]}
        />
        <div className="grid grid-cols-3 gap-3 text-body-md">
          <div>
            <div className="font-mono text-headline-md text-primary">{integer(by.imported)}</div>
            <div className="text-body-sm text-on-surface-variant">translated whole</div>
          </div>
          <div>
            <div className="font-mono text-headline-md text-on-surface">{integer(by.partial)}</div>
            <div className="text-body-sm text-on-surface-variant">in part (exact branches only)</div>
          </div>
          <div>
            <div className="font-mono text-headline-md text-on-surface-variant">{integer(by.rejected)}</div>
            <div className="text-body-sm text-on-surface-variant">not offered</div>
          </div>
        </div>
        <dl className="grid grid-cols-[1fr_auto] gap-x-4 gap-y-1 border-t border-outline-variant/40 pt-3 text-body-md">
          <dt className="text-on-surface-variant">Engine rules generated</dt>
          <dd className="text-right font-mono text-code-md">{integer(source.summary.generated_rules)}</dd>
          <dt className="text-on-surface-variant">ATT&amp;CK ids with a translated rule</dt>
          <dd className="text-right font-mono text-code-md">{integer(source.summary.attack_ids_with_imported_rule)}</dd>
          {Object.entries(source.summary.rejected_by_reason).map(([reason, count]) => (
            <div key={reason} className="contents">
              <dt className="text-on-surface-variant">Not offered · {reason.replace(/_/g, " ")}</dt>
              <dd className="text-right font-mono text-code-md">{integer(count)}</dd>
            </div>
          ))}
        </dl>
        <details className="group border-t border-outline-variant/40 pt-3">
          <summary className="cursor-pointer text-label-md text-on-surface-variant hover:text-on-surface">
            Most frequent reasons a rule (or a branch of one) was not translated
          </summary>
          <ul className="mt-2 space-y-1">
            {source.top_rejection_reasons.map((row) => (
              <li key={row.reason} className="flex items-baseline justify-between gap-3">
                <span className="min-w-0 break-all font-mono text-code-sm text-on-surface-variant">{row.reason}</span>
                <span className="shrink-0 font-mono text-code-sm text-on-surface">{integer(row.rules)}</span>
              </li>
            ))}
          </ul>
        </details>
      </div>
    </Card>
  );
}

const BASIS_LABEL: Record<string, string> = {
  group_tag: "Group tag on the rule",
  directory_alias: "Filed under the Group's name",
  directory_software: "Filed under software of one Group",
  software_tag: "Tag for software of one Group",
};

function ActorSpecific({
  actor,
  activeGroups,
}: {
  actor: NonNullable<Coverage["actor_specific"]>;
  activeGroups: number;
}) {
  // Groups the platform can name today: an accepted association on a rule that runs here.
  const nameable = new Map<string, { name: string; rules: number }>();
  for (const rule of actor.rules) {
    if (rule.status === "rejected") continue;
    for (const tag of rule.actor_tags) {
      if (tag.decision !== "accept" || !tag.group_id) continue;
      const entry = nameable.get(tag.group_id) ?? { name: tag.group_name ?? tag.group_id, rules: 0 };
      entry.rules += 1;
      nameable.set(tag.group_id, entry);
    }
  }
  const named = [...nameable.entries()].sort(([, a], [, b]) => a.name.localeCompare(b.name));
  const [show, setShow] = useState<"accepted" | "all">("accepted");
  const rows = actor.rules.filter((rule) => show === "all" || rule.actor_tags.some((tag) => tag.decision === "accept"));
  const usable = actor.summary.by_status.imported + actor.summary.by_status.partial;
  return (
    <>
    <Card>
      <h2 className="text-headline-sm text-on-surface">Groups this platform can name</h2>
      <p className="mt-1 max-w-4xl text-body-md text-on-surface-variant">
        <span className="text-on-surface">
          {named.length} of {activeGroups} active ATT&CK Groups.
        </span>{" "}
        A Group can be named only when a rule accepted by the review below fires on an artefact of that Group's own
        tooling. For every other Group the platform has no such content: its activity can be detected and compared by
        technique, but the verdict will not single it out. A named Group is a lead to verify, not a conclusion.
      </p>
      <div className="mt-3 flex flex-wrap gap-2">
        {named.map(([id, entry]) => (
          <span
            key={id}
            data-nameable-group={id}
            className="inline-flex items-center gap-2 rounded-sm border border-outline-variant bg-surface px-2 py-1 text-body-sm"
          >
            <span className="text-on-surface">{entry.name}</span>
            <AttackId id={id} tone="muted" />
            <span className="font-mono text-code-sm text-outline">
              {entry.rules} {entry.rules === 1 ? "rule" : "rules"}
            </span>
          </span>
        ))}
      </div>
    </Card>
    <Card padded={false}>
      <CardHeader
        title="Actor-specific content"
        hint={`Sigma rules associated with one ATT&CK Group — by a Group tag, or by being filed under the Group's name or under software ATT&CK records for that Group alone. An association counts only if a review of the rule's logic accepts it: ${actor.summary.group_tags_accepted} of ${actor.summary.group_tags_reviewed} accepted, ${usable} rules usable on ingested telemetry, for ${actor.summary.groups_with_a_usable_rule.length} Groups. This is the only content that can name an actor.`}
        right={
          <Segmented
            ariaLabel="Actor rules shown"
            value={show}
            onChange={setShow}
            options={[
              { value: "accepted", label: "Accepted", count: actor.rules.filter((r) => r.actor_tags.some((t) => t.decision === "accept")).length },
              { value: "all", label: "All reviewed", count: actor.rules.length },
            ]}
          />
        }
      />
      <div className="max-h-[32rem] overflow-auto">
        <table className="w-full border-collapse text-body-md">
          <thead>
            <tr>
              <Th>Rule</Th>
              <Th>Group named</Th>
              <Th>Decision</Th>
              <Th>Reason</Th>
              <Th>On this platform</Th>
            </tr>
          </thead>
          <tbody>
            {rows.flatMap((rule) =>
              rule.actor_tags.map((tag) => (
                <tr key={`${rule.sigma_id}::${tag.tag}`} className="align-top hover:bg-surface">
                  <Td className="max-w-xs">
                    <a href={rule.url} target="_blank" rel="noreferrer noopener" className="text-primary hover:underline">
                      {rule.title}
                    </a>
                    <div className="font-mono text-code-sm text-outline">{rule.logsource}</div>
                  </Td>
                  <Td className="whitespace-nowrap">
                    {tag.group_name ?? "—"} {tag.group_id && <AttackId id={tag.group_id} tone="muted" />}
                    <div className="mt-0.5 whitespace-normal text-body-sm text-outline">
                      {(tag.bases ?? []).map((basis) => BASIS_LABEL[basis] ?? basis).join(" · ")}
                    </div>
                  </Td>
                  <Td>
                    <Badge tone={tag.decision === "accept" ? "primary" : "muted"}>{tag.decision === "accept" ? "accepted" : "rejected"}</Badge>
                  </Td>
                  <Td className="max-w-xl text-body-sm text-on-surface-variant">{tag.reason}</Td>
                  <Td className="whitespace-nowrap text-body-sm text-on-surface-variant">
                    {tag.decision !== "accept"
                      ? "not used"
                      : rule.status === "rejected"
                        ? `not usable: ${(rule.rejection ?? "").replace(/_/g, " ")}`
                        : rule.status === "partial"
                          ? "usable in part"
                          : "usable"}
                  </Td>
                </tr>
              )),
            )}
          </tbody>
        </table>
      </div>
    </Card>
    </>
  );
}

export function CoveragePage() {
  const coverage = useApi<Coverage>(paths.coverage());
  const catalogue = useApi<TechniqueCatalogue>(paths.techniques());
  const [scope, setScope] = useState<"group_used" | "all">("group_used");
  const [status, setStatus] = useState("");
  const [tactic, setTactic] = useState("");
  const [text, setText] = useState("");
  const [limit, setLimit] = useState(PAGE);
  const [supportedOnly, setSupportedOnly] = useState(true);

  const index = useMemo(() => (catalogue.state === "ready" ? indexTechniques(catalogue.data) : null), [catalogue.state, catalogue.data]);
  const scoped = useMemo(() => {
    if (coverage.state !== "ready" || !index) return [];
    return coverage.data.techniques.filter(
      (row) => scope === "all" || (index.byAttackId.get(row.attack_id)?.groups_using ?? 0) > 0,
    );
  }, [coverage.state, coverage.data, index, scope]);
  const byTactic = useMemo(() => (index ? coverageByTactic(scoped, index) : []), [scoped, index]);
  const rows = useMemo(() => {
    const needle = text.trim().toLowerCase();
    return scoped.filter(
      (row) =>
        (status === "" || row.status === status) &&
        (tactic === "" || (index?.byAttackId.get(row.attack_id)?.tactics ?? []).includes(tactic)) &&
        (needle === "" || row.attack_id.toLowerCase().startsWith(needle) || row.name.toLowerCase().includes(needle)),
    );
  }, [scoped, status, tactic, text, index]);

  if (coverage.state === "error") return <ErrorState failure={coverage.error} onRetry={coverage.reload} />;
  if (catalogue.state === "error") return <ErrorState failure={catalogue.error} onRetry={catalogue.reload} />;
  if (coverage.state !== "ready" || !index) return <PageSkeleton rows={8} />;

  const report = coverage.data;
  const summary = report.summary;
  const counts = scope === "all" ? summary.techniques_by_status : summary.group_used_techniques_by_status;
  const total = scope === "all" ? summary.active_techniques : summary.group_used_techniques;
  const sigma = report.provenance.sigma_import;
  const elastic = report.provenance.elastic_import;
  const both = summary.techniques_by_status.covered - summary.covered_techniques_by_origin_only.sigma! - summary.covered_techniques_by_origin_only.elastic!;
  const products = [...new Set(report.logsources.map((l) => l.product))];
  const blockers = report.gap_ranking.filter((row) => !supportedOnly || row.supported_product);

  return (
    <>
      <PageHeader
        eyebrow={`Coverage report · ${report.report_version}`}
        title="Detection coverage"
        description="Which ATT&CK techniques the pinned detection content can actually observe on the telemetry this platform ingests — and, for the rest, exactly why not. A technique that cannot be detected can never appear as evidence, so this bounds what any attribution here can say."
        right={
          <Segmented
            ariaLabel="Technique scope"
            value={scope}
            onChange={(value) => {
              setScope(value);
              setLimit(PAGE);
            }}
            options={[
              { value: "group_used", label: "Used by a Group", count: summary.group_used_techniques },
              { value: "all", label: "All active", count: summary.active_techniques },
            ]}
          />
        }
      />

      <div className="mb-6 grid grid-cols-2 gap-4 xl:grid-cols-4">
        <Stat
          label={scope === "all" ? "Active techniques covered" : "Group-used techniques covered"}
          value={
            <>
              {integer(counts.covered)}
              <span className="text-headline-md text-on-surface-variant"> / {integer(total)}</span>
            </>
          }
          accent
          sub="at least one translated rule can fire"
        />
        <Stat
          label="Groups with ≥ 2 covered techniques"
          value={
            <>
              {integer(summary.groups_with_at_least_2_covered)}
              <span className="text-headline-md text-on-surface-variant"> / {integer(summary.active_groups)}</span>
            </>
          }
          sub={`≥ 5: ${summary.groups_with_at_least_5_covered} · ≥ 10: ${summary.groups_with_at_least_10_covered} · none: ${summary.groups_with_zero_covered}`}
        />
        <Stat
          label="Covered by source"
          value={<span className="text-headline-lg">{integer(summary.covered_techniques_by_origin.sigma ?? 0)} Sigma · {integer(summary.covered_techniques_by_origin.elastic ?? 0)} Elastic</span>}
          sub={`all active techniques · only Sigma ${summary.covered_techniques_by_origin_only.sigma} · only Elastic ${summary.covered_techniques_by_origin_only.elastic} · both ${both}`}
        />
        <Stat
          label="Translated rules"
          value={integer(report.content.sigma.summary.by_status.imported + report.content.sigma.summary.by_status.partial + report.content.elastic.summary.by_status.imported + report.content.elastic.summary.by_status.partial)}
          sub={`${integer(report.content.sigma.summary.generated_rules + report.content.elastic.summary.generated_rules)} engine rules`}
        />
      </div>

      <div className="space-y-6">
        <Card padded={false}>
          <CardHeader
            title={scope === "all" ? `Status of all ${integer(total)} active techniques` : `Status of the ${integer(total)} techniques at least one Group uses`}
            hint="Every technique has exactly one status. Click a status to filter the technique table below."
          />
          <div className="space-y-4 p-4">
            <StackedBar segments={segments(counts)} height={18} />
            <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-5">
              {COVERAGE_STATUSES.map((key) => (
                <button
                  key={key}
                  type="button"
                  onClick={() => setStatus(status === key ? "" : key)}
                  aria-pressed={status === key}
                  className={cx(
                    "rounded-sm border p-3 text-left transition-colors",
                    status === key ? "border-primary bg-primary/5" : "border-outline-variant/70 bg-surface-lowest hover:border-outline",
                  )}
                >
                  <div className="flex items-center gap-2">
                    <StatusDot status={key} />
                    <span className="font-mono text-headline-md text-on-surface">{integer(counts[key] ?? 0)}</span>
                  </div>
                  <div className="mt-1 text-label-md text-on-surface">{COVERAGE_LABEL[key]}</div>
                  <p className="mt-1 text-body-sm text-on-surface-variant">{COVERAGE_MEANING[key]}</p>
                </button>
              ))}
            </div>
          </div>
        </Card>

        <Card padded={false}>
          <CardHeader title="By tactic" hint="A technique in several tactics is counted in each. Tactics in ATT&CK matrix order." />
          <div className="divide-y divide-outline-variant/40">
            {byTactic.map((row) => (
              <button
                key={row.tactic}
                type="button"
                onClick={() => setTactic(tactic === row.tactic ? "" : row.tactic)}
                aria-pressed={tactic === row.tactic}
                className={cx("grid w-full grid-cols-[14rem_1fr_7rem] items-center gap-4 px-4 py-2 text-left hover:bg-surface", tactic === row.tactic && "bg-primary/5")}
              >
                <span className="truncate text-body-md text-on-surface">{row.name}</span>
                <StackedBar segments={segments(row.byStatus)} height={10} />
                <span className="text-right font-mono text-code-md text-on-surface-variant">
                  <span className="text-on-surface">{row.byStatus.covered}</span> / {row.total}
                </span>
              </button>
            ))}
          </div>
        </Card>

        <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
          <Source name="Sigma rules" source={report.content.sigma} version={`SigmaHQ ${String(sigma.sigma_release ?? "")} · ${String(sigma.importer ?? "")} · ${String(sigma.field_map_version ?? "")}`} />
          <Source name="Elastic prebuilt rules" source={report.content.elastic} version={`elastic/detection-rules @ ${shortHash(String(elastic.source_commit ?? ""), 12)} · ${String(elastic.importer ?? "")} · ${String(elastic.field_map_version ?? "")}`} />
        </div>

        {report.actor_specific && (
          <ActorSpecific actor={report.actor_specific} activeGroups={report.groups.length} />
        )}

        <Card padded={false}>
          <CardHeader title="Telemetry the content can fire on" hint="Translated rules per log source, grouped by product. A log source listed here is one the platform ingests and at least one rule reads." />
          <div className="grid grid-cols-1 gap-4 p-4 md:grid-cols-2 2xl:grid-cols-3">
            {products.map((product) => {
              const sources = report.logsources.filter((l) => l.product === product);
              const s = sources.reduce((n, l) => n + l.sigma_rules, 0);
              const e = sources.reduce((n, l) => n + l.elastic_rules, 0);
              const max = Math.max(...sources.map((l) => l.sigma_rules + l.elastic_rules), 1);
              return (
                <div key={product} className="rounded-sm border border-outline-variant/70 bg-surface-lowest">
                  <div className="flex items-center justify-between gap-3 border-b border-outline-variant/60 px-3 py-2">
                    <span className="text-headline-sm text-on-surface">{product || "(any product)"}</span>
                    <span className="flex gap-1.5">
                      {s > 0 && <Badge tone="neutral">{integer(s)} sigma</Badge>}
                      {e > 0 && <Badge tone="tertiary">{integer(e)} elastic</Badge>}
                    </span>
                  </div>
                  <ul className="max-h-56 space-y-1.5 overflow-y-auto p-3">
                    {sources.map((l) => (
                      <li key={l.logsource} className="grid grid-cols-[1fr_5rem_3rem] items-center gap-2">
                        <span className="truncate font-mono text-code-sm text-on-surface-variant" title={l.logsource}>
                          {l.logsource.slice(product.length + 1) || l.logsource}
                        </span>
                        <StackedBar
                          height={6}
                          segments={[
                            { key: "s", label: "Sigma", value: l.sigma_rules, color: "var(--color-on-surface-variant)" },
                            { key: "e", label: "Elastic", value: l.elastic_rules, color: "var(--color-tertiary-container)" },
                            { key: "r", label: "", value: max - l.sigma_rules - l.elastic_rules, color: "transparent" },
                          ]}
                        />
                        <span className="text-right font-mono text-code-sm text-on-surface">{integer(l.sigma_rules + l.elastic_rules)}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              );
            })}
          </div>
        </Card>

        <Card padded={false}>
          <CardHeader
            title="Telemetry blockers"
            hint="A log source or field that rejected rules need. Counts are upper bounds: techniques whose status is “telemetry gap” with at least one rejected rule waiting on this blocker — ingesting it could cover at most that many."
            right={
              <Segmented
                ariaLabel="Blocker scope"
                value={supportedOnly ? "supported" : "all"}
                onChange={(value) => setSupportedOnly(value === "supported")}
                options={[
                  { value: "supported", label: "Supported products", count: report.gap_ranking.filter((r) => r.supported_product).length },
                  { value: "all", label: "All", count: report.gap_ranking.length },
                ]}
              />
            }
          />
          <div className="max-h-[28rem] overflow-auto">
            <table className="w-full border-collapse text-body-md">
              <thead>
                <tr>
                  <Th>Blocker</Th>
                  <Th>Kind</Th>
                  <Th align="right">Techniques ≤</Th>
                  <Th align="right">Group-used ≤</Th>
                  <Th align="right">Groups touched ≤</Th>
                </tr>
              </thead>
              <tbody>
                {blockers.map((row) => {
                  const [kind, ...rest] = row.blocker.split(":");
                  return (
                    <tr key={row.blocker} className="hover:bg-surface">
                      <Td className="font-mono text-code-md">{rest.join(":")}</Td>
                      <Td>
                        <Badge tone="muted">{kind}</Badge>
                        {!row.supported_product && <Badge tone="muted" className="ml-1.5" title="A product this platform has no adapter for.">unsupported product</Badge>}
                      </Td>
                      <Td align="right" className="font-mono tabular-nums">{integer(row.techniques_upper_bound)}</Td>
                      <Td align="right" className="font-mono tabular-nums">{integer(row.group_used_techniques_upper_bound)}</Td>
                      <Td align="right" className="font-mono tabular-nums">{integer(row.groups_touched_upper_bound)}</Td>
                    </tr>
                  );
                })}
                {blockers.length === 0 && (
                  <tr>
                    <Td colSpan={5} className="py-6 text-center text-on-surface-variant">No blocker in this scope.</Td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </Card>

        <Card padded={false}>
          <CardHeader
            title="Techniques"
            hint={`${integer(rows.length)} of ${integer(scoped.length)} · ${scope === "all" ? "all active techniques" : "techniques at least one Group uses"}`}
            right={
              <>
                <Select
                  ariaLabel="Status"
                  value={status}
                  onChange={setStatus}
                  options={[{ value: "", label: "Any status" }, ...COVERAGE_STATUSES.map((s) => ({ value: s, label: COVERAGE_LABEL[s] }))]}
                />
                <Select
                  ariaLabel="Tactic"
                  value={tactic}
                  onChange={setTactic}
                  options={[{ value: "", label: "Any tactic" }, ...index.tacticOrder.map((t) => ({ value: t, label: index.tacticName.get(t) ?? t }))]}
                />
                <TextInput value={text} onChange={setText} placeholder="T1059 or name" icon={<Search size={14} />} className="w-48" />
              </>
            }
          />
          <div className="overflow-x-auto">
            <table className="w-full border-collapse text-body-md">
              <thead>
                <tr>
                  <Th>Technique</Th>
                  <Th>Name</Th>
                  <Th>Status</Th>
                  <Th align="right">Sigma rules</Th>
                  <Th align="right">Elastic rules</Th>
                  <Th align="right">Groups using</Th>
                  <Th>Rejected rules wait on</Th>
                </tr>
              </thead>
              <tbody>
                {rows.slice(0, limit).map((row) => (
                  <tr key={row.attack_id} className="hover:bg-surface">
                    <Td>
                      <AttackId id={row.attack_id} />
                    </Td>
                    <Td className="text-on-surface">{row.name}</Td>
                    <Td>
                      <span className="flex items-center gap-2 whitespace-nowrap">
                        <StatusDot status={row.status} />
                        {COVERAGE_LABEL[row.status]}
                      </span>
                    </Td>
                    <Td align="right" className="font-mono tabular-nums">{row.rule_sources_by_origin.sigma ?? 0}</Td>
                    <Td align="right" className="font-mono tabular-nums">{row.rule_sources_by_origin.elastic ?? 0}</Td>
                    <Td align="right" className="font-mono tabular-nums">{index.byAttackId.get(row.attack_id)?.groups_using ?? 0}</Td>
                    <Td className="max-w-md">
                      <span className="line-clamp-2 font-mono text-code-sm text-on-surface-variant" title={row.rejected_rules_blocked_by.join(", ")}>
                        {row.rejected_rules_blocked_by.join(", ") || "—"}
                      </span>
                    </Td>
                  </tr>
                ))}
                {rows.length === 0 && (
                  <tr>
                    <Td colSpan={7} className="py-8 text-center text-on-surface-variant">No technique matches these filters.</Td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
          {rows.length > limit && (
            <div className="flex items-center justify-between border-t border-outline-variant/70 px-4 py-3">
              <span className="text-body-sm text-on-surface-variant">Showing {integer(limit)} of {integer(rows.length)}</span>
              <Button onClick={() => setLimit((n) => n + PAGE * 2)}>Show more</Button>
            </div>
          )}
        </Card>
      </div>
    </>
  );
}
