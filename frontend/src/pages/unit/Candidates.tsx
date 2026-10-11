import { Info, Search } from "lucide-react";
import { useMemo, useState } from "react";
import {
  AttackId,
  Badge,
  Card,
  CardHeader,
  Disclosure,
  EmptyState,
  Segmented,
  Select,
  Td,
  TextInput,
  Th,
  UncalibratedBadge,
  cx,
} from "../../components/ui";
import type { CandidateRow } from "../../lib/derive";
import { integer, ratio, titleCase } from "../../lib/format";
import { links } from "../../lib/router";
import type { UnitData } from "../Unit";

function Dot({ on, label }: { on: boolean; label: string }) {
  return (
    <span
      role="img"
      aria-label={label}
      title={label}
      className={cx(
        "inline-block h-2.5 w-2.5 rounded-full border",
        on ? "border-primary bg-primary" : "border-outline-variant bg-transparent",
      )}
    />
  );
}

function Contributions({ row, data }: { row: CandidateRow; data: UnitData }) {
  const { index } = data;
  const hypothesis = row.hypothesis;
  const analysis = data.unit.attribution_analysis;
  const label = (stixId: string) => index.byStix.get(stixId)?.attack_id ?? stixId;
  return (
    <div className="space-y-3 bg-surface-lowest/60 px-4 py-4 pl-10">
      <div className="flex items-start gap-2 text-body-sm text-on-surface-variant">
        <Info size={13} className="mt-0.5 shrink-0 text-warning" />
        <p className="max-w-3xl">
          These are ADR-0005’s documented quantities for this candidate, shown so the comparison can be checked by hand. They
          are uncalibrated: not probabilities, not a confidence, and this table is never ordered by them.
        </p>
      </div>
      {row.candidate.attack_external_id && (
        <a
          href={links.units({ candidate: row.candidate.attack_external_id })}
          className="inline-flex items-center gap-1 text-label-md text-primary hover:underline"
        >
          All units with {row.candidate.name} among their candidates
        </a>
      )}
      {hypothesis === null ? (
        <p className="max-w-3xl text-body-md text-on-surface-variant">
          {analysis.comparison_status === "not_computed"
            ? analysis.comparison_note
            : "No hypothesis record is stored for this candidate."}
        </p>
      ) : (
        <div className="grid grid-cols-1 gap-4 xl:grid-cols-[1fr_18rem]">
          <div className="overflow-hidden rounded-sm border border-outline-variant/60">
            <table className="w-full border-collapse text-body-md">
              <thead>
                <tr className="bg-surface-low">
                  <th className="label px-3 py-1.5 text-left">Observed feature</th>
                  <th className="label px-3 py-1.5 text-left">Outcome</th>
                  <th className="label px-3 py-1.5 text-right" title="Share of active ATT&CK Groups using the feature">g</th>
                  <th className="label px-3 py-1.5 text-right" title="1 − g">D</th>
                  <th className="label px-3 py-1.5 text-right">Contribution</th>
                </tr>
              </thead>
              <tbody>
                {hypothesis.contributions.map((c, i) => (
                  <tr key={i} className="border-t border-outline-variant/40">
                    <td className="px-3 py-1.5">
                      <span className="flex flex-wrap items-center gap-1.5">
                        {c.feature_technique_ids.map((id) => (
                          <AttackId key={id} id={label(id)} />
                        ))}
                        <span className="text-on-surface-variant">
                          {c.feature_technique_ids.length === 1
                            ? (index.byStix.get(c.feature_technique_ids[0] ?? "")?.name ?? "")
                            : "combination"}
                        </span>
                      </span>
                    </td>
                    <td className="px-3 py-1.5">
                      <Badge tone={c.diagnosticity_outcome === "resolved" ? "muted" : "warning"}>
                        {titleCase(c.diagnosticity_outcome)}
                      </Badge>
                    </td>
                    <td className="px-3 py-1.5 text-right font-mono text-code-md tabular-nums">{ratio(c.g_value)}</td>
                    <td className="px-3 py-1.5 text-right font-mono text-code-md tabular-nums">{ratio(c.d_value)}</td>
                    <td className="px-3 py-1.5 text-right font-mono text-code-md tabular-nums">{ratio(c.contribution_value)}</td>
                  </tr>
                ))}
                {hypothesis.contributions.length === 0 && (
                  <tr>
                    <td colSpan={5} className="px-3 py-3 text-on-surface-variant">
                      No contribution is recorded.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
          <dl className="grid grid-cols-[1fr_auto] content-start gap-x-4 gap-y-1.5 rounded-sm border border-outline-variant/60 bg-surface-lowest p-3 text-body-md">
            <dt className="text-on-surface-variant" title="Techniques ATT&CK records for this candidate">
              Profile breadth
            </dt>
            <dd className="text-right font-mono text-code-md">{hypothesis.profile_breadth ?? "—"}</dd>
            <dt className="text-on-surface-variant" title="Profiles narrower than this are treated as this wide">
              Profile floor
            </dt>
            <dd className="text-right font-mono text-code-md">{analysis.min_profile_floor}</dd>
            <dt className="text-on-surface-variant">Support value</dt>
            <dd className="text-right font-mono text-code-md">{hypothesis.support_value.toPrecision(4)}</dd>
            <dt className="text-on-surface-variant">Unattributed baseline</dt>
            <dd className="text-right font-mono text-code-md">
              {analysis.unattributed_decision_support === null ? "—" : analysis.unattributed_decision_support.toPrecision(4)}
            </dd>
          </dl>
        </div>
      )}
    </div>
  );
}

export function CandidatesTab({ data }: { data: UnitData }) {
  const analysis = data.unit.attribution_analysis;
  const features = data.techniques.filter((t) => t.role === "feature");
  const [text, setText] = useState("");
  const [kind, setKind] = useState<"all" | "group" | "campaign">("all");
  const [uses, setUses] = useState("");
  const [open, setOpen] = useState<Set<string>>(new Set());

  const rows = useMemo(() => {
    const needle = text.trim().toLowerCase();
    return data.candidates.filter(
      (row) =>
        (kind === "all" || row.candidate.kind === kind) &&
        (uses === "" || row.uses.has(uses)) &&
        (needle === "" ||
          row.candidate.name.toLowerCase().includes(needle) ||
          (row.candidate.attack_external_id ?? "").toLowerCase().includes(needle)),
    );
  }, [data.candidates, text, kind, uses]);

  if (analysis.candidates.length === 0) {
    return (
      <EmptyState title="No candidate">
        <p>
          {features.length === 0
            ? "This unit has no decision feature, so no ATT&CK Group or Campaign can be compared against it."
            : "No ATT&CK Group or Campaign is recorded using any technique observed here."}
        </p>
      </EmptyState>
    );
  }
  const groups = data.candidates.filter((r) => r.candidate.kind === "group").length;
  const toggle = (id: string) =>
    setOpen((current) => {
      const next = new Set(current);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });

  return (
    <div className="space-y-4">
      <div className="flex items-start gap-3 rounded-md border border-warning/30 bg-warning/5 px-4 py-3">
        <UncalibratedBadge compact />
        <p className="text-body-md text-on-surface-variant">
          Every ATT&amp;CK Group or Campaign whose recorded profile includes at least one observed technique,{" "}
          <span className="font-semibold text-on-surface">in alphabetical order</span>. A filled dot means ATT&amp;CK records
          the candidate using that technique; the count is how many observed techniques the profile includes — a fact, not a
          score. Being listed here is not an accusation, and absence of a dot is not evidence of absence.
        </p>
      </div>
      {analysis.comparison_status === "not_computed" && (
        <div className="rounded-md border border-warning/30 bg-warning/5 px-4 py-3 text-body-md text-on-surface-variant">
          <span className="font-semibold text-on-surface">Per-candidate quantities are absent for this unit.</span>{" "}
          {analysis.comparison_note} The matrix below is unaffected: it only states which candidates ATT&amp;CK records using
          which observed technique.
        </div>
      )}
      <Card padded={false}>
        <CardHeader
          title="Candidate × observed technique"
          hint={`${rows.length === data.candidates.length ? "" : `${integer(rows.length)} of `}${integer(data.candidates.length)} candidates · ${integer(features.length)} observed technique${features.length === 1 ? "" : "s"}`}
          right={
            <>
              <Segmented
                ariaLabel="Candidate kind"
                value={kind}
                onChange={setKind}
                options={[
                  { value: "all", label: "All", count: data.candidates.length },
                  { value: "group", label: "Groups", count: groups },
                  { value: "campaign", label: "Campaigns", count: data.candidates.length - groups },
                ]}
              />
              {features.length > 1 && (
                <Select
                  ariaLabel="Uses technique"
                  value={uses}
                  onChange={setUses}
                  options={[
                    { value: "", label: "Any observed technique" },
                    ...features.map((t) => ({ value: t.stixId, label: `uses ${t.attackId}` })),
                  ]}
                />
              )}
              <TextInput value={text} onChange={setText} placeholder="Name or id" icon={<Search size={14} />} className="w-48" />
            </>
          }
        />
        <div className="max-h-[70vh] overflow-auto">
          <table className="w-full border-separate border-spacing-0 text-body-md">
            <thead>
              <tr>
                <Th className="left-0 z-20 w-8" />
                <Th className="min-w-56">Candidate (A–Z)</Th>
                <Th>Kind</Th>
                <Th align="right" className="whitespace-nowrap">
                  Observed in profile
                </Th>
                {features.map((t) => (
                  <Th key={t.stixId} align="center" className="whitespace-nowrap normal-case tracking-normal">
                    <span title={t.name}>{t.attackId}</span>
                  </Th>
                ))}
              </tr>
            </thead>
            <tbody>
              <tr className="bg-surface/60">
                <Td />
                <Td>
                  <span className="font-medium text-on-surface">Unattributed</span>
                  <span className="ml-2 text-body-sm text-on-surface-variant">baseline — no Group involved</span>
                </Td>
                <Td>
                  <Badge tone="muted">baseline</Badge>
                </Td>
                <Td align="right" className="font-mono text-code-md text-on-surface-variant">
                  {analysis.unattributed_decision_support === null
                    ? "not computed"
                    : `support ${ratio(analysis.unattributed_decision_support)}`}
                </Td>
                {features.map((t) => (
                  <Td key={t.stixId} align="center" className="text-outline">
                    —
                  </Td>
                ))}
              </tr>
              {rows.map((row) => {
                const id = row.candidate.candidate_id;
                const expanded = open.has(id);
                return [
                  <tr
                    key={id}
                    onClick={() => toggle(id)}
                    aria-expanded={expanded}
                    className={cx("cursor-pointer hover:bg-surface", expanded && "bg-surface")}
                  >
                    <Td className="pr-0">
                      <Disclosure open={expanded} />
                    </Td>
                    <Td>
                      <span className="flex items-center gap-2">
                        <span className="font-medium text-on-surface">{row.candidate.name}</span>
                        {row.candidate.attack_external_id && <AttackId id={row.candidate.attack_external_id} tone="muted" />}
                      </span>
                    </Td>
                    <Td>
                      <Badge tone="muted">{row.candidate.kind}</Badge>
                    </Td>
                    <Td align="right" className="font-mono tabular-nums">
                      {row.uses.size} <span className="text-outline">/ {features.length}</span>
                    </Td>
                    {features.map((t) => (
                      <Td key={t.stixId} align="center">
                        <Dot
                          on={row.uses.has(t.stixId)}
                          label={`${row.candidate.name} ${row.uses.has(t.stixId) ? "is recorded using" : "is not recorded using"} ${t.attackId}`}
                        />
                      </Td>
                    ))}
                  </tr>,
                  expanded && (
                    <tr key={`${id}::detail`}>
                      <td colSpan={4 + features.length} className="border-b border-outline-variant/40 p-0">
                        <Contributions row={row} data={data} />
                      </td>
                    </tr>
                  ),
                ];
              })}
              {rows.length === 0 && (
                <tr>
                  <Td colSpan={4 + features.length} className="py-8 text-center text-on-surface-variant">
                    No candidate matches these filters.
                  </Td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
}
