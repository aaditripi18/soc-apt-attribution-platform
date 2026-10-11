import { ArrowRight, Quote, Scale, Search } from "lucide-react";
import { useMemo, useState } from "react";
import { paths, useApi, type Assessment, type Validation, type Verdict } from "../lib/api";
import { integer, plural } from "../lib/format";
import { links } from "../lib/router";
import {
  AttackId,
  Badge,
  Card,
  CardHeader,
  Disclosure,
  ErrorState,
  Skeleton,
  Td,
  TextInput,
  Th,
  cx,
} from "./ui";

export const VERDICT_LABEL: Record<Verdict, string> = {
  no_decision_features: "Nothing attributable",
  not_distinguishable: "No actor can be singled out",
  third_party_lead: "No actor singled out · advisory lead",
  actor_specific_evidence: "Actor-specific evidence · a lead",
};

/** One sentence on how the platform has done on recordings with a known answer. */
export function TrackRecordLine({ validation }: { validation: Validation }) {
  const s = validation.summary;
  return (
    <>
      On the {plural(s.emulations, "recording")} whose emulated actor is known, ordering candidates by technique overlap
      put that actor first under {s.orderings_naming_the_known_actor_first} of {s.orderings_measured} orderings tried
      {s.best_position_of_a_known_actor !== null && (
        <>
          {" "}
          (its position ranged from {s.best_position_of_a_known_actor} to {s.worst_position_of_a_known_actor})
        </>
      )}
      {s.tool_tests > 0 && (
        <>
          ; on the {plural(s.tool_tests, "tool test")} with no actor at all it would still have named one in{" "}
          {s.actors_an_ordering_would_name_on_tool_tests} of {s.orderings_on_tool_tests} orderings
        </>
      )}
      .
    </>
  );
}

function Candidates({ assessment }: { assessment: Assessment }) {
  const [text, setText] = useState("");
  const [open, setOpen] = useState<string | null>(null);
  const total = assessment.observed_techniques.length;
  const rows = useMemo(() => {
    const needle = text.trim().toLowerCase();
    return assessment.candidates.filter(
      (c) => needle === "" || c.name.toLowerCase().includes(needle) || c.candidate_id.toLowerCase().includes(needle),
    );
  }, [assessment.candidates, text]);
  return (
    <div className="border-t border-outline-variant/70">
      <div className="flex flex-wrap items-center justify-between gap-3 px-4 py-3">
        <p className="max-w-3xl text-body-sm text-on-surface-variant">
          Every consistent Group and Campaign, <span className="text-on-surface">in name order</span>. “Observed in profile”
          counts how many of the {total} observed techniques ATT&amp;CK records for it — a fact about its published profile,
          not a measure of how likely it is.
        </p>
        <TextInput value={text} onChange={setText} placeholder="Name or id" icon={<Search size={14} />} className="w-48" />
      </div>
      <div className="max-h-[28rem] overflow-auto">
        <table className="w-full border-collapse text-body-md">
          <thead>
            <tr>
              <Th className="w-8" />
              <Th>Candidate (A–Z)</Th>
              <Th>Kind</Th>
              <Th align="right">Observed in profile</Th>
              <Th align="right">Profile size</Th>
              <Th align="right">Candidate in units</Th>
            </tr>
          </thead>
          <tbody>
            {rows.map((c) => {
              const expanded = open === c.stix_id;
              return [
                <tr
                  key={c.stix_id}
                  onClick={() => setOpen(expanded ? null : c.stix_id)}
                  aria-expanded={expanded}
                  className={cx("cursor-pointer hover:bg-surface", expanded && "bg-surface")}
                >
                  <Td className="pr-0">
                    <Disclosure open={expanded} />
                  </Td>
                  <Td>
                    <span className="flex items-center gap-2">
                      <span className="font-medium text-on-surface">{c.name}</span>
                      <AttackId id={c.candidate_id} tone="muted" />
                    </span>
                  </Td>
                  <Td>
                    <Badge tone="muted">{c.kind}</Badge>
                  </Td>
                  <Td align="right" className="font-mono tabular-nums">
                    {c.matched_technique_ids.length} <span className="text-outline">/ {total}</span>
                  </Td>
                  <Td align="right" className="font-mono tabular-nums text-on-surface-variant">
                    {c.profile_techniques}
                  </Td>
                  <Td align="right" className="font-mono tabular-nums text-on-surface-variant">
                    {c.units_as_candidate} <span className="text-outline">/ {assessment.units_total}</span>
                  </Td>
                </tr>,
                expanded && (
                  <tr key={`${c.stix_id}::detail`}>
                    <td colSpan={6} className="border-b border-outline-variant/40 bg-surface-lowest/60 px-4 py-3 pl-10">
                      <div className="label mb-1.5">Observed techniques in its recorded profile</div>
                      <div className="flex flex-wrap gap-1">
                        {c.matched_technique_ids.map((id) => (
                          <AttackId key={id} id={id} />
                        ))}
                      </div>
                      <a
                        href={links.units({ candidate: c.candidate_id, investigation: assessment.investigation_id })}
                        className="mt-2 inline-flex items-center gap-1 text-label-md text-primary hover:underline"
                      >
                        Units of this investigation with {c.name} among their candidates
                        <ArrowRight size={12} />
                      </a>
                    </td>
                  </tr>
                ),
              ];
            })}
            {rows.length === 0 && (
              <tr>
                <Td colSpan={6} className="py-6 text-center text-on-surface-variant">
                  No candidate matches “{text}”.
                </Td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

/** The investigation-level verdict (ADR-0017), exactly as the backend stored it. */
export function AssessmentCard({ investigationId }: { investigationId: string }) {
  const assessment = useApi<Assessment>(paths.assessment(investigationId));
  const validation = useApi<Validation>(paths.validation());
  const [showCandidates, setShowCandidates] = useState(false);

  if (assessment.state === "loading") return <Skeleton className="h-40" />;
  if (assessment.state === "error") return <ErrorState failure={assessment.error} onRetry={assessment.reload} />;
  const a = assessment.data;
  const total = a.observed_techniques.length;
  const candidates = a.candidates.length;

  return (
    <Card padded={false}>
      <CardHeader
        title="Attribution assessment"
        hint="The verdict about the whole investigation, with its reasons. It never names an actor from technique overlap; it names one only when an artefact specific to that Group matched, and then as a lead."
        right={<Badge tone={a.verdict === "third_party_lead" ? "tertiary" : "warning"}>{VERDICT_LABEL[a.verdict]}</Badge>}
      />
      <div className="grid grid-cols-1 gap-6 p-4 xl:grid-cols-[1fr_22rem]">
        <div className="min-w-0 space-y-4">
          <p className="flex gap-3 text-headline-md font-normal text-on-surface">
            <Scale size={20} className="mt-0.5 shrink-0 text-warning" />
            <span>{a.statement}</span>
          </p>
          {a.reasons.length > 0 && (
            <ul className="space-y-1.5 pl-8">
              {a.reasons.map((reason) => (
                <li key={reason} className="list-disc text-body-lg text-on-surface-variant marker:text-outline">
                  {reason}
                </li>
              ))}
              {validation.state === "ready" && (
                <li className="list-disc text-body-lg text-on-surface-variant marker:text-outline">
                  <TrackRecordLine validation={validation.data} />{" "}
                  <a href={links.about()} className="text-primary hover:underline">
                    Known-answer checks
                  </a>
                </li>
              )}
            </ul>
          )}
          {a.actor_leads.map((lead) => (
            <div key={lead.evidence_id} className="ml-8 rounded-sm border border-warning/40 bg-warning/5 p-3">
              <div className="flex flex-wrap items-center gap-2 text-body-md">
                <Badge tone="warning">Actor-specific evidence</Badge>
                <span className="font-semibold text-on-surface">{lead.actor_name}</span>
                {lead.actor_attack_id && <AttackId id={lead.actor_attack_id} tone="warning" />}
                <a href={links.unit(lead.group_id, "evidence")} className="text-label-md text-primary hover:underline">
                  Open the unit
                </a>
              </div>
              <p className="mt-1.5 break-words font-mono text-code-sm leading-relaxed text-on-surface-variant">{lead.claim}</p>
            </div>
          ))}
          {a.indicator_leads.map((lead) => (
            <div key={`${lead.value}::${lead.group_id}`} className="ml-8 rounded-sm border border-tertiary-dim/40 bg-tertiary-dim/5 p-3">
              <div className="flex flex-wrap items-center gap-2 text-body-md">
                <Badge tone="tertiary">Lead — the publisher’s claim</Badge>
                <span className="font-semibold text-on-surface">{lead.actor_name}</span>
                {lead.actor_attack_id && <AttackId id={lead.actor_attack_id} tone="muted" />}
                <Badge tone={lead.within_validity === false ? "warning" : "muted"}>
                  {lead.within_validity === true ? "inside" : lead.within_validity === false ? "outside" : "no stated"} validity
                  window
                </Badge>
              </div>
              <p className="mt-1.5 text-body-md text-on-surface-variant">
                An observed {lead.kind} equals indicator <span className="text-on-surface">{lead.indicator_name}</span> in{" "}
                {lead.report_name ?? "a pinned advisory"}.{" "}
                <a href={links.unit(lead.group_id, "indicators")} className="text-primary hover:underline">
                  Open the unit
                </a>
              </p>
              {lead.attribution_quote && (
                <blockquote className="mt-2 flex gap-2 border-l-2 border-outline-variant pl-3 text-body-md italic text-on-surface-variant">
                  <Quote size={13} className="mt-1 shrink-0 text-outline" />
                  <span>{lead.attribution_quote}</span>
                </blockquote>
              )}
            </div>
          ))}
        </div>

        <div className="space-y-4">
          {total > 0 && (
            <div className="rounded-sm border border-outline-variant/70 bg-surface-lowest p-3">
              <div className="label mb-2">Candidates by how much of the evidence their profile includes</div>
              <ul className="space-y-2">
                {a.overlap_counts.map((row) => (
                  <li key={row.min_matched}>
                    <div className="flex items-baseline justify-between gap-3 text-body-md">
                      <span className="text-on-surface-variant">
                        at least {row.min_matched} of {total} technique{total === 1 ? "" : "s"}
                      </span>
                      <span className="font-mono tabular-nums text-on-surface">{integer(row.candidates)}</span>
                    </div>
                    <div className="mt-1 h-1.5 overflow-hidden rounded-full bg-surface-highest">
                      <div
                        className="h-full rounded-full bg-outline"
                        style={{ width: `${candidates ? (row.candidates / candidates) * 100 : 0}%` }}
                      />
                    </div>
                  </li>
                ))}
              </ul>
              <p className="mt-2 text-body-sm text-on-surface-variant">
                Counts of candidates, of {integer(candidates)} ({a.candidate_groups} Groups, {a.candidate_campaigns}{" "}
                Campaigns; ATT&amp;CK has {a.active_groups} active Groups).
              </p>
            </div>
          )}
          <div>
            <div className="label mb-1.5">What this does not establish</div>
            <ul className="space-y-1.5">
              {a.limits.map((limit) => (
                <li key={limit} className="text-body-sm text-on-surface-variant">
                  {limit}
                </li>
              ))}
            </ul>
          </div>
        </div>
      </div>
      {candidates > 0 && (
        <>
          <button
            type="button"
            onClick={() => setShowCandidates((value) => !value)}
            aria-expanded={showCandidates}
            className="flex w-full items-center gap-2 border-t border-outline-variant/70 px-4 py-2.5 text-left text-label-md text-on-surface-variant hover:bg-surface hover:text-on-surface"
          >
            <Disclosure open={showCandidates} />
            {showCandidates ? "Hide" : "Show"} the {integer(candidates)} consistent Groups and Campaigns
            <span className="font-mono text-code-sm text-outline">
              {integer(a.units_with_decision_features)} of {integer(a.units_total)} units contribute techniques · method{" "}
              {a.method_version}
            </span>
          </button>
          {showCandidates && <Candidates assessment={a} />}
        </>
      )}
    </Card>
  );
}
