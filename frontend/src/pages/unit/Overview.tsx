import { ArrowRight } from "lucide-react";
import type { ReactNode } from "react";
import { AttackId, Badge, Card, CardHeader, Meter } from "../../components/ui";
import { integer, plural, ratio, utcDateTime } from "../../lib/format";
import { links } from "../../lib/router";
import type { UnitData } from "../Unit";

function More({ href, children }: { href: string; children: ReactNode }) {
  return (
    <a href={href} className="inline-flex items-center gap-1 text-label-md text-primary hover:underline">
      {children}
      <ArrowRight size={12} />
    </a>
  );
}

function Fact({ n, children }: { n: number; children: ReactNode }) {
  return (
    <li className="flex gap-3">
      <span className="mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-sm border border-outline-variant bg-surface-high font-mono text-code-sm text-on-surface-variant">
        {n}
      </span>
      <span className="text-body-lg text-on-surface-variant">{children}</span>
    </li>
  );
}

const strong = "font-semibold text-on-surface";

export function OverviewTab({ data, unitId }: { data: UnitData; unitId: string }) {
  const { unit, techniques, candidates } = data;
  const analysis = unit.attribution_analysis;
  const features = techniques.filter((t) => t.role === "feature");
  const unmatched = techniques.filter((t) => t.role === "unmatched");
  const context = techniques.filter((t) => t.role === "context");
  const observations = Object.keys(data.evidence.observations).length;
  const matchAll = candidates.filter((row) => row.uses.size === features.length).length;
  const questions = analysis.collection_guidance?.questions ?? [];

  return (
    <div className="space-y-6">
      {analysis.actor_specific_evidence.length > 0 && (
        <Card className="border-warning/40 bg-warning/5">
          <div className="flex flex-wrap items-center gap-2">
            <Badge tone="warning">Actor-specific evidence</Badge>
            <h2 className="text-headline-md text-on-surface">
              {[...new Set(analysis.actor_specific_evidence.map((e) => e.actor_name))].sort().join(", ")}
            </h2>
          </div>
          <p className="mt-2 max-w-4xl text-body-md text-on-surface-variant">
            A rule written from published reporting on this Group’s own tooling matched here, and the reviewed decision
            for that rule accepts it as specific. It is a lead to verify — anyone with the same tooling, or copying its
            artefacts, would produce it too — and it is not part of the technique comparison.
          </p>
          <ul className="mt-3 space-y-2">
            {analysis.actor_specific_evidence.map((item) => (
              <li key={item.evidence_id} className="rounded-sm border border-outline-variant/60 bg-surface-lowest p-3">
                <div className="flex flex-wrap items-center gap-2 text-body-md">
                  <span className="font-semibold text-on-surface">{item.actor_name}</span>
                  {item.actor_attack_id && <AttackId id={item.actor_attack_id} tone="warning" />}
                  <span className="font-mono text-code-sm text-on-surface-variant">{utcDateTime(item.observed_at, true)}</span>
                </div>
                <p className="mt-1.5 break-words font-mono text-code-sm leading-relaxed text-on-surface-variant">{item.claim}</p>
              </li>
            ))}
          </ul>
          <div className="mt-3">
            <More href={links.unit(unitId, "evidence")}>Evidence</More>
          </div>
        </Card>
      )}
      <div className="grid grid-cols-1 gap-6 xl:grid-cols-3">
        <Card padded={false} className="xl:col-span-2">
          <CardHeader title="What this unit establishes" hint="Each statement is a stored fact; open the tab beside it for the records behind it." />
          <ol className="space-y-4 p-4">
            <Fact n={1}>
              <span className={strong}>{plural(observations, "observation")}</span> on{" "}
              {data.hosts.length > 0 ? (
                <span className="font-mono text-code-md text-on-surface">{data.hosts.join(", ")}</span>
              ) : (
                "no named host"
              )}{" "}
              between <span className="font-mono text-code-md text-on-surface">{utcDateTime(data.firstSeen, true)}</span>{" "}
              and <span className="font-mono text-code-md text-on-surface">{utcDateTime(data.lastSeen, true)}</span>, joined into{" "}
              {plural(unit.sequence.steps.length, "behavioural step")} by{" "}
              {plural(unit.group.structural_link_ids.length, "structural link")} — never by a shared host or user alone.{" "}
              <More href={links.unit(unitId, "sequence")}>Attack sequence</More>
            </Fact>
            <Fact n={2}>
              <span className={strong}>{plural(data.coreEvidence, "core Evidence item")}</span> and{" "}
              {plural(data.contextEvidence, "low-level item")}. Each is one detection rule matching one observation; low-level
              items are context and add no technique to the comparison.{" "}
              <More href={links.unit(unitId, "evidence")}>Evidence</More>
            </Fact>
            <Fact n={3}>
              {features.length === 0 ? (
                <>
                  <span className={strong}>No decision feature</span>: no technique here is both supported by core Evidence
                  and recorded for an ATT&amp;CK Group or Campaign, so there is nothing to compare.{" "}
                </>
              ) : (
                <>
                  <span className={strong}>{plural(features.length, "decision feature")}</span>: ATT&amp;CK technique
                  {features.length === 1 ? "" : "s"} supported by core Evidence and recorded for at least one Group or
                  Campaign.{" "}
                </>
              )}
              {unmatched.length > 0 && (
                <>
                  {plural(unmatched.length, "more technique")} with core Evidence {unmatched.length === 1 ? "is" : "are"}{" "}
                  used by no candidate.{" "}
                </>
              )}
              {context.length > 0 && <>{plural(context.length, "technique")} seen only in low-level evidence. </>}
              <More href={links.unit(unitId, "techniques")}>Techniques</More>
            </Fact>
            <Fact n={4}>
              {analysis.candidates.length === 0 ? (
                <span className={strong}>No ATT&amp;CK Group or Campaign uses any observed technique.</span>
              ) : (
                <>
                  <span className={strong}>{plural(analysis.candidates.length, "candidate")}</span> — every ATT&amp;CK Group or
                  Campaign whose recorded profile includes at least one observed technique.{" "}
                  {features.length > 1 && (
                    <>
                      {matchAll === 0 ? "None includes" : `${integer(matchAll)} include${matchAll === 1 ? "s" : ""}`} all{" "}
                      {features.length}.{" "}
                    </>
                  )}
                  They are listed alphabetically; nothing here says which is more likely.
                </>
              )}{" "}
              <More href={links.unit(unitId, "candidates")}>Candidate actors</More>
            </Fact>
            <Fact n={5}>
              {questions.length === 0 ? (
                "No unobserved technique separates these candidates."
              ) : (
                <>
                  <span className={strong}>{plural(questions.length, "unobserved technique")}</span> would set candidates apart
                  if looked for.
                </>
              )}{" "}
              <More href={links.unit(unitId, "guidance")}>What evidence would help</More>
            </Fact>
            <Fact n={6}>
              {analysis.indicator_matches.length === 0 ? (
                "No observed value equals a pinned advisory indicator."
              ) : (
                <>
                  <span className={strong}>{plural(analysis.indicator_matches.length, "observed value")}</span> equal an
                  indicator from a government advisory — context only, never part of the attribution quantities.
                </>
              )}{" "}
              <More href={links.unit(unitId, "indicators")}>Indicator context</More>
            </Fact>
          </ol>
        </Card>

        <Card padded={false}>
          <CardHeader title="How strong is this?" />
          <div className="space-y-4 p-4">
            <Badge tone="warning">{analysis.calibration_status}</Badge>
            <p className="text-body-md text-on-surface-variant">{analysis.calibration_note}</p>
            {analysis.comparison_status !== "computed" ? (
              <div className="rounded-sm border border-warning/30 bg-warning/5 p-3">
                <div className="label text-warning">
                  {analysis.comparison_status === "not_computed" ? "Comparison not computed" : "Baseline not computed"}
                </div>
                <p className="mt-1 text-body-sm text-on-surface-variant">{analysis.comparison_note}</p>
                <p className="mt-1 text-body-sm text-on-surface-variant">Nothing was estimated in its place.</p>
              </div>
            ) : (
              <div className="rounded-sm border border-outline-variant/70 bg-surface-lowest p-3">
                <div className="label">Unattributed baseline</div>
                <div className="mt-1 font-mono text-headline-lg text-on-surface">
                  {ratio(analysis.unattributed_decision_support)}
                </div>
                <p className="mt-1 text-body-sm text-on-surface-variant">
                  ADR-0005 support if no Group is involved. A reference point for the per-candidate values, not a probability.
                </p>
              </div>
            )}
          </div>
        </Card>
      </div>

      {features.length > 0 && (
        <Card padded={false}>
          <CardHeader
            title="Observed techniques"
            hint="g = share of active ATT&CK Groups recorded using the technique; D = 1 − g. The rarer a technique, the more it separates candidates."
            right={<More href={links.unit(unitId, "techniques")}>All techniques</More>}
          />
          <div className="divide-y divide-outline-variant/40">
            {features.map((t) => (
              <div key={t.stixId} className="grid grid-cols-[7rem_1fr_15rem] items-center gap-4 px-4 py-2.5">
                <AttackId id={t.attackId} />
                <span className="min-w-0 truncate text-body-md text-on-surface">{t.name}</span>
                <span className="flex items-center gap-3">
                  <span className="w-24 shrink-0 font-mono text-code-sm text-on-surface-variant">D {ratio(t.d)}</span>
                  {t.d !== null && <Meter value={t.d} label={`D = ${ratio(t.d)}`} />}
                </span>
              </div>
            ))}
          </div>
        </Card>
      )}
    </div>
  );
}
