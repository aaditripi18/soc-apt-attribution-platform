import { ArrowRight } from "lucide-react";
import { AttackId, Badge, Card, EmptyState, Meter } from "../../components/ui";
import { ruleOf, type UnitTechnique } from "../../lib/derive";
import { integer, plural, ratio } from "../../lib/format";
import { links } from "../../lib/router";
import type { UnitData } from "../Unit";

function TechniqueCard({ technique, data, unitId }: { technique: UnitTechnique; data: UnitData; unitId: string }) {
  const { index } = data;
  const rules = new Map<string, string>();
  for (const item of technique.evidence) {
    const rule = ruleOf(item, data.evidence.rules);
    rules.set(item.provenance.method.split(":").slice(0, 2).join(":"), rule?.title ?? item.provenance.method);
  }
  const feature = technique.role === "feature";
  return (
    <Card className="flex flex-col gap-3">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <AttackId id={technique.attackId} />
            {technique.tactics.map((tactic) => (
              <Badge key={tactic} tone="muted">
                {index.tacticName.get(tactic) ?? tactic}
              </Badge>
            ))}
          </div>
          <h3 className="mt-2 text-headline-md text-on-surface">{technique.name || technique.stixId}</h3>
        </div>
        <Badge
          tone={feature ? "primary" : technique.role === "unmatched" ? "warning" : "muted"}
          title={
            feature
              ? "Supported by core Evidence: part of the comparison."
              : technique.role === "unmatched"
                ? "Supported by core Evidence, but no ATT&CK Group or Campaign is recorded using it: it places no candidate."
                : "Seen only in low-level Evidence: shown as context, adds nothing to the comparison."
          }
        >
          {feature ? "Decision feature" : technique.role === "unmatched" ? "No candidate uses it" : "Context only"}
        </Badge>
      </div>

      {technique.groupsUsing !== null && (
        <div className="rounded-sm border border-outline-variant/70 bg-surface-lowest p-3">
          <div className="flex items-baseline justify-between gap-3">
            <span className="text-body-md text-on-surface">
              Used by <span className="font-mono font-semibold">{integer(technique.groupsUsing)}</span> of{" "}
              <span className="font-mono">{integer(index.activeGroups)}</span> active ATT&amp;CK Groups
            </span>
            <span className="shrink-0 font-mono text-code-md text-on-surface-variant">
              g {ratio(technique.g)} · D {ratio(technique.d)}
            </span>
          </div>
          <div className="mt-2">
            <Meter value={technique.d ?? 0} tone={feature ? "primary" : "muted"} label={`D = ${ratio(technique.d)}`} />
          </div>
          <p className="mt-1.5 text-body-sm text-on-surface-variant">
            D = 1 − g: the fewer Groups use a technique, the more observing it separates candidates.
            {index.byStix.get(technique.stixId)?.is_subtechnique === false &&
              " This counts Groups ATT&CK records using the technique itself; use recorded against one of its sub-techniques is counted there."}
          </p>
        </div>
      )}

      <div>
        <div className="label mb-1.5">
          Why it is supported — {plural(technique.evidence.length, "Evidence item")} from {plural(rules.size, "rule")}
        </div>
        <ul className="space-y-1">
          {[...rules.entries()].slice(0, 4).map(([key, title]) => (
            <li key={key} className="flex items-start gap-2 text-body-md text-on-surface-variant">
              <Badge tone="muted" className="mt-0.5">
                {key.split(":")[0]}
              </Badge>
              <span className="min-w-0">{title}</span>
            </li>
          ))}
          {rules.size > 4 && <li className="text-body-sm text-outline">… and {rules.size - 4} more rules</li>}
        </ul>
      </div>
      <a
        href={links.unit(unitId, "evidence") + `?technique=${encodeURIComponent(technique.attackId)}`}
        className="mt-auto inline-flex items-center gap-1 text-label-md text-primary hover:underline"
      >
        Show this technique’s evidence
        <ArrowRight size={12} />
      </a>
      <a
        href={links.units({ technique: technique.attackId })}
        className="inline-flex items-center gap-1 text-label-md text-on-surface-variant hover:text-primary"
      >
        All units where {technique.attackId} was observed
        <ArrowRight size={12} />
      </a>
    </Card>
  );
}

export function TechniquesTab({ data, unitId }: { data: UnitData; unitId: string }) {
  const features = data.techniques.filter((t) => t.role === "feature");
  const unmatched = data.techniques.filter((t) => t.role === "unmatched");
  const context = data.techniques.filter((t) => t.role === "context");
  if (data.techniques.length === 0) {
    return (
      <EmptyState title="No ATT&CK technique in this unit">
        <p>None of this unit’s Evidence carries a technique mapping, so there is nothing to compare against ATT&amp;CK Group profiles.</p>
      </EmptyState>
    );
  }
  return (
    <div className="space-y-8">
      <section>
        <h2 className="text-headline-md text-on-surface">Decision features</h2>
        <p className="mb-4 mt-1 max-w-3xl text-body-md text-on-surface-variant">
          Techniques supported by core Evidence that at least one ATT&amp;CK Group or Campaign is recorded using. These
          are the features the candidate comparison uses.
        </p>
        {features.length === 0 ? (
          <EmptyState title="This unit has no decision feature">
            <p>
              {unmatched.length > 0
                ? "Its core Evidence maps only to techniques no ATT&CK Group or Campaign is recorded using."
                : "Everything observed here is low-level context."}{" "}
              Nothing here can be compared against ATT&amp;CK profiles.
            </p>
          </EmptyState>
        ) : (
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2 2xl:grid-cols-3">
            {features.map((t) => (
              <TechniqueCard key={t.stixId} technique={t} data={data} unitId={unitId} />
            ))}
          </div>
        )}
      </section>
      {unmatched.length > 0 && (
        <section>
          <h2 className="text-headline-md text-on-surface">Observed, but used by no candidate</h2>
          <p className="mb-4 mt-1 max-w-3xl text-body-md text-on-surface-variant">
            Supported by core Evidence, but ATT&amp;CK records no active Group or Campaign using the technique itself (use is
            often recorded against a sub-technique instead). It therefore places no candidate and is not a decision feature —
            it is still part of what happened.
          </p>
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2 2xl:grid-cols-3">
            {unmatched.map((t) => (
              <TechniqueCard key={t.stixId} technique={t} data={data} unitId={unitId} />
            ))}
          </div>
        </section>
      )}
      {context.length > 0 && (
        <section>
          <h2 className="text-headline-md text-on-surface">Context only</h2>
          <p className="mb-4 mt-1 max-w-3xl text-body-md text-on-surface-variant">
            Techniques seen only in low-level (enrich-tier) Evidence — common administrative behaviour that joins the unit but
            adds no technique to the comparison (ADR-0003 Amendment H).
          </p>
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2 2xl:grid-cols-3">
            {context.map((t) => (
              <TechniqueCard key={t.stixId} technique={t} data={data} unitId={unitId} />
            ))}
          </div>
        </section>
      )}
    </div>
  );
}
