import { Quote, ShieldAlert } from "lucide-react";
import { AttackId, Badge, Card, EmptyState, Id } from "../../components/ui";
import type { IndicatorMatch } from "../../lib/api";
import { shortHash, utcDateTime } from "../../lib/format";
import type { UnitData } from "../Unit";

function Validity({ value }: { value: boolean | null }) {
  if (value === true) return <Badge tone="primary">Inside validity window</Badge>;
  if (value === false) {
    return (
      <Badge tone="warning" title="The observation is outside the period the advisory states for this indicator.">
        Outside validity window
      </Badge>
    );
  }
  return <Badge tone="muted">No stated validity</Badge>;
}

function Match({ match }: { match: IndicatorMatch }) {
  return (
    <Card className="space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex flex-wrap items-center gap-2">
          <Badge tone="neutral">{match.kind}</Badge>
          <Validity value={match.within_validity} />
        </div>
        <span className="font-mono text-code-sm text-on-surface-variant">observed {utcDateTime(match.observed_at)}</span>
      </div>
      <Id value={match.value} className="max-w-full" />
      <dl className="grid grid-cols-[8rem_1fr] gap-x-3 gap-y-1.5 text-body-md">
        <dt className="text-on-surface-variant">Indicator</dt>
        <dd className="min-w-0 text-on-surface">{match.indicator_name}</dd>
        <dt className="text-on-surface-variant">Advisory</dt>
        <dd className="min-w-0 text-on-surface">
          {match.report_name ?? "—"}
          <span className="ml-2 font-mono text-code-sm text-outline">{match.bundle_file}</span>
        </dd>
        <dt className="text-on-surface-variant">Observation</dt>
        <dd className="min-w-0">
          <Id value={match.observation_id} display={shortHash(match.observation_id, 44)} />
        </dd>
      </dl>
      {match.named_actor && (
        <div className="rounded-sm border border-outline-variant/70 bg-surface-lowest p-3">
          <div className="flex flex-wrap items-center gap-2 text-body-md">
            <span className="text-on-surface-variant">The publisher names</span>
            <span className="font-semibold text-on-surface">{match.named_actor}</span>
            {match.named_actor_attack_id && <AttackId id={match.named_actor_attack_id} tone="muted" />}
          </div>
          {match.attribution_quote && (
            <blockquote className="mt-2 flex gap-2 border-l-2 border-outline-variant pl-3 text-body-md italic text-on-surface-variant">
              <Quote size={13} className="mt-1 shrink-0 text-outline" />
              <span>{match.attribution_quote}</span>
            </blockquote>
          )}
        </div>
      )}
    </Card>
  );
}

export function IndicatorsTab({ data }: { data: UnitData }) {
  const matches = data.unit.attribution_analysis.indicator_matches;
  return (
    <div className="space-y-4">
      <div className="flex items-start gap-3 rounded-md border border-outline-variant bg-surface-low px-4 py-3">
        <ShieldAlert size={16} className="mt-0.5 shrink-0 text-tertiary" />
        <p className="text-body-md text-on-surface-variant">
          <span className="font-semibold text-on-surface">Context only — not part of attribution.</span> An observed value
          that equals an indicator published in a pinned government advisory. The actor named is the publisher’s claim, quoted
          verbatim; it changes none of the quantities on the other tabs, and indicators are easy for others to reuse.
        </p>
      </div>
      {matches.length === 0 ? (
        <EmptyState title="No observed value matches a pinned advisory indicator" />
      ) : (
        <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
          {matches.map((match) => (
            <Match key={`${match.indicator_id}::${match.observation_id}`} match={match} />
          ))}
        </div>
      )}
    </div>
  );
}
