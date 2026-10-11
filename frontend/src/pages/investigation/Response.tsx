import { ShieldCheck } from "lucide-react";
import { AttackId, Card, CardHeader, EmptyState, ErrorState, ExternalA, PageSkeleton, Stat } from "../../components/ui";
import { paths, useApi, type ProfileMatchRecord } from "../../lib/api";
import { integer, plural } from "../../lib/format";

const mitigationUrl = (id: string) => `https://attack.mitre.org/mitigations/${id}/`;

/** What to do about what was observed: ATT&CK's mitigations for the observed techniques. */
export function ResponseTab({ investigationId }: { investigationId: string }) {
  const profile = useApi<ProfileMatchRecord>(paths.profileMatch(investigationId));
  if (profile.state === "loading") return <PageSkeleton rows={5} />;
  if (profile.state === "error") return <ErrorState failure={profile.error} onRetry={profile.reload} />;
  const match = profile.data;
  const observed = match.observed.length;
  if (observed === 0) {
    return <EmptyState title="No observed technique to respond to" />;
  }
  const addressed = new Set(match.mitigations.flatMap((m) => m.technique_ids)).size;
  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-3">
        <Stat label="Recommended mitigations" value={integer(match.mitigations.length)} sub="from MITRE ATT&CK, for the observed techniques" accent />
        <Stat label="Techniques addressed" value={`${addressed} of ${observed}`} sub="observed techniques with a recorded mitigation" />
        <Stat
          label="No recorded mitigation"
          value={integer(match.techniques_without_mitigation.length)}
          sub="techniques that abuse normal system features"
        />
      </div>

      <Card padded={false}>
        <CardHeader
          title="Response priorities"
          hint="Mitigations ordered by how many of the observed techniques each one addresses. They apply whoever is behind the activity."
        />
        <ol className="divide-y divide-outline-variant/50">
          {match.mitigations.map((mitigation, index) => (
            <li key={mitigation.stix_id} className="flex gap-4 px-4 py-4" data-mitigation={mitigation.mitigation_id}>
              <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-sm border border-outline-variant bg-surface-high font-mono text-code-md text-on-surface-variant">
                {index + 1}
              </span>
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
                  <span className="text-headline-sm text-on-surface">{mitigation.name}</span>
                  <ExternalA href={mitigationUrl(mitigation.mitigation_id)}>{mitigation.mitigation_id}</ExternalA>
                  <span className="font-mono text-code-sm text-outline">
                    addresses {plural(mitigation.technique_ids.length, "observed technique")}
                  </span>
                </div>
                <p className="mt-1 max-w-4xl text-body-md text-on-surface-variant">{mitigation.description}</p>
                <div className="mt-2 flex flex-wrap gap-1">
                  {mitigation.technique_ids.map((id) => (
                    <AttackId key={id} id={id} />
                  ))}
                </div>
              </div>
            </li>
          ))}
        </ol>
      </Card>

      {match.techniques_without_mitigation.length > 0 && (
        <Card>
          <div className="flex gap-3">
            <ShieldCheck size={18} className="mt-0.5 shrink-0 text-on-surface-variant" />
            <div>
              <h2 className="text-headline-sm text-on-surface">Detect rather than prevent</h2>
              <p className="mt-1 max-w-4xl text-body-md text-on-surface-variant">
                ATT&CK records no preventive mitigation for these techniques, because they use features a system needs to
                work. Monitoring is the control: keep collecting the telemetry that revealed them.
              </p>
              <div className="mt-2 flex flex-wrap gap-1">
                {match.techniques_without_mitigation.map((id) => (
                  <AttackId key={id} id={id} />
                ))}
              </div>
            </div>
          </div>
        </Card>
      )}
    </div>
  );
}
