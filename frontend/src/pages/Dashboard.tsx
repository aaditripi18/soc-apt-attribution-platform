import {
  ArrowRight,
  Bot,
  Crosshair,
  FileUp,
  Fingerprint,
  GitBranch,
  ListChecks,
  Network,
  ShieldCheck,
  Users,
} from "lucide-react";
import type { ReactNode } from "react";
import { Button } from "../components/ui";
import {
  SNAPSHOT,
  paths,
  useApi,
  type Coverage,
  type GroupCatalogue,
  type InvestigationSummary,
  type TechniqueCatalogue,
} from "../lib/api";
import { integer } from "../lib/format";
import { links } from "../lib/router";

function Step({ number, title, text }: { number: number; title: string; text: string }) {
  return (
    <li className="relative rounded-md border border-outline-variant/70 bg-surface-low p-4">
      <span className="flex h-7 w-7 items-center justify-center rounded-sm border border-primary/40 bg-primary/10 font-mono text-code-md text-primary">
        {number}
      </span>
      <h3 className="mt-3 text-headline-sm text-on-surface">{title}</h3>
      <p className="mt-1 text-body-md text-on-surface-variant">{text}</p>
    </li>
  );
}

function Feature({ icon, title, text, href, cta }: { icon: ReactNode; title: string; text: string; href?: string; cta?: string }) {
  return (
    <div className="rounded-md border border-outline-variant/70 bg-surface-low p-5">
      <span className="flex h-10 w-10 items-center justify-center rounded-md border border-primary/30 bg-primary/10 text-primary">{icon}</span>
      <h3 className="mt-3 text-headline-md text-on-surface">{title}</h3>
      <p className="mt-1.5 text-body-md text-on-surface-variant">{text}</p>
      {href && cta && (
        <a href={href} className="mt-3 inline-flex items-center gap-1.5 text-label-md text-primary hover:underline">
          {cta}
          <ArrowRight size={13} />
        </a>
      )}
    </div>
  );
}

function Figure({ value, label }: { value: string; label: string }) {
  return (
    <div>
      <div className="font-mono text-display-sm tabular-nums text-on-surface">{value}</div>
      <div className="mt-0.5 text-body-md text-on-surface-variant">{label}</div>
    </div>
  );
}

/** The front page: what the platform does for an analyst, and the way in. */
export function DashboardPage() {
  const coverage = useApi<Coverage>(paths.coverage());
  const groups = useApi<GroupCatalogue>(paths.groups());
  const catalogue = useApi<TechniqueCatalogue>(paths.techniques());
  const investigations = useApi<InvestigationSummary[]>(paths.investigations());

  const summary = coverage.state === "ready" ? coverage.data.summary : null;
  const rules =
    coverage.state === "ready"
      ? [coverage.data.content.sigma, coverage.data.content.elastic].reduce(
          (n, source) => n + source.summary.by_status.imported + source.summary.by_status.partial,
          0,
        )
      : null;
  const analysed = investigations.state === "ready" ? investigations.data.length : 0;

  return (
    <div className="space-y-10">
      <section className="rounded-lg border border-outline-variant/70 bg-gradient-to-br from-surface-low to-surface-lowest px-8 py-10">
        <div className="label text-primary">APT attribution platform</div>
        <h1 className="mt-2 max-w-4xl text-display-sm text-on-surface">
          From raw logs to techniques, attack chain and the threat group behind them.
        </h1>
        <p className="mt-4 max-w-3xl text-body-lg text-on-surface-variant">
          Upload security telemetry and get every detected MITRE ATT&amp;CK technique, the reconstructed attack chain,
          the indicators to hunt on, the threat groups the behaviour matches, and the mitigations that address it —
          each traced back to the log event and detection rule it came from.
        </p>
        <div className="mt-6 flex flex-wrap gap-3">
          {SNAPSHOT ? (
            // The hosted snapshot cannot upload: lead with the investigations it does hold.
            <>
              <Button href={links.investigations()} variant="primary">
                {`View ${integer(analysed)} ${analysed === 1 ? "investigation" : "investigations"}`}
              </Button>
              <Button href={links.actors()}>Browse threat actors</Button>
            </>
          ) : (
            <>
              <Button href={links.upload()} variant="primary">
                <FileUp size={14} />
                Analyze logs
              </Button>
              <Button href={links.actors()}>Browse threat actors</Button>
              {analysed > 0 && <Button href={links.investigations()} variant="ghost">{`View ${integer(analysed)} ${analysed === 1 ? "investigation" : "investigations"}`}</Button>}
            </>
          )}
        </div>
        <div className="mt-8 grid grid-cols-2 gap-6 border-t border-outline-variant/60 pt-6 lg:grid-cols-4">
          <Figure value={summary ? `${summary.techniques_by_status.covered}` : "—"} label={`of ${summary?.active_techniques ?? "—"} ATT&CK techniques detectable`} />
          <Figure value={rules ? integer(rules) : "—"} label="Sigma and Elastic detection rules" />
          <Figure value={groups.state === "ready" ? integer(groups.data.active_groups) : "—"} label="threat groups profiled" />
          <Figure value={groups.state === "ready" ? integer(groups.data.groups_with_specific_evidence) : "—"} label="groups with identifying artefacts or advisory indicators" />
        </div>
      </section>

      <section>
        <h2 className="text-headline-lg text-on-surface">How an analysis runs</h2>
        <ol className="mt-4 grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-5">
          <Step number={1} title="Ingest" text="Windows (Sysmon, Security, PowerShell, System), Linux, macOS, cloud audit and network logs, and Wazuh alerts, are normalised to one schema." />
          <Step number={2} title="Detect & map" text="Translated Sigma and Elastic rules fire on single events; each detection is mapped to its ATT&CK technique." />
          <Step number={3} title="Correlate" text="Detections are linked by process lineage into activity clusters and ordered into an attack chain." />
          <Step number={4} title="Attribute" text="Group-specific artefacts identify a group; otherwise behaviour is matched against every group profile." />
          <Step number={5} title="Respond" text="Indicators to hunt on and ATT&CK mitigations for exactly the techniques that were observed." />
        </ol>
      </section>

      <section>
        <h2 className="text-headline-lg text-on-surface">What you get for every log source</h2>
        <div className="mt-4 grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
          <Feature
            icon={<Crosshair size={20} />}
            title="Technique identification"
            text="Every detected technique and sub-technique on the ATT&CK matrix, with the rule that fired and the raw event it fired on."
            href={links.coverage()}
            cta="Technique coverage"
          />
          <Feature
            icon={<GitBranch size={20} />}
            title="Attack chain"
            text="Tactics in the order they were observed, and under each one the exact parent-to-child process sequence behind it."
          />
          <Feature
            icon={<Network size={20} />}
            title="Indicators of compromise"
            text="File hashes, addresses and domains taken from the detected events, checked against published government advisories, exportable as CSV."
          />
          <Feature
            icon={<Fingerprint size={20} />}
            title="APT attribution"
            text="A group is identified on evidence specific to it. Where none exists, the closest behavioural profiles are shown with their overlap and the reason they cannot be separated."
            href={links.actors()}
            cta={catalogue.state === "ready" ? `${integer(catalogue.data.active_groups)} groups tracked` : "Threat actors"}
          />
          <Feature
            icon={<ShieldCheck size={20} />}
            title="Response guidance"
            text="MITRE ATT&CK mitigations for the observed techniques, prioritised by how many of them each one addresses."
          />
          <Feature
            icon={<Bot size={20} />}
            title="AI analyst"
            text="Ask questions about an investigation in plain language and get a summary on demand. It answers from the investigation's own results and keeps the conversation in mind."
          />
        </div>
      </section>

      <section className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <div className="rounded-md border border-outline-variant/70 bg-surface-low p-5">
          <div className="flex items-center gap-2">
            <ListChecks size={18} className="text-primary" />
            <h2 className="text-headline-md text-on-surface">Evidence you can check</h2>
          </div>
          <p className="mt-2 text-body-md text-on-surface-variant">
            Nothing on this platform is asserted without its source. A technique links to the rule and the event; an
            attribution links to the artefact or the overlapping techniques; a percentage states its formula. The
            method and its validation results are published in full.
          </p>
          <a href={links.about()} className="mt-3 inline-flex items-center gap-1.5 text-label-md text-primary hover:underline">
            Methodology and validation
            <ArrowRight size={13} />
          </a>
        </div>
        <div className="rounded-md border border-outline-variant/70 bg-surface-low p-5">
          <div className="flex items-center gap-2">
            <Users size={18} className="text-primary" />
            <h2 className="text-headline-md text-on-surface">Built on open threat knowledge</h2>
          </div>
          <p className="mt-2 text-body-md text-on-surface-variant">
            MITRE ATT&amp;CK for techniques, groups, software and mitigations; SigmaHQ and Elastic detection rules,
            translated exactly; CISA advisory indicators. Every source is version-pinned so a result can be reproduced.
          </p>
          <a href={links.upload()} className="mt-3 inline-flex items-center gap-1.5 text-label-md text-primary hover:underline">
            Analyze your logs
            <ArrowRight size={13} />
          </a>
        </div>
      </section>
    </div>
  );
}
