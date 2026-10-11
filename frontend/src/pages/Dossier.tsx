import { Check, Copy, Download, FileText, Printer } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import Markdown from "react-markdown";
import remarkGfm from "remark-gfm";
import {
  Button,
  Card,
  CardHeader,
  EmptyState,
  ErrorState,
  PageHeader,
  PageSkeleton,
  Segmented,
  Select,
  UncalibratedBadge,
  cx,
} from "../components/ui";
import { paths, useApi, type Dossier, type InvestigationSummary } from "../lib/api";
import { useCrumbs } from "../lib/crumbs";
import { integer, plural } from "../lib/format";
import { links, navigate } from "../lib/router";

interface Heading {
  line: number;
  depth: 2 | 3;
  text: string;
  /** Line of the `##` heading this one belongs to (its own line for a `##`). */
  section: number;
}

/** `##` and `###` headings with their 1-based source line (the anchor id). */
export function headings(markdown: string): Heading[] {
  const found: Heading[] = [];
  let fenced = false;
  let section = 0;
  markdown.split("\n").forEach((line, i) => {
    if (line.startsWith("```")) fenced = !fenced;
    if (fenced) return;
    const match = /^(#{2,3})\s+(.*)$/.exec(line);
    if (match) {
      const depth = match[1]!.length as 2 | 3;
      if (depth === 2) section = i + 1;
      found.push({ line: i + 1, depth, text: match[2]!.replace(/[`*_]/g, ""), section });
    }
  });
  return found;
}

const anchor = (line: number | undefined) => `dossier-L${line ?? 0}`;

function Picker({ investigations }: { investigations: InvestigationSummary[] }) {
  return (
    <Card padded={false}>
      <CardHeader title="Choose an investigation" hint="A dossier is rendered per investigation, from its stored records." />
      <ul className="divide-y divide-outline-variant/40">
        {investigations.map((item) => (
          <li key={item.investigation_id}>
            <a href={links.dossier(item.investigation_id)} className="flex items-center justify-between gap-4 px-4 py-3 hover:bg-surface">
              <span className="flex min-w-0 items-center gap-3">
                <FileText size={16} className="shrink-0 text-outline" />
                <span className="truncate text-body-lg text-on-surface">{item.source_id}</span>
              </span>
              <span className="shrink-0 font-mono text-code-md text-on-surface-variant">
                {plural(item.units, "unit")} · {integer(item.evidence)} evidence
              </span>
            </a>
          </li>
        ))}
      </ul>
    </Card>
  );
}

function Viewer({ id, investigations }: { id: string; investigations: InvestigationSummary[] }) {
  const dossier = useApi<Dossier>(paths.dossier(id));
  const [view, setView] = useState<"rendered" | "raw">("rendered");
  const [copied, setCopied] = useState(false);
  const [current, setCurrent] = useState<number | null>(null);
  const markdown = dossier.state === "ready" ? dossier.data.markdown : "";
  const toc = useMemo(() => headings(markdown), [markdown]);
  const source = investigations.find((i) => i.investigation_id === id)?.source_id;
  // The contents list every unit; a unit's own sections show only while it is in view.
  const activeSection = toc.find((heading) => heading.line === current)?.section ?? toc[0]?.section ?? 0;

  useCrumbs([{ label: "Attribution Dossier", href: links.dossier() }, { label: source ?? "Dossier" }]);

  useEffect(() => {
    if (view !== "rendered" || toc.length === 0) return;
    const onScroll = () => {
      let active: number | null = null;
      for (const heading of toc) {
        const element = document.getElementById(anchor(heading.line));
        if (element && element.getBoundingClientRect().top <= 120) active = heading.line;
      }
      setCurrent(active);
    };
    onScroll();
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, [toc, view]);

  if (dossier.state === "loading") return <PageSkeleton rows={10} />;
  if (dossier.state === "error") return <ErrorState failure={dossier.error} onRetry={dossier.reload} />;

  const download = () => {
    const url = URL.createObjectURL(new Blob([markdown], { type: "text/markdown;charset=utf-8" }));
    const link = document.createElement("a");
    link.href = url;
    link.download = `dossier-${(source ?? "investigation").replace(/[^\w.-]+/g, "_")}.md`;
    link.click();
    URL.revokeObjectURL(url);
  };
  const jump = (line: number) => {
    setView("rendered");
    window.setTimeout(() => document.getElementById(anchor(line))?.scrollIntoView({ behavior: "smooth", block: "start" }), 0);
  };

  return (
    <>
      <div className="no-print">
        <PageHeader
          eyebrow={`Attribution dossier · ${dossier.data.dossier_version}`}
          title={source ?? "Dossier"}
          description="One investigation explained in plain language: what was observed, the evidence, the techniques and why, the actors consistent with it, what remains uncertain and what would help. Rendered by the backend from the stored records — this page only displays it."
          right={
            <>
              <UncalibratedBadge compact />
              {investigations.length > 1 && (
                <Select
                  ariaLabel="Investigation"
                  value={id}
                  onChange={(value) => navigate(links.dossier(value))}
                  options={investigations.map((i) => ({ value: i.investigation_id, label: i.source_id }))}
                />
              )}
              <Segmented
                ariaLabel="View"
                value={view}
                onChange={setView}
                options={[
                  { value: "rendered", label: "Rendered" },
                  { value: "raw", label: "Markdown" },
                ]}
              />
              <Button
                onClick={() =>
                  void navigator.clipboard.writeText(markdown).then(() => {
                    setCopied(true);
                    window.setTimeout(() => setCopied(false), 1400);
                  })
                }
              >
                {copied ? <Check size={13} className="text-primary" /> : <Copy size={13} />}
                {copied ? "Copied" : "Copy"}
              </Button>
              <Button onClick={download}>
                <Download size={13} />
                .md
              </Button>
              <Button onClick={() => window.print()} title="Print, or save as PDF from the print dialog">
                <Printer size={13} />
                Print
              </Button>
            </>
          }
        />
      </div>
      <div className="grid grid-cols-1 gap-6 xl:grid-cols-[1fr_17rem]">
        <article className="min-w-0 rounded-md border border-outline-variant/70 bg-surface-low px-8 py-8 print:border-0 print:bg-transparent print:p-0">
          {view === "rendered" ? (
            <div className="dossier mx-auto max-w-4xl">
              <Markdown
                remarkPlugins={[remarkGfm]}
                components={{
                  h2: ({ node, children }) => <h2 id={anchor(node?.position?.start.line)}>{children}</h2>,
                  h3: ({ node, children }) => <h3 id={anchor(node?.position?.start.line)}>{children}</h3>,
                  table: ({ children }) => (
                    <div className="table-wrap">
                      <table>{children}</table>
                    </div>
                  ),
                  a: ({ href, children }) => (
                    <a href={href} target="_blank" rel="noreferrer noopener" className="text-primary hover:underline">
                      {children}
                    </a>
                  ),
                }}
              >
                {markdown}
              </Markdown>
            </div>
          ) : (
            <pre className="overflow-x-auto whitespace-pre-wrap break-words font-mono text-code-md text-on-surface-variant">{markdown}</pre>
          )}
        </article>
        <nav aria-label="Contents" className="no-print hidden xl:block">
          <div className="sticky top-20 max-h-[calc(100vh-6rem)] overflow-y-auto rounded-md border border-outline-variant/70 bg-surface-low p-3">
            <div className="label mb-2 px-2">Contents</div>
            <ul className="space-y-0.5">
              {toc.filter((heading) => heading.depth === 2 || heading.section === activeSection).map((heading) => (
                <li key={heading.line}>
                  <button
                    type="button"
                    onClick={() => jump(heading.line)}
                    className={cx(
                      "block w-full truncate rounded-sm border-l-2 px-2 py-1 text-left",
                      heading.depth === 2 ? "text-body-md" : "pl-5 text-body-sm",
                      current === heading.line
                        ? "border-primary bg-primary/10 text-primary"
                        : cx("border-transparent hover:text-on-surface", heading.depth === 2 ? "text-on-surface" : "text-on-surface-variant"),
                    )}
                    title={heading.text}
                  >
                    {heading.text}
                  </button>
                </li>
              ))}
            </ul>
          </div>
        </nav>
      </div>
    </>
  );
}

export function DossierPage({ id }: { id: string | undefined }) {
  const investigations = useApi<InvestigationSummary[]>(paths.investigations());
  const only = investigations.state === "ready" && investigations.data.length === 1 ? investigations.data[0] : undefined;
  useEffect(() => {
    if (id === undefined && only) navigate(links.dossier(only.investigation_id), { replace: true });
  }, [id, only]);

  if (investigations.state === "loading") return <PageSkeleton />;
  if (investigations.state === "error") return <ErrorState failure={investigations.error} onRetry={investigations.reload} />;
  if (id !== undefined) return <Viewer id={id} investigations={investigations.data} />;
  return (
    <>
      <PageHeader
        eyebrow="Attribution dossier"
        title="Attribution dossier"
        description="The written explanation of an investigation, generated by the backend from the stored records."
      />
      {investigations.data.length === 0 ? (
        <EmptyState title="No investigation to write a dossier for">
          <p>Run an investigation first; its dossier is rendered from what the run stores.</p>
        </EmptyState>
      ) : (
        <Picker investigations={investigations.data} />
      )}
    </>
  );
}
