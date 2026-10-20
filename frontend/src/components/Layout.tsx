import {
  Activity,
  BookOpenText,
  ChevronRight,
  CornerDownLeft,
  FileText,
  FolderSearch,
  BookOpen,
  LayoutDashboard,
  Menu,
  Users,
  Radar,
  Search,
  ShieldCheck,
  Target,
  UploadCloud,
} from "lucide-react";
import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import {
  SNAPSHOT,
  paths,
  useApi,
  type InvestigationSummary,
  type TechniqueCatalogue,
} from "../lib/api";
import { shortId } from "../lib/format";
import { links, navigate, type Route } from "../lib/router";
import { cx } from "./ui";

export interface Crumb {
  label: string;
  href?: string;
}

const NAV = [
  { key: "overview", label: "Overview", href: links.home(), icon: LayoutDashboard, group: "Operations" },
  { key: "investigations", label: "Investigations", href: links.investigations(), icon: FolderSearch, group: "Operations" },
  { key: "upload", label: "Analyze Logs", href: links.upload(), icon: UploadCloud, group: "Operations" },
  { key: "live", label: "Live Monitoring", href: links.live(), icon: Activity, group: "Operations" },
  { key: "units", label: "Activity Search", href: links.units(), icon: Target, group: "Operations" },
  { key: "actors", label: "Threat Actors", href: links.actors(), icon: Users, group: "Intelligence" },
  { key: "coverage", label: "Technique Coverage", href: links.coverage(), icon: Radar, group: "Intelligence" },
  { key: "dossier", label: "Reports", href: links.dossier(), icon: FileText, group: "Reporting" },
  { key: "about", label: "Methodology", href: links.about(), icon: BookOpen, group: "Reporting" },
] as const;

export type Section = (typeof NAV)[number]["key"];

export function sectionOf(route: Route): Section {
  const head = route.segments[0];
  // A unit workspace is reached from its investigation; only the search is "Units Search".
  if (head === "units") return route.segments.length > 1 ? "investigations" : "units";
  if (head === undefined) return "overview";
  if (head === "upload") return "upload";
  if (head === "live") return "live";
  if (head === "actors") return "actors";
  if (head === "coverage") return "coverage";
  if (head === "dossier") return "dossier";
  if (head === "about") return "about";
  return "investigations";
}

function Sidebar({ section, open }: { section: Section; open: boolean }) {
  const catalogue = useApi<TechniqueCatalogue>(paths.techniques());
  return (
    <aside
      className={cx(
        "no-print fixed inset-y-0 left-0 z-40 flex w-64 flex-col border-r border-outline-variant/70 bg-surface-lowest transition-transform lg:z-30 lg:translate-x-0",
        open ? "translate-x-0" : "-translate-x-full",
      )}
    >
      <a href={links.home()} className="flex h-14 items-center gap-2.5 border-b border-outline-variant/70 px-4">
        <span className="flex h-8 w-8 items-center justify-center rounded-md border border-primary/40 bg-primary/10 text-primary">
          <ShieldCheck size={17} strokeWidth={2} />
        </span>
        <span className="min-w-0">
          <span className="block truncate text-headline-sm text-on-surface">APT Attribution</span>
          <span className="label block truncate">Detection &amp; attribution</span>
        </span>
      </a>
      <nav aria-label="Primary" className="flex-1 space-y-0.5 overflow-y-auto p-2">
        {NAV.map((item, position) => {
          const active = item.key === section;
          const Icon = item.icon;
          const heading = position === 0 || NAV[position - 1]?.group !== item.group;
          return (
            <div key={item.key}>
              {heading && <div className="label px-3 pb-1 pt-3 first:pt-1">{item.group}</div>}
            <a
              href={item.href}
              aria-current={active ? "page" : undefined}
              className={cx(
                "flex h-9 items-center gap-2.5 rounded-sm border-l-2 px-3 text-body-md transition-colors",
                active
                  ? "border-primary bg-primary/10 text-primary"
                  : "border-transparent text-on-surface-variant hover:bg-surface-low hover:text-on-surface",
              )}
            >
              <Icon size={16} strokeWidth={1.8} className="shrink-0" />
              <span className="truncate">{item.label}</span>
            </a>
            </div>
          );
        })}
      </nav>
      <div className="border-t border-outline-variant/70 px-4 py-3 font-mono text-code-sm text-outline">
        MITRE {catalogue.state === "ready" ? catalogue.data.attack_kb_version.replace("enterprise-attack-", "ATT&CK v") : "ATT&CK"}
      </div>
    </aside>
  );
}

// ---------------------------------------------------------------------------
// Global search (Ctrl+K)
// ---------------------------------------------------------------------------

interface Hit {
  key: string;
  group: string;
  title: string;
  hint: string;
  href: string;
  icon: ReactNode;
}

const TECHNIQUE = /^T\d{4}(\.\d{3})?$/i;
const CANDIDATE = /^[GC]\d{4}$/i;

function useHits(text: string, open: boolean): Hit[] {
  const investigations = useApi<InvestigationSummary[]>(open ? paths.investigations() : null);
  const catalogue = useApi<TechniqueCatalogue>(open ? paths.techniques() : null);
  return useMemo(() => {
    const query = text.trim();
    const needle = query.toLowerCase();
    const hits: Hit[] = [];
    if (TECHNIQUE.test(query)) {
      const id = query.toUpperCase();
      hits.push({
        key: `t:${id}`,
        group: "Search units",
        title: `Units where ${id} was observed`,
        hint: "technique filter",
        href: links.units({ technique: id }),
        icon: <Target size={15} />,
      });
    } else if (CANDIDATE.test(query)) {
      const id = query.toUpperCase();
      hits.push({
        key: `c:${id}`,
        group: "Search units",
        title: `Units with ${id} among their candidates`,
        hint: "candidate filter",
        href: links.units({ candidate: id }),
        icon: <Target size={15} />,
      });
    }
    if (investigations.state === "ready") {
      for (const item of investigations.data) {
        if (
          needle === "" ||
          item.source_id.toLowerCase().includes(needle) ||
          item.investigation_id.toLowerCase().includes(needle)
        ) {
          hits.push({
            key: `i:${item.investigation_id}`,
            group: "Investigations",
            title: item.source_id,
            hint: shortId(item.investigation_id),
            href: links.investigation(item.investigation_id),
            icon: <FolderSearch size={15} />,
          });
        }
      }
    }
    if (catalogue.state === "ready" && needle.length >= 2) {
      const matches = catalogue.data.techniques
        .filter(
          (t) => t.attack_id.toLowerCase().startsWith(needle) || t.name.toLowerCase().includes(needle),
        )
        .slice(0, 8);
      for (const t of matches) {
        if (TECHNIQUE.test(query) && t.attack_id === query.toUpperCase()) continue;
        hits.push({
          key: `tn:${t.attack_id}`,
          group: "ATT&CK techniques — units where observed",
          title: `${t.attack_id}  ${t.name}`,
          hint: "technique filter",
          href: links.units({ technique: t.attack_id }),
          icon: <BookOpenText size={15} />,
        });
      }
    }
    if (query !== "" && !/\s/.test(query) && !TECHNIQUE.test(query) && !CANDIDATE.test(query)) {
      hits.push({
        key: `h:${needle}`,
        group: "Search units",
        title: `Units on host ${needle}`,
        hint: "exact host name",
        href: links.units({ host: needle }),
        icon: <Target size={15} />,
      });
    }
    return hits;
  }, [text, investigations.state, investigations.data, catalogue.state, catalogue.data]);
}

function Palette({ open, onClose }: { open: boolean; onClose: () => void }) {
  const [text, setText] = useState("");
  const [cursor, setCursor] = useState(0);
  const input = useRef<HTMLInputElement>(null);
  const list = useRef<HTMLDivElement>(null);
  const hits = useHits(text, open);

  useEffect(() => {
    if (open) {
      setText("");
      setCursor(0);
      window.setTimeout(() => input.current?.focus(), 0);
    }
  }, [open]);
  useEffect(() => setCursor(0), [text]);
  useEffect(() => {
    list.current?.querySelector(`[data-index="${cursor}"]`)?.scrollIntoView({ block: "nearest" });
  }, [cursor]);

  if (!open) return null;
  const go = (hit: Hit | undefined) => {
    if (!hit) return;
    navigate(hit.href);
    onClose();
  };
  let lastGroup = "";
  return (
    <div
      className="no-print fixed inset-0 z-50 flex items-start justify-center bg-background/80 px-4 pt-[12vh] backdrop-blur-sm"
      onMouseDown={onClose}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-label="Search"
        onMouseDown={(event) => event.stopPropagation()}
        className="w-full max-w-xl overflow-hidden rounded-md border border-outline-variant bg-surface-low shadow-2xl shadow-black/60"
      >
        <div className="flex items-center gap-3 border-b border-outline-variant px-4">
          <Search size={16} className="shrink-0 text-outline" />
          <input
            ref={input}
            autoFocus
            value={text}
            onChange={(event) => setText(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === "ArrowDown") {
                event.preventDefault();
                setCursor((c) => Math.min(c + 1, hits.length - 1));
              } else if (event.key === "ArrowUp") {
                event.preventDefault();
                setCursor((c) => Math.max(c - 1, 0));
              } else if (event.key === "Enter") {
                event.preventDefault();
                go(hits[cursor]);
              } else if (event.key === "Escape") {
                onClose();
              }
            }}
            placeholder="Technique id (T1003.001), Group id (G0016), host, recording…"
            spellCheck={false}
            className="h-12 w-full bg-transparent text-body-lg text-on-surface outline-none placeholder:text-outline"
          />
          <kbd className="rounded-sm border border-outline-variant px-1.5 py-0.5 text-code-sm text-outline">
            Esc
          </kbd>
        </div>
        <div ref={list} className="max-h-[50vh] overflow-y-auto py-1">
          {hits.length === 0 && (
            <p className="px-4 py-6 text-center text-body-md text-on-surface-variant">
              {text.trim() === "" ? "Type a technique id, a Group id, a host name or a recording name." : "Nothing matches."}
            </p>
          )}
          {hits.map((hit, index) => {
            const heading = hit.group !== lastGroup ? hit.group : null;
            lastGroup = hit.group;
            return (
              <div key={hit.key}>
                {heading && <div className="label px-4 pb-1 pt-3">{heading}</div>}
                <button
                  type="button"
                  data-index={index}
                  onMouseEnter={() => setCursor(index)}
                  onClick={() => go(hit)}
                  className={cx(
                    "flex w-full items-center gap-3 px-4 py-2 text-left",
                    index === cursor ? "bg-primary/10 text-primary" : "text-on-surface",
                  )}
                >
                  <span className="shrink-0 text-outline">{hit.icon}</span>
                  <span className="min-w-0 flex-1 truncate text-body-md">{hit.title}</span>
                  <span className="shrink-0 font-mono text-code-sm text-outline">{hit.hint}</span>
                  {index === cursor && <CornerDownLeft size={13} className="shrink-0" />}
                </button>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Shell
// ---------------------------------------------------------------------------

export function Shell({
  route,
  crumbs,
  children,
}: {
  route: Route;
  crumbs: Crumb[];
  children: ReactNode;
}) {
  const [searching, setSearching] = useState(false);
  const [menuOpen, setMenuOpen] = useState(false);
  const path = route.segments.join("/");
  useEffect(() => setMenuOpen(false), [path]);
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        setSearching((value) => !value);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  return (
    <div className="min-h-screen">
      <Sidebar section={sectionOf(route)} open={menuOpen} />
      {menuOpen && (
        <button
          type="button"
          aria-label="Close the menu"
          onClick={() => setMenuOpen(false)}
          className="no-print fixed inset-0 z-30 bg-background/60 lg:hidden"
        />
      )}
      <header className="no-print fixed left-0 right-0 top-0 z-20 flex h-14 items-center gap-3 border-b border-outline-variant/70 bg-background/90 px-3 backdrop-blur lg:left-64 lg:gap-4 lg:px-6">
        <button
          type="button"
          aria-label="Open the menu"
          aria-expanded={menuOpen}
          onClick={() => setMenuOpen(true)}
          className="flex h-8 w-8 shrink-0 items-center justify-center rounded-sm border border-outline-variant/70 text-on-surface-variant lg:hidden"
        >
          <Menu size={16} />
        </button>
        <nav aria-label="Breadcrumb" className="flex min-w-0 flex-1 items-center gap-1.5 text-body-md">
          {crumbs.map((crumb, index) => {
            const last = index === crumbs.length - 1;
            return (
              <span key={`${crumb.label}-${index}`} className="flex min-w-0 items-center gap-1.5">
                {index > 0 && <ChevronRight size={13} className="shrink-0 text-outline" />}
                {crumb.href && !last ? (
                  <a href={crumb.href} className="truncate text-on-surface-variant hover:text-primary">
                    {crumb.label}
                  </a>
                ) : (
                  <span
                    className={cx("truncate", last ? "text-on-surface" : "text-on-surface-variant")}
                    aria-current={last ? "page" : undefined}
                  >
                    {crumb.label}
                  </span>
                )}
              </span>
            );
          })}
        </nav>
        <button
          type="button"
          onClick={() => setSearching(true)}
          aria-label="Search units, techniques, recordings"
          className="flex h-8 shrink-0 items-center gap-2 rounded-sm border border-outline-variant/70 bg-surface-lowest px-2.5 text-body-md text-outline hover:border-outline md:w-72"
        >
          <Search size={14} />
          <span className="hidden flex-1 truncate text-left md:block">Search units, techniques, recordings…</span>
          <kbd className="hidden rounded-sm border border-outline-variant px-1 font-mono text-code-sm md:block">Ctrl K</kbd>
        </button>
      </header>
      <main className="print-root px-3 pb-16 pt-20 lg:ml-64 lg:px-6">
        {SNAPSHOT && (
          <div className="no-print mx-auto mb-4 max-w-[1500px] rounded-md border border-tertiary/40 bg-tertiary/5 px-4 py-2.5 text-body-sm text-on-surface-variant">
            <span className="font-semibold text-on-surface">Read-only snapshot.</span> These are six real
            investigations, exported unchanged from the platform's own API (public lab recordings: an APT29 and an
            APT3 emulation, credential-dumping tool runs). Uploading logs, live monitoring and the AI analyst run
            with the platform on your own machine —{" "}
            <a
              className="text-primary hover:underline"
              href="https://github.com/aaditripi18/soc-apt-attribution-platform"
              target="_blank"
              rel="noreferrer"
            >
              source and instructions on GitHub
            </a>
            .
          </div>
        )}
        <div className="mx-auto max-w-[1500px]">{children}</div>
      </main>
      <Palette open={searching} onClose={() => setSearching(false)} />
    </div>
  );
}
