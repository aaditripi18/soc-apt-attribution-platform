import { useCallback, useEffect, useState } from "react";
import { Shell } from "./components/Layout";
import { Button, NotFoundState } from "./components/ui";
import { paths, useApi, type Investigation } from "./lib/api";
import { CrumbsContext, useCrumbs, type Crumb } from "./lib/crumbs";
import { shortId } from "./lib/format";
import { links, useRoute, type Route } from "./lib/router";
import { AboutPage } from "./pages/About";
import { ActorPage, ActorsPage } from "./pages/Actors";
import { CoveragePage } from "./pages/Coverage";
import { DashboardPage } from "./pages/Dashboard";
import { DossierPage } from "./pages/Dossier";
import { InvestigationDetailPage } from "./pages/InvestigationDetail";
import { InvestigationsPage } from "./pages/Investigations";
import { UnitPage } from "./pages/Unit";
import { UploadPage } from "./pages/Upload";
import { UnitsSearchPage } from "./pages/UnitsSearch";

function Titled({ crumbs, children }: { crumbs: Crumb[]; children: React.ReactNode }) {
  useCrumbs(crumbs);
  return <>{children}</>;
}

function InvestigationRoute({ id, tab }: { id: string; tab: string | undefined }) {
  const record = useApi<Investigation>(paths.investigation(id));
  useCrumbs([
    { label: "Investigations", href: links.investigations() },
    { label: record.state === "ready" ? record.data.source_id : shortId(id, 8) },
  ]);
  return <InvestigationDetailPage id={id} tab={tab} />;
}

function UnknownPage({ route }: { route: Route }) {
  useCrumbs([{ label: "Not found" }]);
  return (
    <NotFoundState title="No such page">
      <p className="font-mono text-code-md">#/{route.segments.join("/")}</p>
      <div>
        <Button href={links.home()} variant="primary">
          Go to Overview
        </Button>
      </div>
    </NotFoundState>
  );
}

function Page({ route }: { route: Route }) {
  const [head, second, third, ...rest] = route.segments;
  if (head === undefined) {
    return (
      <Titled crumbs={[{ label: "Overview" }]}>
        <DashboardPage />
      </Titled>
    );
  }
  if (head === "actors" && second === undefined) {
    return (
      <Titled crumbs={[{ label: "Threat Actors" }]}>
        <ActorsPage query={route.query} />
      </Titled>
    );
  }
  if (head === "actors" && second !== undefined && third === undefined) {
    return <ActorPage key={second} id={second} />;
  }
  if (head === "investigations" && second === undefined) {
    return (
      <Titled crumbs={[{ label: "Investigations" }]}>
        <InvestigationsPage />
      </Titled>
    );
  }
  if (head === "investigations" && second !== undefined && rest.length === 0) {
    return <InvestigationRoute key={second} id={second} tab={third} />;
  }
  if (head === "units" && second === undefined) {
    return (
      <Titled crumbs={[{ label: "Activity Search" }]}>
        <UnitsSearchPage query={route.query} />
      </Titled>
    );
  }
  if (head === "units" && second !== undefined && rest.length === 0) {
    return <UnitPage key={second} id={second} tab={third} query={route.query} />;
  }
  if (head === "upload" && second === undefined) {
    return (
      <Titled crumbs={[{ label: "Analyze Logs" }]}>
        <UploadPage />
      </Titled>
    );
  }
  if (head === "coverage" && second === undefined) {
    return (
      <Titled crumbs={[{ label: "Technique Coverage" }]}>
        <CoveragePage />
      </Titled>
    );
  }
  if (head === "dossier" && third === undefined) {
    return (
      <Titled crumbs={[{ label: "Reports" }]}>
        <DossierPage key={second ?? ""} id={second} />
      </Titled>
    );
  }
  if (head === "about" && second === undefined) {
    return (
      <Titled crumbs={[{ label: "Methodology" }]}>
        <AboutPage />
      </Titled>
    );
  }
  return <UnknownPage route={route} />;
}

export function App() {
  const route = useRoute();
  const [crumbs, setCrumbs] = useState<Crumb[]>([]);
  const set = useCallback((next: Crumb[]) => setCrumbs(next), []);
  const path = route.segments.join("/");

  useEffect(() => {
    // A new page or tab starts at the top; a query change (filters) keeps the scroll.
    const [head, id] = route.segments;
    window.scrollTo({ top: 0 });
    void head;
    void id;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [route.segments[0], route.segments[1], route.segments[2]]);

  useEffect(() => {
    const last = crumbs[crumbs.length - 1]?.label;
    document.title = last ? `${last} · APT Attribution` : "SOC APT Attribution Platform";
  }, [crumbs]);

  return (
    <CrumbsContext.Provider value={set}>
      <Shell route={route} crumbs={crumbs}>
        <div key={path === "" ? "root" : undefined}>
          <Page route={route} />
        </div>
      </Shell>
    </CrumbsContext.Provider>
  );
}
