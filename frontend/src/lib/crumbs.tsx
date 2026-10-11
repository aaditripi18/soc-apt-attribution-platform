import { createContext, useContext, useEffect } from "react";

export interface Crumb {
  label: string;
  href?: string;
}

export const CrumbsContext = createContext<(crumbs: Crumb[]) => void>(() => undefined);

/** Set the top-bar breadcrumb from a page; `key` changes when the trail does. */
export function useCrumbs(crumbs: Crumb[]): void {
  const set = useContext(CrumbsContext);
  const key = crumbs.map((c) => `${c.label}|${c.href ?? ""}`).join(">");
  useEffect(() => {
    set(crumbs);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key, set]);
}
