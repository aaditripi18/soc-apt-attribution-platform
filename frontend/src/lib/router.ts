/**
 * A fragment router: `#/units/<id>/evidence?tier=core`.
 *
 * Fragments never reach the server, so the built frontend can be served by the
 * read-model API itself without any page path colliding with a JSON route, and
 * identifiers (which contain ":" and "/") are simply percent-encoded segments.
 */
import { useEffect, useState } from "react";

export interface Route {
  /** Decoded path segments after `#/`. */
  segments: string[];
  query: URLSearchParams;
}

export function parseHash(hash: string): Route {
  const raw = hash.replace(/^#\/?/, "");
  const cut = raw.indexOf("?");
  const path = cut === -1 ? raw : raw.slice(0, cut);
  const query = new URLSearchParams(cut === -1 ? "" : raw.slice(cut + 1));
  const segments = path
    .split("/")
    .filter((segment) => segment !== "")
    .map((segment) => {
      try {
        return decodeURIComponent(segment);
      } catch {
        return segment;
      }
    });
  return { segments, query };
}

export function href(segments: string[], query?: Record<string, string | undefined>): string {
  const path = segments.map(encodeURIComponent).join("/");
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query ?? {})) {
    if (value !== undefined && value !== "") params.set(key, value);
  }
  const suffix = params.toString();
  return `#/${path}${suffix ? `?${suffix}` : ""}`;
}

export function navigate(target: string, options: { replace?: boolean } = {}): void {
  if (options.replace) {
    window.history.replaceState(null, "", target);
    window.dispatchEvent(new HashChangeEvent("hashchange"));
  } else {
    window.location.hash = target;
  }
}

export function useRoute(): Route {
  const [route, setRoute] = useState(() => parseHash(window.location.hash));
  useEffect(() => {
    const onChange = () => setRoute(parseHash(window.location.hash));
    window.addEventListener("hashchange", onChange);
    return () => window.removeEventListener("hashchange", onChange);
  }, []);
  return route;
}

export const links = {
  home: () => href([]),
  investigations: () => href(["investigations"]),
  actors: (filters: Record<string, string | undefined> = {}) => href(["actors"], filters),
  actor: (id: string) => href(["actors", id]),
  investigation: (id: string, tab?: string) => href(tab ? ["investigations", id, tab] : ["investigations", id]),
  unit: (id: string, tab?: string) => href(tab ? ["units", id, tab] : ["units", id]),
  units: (filters: Record<string, string | undefined> = {}) => href(["units"], filters),
  upload: () => href(["upload"]),
  live: () => href(["live"]),
  coverage: () => href(["coverage"]),
  dossier: (id?: string) => href(id ? ["dossier", id] : ["dossier"]),
  about: () => href(["about"]),
};
