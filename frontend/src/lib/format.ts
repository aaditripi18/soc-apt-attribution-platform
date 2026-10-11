/** Display helpers. All times are shown in UTC, as the backend records them. */

const pad = (n: number, width = 2) => String(n).padStart(width, "0");

export function parseTime(value: string | null | undefined): Date | null {
  if (!value) return null;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
}

export function utcDate(value: string | null | undefined): string {
  const d = parseTime(value);
  if (!d) return "—";
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}`;
}

export function utcClock(value: string | null | undefined, millis = false): string {
  const d = parseTime(value);
  if (!d) return "—";
  const base = `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}`;
  return millis ? `${base}.${pad(d.getUTCMilliseconds(), 3)}` : base;
}

export function utcDateTime(value: string | null | undefined, millis = false): string {
  return parseTime(value) ? `${utcDate(value)} ${utcClock(value, millis)}Z` : "—";
}

export function duration(start: string | null | undefined, end: string | null | undefined): string {
  const a = parseTime(start);
  const b = parseTime(end);
  if (!a || !b) return "—";
  return durationMs(b.getTime() - a.getTime());
}

export function durationMs(ms: number): string {
  if (ms < 0) return "—";
  if (ms < 1000) return `${ms} ms`;
  const seconds = ms / 1000;
  if (seconds < 60) return `${seconds < 10 ? seconds.toFixed(1) : Math.round(seconds)} s`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes} min ${pad(Math.floor(seconds % 60))} s`;
  const hours = Math.floor(minutes / 60);
  if (hours < 48) return `${hours} h ${pad(minutes % 60)} min`;
  return `${Math.floor(hours / 24)} d ${hours % 24} h`;
}

export const integer = (n: number): string => n.toLocaleString("en-US");

/** A ratio in [0, 1] to three decimals, as the dossier prints g and D. */
export const ratio = (n: number | null | undefined): string =>
  n === null || n === undefined ? "—" : n.toFixed(3);

/** `prefix::<64 hex>` -> `prefix::0123abcd…` for display; the full id stays copyable. */
export function shortId(id: string, keep = 10): string {
  const cut = id.lastIndexOf("::");
  if (cut === -1) return id.length > keep * 2 + 1 ? `${id.slice(0, keep)}…${id.slice(-6)}` : id;
  const head = id.slice(0, cut + 2);
  const tail = id.slice(cut + 2);
  return tail.length > keep + 1 ? `${head}${tail.slice(0, keep)}…` : id;
}

export function shortHash(hash: string | null | undefined, keep = 12): string {
  if (!hash) return "—";
  return hash.length > keep + 1 ? `${hash.slice(0, keep)}…` : hash;
}

export function plural(count: number, one: string, many = `${one}s`): string {
  return `${integer(count)} ${count === 1 ? one : many}`;
}

/** https://attack.mitre.org page of a technique, Group or Campaign id. */
export function attackUrl(id: string): string | null {
  if (/^T\d{4}(\.\d{3})?$/.test(id)) return `https://attack.mitre.org/techniques/${id.replace(".", "/")}/`;
  if (/^G\d{4}$/.test(id)) return `https://attack.mitre.org/groups/${id}/`;
  if (/^C\d{4}$/.test(id)) return `https://attack.mitre.org/campaigns/${id}/`;
  if (/^TA\d{4}$/.test(id)) return `https://attack.mitre.org/tactics/${id}/`;
  return null;
}

export function titleCase(value: string): string {
  return value
    .replace(/[_-]+/g, " ")
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
}
