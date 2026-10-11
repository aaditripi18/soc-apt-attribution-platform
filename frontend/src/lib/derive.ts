/**
 * View shaping only: joins and groupings of records the API already returned.
 *
 * Nothing here scores, ranks or estimates. Candidates are ordered by name
 * (never by a support value), counts are counts of stored facts, and the one
 * arithmetic this file does on attribution data is `n of m`.
 */
import type {
  AttackRef,
  AttributionAnalysis,
  BehavioralSequence,
  Candidate,
  Contribution,
  CoverageStatus,
  CoverageTechnique,
  Evidence,
  Hypothesis,
  Observation,
  RuleInfo,
  Technique,
  TechniqueCatalogue,
  UnitSummary,
} from "./api";
import { parseTime } from "./format";

// ---------------------------------------------------------------------------
// ATT&CK lookups
// ---------------------------------------------------------------------------

export interface TechniqueIndex {
  byStix: Map<string, Technique>;
  byAttackId: Map<string, Technique>;
  activeGroups: number;
  tacticName: Map<string, string>;
  tacticOrder: string[];
}

export function indexTechniques(catalogue: TechniqueCatalogue): TechniqueIndex {
  return {
    byStix: new Map(catalogue.techniques.map((t) => [t.stix_id, t])),
    byAttackId: new Map(catalogue.techniques.map((t) => [t.attack_id, t])),
    activeGroups: catalogue.active_groups,
    tacticName: new Map(catalogue.tactics.map((t) => [t.shortname, t.name])),
    tacticOrder: catalogue.tactics.map((t) => t.shortname),
  };
}

/** `sigma:<uuid>:000` / `elastic:<uuid>:<profile>:000` -> `<origin>:<uuid>`. */
export function ruleKey(method: string): string {
  return method.split(":").slice(0, 2).join(":");
}

export function ruleOf(evidence: Evidence, rules: Record<string, RuleInfo>): RuleInfo | null {
  return rules[ruleKey(evidence.provenance.method)] ?? null;
}

/** Evidence mapped to a technique (not unmapped, and not a Group reference — ADR-0018). */
export function isTechniqueEvidence(evidence: Evidence): evidence is Evidence & { attack_ref: AttackRef } {
  return evidence.attack_ref?.object_type === "attack-pattern";
}

/** Actor-specific Evidence: its rule is specific to one Group (ADR-0018). */
export const isActorEvidence = (evidence: Evidence): boolean =>
  evidence.attack_ref?.object_type === "intrusion-set";

/** Low-quality Evidence is context: it joins a unit but adds no attribution feature. */
export const isContextEvidence = (evidence: Evidence): boolean => evidence.quality === "low";

// ---------------------------------------------------------------------------
// Techniques of a unit
// ---------------------------------------------------------------------------

export interface UnitTechnique {
  stixId: string;
  attackId: string;
  name: string;
  tactics: string[];
  /**
   * - `feature`: core Evidence, and at least one ATT&CK Group or Campaign is recorded
   *   using it — a decision feature of the comparison.
   * - `unmatched`: core Evidence, but no active Group or Campaign is recorded using the
   *   technique itself, so it places no candidate and is not a decision feature.
   * - `context`: seen only in low-level Evidence.
   */
  role: "feature" | "unmatched" | "context";
  evidence: Evidence[];
  groupsUsing: number | null;
  /** g = share of active Groups using it; D = 1 - g. Null without a catalogue entry. */
  g: number | null;
  d: number | null;
}

export function unitTechniques(
  analysis: AttributionAnalysis,
  evidence: Evidence[],
  index: TechniqueIndex,
): UnitTechnique[] {
  const features = new Set(analysis.observed_feature_technique_ids);
  const byStix = new Map<string, Evidence[]>();
  for (const item of evidence) {
    if (!isTechniqueEvidence(item)) continue;
    const list = byStix.get(item.attack_ref.stix_id) ?? [];
    list.push(item);
    byStix.set(item.attack_ref.stix_id, list);
  }
  for (const stixId of features) if (!byStix.has(stixId)) byStix.set(stixId, []);
  const rows = [...byStix.entries()].map(([stixId, items]): UnitTechnique => {
    const known = index.byStix.get(stixId);
    const attackId = known?.attack_id ?? items[0]?.attack_ref?.external_id ?? stixId;
    const g = known && index.activeGroups > 0 ? known.groups_using / index.activeGroups : null;
    return {
      stixId,
      attackId,
      name: known?.name ?? "",
      tactics: known?.tactics ?? [],
      role: features.has(stixId)
        ? "feature"
        : items.some((item) => !isContextEvidence(item))
          ? "unmatched"
          : "context",
      evidence: items,
      groupsUsing: known?.groups_using ?? null,
      g,
      d: g === null ? null : 1 - g,
    };
  });
  return rows.sort((a, b) => a.attackId.localeCompare(b.attackId));
}

// ---------------------------------------------------------------------------
// Candidates — alphabetical, never by support
// ---------------------------------------------------------------------------

export interface CandidateRow {
  candidate: Candidate;
  hypothesis: Hypothesis | null;
  /** Observed feature STIX ids this candidate's ATT&CK profile includes. */
  uses: Set<string>;
  /** Contribution per single-feature id, where the analysis recorded one. */
  contributionByFeature: Map<string, Contribution>;
}

export function candidateRows(analysis: AttributionAnalysis): CandidateRow[] {
  const observed = new Set(analysis.observed_feature_technique_ids);
  const hypotheses = new Map(analysis.hypotheses.map((h) => [h.candidate_id, h]));
  const rows = analysis.candidates.map((candidate): CandidateRow => {
    const hypothesis = hypotheses.get(candidate.candidate_id) ?? null;
    const uses = new Set(candidate.generation_basis.filter((id) => observed.has(id)));
    const contributionByFeature = new Map<string, Contribution>();
    for (const contribution of hypothesis?.contributions ?? []) {
      for (const id of contribution.feature_technique_ids) {
        if (observed.has(id)) uses.add(id);
      }
      const [only] = contribution.feature_technique_ids;
      if (contribution.feature_technique_ids.length === 1 && only !== undefined) {
        contributionByFeature.set(only, contribution);
      }
    }
    return { candidate, hypothesis, uses, contributionByFeature };
  });
  return rows.sort(
    (a, b) =>
      a.candidate.name.toLowerCase().localeCompare(b.candidate.name.toLowerCase()) ||
      a.candidate.candidate_id.localeCompare(b.candidate.candidate_id),
  );
}

// ---------------------------------------------------------------------------
// Sequence layout: a layered drawing of the stored DAG
// ---------------------------------------------------------------------------

export interface PlacedStep {
  stepId: string;
  layer: number;
  row: number;
}

export interface SequenceLayout {
  steps: PlacedStep[];
  layers: number;
  rows: number;
}

/**
 * Longest-path layering over the stored edges (a step sits one layer after its
 * latest predecessor); within a layer, steps keep the order `rank` gives
 * (observation time). Steps no edge reaches stay in layer 0. The stored edges
 * are a DAG; a cycle would be a backend defect, so any step left unplaced by
 * the topological pass is put in layer 0 rather than dropped.
 */
export function layoutSequence(
  sequence: BehavioralSequence,
  rank: (stepId: string) => number,
): SequenceLayout {
  const ids = sequence.steps.map((s) => s.step_id);
  const known = new Set(ids);
  const incoming = new Map<string, number>(ids.map((id) => [id, 0]));
  const next = new Map<string, string[]>();
  for (const edge of sequence.edges) {
    if (!known.has(edge.from_step_id) || !known.has(edge.to_step_id)) continue;
    incoming.set(edge.to_step_id, (incoming.get(edge.to_step_id) ?? 0) + 1);
    next.set(edge.from_step_id, [...(next.get(edge.from_step_id) ?? []), edge.to_step_id]);
  }
  const layer = new Map<string, number>();
  const queue = ids.filter((id) => (incoming.get(id) ?? 0) === 0);
  for (const id of queue) layer.set(id, 0);
  for (let head = 0; head < queue.length; head += 1) {
    const id = queue[head] as string;
    for (const target of next.get(id) ?? []) {
      layer.set(target, Math.max(layer.get(target) ?? 0, (layer.get(id) ?? 0) + 1));
      const left = (incoming.get(target) ?? 0) - 1;
      incoming.set(target, left);
      if (left === 0) queue.push(target);
    }
  }
  const byLayer = new Map<number, string[]>();
  for (const id of ids) {
    const l = layer.get(id) ?? 0;
    byLayer.set(l, [...(byLayer.get(l) ?? []), id]);
  }
  const steps: PlacedStep[] = [];
  let rows = 0;
  for (const [l, members] of byLayer) {
    members.sort((a, b) => rank(a) - rank(b) || a.localeCompare(b));
    members.forEach((stepId, row) => steps.push({ stepId, layer: l, row }));
    rows = Math.max(rows, members.length);
  }
  return { steps, layers: byLayer.size === 0 ? 0 : Math.max(...byLayer.keys()) + 1, rows };
}

// ---------------------------------------------------------------------------
// Investigation timeline: one lane per host
// ---------------------------------------------------------------------------

export interface TimelineLane {
  host: string;
  units: UnitSummary[];
}

export interface Timeline {
  start: number;
  end: number;
  lanes: TimelineLane[];
}

export function buildTimeline(units: UnitSummary[]): Timeline | null {
  const times = units
    .flatMap((u) => [parseTime(u.first_seen)?.getTime(), parseTime(u.last_seen)?.getTime()])
    .filter((t): t is number => t !== undefined);
  if (times.length === 0) return null;
  const lanes = new Map<string, UnitSummary[]>();
  for (const unit of units) {
    for (const host of unit.host_names.length > 0 ? unit.host_names : ["(no host)"]) {
      lanes.set(host, [...(lanes.get(host) ?? []), unit]);
    }
  }
  return {
    start: Math.min(...times),
    end: Math.max(...times),
    lanes: [...lanes.entries()]
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([host, laneUnits]) => ({ host, units: laneUnits })),
  };
}

// ---------------------------------------------------------------------------
// Observations
// ---------------------------------------------------------------------------

/** One factual line about what an Observation recorded (as the dossier does). */
export function describeObservation(observation: Observation | undefined): string {
  if (!observation) return "—";
  const process = observation.process;
  if (process?.command_line) return process.command_line;
  if (process?.executable) return process.executable;
  if (observation.event?.action) return observation.event.action;
  return observation.raw_reference?.source_type ?? observation.observation_id;
}

const HIDDEN_FACETS = new Set(["observation_id", "schema_version", "timestamp", "timestamp_precision"]);

function isEmpty(value: unknown): boolean {
  if (value === null || value === undefined || value === "") return true;
  if (Array.isArray(value)) return value.length === 0;
  if (typeof value === "object") return Object.values(value as object).every(isEmpty);
  return false;
}

/** The facets of an Observation that actually hold a value, flattened to rows. */
export function observationFacets(
  observation: Observation,
): { facet: string; rows: { field: string; value: string }[] }[] {
  const facets: { facet: string; rows: { field: string; value: string }[] }[] = [];
  for (const [facet, value] of Object.entries(observation)) {
    if (HIDDEN_FACETS.has(facet) || isEmpty(value)) continue;
    const rows: { field: string; value: string }[] = [];
    const walk = (prefix: string, node: unknown) => {
      if (isEmpty(node)) return;
      if (Array.isArray(node)) {
        if (node.every((item) => typeof item !== "object" || item === null)) {
          rows.push({ field: prefix, value: node.join(", ") });
        } else {
          node.forEach((item, i) => walk(`${prefix}[${i}]`, item));
        }
      } else if (typeof node === "object" && node !== null) {
        for (const [key, inner] of Object.entries(node)) {
          walk(prefix ? `${prefix}.${key}` : key, inner);
        }
      } else {
        rows.push({ field: prefix, value: String(node) });
      }
    };
    walk("", value);
    if (typeof value !== "object" || value === null) {
      facets.push({ facet, rows: [{ field: facet, value: String(value) }] });
    } else if (rows.length > 0) {
      facets.push({ facet, rows });
    }
  }
  return facets.sort((a, b) => a.facet.localeCompare(b.facet));
}

// ---------------------------------------------------------------------------
// Coverage
// ---------------------------------------------------------------------------

export const COVERAGE_STATUSES: CoverageStatus[] = [
  "covered",
  "telemetry_gap",
  "translation_gap",
  "no_sigma_rule",
  "not_observable_on_supported_platforms",
];

export const COVERAGE_LABEL: Record<CoverageStatus, string> = {
  covered: "Covered",
  telemetry_gap: "Telemetry gap",
  translation_gap: "Translation gap",
  no_sigma_rule: "No rule in the pinned content",
  not_observable_on_supported_platforms: "Not observable on supported platforms",
};

export const COVERAGE_MEANING: Record<CoverageStatus, string> = {
  covered: "At least one imported rule can fire on telemetry this platform ingests.",
  telemetry_gap: "Rules exist, but every one needs a log source or field not ingested yet.",
  translation_gap: "Rules exist, but use a construct the rule engine does not translate.",
  no_sigma_rule: "Observable on a supported platform, but no pinned rule maps to it.",
  not_observable_on_supported_platforms:
    "ATT&CK lists no supported platform or data component for it (e.g. pre-compromise).",
};

export interface TacticCoverage {
  tactic: string;
  name: string;
  total: number;
  byStatus: Record<CoverageStatus, number>;
}

/** Coverage rows grouped by ATT&CK tactic, in matrix order. */
export function coverageByTactic(rows: CoverageTechnique[], index: TechniqueIndex): TacticCoverage[] {
  const zero = (): Record<CoverageStatus, number> => ({
    covered: 0,
    telemetry_gap: 0,
    translation_gap: 0,
    no_sigma_rule: 0,
    not_observable_on_supported_platforms: 0,
  });
  const tally = new Map<string, TacticCoverage>(
    index.tacticOrder.map((tactic) => [
      tactic,
      { tactic, name: index.tacticName.get(tactic) ?? tactic, total: 0, byStatus: zero() },
    ]),
  );
  for (const row of rows) {
    for (const tactic of index.byAttackId.get(row.attack_id)?.tactics ?? []) {
      const entry = tally.get(tactic);
      if (!entry) continue;
      entry.total += 1;
      entry.byStatus[row.status] += 1;
    }
  }
  return [...tally.values()].filter((entry) => entry.total > 0);
}
