/**
 * Typed client for the read-model API (ADR-0009, ADR-0016).
 *
 * The frontend computes nothing the backend did not: every type below mirrors
 * a record the API serves, and nothing here invents a field. There is no
 * likelihood, confidence or rank type because the API has none to give.
 */
import { useCallback, useEffect, useRef, useState } from "react";

const BASE = "/api";

// ---------------------------------------------------------------------------
// Records
// ---------------------------------------------------------------------------

export interface Health {
  status: string;
  backend: "reachable" | "unreachable";
  api: string;
}

export interface InvestigationSummary {
  investigation_id: string;
  source_id: string;
  source_kind: string;
  attack_kb_version: string;
  evidence: number;
  evidence_in_units: number;
  units: number;
}

export interface Investigation {
  investigation_id: string;
  source_id: string;
  source_kind: string;
  source_sha256: string;
  attack_kb_version: string;
  detection_pack_content_hash: string;
  method_versions: Record<string, string>;
  observations_persisted: number;
  evidence: number;
  /** Evidence that is a member of some unit. */
  evidence_in_units: number;
  /** Low-level Evidence with no structural link to core Evidence: in no unit. */
  evidence_outside_units: number;
  units: string[];
  schema_version: string;
}

export interface UnitSummary {
  group_id: string;
  investigation_id: string;
  host_names: string[];
  first_seen: string;
  last_seen: string;
  /** Observed ATT&CK ids and their parent techniques. */
  technique_ids: string[];
  /** ATT&CK Group / Campaign ids (G####, C####). */
  candidate_ids: string[];
  evidence: number;
  steps: number;
  schema_version: string;
}

export interface UnitSearch {
  filters: Record<string, string>;
  limit: number;
  truncated: boolean;
  units: UnitSummary[];
}

export interface CorrelationProvenance {
  method?: string;
  method_version?: string;
  [key: string]: unknown;
}

export interface CorrelationGroup {
  group_id: string;
  member_evidence_ids: string[];
  member_observation_ids: string[];
  structural_link_ids: string[];
  contextual_link_ids: string[];
  provenance: CorrelationProvenance;
  schema_version: string;
}

export interface BehavioralStep {
  step_id: string;
  group_id: string;
  evidence_ids: string[];
  observation_id: string;
  technique_stix_ids: string[];
  evidence_types: string[];
  contextual_annotations: string[];
}

export interface SequenceEdge {
  edge_id: string;
  from_step_id: string;
  to_step_id: string;
  basis: {
    basis_kind: "process_lineage" | "temporal_same_entity" | string;
    grounding_link_id: string;
    timestamp_agreement: boolean | null;
    precision_uncertain: boolean;
  };
}

export interface SequenceGap {
  gap_id: string;
  step_id_a: string;
  step_id_b: string;
  grounding_link_id: string;
  reason: string;
}

export interface BehavioralSequence {
  sequence_id: string;
  group_id: string;
  steps: BehavioralStep[];
  edges: SequenceEdge[];
  gaps: SequenceGap[];
  parallel_groups: unknown[];
  provenance: CorrelationProvenance;
  schema_version: string;
}

export interface Contribution {
  feature_technique_ids: string[];
  diagnosticity_outcome: string;
  g_value: number | null;
  d_value: number | null;
  contribution_value: number;
  assessment_ids: string[];
}

export interface Candidate {
  candidate_id: string;
  kind: "group" | "campaign" | string;
  stix_id: string;
  name: string;
  attack_external_id: string | null;
  generation_basis: string[];
}

export interface Hypothesis {
  hypothesis_id: string;
  candidate_id: string;
  support_value: number;
  profile_breadth: number | null;
  contributions: Contribution[];
}

export interface CollectionQuestion {
  technique_id: string;
  technique_stix_id: string;
  technique_name: string;
  candidates_using: string[];
  candidates_total: number;
  split: number;
  data_components: string[];
  platform_detection_status: string | null;
  platform_logsources: string[];
  platform_blocked_by: string[];
  rationale: string;
}

export interface CollectionGuidance {
  method_version: string;
  candidates_total: number;
  questions_considered: number;
  questions: CollectionQuestion[];
}

export interface IndicatorMatch {
  indicator_id: string;
  indicator_name: string;
  kind: string;
  value: string;
  observation_id: string;
  observed_at: string;
  within_validity: boolean | null;
  bundle_file: string;
  report_name: string | null;
  named_actor: string | null;
  named_actor_attack_id: string | null;
  attribution_quote: string | null;
}

export interface AttributionAnalysis {
  group_id: string;
  sequence_id: string;
  investigation_id: string;
  attack_kb_version: string;
  min_profile_floor: number;
  /** STIX ids of the observed decision features (core evidence only). */
  observed_feature_technique_ids: string[];
  /** Null when the comparison was not computed for this unit. */
  unattributed_decision_support: number | null;
  candidates: Candidate[];
  hypotheses: Hypothesis[];
  collection_guidance: CollectionGuidance | null;
  indicator_matches: IndicatorMatch[];
  /** "not_computed": the exact search stopped at its work bound (never approximated). */
  comparison_status: "computed" | "not_computed";
  comparison_note: string | null;
  calibration_status: string;
  calibration_version: string | null;
  calibration_note: string;
  schema_version: string;
}

export interface Unit {
  group: CorrelationGroup;
  sequence: BehavioralSequence;
  attribution_analysis: AttributionAnalysis;
}

export interface AttackRef {
  stix_id: string;
  object_type: string;
  external_id: string | null;
  attack_kb_version: string;
}

export interface Evidence {
  evidence_id: string;
  evidence_type: string;
  claim: string;
  attack_ref: AttackRef | null;
  quality: string | null;
  time_span: { start: string; end: string } | null;
  provenance: {
    method: string;
    method_version: string;
    method_content_hash: string | null;
    source_observation_ids: string[];
    derived_at: string | null;
  };
  schema_version: string;
}

/** An Observation: ECS-aligned facets, most of them null for any one event. */
export interface Observation {
  observation_id: string;
  timestamp: string;
  timestamp_precision: string | null;
  event: {
    action: string | null;
    category: string[];
    type: string[];
    code: string | null;
    dataset: string | null;
    kind: string | null;
    outcome: string | null;
    provider: string | null;
  } | null;
  host: { id: string | null; name: string | null; os_type: string | null; ip: string[] } | null;
  user: { id: string | null; name: string | null; domain: string | null } | null;
  process: {
    executable: string | null;
    command_line: string | null;
    name: string | null;
    pid: number | null;
    parent_executable: string | null;
    parent_command_line: string | null;
    parent_name: string | null;
    parent_pid: number | null;
    [key: string]: unknown;
  } | null;
  raw_reference: {
    source_type: string | null;
    source_event_id: string | null;
    dataset_ref: string | null;
    raw_payload_ref: string | null;
  } | null;
  [facet: string]: unknown;
}

export interface RuleInfo {
  origin: "sigma" | "elastic";
  source_id: string;
  title: string | null;
  url: string | null;
  content_tier: "core" | "enrich" | string;
  logsources: string[];
  translation: "imported" | "partial" | string;
}

export interface UnitEvidence {
  group_id: string;
  evidence: Evidence[];
  observations: Record<string, Observation>;
  rules: Record<string, RuleInfo>;
}

export interface Dossier {
  investigation_id: string;
  dossier_version: string;
  markdown: string;
}

export interface Tactic {
  shortname: string;
  name: string;
  attack_id: string | null;
}

export interface Technique {
  attack_id: string;
  stix_id: string;
  name: string;
  is_subtechnique: boolean;
  tactics: string[];
  platforms: string[];
  groups_using: number;
}

export interface TechniqueCatalogue {
  attack_kb_version: string;
  active_groups: number;
  tactics: Tactic[];
  techniques: Technique[];
}

export type CoverageStatus =
  | "covered"
  | "telemetry_gap"
  | "translation_gap"
  | "not_observable_on_supported_platforms"
  | "no_sigma_rule";

export interface CoverageTechnique {
  attack_id: string;
  name: string;
  status: CoverageStatus;
  rule_sources: number;
  rule_sources_by_origin: Record<string, number>;
  rejected_rules_blocked_by: string[];
  supported_platforms: string[];
  has_data_component: boolean;
}

export interface ImportSummary {
  by_status: { imported: number; partial: number; rejected: number };
  rejected_by_reason: Record<string, number>;
  generated_rules: number;
  attack_ids_with_imported_rule: number;
  sigma_rules_total?: number;
  elastic_rules_total?: number;
}

export interface ContentSource {
  summary: ImportSummary;
  top_rejection_reasons: { reason: string; rules: number }[];
}

export interface Coverage {
  report_version: string;
  notes: unknown;
  provenance: {
    attack_kb_version: string;
    attack_kb_sha256: string;
    rule_packs: { pack_id: string; content_hash: string }[];
    sigma_import: Record<string, unknown>;
    elastic_import: Record<string, unknown>;
  };
  summary: {
    active_techniques: number;
    group_used_techniques: number;
    active_groups: number;
    techniques_by_status: Record<CoverageStatus, number>;
    group_used_techniques_by_status: Record<CoverageStatus, number>;
    covered_techniques_by_origin: Record<string, number>;
    covered_techniques_by_origin_only: Record<string, number>;
    groups_with_empty_technique_profile: number;
    groups_with_zero_covered: number;
    groups_with_at_least_2_covered: number;
    groups_with_at_least_5_covered: number;
    groups_with_at_least_10_covered: number;
  };
  content: { sigma: ContentSource; elastic: ContentSource };
  logsources: { logsource: string; product: string; sigma_rules: number; elastic_rules: number }[];
  gap_ranking: {
    blocker: string;
    supported_product: boolean;
    techniques_upper_bound: number;
    group_used_techniques_upper_bound: number;
    groups_touched_upper_bound: number;
  }[];
  groups: {
    attack_id: string;
    name: string;
    profile_techniques: number;
    covered: number;
    by_status: Record<CoverageStatus, number>;
  }[];
  techniques: CoverageTechnique[];
}

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

export type ApiFailureKind = "unreachable" | "not_found" | "bad_request" | "backend" | "server";

export class ApiFailure extends Error {
  readonly kind: ApiFailureKind;
  readonly status: number | null;
  readonly path: string;

  constructor(kind: ApiFailureKind, message: string, path: string, status: number | null) {
    super(message);
    this.kind = kind;
    this.status = status;
    this.path = path;
  }
}

function kindOf(status: number): ApiFailureKind {
  if (status === 404) return "not_found";
  if (status === 400) return "bad_request";
  if (status === 502) return "backend";
  return "server";
}

export async function request<T>(path: string, signal?: AbortSignal): Promise<T> {
  let response: Response;
  try {
    response = await fetch(BASE + path, { headers: { Accept: "application/json" }, signal });
  } catch (cause) {
    if (cause instanceof DOMException && cause.name === "AbortError") throw cause;
    throw new ApiFailure("unreachable", "The read-model API did not answer.", path, null);
  }
  const text = await response.text();
  let body: unknown = null;
  try {
    body = text ? JSON.parse(text) : null;
  } catch {
    // A non-JSON answer means something other than the API is on this address
    // (a dev server with no backend behind its proxy, for instance).
    throw new ApiFailure(
      "unreachable",
      `The read-model API did not answer (HTTP ${response.status}, not JSON).`,
      path,
      response.status,
    );
  }
  if (!response.ok && body === null && response.status >= 500) {
    // The dev proxy answers an empty 5xx itself when no backend is listening.
    throw new ApiFailure("unreachable", `The read-model API did not answer (HTTP ${response.status}).`, path, response.status);
  }
  if (!response.ok) {
    const message =
      body && typeof body === "object" && "error" in body
        ? String((body as { error: unknown }).error)
        : `HTTP ${response.status}`;
    throw new ApiFailure(kindOf(response.status), message, path, response.status);
  }
  return body as T;
}

export const paths = {
  health: () => "/health",
  investigations: () => "/investigations",
  investigation: (id: string) => `/investigations/${encodeURIComponent(id)}`,
  investigationUnits: (id: string) => `/investigations/${encodeURIComponent(id)}/units?limit=1000`,
  dossier: (id: string) => `/investigations/${encodeURIComponent(id)}/dossier`,
  unit: (id: string) => `/units/${encodeURIComponent(id)}`,
  unitEvidence: (id: string) => `/units/${encodeURIComponent(id)}/evidence`,
  units: (filters: Record<string, string>) => {
    const query = new URLSearchParams(
      Object.entries(filters).filter(([, value]) => value.trim() !== ""),
    ).toString();
    return query ? `/units?${query}` : "/units";
  },
  coverage: () => "/coverage",
  techniques: () => "/attack/techniques",
};

// ---------------------------------------------------------------------------
// Hook: one cached read per path
// ---------------------------------------------------------------------------

const cache = new Map<string, Promise<unknown>>();

function load<T>(path: string): Promise<T> {
  let pending = cache.get(path) as Promise<T> | undefined;
  if (!pending) {
    pending = request<T>(path);
    cache.set(path, pending);
    pending.catch(() => cache.delete(path)); // a failure is never cached
  }
  return pending;
}

export function invalidate(prefix = ""): void {
  for (const key of [...cache.keys()]) if (key.startsWith(prefix)) cache.delete(key);
}

export type Loadable<T> =
  | { state: "loading"; data: null; error: null }
  | { state: "ready"; data: T; error: null }
  | { state: "error"; data: null; error: ApiFailure };

export type Resource<T> = Loadable<T> & { reload: () => void };

const LOADING = { state: "loading", data: null, error: null } as const;

/** Read `path` once (shared between components); `null` skips the read. */
export function useApi<T>(path: string | null): Resource<T> {
  const [result, setResult] = useState<Loadable<T> & { path: string | null }>({
    ...LOADING,
    path,
  });
  const [attempt, setAttempt] = useState(0);
  const live = useRef(true);

  useEffect(() => {
    live.current = true;
    return () => {
      live.current = false;
    };
  }, []);

  useEffect(() => {
    if (path === null) return;
    let current = true;
    setResult({ ...LOADING, path });
    load<T>(path).then(
      (data) => current && live.current && setResult({ state: "ready", data, error: null, path }),
      (error: unknown) => {
        if (!current || !live.current) return;
        const failure =
          error instanceof ApiFailure
            ? error
            : new ApiFailure("server", String(error), path, null);
        setResult({ state: "error", data: null, error: failure, path });
      },
    );
    return () => {
      current = false;
    };
  }, [path, attempt]);

  const reload = useCallback(() => {
    if (path !== null) cache.delete(path);
    setAttempt((n) => n + 1);
  }, [path]);

  // A path change shows "loading" at once, never the previous path's data.
  const visible: Loadable<T> = result.path === path ? result : LOADING;
  return { ...visible, reload } as Resource<T>;
}

/** Backend health, re-checked on an interval and never cached. */
export function useHealth(intervalMs = 15000): {
  health: Health | null;
  failure: ApiFailure | null;
  checkedAt: Date | null;
  recheck: () => void;
} {
  const [health, setHealth] = useState<Health | null>(null);
  const [failure, setFailure] = useState<ApiFailure | null>(null);
  const [checkedAt, setCheckedAt] = useState<Date | null>(null);
  const [tick, setTick] = useState(0);

  useEffect(() => {
    let current = true;
    const check = () =>
      request<Health>(paths.health()).then(
        (value) => {
          if (!current) return;
          setHealth(value);
          setFailure(null);
          setCheckedAt(new Date());
        },
        (error: unknown) => {
          if (!current) return;
          setHealth(null);
          setFailure(
            error instanceof ApiFailure
              ? error
              : new ApiFailure("server", String(error), paths.health(), null),
          );
          setCheckedAt(new Date());
        },
      );
    void check();
    const timer = window.setInterval(check, intervalMs);
    return () => {
      current = false;
      window.clearInterval(timer);
    };
  }, [intervalMs, tick]);

  return { health, failure, checkedAt, recheck: () => setTick((n) => n + 1) };
}
