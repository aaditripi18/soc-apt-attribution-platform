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

export interface ActorEvidence {
  actor_stix_id: string;
  actor_attack_id: string | null;
  actor_name: string;
  evidence_id: string;
  rule_id: string;
  claim: string;
  observation_id: string;
  observed_at: string | null;
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
  /** ADR-0018: Evidence whose rule is specific to one Group. A lead, never a comparison input. */
  actor_specific_evidence: ActorEvidence[];
  /**
   * The exact search stops at a work bound instead of approximating.
   * "baseline_not_computed": per-candidate quantities exist, the Unattributed baseline does not.
   * "not_computed": neither exists.
   */
  comparison_status: "computed" | "baseline_not_computed" | "not_computed";
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
  /** "actor": a rule specific to one Group (ADR-0018). */
  content_tier: "core" | "enrich" | "actor" | string;
  logsources: string[];
  translation: "imported" | "partial" | string;
  actor_tags?: ActorTag[];
}

export interface ActorTag {
  tag: string;
  decision: "accept" | "reject";
  reason: string;
  group_id: string | null;
  group_name: string | null;
  /** How the rule was associated with the Group (ADR-0018 Amendment B). */
  bases?: string[];
  matched?: string[];
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
  /** ADR-0018: every Sigma rule that names a Group, with the reviewed decision per tag. */
  actor_specific: {
    summary: {
      sigma_rules_total: number;
      group_tags_reviewed: number;
      group_tags_accepted: number;
      by_status: { imported: number; partial: number; rejected: number };
      generated_rules: number;
      groups_with_a_usable_rule: string[];
    };
    rules: {
      sigma_id: string;
      title: string;
      url: string;
      logsource: string;
      status: string;
      rejection: string | null;
      actor_tags: ActorTag[];
    }[];
  } | null;
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

/** ADR-0017: the verdict about a whole investigation. It can never name an actor. */
export type Verdict =
  | "no_decision_features"
  | "not_distinguishable"
  | "third_party_lead"
  /** ADR-0018: an artefact specific to one Group matched. The only verdict that names one. */
  | "actor_specific_evidence";

export interface Assessment {
  investigation_id: string;
  attack_kb_version: string;
  units_total: number;
  units_with_decision_features: number;
  active_groups: number;
  observed_techniques: {
    technique_id: string;
    technique_stix_id: string;
    technique_name: string;
    units: number;
    groups_using: number;
    campaigns_using: number;
  }[];
  candidate_groups: number;
  candidate_campaigns: number;
  /** In name order. Overlap is a stored fact per candidate, never an ordering. */
  candidates: {
    candidate_id: string;
    stix_id: string;
    name: string;
    kind: string;
    profile_techniques: number;
    matched_technique_ids: string[];
    units_as_candidate: number;
  }[];
  overlap_counts: { min_matched: number; candidates: number }[];
  indicator_leads: {
    actor_name: string;
    actor_attack_id: string | null;
    indicator_name: string;
    kind: string;
    value: string;
    report_name: string | null;
    within_validity: boolean | null;
    attribution_quote: string | null;
    group_id: string;
  }[];
  actor_leads: (ActorEvidence & { group_id: string })[];
  verdict: Verdict;
  statement: string;
  reasons: string[];
  limits: string[];
  method_version: string;
  schema_version: string;
}

/** ADR-0017: what naming an actor would have got right on known-answer recordings. */
export interface KnownAnswerCase {
  source_id: string;
  source_sha256: string;
  investigation_id: string;
  kind: "emulation" | "tool_test";
  known_actor: { attack_id: string; name: string } | null;
  known_basis: string;
  verdict: Verdict;
  /** ATT&CK ids of Groups the verdict named (actor-specific evidence only). */
  named_actors: string[];
  statement: string;
  units: number;
  observed_techniques: number;
  candidates: number;
  known_actor_profile_techniques: number | null;
  known_actor_techniques_observed: number | null;
  units_with_known_actor_as_candidate: number | null;
  unit_level: {
    units_compared: number;
    first: number;
    top_10: number;
    median_position: number;
    median_candidates: number;
  } | null;
  orderings: {
    ordering: string;
    level: string;
    groups_ordered: number;
    would_name: string | null;
    known_actor_position: number | null;
  }[];
}

export interface Validation {
  version: string;
  pinned: { attack_kb_version?: string; detection_pack_content_hash?: string; method_versions?: Record<string, string> };
  summary: {
    cases: number;
    emulations: number;
    tool_tests: number;
    verdicts_naming_an_actor: number;
    verdicts_naming_a_wrong_actor: number;
    orderings_measured: number;
    orderings_naming_the_known_actor_first: number;
    orderings_with_the_known_actor_in_top_10: number;
    best_position_of_a_known_actor: number | null;
    worst_position_of_a_known_actor: number | null;
    actors_an_ordering_would_name_on_tool_tests: number;
    orderings_on_tool_tests: number;
  };
  cases: KnownAnswerCase[];
}

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

export type ApiFailureKind = "unreachable" | "not_found" | "bad_request" | "backend" | "server";

/** ADR-0019: one Evidence item of an investigation's units, for the matrix and timeline views. */
export interface ActivityEvent {
  time: string | null;
  group_id: string;
  evidence_id: string;
  host: string | null;
  /** A short name of what was observed (a process name or an action) — never a command line. */
  label: string | null;
  attack_id: string | null;
  attack_stix_id: string | null;
  attack_object_type: string | null;
  /** Low-level (enrich-tier) Evidence. */
  context: boolean;
  /** Its technique is a decision feature of its unit. */
  decision_feature: boolean;
}

export interface Activity {
  investigation_id: string;
  evidence_in_units: number;
  evidence_outside_units: number | null;
  events: ActivityEvent[];
}

export type StepOutcome =
  | "technique_detected_in_step"
  | "step_activity_detected"
  | "technique_detected_elsewhere"
  | "not_detected";

export interface EmulationStepComparison {
  order: number;
  name: string;
  technique_id: string | null;
  technique_name: string | null;
  tactic: string | null;
  host: string | null;
  status: string;
  issued_at: string | null;
  collected_at: string | null;
  pid: number | null;
  /** Evidence grounded in the step's own process, inside its time window. */
  step_evidence: number;
  step_technique_ids: string[];
  step_unit_ids: string[];
  /** Evidence for the step's technique anywhere in the investigation. */
  technique_evidence_core: number;
  technique_evidence_context: number;
  outcome: StepOutcome;
}

/** ADR-0019: what an emulation tool reports having run, beside what was detected. */
export interface EmulationComparison {
  investigation_id: string;
  tool: string;
  operation_name: string;
  profile_name: string | null;
  started_at: string | null;
  finished_at: string | null;
  report_sha256: string;
  steps: EmulationStepComparison[];
  outcome_counts: Record<StepOutcome, number>;
  distinct_techniques: number;
  distinct_techniques_with_evidence: number;
  window_slack_seconds: number;
  method_version: string;
  schema_version: string;
}

export type UploadState = "queued" | "checking" | "analysing" | "done" | "refused" | "failed";

/** ADR-0020: one uploaded recording and what became of it. */
export interface UploadJob {
  job_id: string;
  file_name: string;
  size_bytes: number;
  sha256: string;
  received_at: string;
  state: UploadState;
  started_at: string | null;
  finished_at: string | null;
  problems: string[];
  warnings: string[];
  records: number | null;
  converted_by_source: Record<string, number>;
  refused_records: number | null;
  first_event: string | null;
  last_event: string | null;
  investigation_id: string | null;
  evidence: number | null;
  units: number | null;
}

export interface Uploads {
  enabled: boolean;
  max_bytes: number;
  supported_suffixes: string[];
  jobs: UploadJob[];
}

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
  assessment: (id: string) => `/investigations/${encodeURIComponent(id)}/assessment`,
  validation: () => "/validation",
  uploads: () => "/uploads",
  activity: (id: string) => `/investigations/${encodeURIComponent(id)}/activity`,
  emulation: (id: string) => `/investigations/${encodeURIComponent(id)}/emulation`,
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

/**
 * Send a recording to the server (ADR-0020): the file is the raw request body.
 * XMLHttpRequest, not fetch, because only it reports upload progress.
 */
export function uploadRecording(file: File, onProgress: (fraction: number) => void): Promise<UploadJob> {
  const path = `${paths.uploads()}?name=${encodeURIComponent(file.name)}`;
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open("POST", BASE + path);
    xhr.setRequestHeader("Content-Type", "application/octet-stream");
    xhr.upload.onprogress = (event) => {
      if (event.lengthComputable) onProgress(event.loaded / event.total);
    };
    xhr.onerror = () => reject(new ApiFailure("unreachable", "The server did not answer the upload.", path, null));
    xhr.onload = () => {
      let body: unknown = null;
      try {
        body = JSON.parse(xhr.responseText);
      } catch {
        // handled below as a failure without a message
      }
      if (xhr.status === 202 && body) {
        resolve(body as UploadJob);
        return;
      }
      const message =
        body && typeof body === "object" && "error" in body
          ? String((body as { error: unknown }).error)
          : `HTTP ${xhr.status}`;
      reject(new ApiFailure(kindOf(xhr.status), message, path, xhr.status));
    };
    xhr.send(file);
  });
}

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
