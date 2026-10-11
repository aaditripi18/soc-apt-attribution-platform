import { describe, expect, it } from "vitest";
import type {
  AttributionAnalysis,
  BehavioralSequence,
  Candidate,
  CoverageTechnique,
  Evidence,
  Observation,
  TechniqueCatalogue,
  UnitSummary,
} from "./api";
import {
  buildTimeline,
  candidateRows,
  coverageByTactic,
  indexTechniques,
  layoutSequence,
  observationFacets,
  ruleKey,
  unitTechniques,
} from "./derive";
import { attackUrl, durationMs, shortId, utcDateTime } from "./format";
import { href, parseHash } from "./router";

const catalogue: TechniqueCatalogue = {
  attack_kb_version: "enterprise-attack-test",
  active_groups: 10,
  tactics: [
    { shortname: "execution", name: "Execution", attack_id: "TA0002" },
    { shortname: "discovery", name: "Discovery", attack_id: "TA0007" },
  ],
  techniques: [
    { attack_id: "T1033", stix_id: "ap--a", name: "System Owner/User Discovery", is_subtechnique: false, tactics: ["discovery"], platforms: ["Windows"], groups_using: 4 },
    { attack_id: "T1059.001", stix_id: "ap--b", name: "PowerShell", is_subtechnique: true, tactics: ["execution"], platforms: ["Windows"], groups_using: 8 },
    { attack_id: "T1087", stix_id: "ap--c", name: "Account Discovery", is_subtechnique: false, tactics: ["discovery"], platforms: ["Windows"], groups_using: 0 },
  ],
};
const index = indexTechniques(catalogue);

const candidate = (id: string, name: string, basis: string[]): Candidate => ({
  candidate_id: id,
  kind: "group",
  stix_id: `is--${id}`,
  name,
  attack_external_id: null,
  generation_basis: basis,
});

function analysis(partial: Partial<AttributionAnalysis>): AttributionAnalysis {
  return {
    group_id: "g",
    sequence_id: "s",
    investigation_id: "i",
    attack_kb_version: "v",
    min_profile_floor: 1,
    observed_feature_technique_ids: [],
    unattributed_decision_support: 0.5,
    candidates: [],
    hypotheses: [],
    collection_guidance: null,
    indicator_matches: [],
    comparison_status: "computed",
    comparison_note: null,
    calibration_status: "uncalibrated",
    calibration_version: null,
    calibration_note: "",
    schema_version: "attribution-analysis/4",
    ...partial,
  };
}

const evidence = (id: string, stix: string | null, quality: string | null): Evidence => ({
  evidence_id: id,
  evidence_type: "behavioral",
  claim: "",
  attack_ref: stix ? { stix_id: stix, object_type: "attack-pattern", external_id: index.byStix.get(stix)?.attack_id ?? null, attack_kb_version: "v" } : null,
  quality,
  time_span: null,
  provenance: { method: "sigma:u:000", method_version: "r", method_content_hash: null, source_observation_ids: ["o"], derived_at: null },
  schema_version: "evidence/1",
});

describe("candidateRows", () => {
  it("orders candidates by name, never by support", () => {
    const rows = candidateRows(
      analysis({
        observed_feature_technique_ids: ["ap--a", "ap--b"],
        candidates: [candidate("c1", "zebra", ["ap--a", "ap--b"]), candidate("c2", "Apple", ["ap--a"]), candidate("c3", "mango", ["ap--b"])],
        hypotheses: [
          { hypothesis_id: "h1", candidate_id: "c1", support_value: 0.9, profile_breadth: 5, contributions: [] },
          { hypothesis_id: "h2", candidate_id: "c2", support_value: 0.1, profile_breadth: 5, contributions: [] },
        ],
      }),
    );
    expect(rows.map((r) => r.candidate.name)).toEqual(["Apple", "mango", "zebra"]);
    expect(rows.map((r) => r.uses.size)).toEqual([1, 1, 2]);
    expect(rows[1]?.hypothesis).toBeNull();
  });

  it("counts only observed techniques, and reads single-feature contributions", () => {
    const [row] = candidateRows(
      analysis({
        observed_feature_technique_ids: ["ap--a"],
        candidates: [candidate("c1", "A", ["ap--a", "software--x"])],
        hypotheses: [
          {
            hypothesis_id: "h",
            candidate_id: "c1",
            support_value: 0.2,
            profile_breadth: 3,
            contributions: [
              { feature_technique_ids: ["ap--a"], diagnosticity_outcome: "resolved", g_value: 0.4, d_value: 0.6, contribution_value: 0.6, assessment_ids: ["x"] },
            ],
          },
        ],
      }),
    );
    expect([...(row?.uses ?? [])]).toEqual(["ap--a"]);
    expect(row?.contributionByFeature.get("ap--a")?.d_value).toBe(0.6);
  });
});

describe("unitTechniques", () => {
  it("separates decision features from context and derives g and D from the catalogue", () => {
    const rows = unitTechniques(
      analysis({ observed_feature_technique_ids: ["ap--a"] }),
      [evidence("e1", "ap--a", null), evidence("e2", "ap--b", "low"), evidence("e3", null, null), evidence("e4", "ap--c", null)],
      index,
    );
    // T1087: core Evidence, but not a served decision feature (no Group uses it).
    expect(rows.map((r) => [r.attackId, r.role])).toEqual([
      ["T1033", "feature"],
      ["T1059.001", "context"],
      ["T1087", "unmatched"],
    ]);
    expect(rows[0]?.g).toBeCloseTo(0.4);
    expect(rows[0]?.d).toBeCloseTo(0.6);
  });

  it("keeps a technique the catalogue does not know, without inventing g", () => {
    const [row] = unitTechniques(analysis({ observed_feature_technique_ids: ["ap--zz"] }), [], index);
    expect(row).toMatchObject({ stixId: "ap--zz", attackId: "ap--zz", g: null, d: null, groupsUsing: null });
  });
});

describe("layoutSequence", () => {
  const step = (id: string) => ({ step_id: id, group_id: "g", evidence_ids: ["e"], observation_id: id, technique_stix_ids: [], evidence_types: [], contextual_annotations: [] });
  const edge = (from: string, to: string) => ({ edge_id: `${from}>${to}`, from_step_id: from, to_step_id: to, basis: { basis_kind: "process_lineage", grounding_link_id: "l", timestamp_agreement: null, precision_uncertain: false } });
  const sequence = (steps: string[], edges: [string, string][]): BehavioralSequence => ({
    sequence_id: "s",
    group_id: "g",
    steps: steps.map(step),
    edges: edges.map(([a, b]) => edge(a, b)),
    gaps: [],
    parallel_groups: [],
    provenance: {},
    schema_version: "x",
  });
  const order: Record<string, number> = { a: 1, b: 2, c: 3, d: 4 };
  const rank = (id: string) => order[id] ?? 0;

  it("puts a step one layer after its latest predecessor", () => {
    const layout = layoutSequence(sequence(["d", "c", "b", "a"], [["a", "b"], ["a", "c"], ["b", "d"], ["c", "d"]]), rank);
    const at = Object.fromEntries(layout.steps.map((p) => [p.stepId, [p.layer, p.row]]));
    expect(at).toEqual({ a: [0, 0], b: [1, 0], c: [1, 1], d: [2, 0] });
    expect([layout.layers, layout.rows]).toEqual([3, 2]);
  });

  it("places every step even with no edges, and ignores edges to unknown steps", () => {
    const layout = layoutSequence(sequence(["b", "a"], [["a", "zz"]]), rank);
    expect(layout.steps.map((p) => p.stepId)).toEqual(["a", "b"]);
    expect(layout.layers).toBe(1);
  });
});

describe("buildTimeline", () => {
  const unit = (id: string, hosts: string[], first: string, last: string): UnitSummary => ({
    group_id: id, investigation_id: "i", host_names: hosts, first_seen: first, last_seen: last, technique_ids: [], candidate_ids: [], evidence: 1, steps: 1, schema_version: "x",
  });
  it("makes one lane per host over the whole span", () => {
    const timeline = buildTimeline([
      unit("u1", ["b"], "2026-01-01T00:00:10+00:00", "2026-01-01T00:00:20+00:00"),
      unit("u2", ["a", "b"], "2026-01-01T00:00:00+00:00", "2026-01-01T00:00:05+00:00"),
    ]);
    expect(timeline?.lanes.map((l) => [l.host, l.units.length])).toEqual([["a", 1], ["b", 2]]);
    expect((timeline?.end ?? 0) - (timeline?.start ?? 0)).toBe(20000);
    expect(buildTimeline([])).toBeNull();
  });
});

describe("coverageByTactic", () => {
  it("counts a technique in each of its tactics, in matrix order", () => {
    const row = (attack_id: string, status: CoverageTechnique["status"]): CoverageTechnique => ({
      attack_id, name: "", status, rule_sources: 0, rule_sources_by_origin: {}, rejected_rules_blocked_by: [], supported_platforms: [], has_data_component: true,
    });
    const result = coverageByTactic([row("T1033", "covered"), row("T1087", "telemetry_gap"), row("T1059.001", "covered")], index);
    expect(result.map((r) => [r.tactic, r.total, r.byStatus.covered])).toEqual([["execution", 1, 1], ["discovery", 2, 1]]);
  });
});

describe("observationFacets", () => {
  it("shows only fields that hold a value", () => {
    const observation = {
      observation_id: "o", timestamp: "t", timestamp_precision: null, event: null, user: null, raw_reference: null,
      host: { id: null, name: "H", os_type: "windows", ip: [] },
      process: { executable: "C:\\x.exe", command_line: null, name: null, pid: 4, parent_executable: null, parent_command_line: null, parent_name: null, parent_pid: null, hashes: { sha256: "ab" } },
      dns: null,
    } as unknown as Observation;
    expect(observationFacets(observation)).toEqual([
      { facet: "host", rows: [{ field: "name", value: "H" }, { field: "os_type", value: "windows" }] },
      { facet: "process", rows: [{ field: "executable", value: "C:\\x.exe" }, { field: "pid", value: "4" }, { field: "hashes.sha256", value: "ab" }] },
    ]);
  });
});

describe("identifiers and formatting", () => {
  it("names the upstream rule of an engine rule id", () => {
    expect(ruleKey("sigma:0022869c:000")).toBe("sigma:0022869c");
    expect(ruleKey("elastic:000047bb:okta:000")).toBe("elastic:000047bb");
  });
  it("round-trips identifiers containing separators through the fragment", () => {
    const id = "sysmon:HOST.example.com:sha256:ab/cd?x#y";
    const route = parseHash(href(["units", id, "evidence"], { technique: "T1003.001", empty: "" }));
    expect(route.segments).toEqual(["units", id, "evidence"]);
    expect(route.query.get("technique")).toBe("T1003.001");
    expect(route.query.has("empty")).toBe(false);
    expect(parseHash("").segments).toEqual([]);
  });
  it("formats times in UTC and shortens ids without losing the prefix", () => {
    expect(utcDateTime("2023-08-16T04:55:07.148000+00:00", true)).toBe("2023-08-16 04:55:07.148Z");
    expect(utcDateTime("2023-08-16T06:55:07+02:00")).toBe("2023-08-16 04:55:07Z");
    expect(utcDateTime(null)).toBe("—");
    expect(durationMs(950)).toBe("950 ms");
    expect(durationMs(125000)).toBe("2 min 05 s");
    expect(shortId("corr-group::0123456789abcdef", 6)).toBe("corr-group::012345…");
    expect(attackUrl("T1003.001")).toBe("https://attack.mitre.org/techniques/T1003/001/");
    expect(attackUrl("G0016")).toBe("https://attack.mitre.org/groups/G0016/");
    expect(attackUrl("nonsense")).toBeNull();
  });
});
