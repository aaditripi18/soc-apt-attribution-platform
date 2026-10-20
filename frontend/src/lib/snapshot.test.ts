import { describe, expect, it } from "vitest";
import { fnv1a32 } from "./api";

// The hosted snapshot names each exported API answer by this hash of its request
// path; the values are the exporter's own (scripts/export_snapshot.py).
describe("snapshot file names", () => {
  it("match the exporter's FNV-1a for the same request path", () => {
    expect(fnv1a32("/investigations")).toBe("43fd15ed");
    expect(fnv1a32("/units/corr-group%3A%3Aab/evidence")).toBe("5c58ecf9");
    expect(fnv1a32("/units?limit=1000")).toBe("42dea1cd");
  });
});
