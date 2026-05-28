import { describe, expect, test } from "bun:test";

import { GrypeEpssRescanProvider } from "../src/provider.js";
import { EPSS_SOURCE, GRYPE_VERSION } from "../src/tools-manifest.js";

describe("GrypeEpssRescanProvider", () => {
  test("name + stage are immutable identifiers", () => {
    const p = new GrypeEpssRescanProvider();
    expect(p.name).toBe("grype-epss-rescan");
    expect(p.stage).toBe("scheduled.rescan");
  });

  test("toolVersion encodes pinned Grype + EPSS source", () => {
    const p = new GrypeEpssRescanProvider();
    expect(p.toolVersion).toContain(GRYPE_VERSION);
    expect(p.toolVersion).toContain(EPSS_SOURCE);
  });

  test("metadata supports backend + container + iac profiles", () => {
    const p = new GrypeEpssRescanProvider();
    const m = p.metadata();
    expect(m.stage).toBe("scheduled.rescan");
    expect(m.supportedProfiles).toContain("backend");
    expect(m.supportedProfiles).toContain("container");
    expect(m.supportedProfiles).toContain("iac");
  });

  test("cancel() on unknown run is a no-op", async () => {
    const p = new GrypeEpssRescanProvider();
    await expect(p.cancel("nope")).resolves.toBeUndefined();
  });
});
