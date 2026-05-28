import { describe, expect, test } from "bun:test";
import { mkdtempSync, writeFileSync, chmodSync } from "node:fs";
import { tmpdir } from "node:os";
import * as path from "node:path";

import { GrypeEpssRescanProvider } from "../src/provider.js";
import { EPSS_SOURCE, GRYPE_VERSION } from "../src/tools-manifest.js";

const baseInput = (
  overrides: Partial<{
    workdir: string;
    config: Record<string, unknown>;
    vibeId: string;
  }> = {},
) => {
  const wd = overrides.workdir ?? mkdtempSync(path.join(tmpdir(), "rescan-test-"));
  return {
    runId: `rs-${Math.random().toString(36).slice(2, 10)}`,
    vibeId: overrides.vibeId ?? "v1",
    workspaceId: "w1",
    repoUrl: "x",
    repoLocalPath: "/tmp",
    commit: "c",
    stage: "scheduled.rescan" as const,
    profile: { kind: "backend", languages: ["ts"], runtimes: ["bun"] },
    policyLevel: "advisory" as const,
    config: overrides.config ?? {},
    workdir: wd,
  };
};

describe("GrypeEpssRescanProvider — identity + metadata", () => {
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

describe("GrypeEpssRescanProvider — skip when no SBOM available", () => {
  test("no sbomPath + no cached SBOM evidence emits sbom.unavailable info finding", async () => {
    const p = new GrypeEpssRescanProvider();
    // Pre-set grypePath so run() doesn't try to install.
    (p as unknown as { grypePath: string }).grypePath = "/no/such/grype";
    const result = await p.run(
      baseInput({
        vibeId: "vibe-without-prior-sbom-evidence",
        config: { enrichOnline: false },
      }),
    );
    expect(result.status).toBe("succeeded");
    expect(result.findings.length).toBe(1);
    expect(result.findings[0].ruleId).toBe("sbom.unavailable");
    expect(result.findings[0].severity).toBe("info");
    expect(result.findings[0].description).toMatch(/no-prior-sbom-evidence/);
  });
});

const GRYPE_FIXTURE = {
  matches: [
    {
      vulnerability: {
        id: "CVE-2024-1111",
        severity: "High",
        description: "An RCE in libfoo",
        fix: { versions: ["1.2.3"], state: "fixed" },
      },
      artifact: {
        name: "libfoo",
        version: "1.0.0",
        type: "deb",
        locations: [{ path: "/usr/lib/libfoo.so" }],
      },
    },
    {
      vulnerability: {
        id: "CVE-2024-2222",
        severity: "Medium",
        description: "A DoS in libbar",
        fix: { versions: [], state: "not-fixed" },
      },
      artifact: {
        name: "libbar",
        version: "0.5.0",
        type: "npm",
        locations: [{ path: "node_modules/libbar" }],
      },
    },
  ],
};

function writeFakeGrype(fixturePathOverride?: string): string {
  const dir = mkdtempSync(path.join(tmpdir(), "fake-grype-"));
  const fakeGrype = path.join(dir, "grype");
  const fixture = fixturePathOverride ?? JSON.stringify(GRYPE_FIXTURE);
  const script = `#!/usr/bin/env bash
set -e
OUT=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --file) OUT="$2"; shift 2;;
    *) shift;;
  esac
done
if [[ -n "$OUT" ]]; then
  cat > "$OUT" <<'JSON'
${fixture}
JSON
fi
exit 0
`;
  writeFileSync(fakeGrype, script, { mode: 0o755 });
  chmodSync(fakeGrype, 0o755);
  return fakeGrype;
}

function writeSbom(): string {
  const dir = mkdtempSync(path.join(tmpdir(), "sbom-"));
  const sbom = path.join(dir, "sbom.cdx.json");
  writeFileSync(
    sbom,
    JSON.stringify({ bomFormat: "CycloneDX", specVersion: "1.5", components: [] }),
  );
  return sbom;
}

describe("GrypeEpssRescanProvider — fake grype fixture parse", () => {
  test("normalises grype JSON into vuln findings", async () => {
    const p = new GrypeEpssRescanProvider();
    (p as unknown as { grypePath: string }).grypePath = writeFakeGrype();
    const sbomPath = writeSbom();
    const workdir = mkdtempSync(path.join(tmpdir(), "wd-"));
    const result = await p.run(
      baseInput({
        workdir,
        config: { sbomPath, enrichOnline: false },
      }),
    );
    expect(result.status).toBe("succeeded");
    const vulns = result.findings.filter((f) => f.category === "vuln");
    expect(vulns.length).toBe(2);
    const cves = vulns.map((f) => f.cve).sort();
    expect(cves).toEqual(["CVE-2024-1111", "CVE-2024-2222"]);
    expect(result.evidence.length).toBe(1);
    expect(result.evidence[0]?.type).toBe("grype-json");
  });
});

describe("GrypeEpssRescanProvider — EPSS enrichment toggles", () => {
  test("enrichOnline=false skips EPSS calls (no enrichment evidence emitted)", async () => {
    const p = new GrypeEpssRescanProvider();
    (p as unknown as { grypePath: string }).grypePath = writeFakeGrype();
    const sbomPath = writeSbom();
    const workdir = mkdtempSync(path.join(tmpdir(), "wd-"));
    let epssCalled = false;
    const server = Bun.serve({
      port: 0,
      fetch() {
        epssCalled = true;
        return new Response(JSON.stringify({ data: [] }), {
          headers: { "content-type": "application/json" },
        });
      },
    });
    try {
      const result = await p.run(
        baseInput({
          workdir,
          config: {
            sbomPath,
            enrichOnline: false,
            epssApiBase: `http://127.0.0.1:${server.port}/data/v1`,
          },
        }),
      );
      expect(result.status).toBe("succeeded");
      expect(epssCalled).toBe(false);
      // Only the grype.json — no epss-enrichment.json.
      expect(result.evidence.length).toBe(1);
      const vulns = result.findings.filter((f) => f.category === "vuln");
      for (const v of vulns) {
        // No epss=... suffix.
        expect((v.rawProviderRef ?? "").includes("epss=")).toBe(false);
      }
    } finally {
      server.stop(true);
    }
  });

  test("enrichOnline=true attaches EPSS score in rawProviderRef + promotes severity on likely-exploited", async () => {
    const p = new GrypeEpssRescanProvider();
    (p as unknown as { grypePath: string }).grypePath = writeFakeGrype();
    const sbomPath = writeSbom();
    const workdir = mkdtempSync(path.join(tmpdir(), "wd-"));
    const server = Bun.serve({
      port: 0,
      fetch(req) {
        const url = new URL(req.url);
        // Reply with a likely-exploited score for CVE-2024-1111 (HIGH → CRITICAL)
        // and a low score for CVE-2024-2222 (MEDIUM stays MEDIUM).
        if (url.pathname.endsWith("/epss")) {
          return new Response(
            JSON.stringify({
              data: [
                { cve: "CVE-2024-1111", epss: 0.92, percentile: 0.98 },
                { cve: "CVE-2024-2222", epss: 0.01, percentile: 0.3 },
              ],
            }),
            { headers: { "content-type": "application/json" } },
          );
        }
        return new Response("not found", { status: 404 });
      },
    });
    try {
      const result = await p.run(
        baseInput({
          workdir,
          config: {
            sbomPath,
            enrichOnline: true,
            epssApiBase: `http://127.0.0.1:${server.port}/data/v1`,
          },
        }),
      );
      expect(result.status).toBe("succeeded");
      const promoted = result.findings.find((f) => f.cve === "CVE-2024-1111");
      const unchanged = result.findings.find((f) => f.cve === "CVE-2024-2222");
      expect(promoted).toBeDefined();
      expect(unchanged).toBeDefined();
      expect(promoted?.severity).toBe("critical"); // promoted from high
      expect(unchanged?.severity).toBe("medium"); // no promotion
      expect(promoted?.rawProviderRef).toMatch(/epss=0\.92:0\.98/);
      expect(unchanged?.rawProviderRef).toMatch(/epss=0\.01:0\.3/);
      // Both grype.json + epss-enrichment.json.
      expect(result.evidence.length).toBe(2);
    } finally {
      server.stop(true);
    }
  });
});
