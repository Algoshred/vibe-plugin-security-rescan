/**
 * GrypeEpssRescanProvider — implements SecurityProvider for stage
 * `scheduled.rescan`.
 *
 * Pipeline:
 *
 *   1. Resolve an SBOM path. Either explicit (`input.config.sbomPath`) or
 *      the latest cached SBOM evidence for the vibe (lookup against the
 *      agent's local `<dataDir>/security/security.sqlite`, joining
 *      `security_evidence` × `security_scan_runs` on `vibe_id` and
 *      ordering by finished_at DESC). When neither produces a path, the
 *      provider emits one info finding `sbom.unavailable` and skips.
 *
 *   2. Spawn the pinned Grype binary in offline mode against the SBOM
 *      (`grype sbom:<path> --output json --quiet --add-cpes-if-none`).
 *      Auto-installs via the shared tool-installer (sha256-pinned per
 *      platform in `./tools-manifest.ts`).
 *
 *   3. Normalise via the meta plugin's `normalizeGrype` so findings are
 *      indistinguishable from build-stage Grype findings (same fingerprint
 *      → seamless dedup).
 *
 *   4. EPSS enrichment (FIRST.org public API, no auth) for every finding
 *      with a `cve` field. Batched at 100 CVEs per call. Each enriched
 *      finding gets `epss=<probability>:<percentile>` appended to its
 *      `rawProviderRef`. Findings with `epss > 0.5` AND `percentile > 0.95`
 *      are promoted up one severity notch (likely-exploited heuristic).
 */
import { spawn, type ChildProcess } from "node:child_process";
import { createHash } from "node:crypto";
import { promises as fs } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import type { HostServices } from "@vibecontrols/plugin-sdk/contract";
import { normalizeGrype } from "@vibecontrols/vibe-plugin-security/normalizer";
import { resolveToolPath } from "@vibecontrols/vibe-plugin-security/tool-installer";
import type {
  NormalizedFinding,
  ScanEvidenceArtifact,
  SecurityProvider,
  SecurityProviderMetadata,
  SecurityScanInput,
  SecurityScanResult,
  SecurityScanSummary,
  SecurityStage,
  SecuritySeverity,
} from "@vibecontrols/vibe-plugin-security/types";

import { EPSS_SOURCE, GRYPE_VERSION, TOOLS_MANIFEST } from "./tools-manifest.js";

const GRYPE_TIMEOUT_MS = 5 * 60 * 1000;
const DEFAULT_EPSS_API_BASE = "https://api.first.org/data/v1";
const EPSS_BATCH_SIZE = 100;
const EPSS_PROMOTE_PROB = 0.5;
const EPSS_PROMOTE_PCTL = 0.95;

const SEVERITY_LADDER: SecuritySeverity[] = ["info", "low", "medium", "high", "critical"];

interface RescanConfig {
  sbomPath?: string;
  enrichOnline?: boolean;
  epssApiBase?: string;
}

interface EpssApiResponse {
  data?: Array<{
    cve?: string;
    epss?: number | string;
    percentile?: number | string;
  }>;
}

export class GrypeEpssRescanProvider implements SecurityProvider {
  readonly name = "grype-epss-rescan";
  readonly stage: SecurityStage = "scheduled.rescan";
  readonly toolVersion = `grype@${GRYPE_VERSION}+epss@${EPSS_SOURCE}`;

  private host?: HostServices;
  private grypePath?: string;
  private active = new Map<string, ChildProcess>();

  async init(host: HostServices): Promise<void> {
    this.host = host;
  }

  async ensureToolInstalled(): Promise<void> {
    const dataDir =
      this.host?.getDataDir?.() ?? path.join(os.homedir(), ".boff/vibecontrols");
    this.grypePath = await resolveToolPath(
      {
        dataDir,
        log: {
          info: (m) => this.host?.logger?.info?.("security-rescan-provider", m),
          warn: (m) => this.host?.logger?.warn?.("security-rescan-provider", m),
          error: (m) => this.host?.logger?.error?.("security-rescan-provider", m),
        },
      },
      "grype",
      TOOLS_MANIFEST.grype,
    );
  }

  async run(input: SecurityScanInput): Promise<SecurityScanResult> {
    const startedAt = Date.now();
    if (!this.grypePath) {
      await this.ensureToolInstalled();
    }
    if (!this.grypePath) throw new Error("security-rescan-provider: grypePath unavailable");

    const cfg = (input.config as RescanConfig) ?? {};
    const findings: NormalizedFinding[] = [];
    const evidence: ScanEvidenceArtifact[] = [];

    input.onProgress?.({ pct: 5, message: "Resolving SBOM" });
    const sbomPath = await resolveSbomPath(cfg.sbomPath, this.host?.getDataDir?.(), input.vibeId);
    if (!sbomPath) {
      findings.push(
        makeSkipFinding({
          ruleId: "sbom.unavailable",
          title: "Scheduled rescan skipped — no SBOM evidence available",
          description:
            "no-prior-sbom-evidence; build-stage must run first. Configure sbomPath explicitly or run an SBOM build (sbom-cyclonedx / sbom-spdx) before scheduling a rescan.",
          fpInput: `sbom-unavailable:${input.vibeId}`,
        }),
      );
      input.onProgress?.({ pct: 100, message: "Skipped (no SBOM)" });
      return {
        runId: input.runId,
        status: "succeeded",
        findings,
        evidence,
        durationMs: Date.now() - startedAt,
        summary: summarize(findings),
      };
    }

    input.onProgress?.({ pct: 20, message: `Grype rescan against ${path.basename(sbomPath)}` });
    const grypeOut = path.join(input.workdir, "grype.json");
    const args = [
      `sbom:${sbomPath}`,
      "--output",
      "json",
      "--file",
      grypeOut,
      "--quiet",
      "--add-cpes-if-none",
    ];
    const grypeResult = await this.spawnAndWait(
      `${input.runId}::grype`,
      this.grypePath,
      args,
      GRYPE_TIMEOUT_MS,
    );
    if (grypeResult.code !== 0) {
      return {
        runId: input.runId,
        status: "errored",
        findings,
        evidence,
        durationMs: Date.now() - startedAt,
        summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
        errorReason: `grype exited ${grypeResult.code}: ${grypeResult.stderr.slice(0, 500)}`,
      };
    }

    input.onProgress?.({ pct: 60, message: "Normalising findings" });
    try {
      const raw = await fs.readFile(grypeOut, "utf-8");
      const normalised = normalizeGrype(raw, this.name);
      findings.push(...normalised);
      const stat = await fs.stat(grypeOut);
      const sha256 = createHash("sha256").update(raw).digest("hex");
      evidence.push({
        type: "grype-json",
        localPath: grypeOut,
        sha256,
        sizeBytes: stat.size,
      });
    } catch (err) {
      this.host?.logger?.warn?.(
        "security-rescan-provider",
        `failed to parse grype output: ${String(err)}`,
      );
    }

    // EPSS enrichment.
    const enrichOnline = cfg.enrichOnline !== false;
    if (enrichOnline && findings.some((f) => Boolean(f.cve))) {
      input.onProgress?.({ pct: 80, message: "Enriching with FIRST.org EPSS scores" });
      const apiBase = cfg.epssApiBase ?? DEFAULT_EPSS_API_BASE;
      try {
        const epssMap = await fetchEpssScores(
          findings.map((f) => f.cve).filter((c): c is string => Boolean(c)),
          apiBase,
        );
        const enrichmentPath = path.join(input.workdir, "epss-enrichment.json");
        await fs.writeFile(enrichmentPath, JSON.stringify(Array.from(epssMap.entries()), null, 2));
        const stat = await fs.stat(enrichmentPath);
        const sha256 = createHash("sha256")
          .update(await fs.readFile(enrichmentPath))
          .digest("hex");
        // TODO(evidence-types): add dedicated `epss-enrichment-json` type to
        // vibe-plugin-security/types. Until then, repurpose `grype-json` so the
        // evidence-uploader knows how to handle it.
        evidence.push({
          type: "grype-json",
          localPath: enrichmentPath,
          sha256,
          sizeBytes: stat.size,
        });
        for (const f of findings) {
          if (!f.cve) continue;
          const hit = epssMap.get(f.cve);
          if (!hit) continue;
          const ref = f.rawProviderRef
            ? `${f.rawProviderRef} epss=${hit.epss}:${hit.percentile}`
            : `epss=${hit.epss}:${hit.percentile}`;
          f.rawProviderRef = ref;
          if (hit.epss > EPSS_PROMOTE_PROB && hit.percentile > EPSS_PROMOTE_PCTL) {
            f.severity = promoteSeverity(f.severity);
          }
        }
      } catch (err) {
        this.host?.logger?.warn?.(
          "security-rescan-provider",
          `EPSS enrichment failed (continuing without): ${String(err)}`,
        );
      }
    }

    input.onProgress?.({ pct: 100, message: "Rescan complete" });
    return {
      runId: input.runId,
      status: "succeeded",
      findings,
      evidence,
      durationMs: Date.now() - startedAt,
      summary: summarize(findings),
    };
  }

  async cancel(runId: string): Promise<void> {
    for (const [key, child] of this.active.entries()) {
      if (!key.startsWith(runId)) continue;
      try {
        child.kill("SIGTERM");
        setTimeout(() => {
          try {
            child.kill("SIGKILL");
          } catch {
            /* already gone */
          }
        }, 5000);
      } finally {
        this.active.delete(key);
      }
    }
  }

  metadata(): SecurityProviderMetadata {
    return {
      stage: this.stage,
      supportedProfiles: ["backend", "frontend", "cli", "sdk", "mcp", "container", "iac"],
      toolVersion: this.toolVersion,
      description:
        "Grype offline rescan against the latest cached SBOM with optional FIRST.org EPSS enrichment.",
    };
  }

  private spawnAndWait(
    key: string,
    cmd: string,
    args: string[],
    timeoutMs: number,
  ): Promise<{ code: number | null; stdout: string; stderr: string }> {
    return new Promise((resolve) => {
      const child = spawn(cmd, args, { stdio: ["ignore", "pipe", "pipe"] });
      this.active.set(key, child);
      let stdout = "";
      let stderr = "";
      child.stdout?.on("data", (b: Buffer) => (stdout += b.toString()));
      child.stderr?.on("data", (b: Buffer) => (stderr += b.toString()));
      const timer = setTimeout(() => {
        try {
          child.kill("SIGTERM");
        } catch {
          /* ignore */
        }
      }, timeoutMs);
      child.on("close", (code) => {
        clearTimeout(timer);
        this.active.delete(key);
        resolve({ code, stdout, stderr });
      });
      child.on("error", (err) => {
        clearTimeout(timer);
        this.active.delete(key);
        resolve({ code: -1, stdout, stderr: err.message });
      });
    });
  }
}

async function resolveSbomPath(
  explicit: string | undefined,
  dataDir: string | undefined,
  vibeId: string,
): Promise<string | null> {
  if (explicit) {
    try {
      await fs.access(explicit);
      return explicit;
    } catch {
      return null;
    }
  }
  if (!dataDir) return null;
  const dbPath = path.join(dataDir, "security", "security.sqlite");
  try {
    await fs.access(dbPath);
  } catch {
    return null;
  }
  // Dynamic import keeps the dependency optional and side-effect-free at module load.
  try {
    const sqliteMod = (await import("bun:sqlite")) as {
      Database: new (path: string, opts?: { readonly?: boolean }) => SqliteDb;
    };
    const db = new sqliteMod.Database(dbPath, { readonly: true });
    try {
      const row = db
        .prepare(
          `SELECT ev.local_path AS local_path
           FROM security_evidence ev
           INNER JOIN security_scan_runs r ON ev.scan_run_id = r.run_id
           WHERE r.vibe_id = ? AND ev.type IN ('sbom-cyclonedx', 'sbom-spdx')
           ORDER BY COALESCE(r.finished_at, r.started_at, 0) DESC
           LIMIT 1`,
        )
        .get(vibeId) as { local_path?: string } | null;
      if (!row?.local_path) return null;
      try {
        await fs.access(row.local_path);
        return row.local_path;
      } catch {
        return null;
      }
    } finally {
      db.close();
    }
  } catch {
    return null;
  }
}

interface SqliteDb {
  prepare(sql: string): { get(...args: unknown[]): unknown };
  close(): void;
}

async function fetchEpssScores(
  cves: string[],
  apiBase: string,
): Promise<Map<string, { epss: number; percentile: number }>> {
  const out = new Map<string, { epss: number; percentile: number }>();
  const unique = Array.from(new Set(cves)).filter((c) => /^CVE-\d{4}-\d+$/.test(c));
  for (let i = 0; i < unique.length; i += EPSS_BATCH_SIZE) {
    const batch = unique.slice(i, i + EPSS_BATCH_SIZE);
    const url = `${apiBase}/epss?cve=${batch.join(",")}`;
    const res = await fetch(url);
    if (!res.ok) {
      throw new Error(`EPSS API ${res.status} for ${batch.length} CVEs`);
    }
    const json = (await res.json()) as EpssApiResponse;
    for (const row of json.data ?? []) {
      if (!row.cve) continue;
      const epss = typeof row.epss === "string" ? Number(row.epss) : (row.epss ?? 0);
      const percentile =
        typeof row.percentile === "string" ? Number(row.percentile) : (row.percentile ?? 0);
      if (Number.isFinite(epss) && Number.isFinite(percentile)) {
        out.set(row.cve, { epss, percentile });
      }
    }
  }
  return out;
}

function promoteSeverity(sev: SecuritySeverity): SecuritySeverity {
  const idx = SEVERITY_LADDER.indexOf(sev);
  if (idx === -1 || idx === SEVERITY_LADDER.length - 1) return sev;
  return SEVERITY_LADDER[idx + 1];
}

interface SkipFindingInput {
  ruleId: string;
  title: string;
  description: string;
  fpInput: string;
}

function makeSkipFinding(i: SkipFindingInput): NormalizedFinding {
  return {
    fingerprint: createHash("sha256").update(i.fpInput).digest("hex"),
    ruleId: i.ruleId,
    title: i.title,
    description: i.description,
    severity: "info",
    category: "policy",
  };
}

function summarize(findings: NormalizedFinding[]): SecurityScanSummary {
  const s: SecurityScanSummary = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) s[f.severity]++;
  return s;
}
