/**
 * GrypeEpssRescanProvider — implements SecurityProvider for stage
 * `scheduled.rescan`.
 *
 * Wave 2 scaffold. Real implementation will:
 *   1. Locate the latest cached SBOM evidence (cyclonedx-json) for the
 *      vibe by walking the agent's local scan_runs / evidence tables.
 *   2. Spawn the pinned Grype binary in offline mode against the SBOM.
 *   3. Optionally enrich each finding's CVE with an EPSS score by
 *      querying https://api.first.org/data/v1/epss?cve=<cve>.
 *   4. Emit NormalizedFinding[] with `category: "vuln"`, evidence as
 *      grype-json, and tag the evidence with `epss: "unavailable"`
 *      when FIRST.org cannot be reached.
 *
 * For now, the run() stub returns one info-severity NormalizedFinding
 * that explains the pending integration; the orchestration / dispatch
 * surface area is complete so the meta plugin can already exercise the
 * provider lifecycle end-to-end.
 */
import { fingerprint } from "@vibecontrols/vibe-plugin-security/fingerprint";
import type { HostServices } from "@vibecontrols/plugin-sdk/contract";
import type {
  NormalizedFinding,
  ScanEvidenceArtifact,
  SecurityProvider,
  SecurityProviderMetadata,
  SecurityScanInput,
  SecurityScanResult,
  SecurityScanSummary,
  SecurityStage,
} from "@vibecontrols/vibe-plugin-security/types";

import { EPSS_SOURCE, GRYPE_VERSION } from "./tools-manifest.js";

interface RescanConfig {
  enrichWithEpss?: boolean;
  epssEndpoint?: string;
  offline?: boolean;
}

export class GrypeEpssRescanProvider implements SecurityProvider {
  readonly name = "grype-epss-rescan";
  readonly stage: SecurityStage = "scheduled.rescan";
  readonly toolVersion = `grype@${GRYPE_VERSION}+epss@${EPSS_SOURCE}`;

  private host?: HostServices;

  async init(host: HostServices): Promise<void> {
    this.host = host;
  }

  async ensureToolInstalled(): Promise<void> {
    // Wave 2 scaffold — actual Grype install happens here once the run()
    // implementation lands. The pinned binary is declared in
    // ./tools-manifest.ts so the host can pre-stage it if it wants to.
    this.host?.logger?.info?.(
      "security-rescan-provider",
      `scaffold: Grype install deferred; pinned version is ${GRYPE_VERSION}`,
    );
  }

  async run(input: SecurityScanInput): Promise<SecurityScanResult> {
    const startedAt = Date.now();
    const cfg = (input.config as RescanConfig) ?? {};

    input.onProgress?.({ pct: 10, message: "Locating cached SBOM" });
    input.onProgress?.({ pct: 50, message: "Scaffold: Grype rescan deferred" });

    const finding: NormalizedFinding = {
      fingerprint: fingerprint({
        providerName: this.name,
        ruleId: "scaffold.pending",
        file: input.repoLocalPath,
      }),
      ruleId: "scaffold.pending",
      title: "Scheduled rescan scaffold — real Grype/EPSS integration pending",
      description:
        `This is a Wave 2 scaffold of the ${this.name} provider for the ${this.stage} stage. ` +
        `The real implementation will reload cached SBOM evidence, run Grype offline (${GRYPE_VERSION}), ` +
        `and optionally enrich findings via the EPSS feed (${EPSS_SOURCE}). ` +
        (cfg.enrichWithEpss && cfg.offline
          ? `EPSS enrichment was requested but offline=true was set; tagging evidence epss=unavailable.`
          : `Configure enrichWithEpss=true to enable EPSS enrichment.`),
      severity: "info",
      category: "policy",
      rawProviderRef: "scaffold",
    };

    const evidence: ScanEvidenceArtifact[] = [];

    input.onProgress?.({ pct: 100, message: "Scaffold run complete" });

    return {
      runId: input.runId,
      status: "succeeded",
      findings: [finding],
      evidence,
      durationMs: Date.now() - startedAt,
      summary: summarize([finding]),
    };
  }

  async cancel(_runId: string): Promise<void> {
    // No subprocess in the scaffold yet — nothing to cancel.
  }

  metadata(): SecurityProviderMetadata {
    return {
      stage: this.stage,
      supportedProfiles: ["backend", "frontend", "cli", "sdk", "mcp", "container", "iac"],
      toolVersion: this.toolVersion,
      description:
        "Scheduled nightly rescan provider — Grype offline + optional EPSS enrichment (Wave 2 scaffold).",
    };
  }
}

function summarize(findings: NormalizedFinding[]): SecurityScanSummary {
  const s: SecurityScanSummary = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) s[f.severity]++;
  return s;
}
