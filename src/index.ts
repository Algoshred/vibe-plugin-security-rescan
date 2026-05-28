/**
 * @vibecontrols/vibe-plugin-security-rescan
 *
 * Scheduled nightly rescan provider. Registers as a `security.runtime`
 * provider with @vibecontrols/vibe-plugin-security on the host's
 * ServiceRegistry. The user picks "grype-epss-rescan" as their default
 * provider for the `scheduled.rescan` stage and the meta plugin
 * dispatches.
 *
 * Wave 2 scaffold — real Grype + EPSS integration pending.
 */
import { ProviderRegistry, TelemetryEmitter, createLifecycleHooks } from "@vibecontrols/plugin-sdk";
import type {
  HostServices,
  ProfileContext,
  VibePlugin,
  VibePluginFactory,
} from "@vibecontrols/plugin-sdk/contract";

import { GrypeEpssRescanProvider } from "./provider.js";

const PLUGIN_NAME = "security-rescan";
const PLUGIN_VERSION = "2026.528.2";

export const createPlugin: VibePluginFactory = (_ctx: ProfileContext): VibePlugin => {
  const provider = new GrypeEpssRescanProvider();
  const telemetry = new TelemetryEmitter(PLUGIN_NAME, PLUGIN_VERSION);

  const lifecycle = createLifecycleHooks({
    name: PLUGIN_NAME,
    telemetryEventName: "security.rescan.ready",
    onInit: async (host: HostServices) => {
      await provider.init(host);
      const registry = new ProviderRegistry(host);
      registry.registerProvider("security.runtime", "grype-epss-rescan", provider);
      telemetry.emit("security.rescan.registered", {
        provider: "grype-epss-rescan",
        toolVersion: provider.toolVersion,
      });
    },
  });

  return {
    name: PLUGIN_NAME,
    version: PLUGIN_VERSION,
    description:
      "Scheduled nightly rescan for the scheduled.rescan lifecycle stage — Grype offline against the latest cached SBOM with optional FIRST.org EPSS enrichment.",
    tags: ["backend", "provider", "integration"],
    capabilities: {
      storage: "rw",
      subprocess: true,
      audit: true,
      telemetry: true,
    },
    onServerStart: lifecycle.onServerStart,
    onServerStop: lifecycle.onServerStop,
  };
};

export default createPlugin;
export { GrypeEpssRescanProvider } from "./provider.js";
