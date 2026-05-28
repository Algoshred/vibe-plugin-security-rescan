# @vibecontrols/vibe-plugin-security-rescan

Scheduled nightly rescan provider for the `scheduled.rescan` lifecycle stage in [VibeControls](https://vibecontrols.com). Registers under provider name `grype-epss-rescan` against provider type `security.runtime`, wrapping pinned Grype (`0.83.0`) with optional EPSS score enrichment from FIRST.org. **Wave 2 scaffold — real tool integration pending.**

The host security meta plugin ([`@vibecontrols/vibe-plugin-security`](https://www.npmjs.com/package/@vibecontrols/vibe-plugin-security)) dispatches scan runs for `scheduled.rescan` to this provider when the user picks "grype-epss-rescan" as their default.

## Install

```bash
vibe plugin install @vibecontrols/vibe-plugin-security-rescan
vibe security providers set-default --stage scheduled.rescan --provider grype-epss-rescan
```

The plugin downloads the Grype binary automatically on first use (sha256-verified per platform) into `~/.boff/vibecontrols/agents/<profile>/tools/grype/`.

## Planned behavior

- Reload the latest SBOM evidence (cyclonedx-json) from the agent's local cache for the vibe being rescanned.
- Run `grype sbom:<path> -o json` in offline mode against the cached SBOM.
- Normalize matches to `category: "vuln"` with severity derived from Grype's `severity` field.
- For each finding with a CVE, optionally enrich with an EPSS score (`probability`, `percentile`) by calling `https://api.first.org/data/v1/epss?cve=<cve>`.

## Skip / fallback paths

- **EPSS offline**: when the FIRST.org endpoint is unreachable (offline runners, blocked egress), the provider emits findings without EPSS scores and tags the evidence with `epss: "unavailable"`.
- **Grype DB stale**: if the Grype vuln DB is older than the configured `maxDbAgeDays`, the provider records a `policy` severity-low finding noting the staleness and runs anyway.

## Configuration

Per-vibe config (stored in `RepositorySecurityConfig.pluginAssignments["scheduled.rescan"].config`):

```yaml
provider: grype-epss-rescan
config:
  enrichWithEpss: true # call FIRST.org for each CVE
  epssEndpoint: https://api.first.org/data/v1/epss
  offline: false # set true to skip EPSS calls entirely
  maxDbAgeDays: 7 # warn if Grype DB is older than this
```

## License

Proprietary — Burdenoff Consultancy Services Pvt. Ltd.
