# @vibecontrols/vibe-plugin-security-rescan

<!-- VIBECONTROLS_OSS_HEADER_START -->

> **License**: MIT — see [LICENSE](./LICENSE).
> **Note**: This plugin is open source. The `@vibecontrols/agent` runtime that loads it is **not** open source — it is a proprietary product of Burdenoff Consultancy Services Pvt. Ltd. See [vibecontrols.com](https://vibecontrols.com) for the agent.

<!-- VIBECONTROLS_OSS_HEADER_END -->

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

<!-- VIBECONTROLS_OSS_FOOTER_START -->

---

## License

Released under the [MIT License](./LICENSE).

Copyright (c) 2026 Burdenoff Consultancy Services Private Limited, Algoshred Technologies Private Limited, and all its sister companies.

Maintainer: **Vignesh T.V** — <https://github.com/tvvignesh>

## Credits

This plugin builds on the following upstream open-source projects. All trademarks and copyrights remain with their respective owners.

- **Grype** — <https://github.com/anchore/grype>
- **FIRST.org EPSS** — <https://www.first.org/epss/>

## About VibeControls

**VibeControls** is the agentic engineering mission control for AI-native teams. Vibe-plugins extend the VibeControls agent with new providers, tools, sessions, tunnels, storage backends, and security stages.

- Website: <https://vibecontrols.com>
- Documentation: <https://docs.vibecontrols.com>
- Plugin SDK: <https://github.com/algoshred/vibecontrols-plugin-sdk>
- All plugins: <https://github.com/algoshred?q=vibe-plugin-&type=all>

## Important: agent is not open source

The `@vibecontrols/agent` runtime that loads and orchestrates these plugins is **closed source** and proprietary to Burdenoff Consultancy Services Pvt. Ltd. Only the plugin contract and the plugins themselves are released under MIT. If you want a fully self-hostable agent, please open an issue or contact the maintainer.

<!-- VIBECONTROLS_OSS_FOOTER_END -->
