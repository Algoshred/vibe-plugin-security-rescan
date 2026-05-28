/**
 * Grype binary manifest. sha256 values pinned to v0.83.0 release
 * assets at https://github.com/anchore/grype/releases/tag/v0.83.0.
 *
 * Updating the version is a deliberate, audited operation: bump the
 * version + sha256 here, re-run sanity, publish a new CalVer release.
 * The agent picks up the new pin via the new plugin version.
 *
 * EPSS data is fetched from FIRST.org at runtime — there is no binary
 * to pin. The provider tags evidence with `epss: "unavailable"` when
 * the FIRST.org endpoint is unreachable (e.g. offline runners).
 */
import type { ToolManifest } from "@vibecontrols/vibe-plugin-security/tool-installer";

export const GRYPE_VERSION = "0.83.0";
export const EPSS_SOURCE = "first.org";

export const TOOLS_MANIFEST: ToolManifest = {
  grype: {
    version: GRYPE_VERSION,
    binaryName: "grype",
    versionMatcher: GRYPE_VERSION.replace(/\./g, "\\."),
    downloads: {
      "linux-x64": {
        url: `https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/grype_${GRYPE_VERSION}_linux_amd64.tar.gz`,
        sha256: "d7e333b549a9f989948c4efe65ca9101fcd9cdd7ca39af78b7445abd7bfe4f26",
        binaryWithinArchive: "grype",
        archive: "tar.gz",
      },
      "linux-arm64": {
        url: `https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/grype_${GRYPE_VERSION}_linux_arm64.tar.gz`,
        sha256: "80f13f7da2fe6afa684a236611eb9a49af0c05bdc532f41a39907766c841aad8",
        binaryWithinArchive: "grype",
        archive: "tar.gz",
      },
      "darwin-x64": {
        url: `https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/grype_${GRYPE_VERSION}_darwin_amd64.tar.gz`,
        sha256: "fc46f9ee5e76262f990834f120af63ab4952180a0d416228ad4fdf38bf02e1a3",
        binaryWithinArchive: "grype",
        archive: "tar.gz",
      },
      "darwin-arm64": {
        url: `https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/grype_${GRYPE_VERSION}_darwin_arm64.tar.gz`,
        sha256: "c9b2130a8312341476f4c624f95c58b5edf0a51b1d16263a96d6c985d74ba893",
        binaryWithinArchive: "grype",
        archive: "tar.gz",
      },
    },
  },
};
