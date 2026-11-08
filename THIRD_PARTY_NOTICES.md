# Third-party software and assets

Argos's root MIT license applies to Argos-authored code. It does not replace the terms of third-party software that Argos downloads or invokes. Desktop packages ship Argos MCP servers and configuration. When the Linux-first worker package is built, it also includes Playwright Core and its pinned Chromium browser bundle; the other security tools listed below are downloaded on demand to the user's tool cache. Their upstream licenses and terms continue to apply.

| Tool | Pinned version | Upstream license or terms |
|---|---:|---|
| Playwright Core and its pinned Chromium browser bundle | `argos-bin/worker/browser/package-lock.json` and `argos-bin/worker/Dockerfile` | Playwright Core is [Apache License 2.0](https://github.com/microsoft/playwright/blob/main/LICENSE); the worker image copies its license and the Chromium license inventory shipped with the pinned browser bundle to `/usr/share/doc/argos-browser/licenses`. Chromium and bundled components retain their upstream notices, including the [Chromium license inventory](https://chromium.googlesource.com/chromium/src/+/main/LICENSE). |
| Nuclei v3.11.0, httpx v1.10.0, katana v1.6.1, subfinder v2.14.0, dnsx v1.3.0, interactsh-client v1.3.1, tlsx v1.1.7, naabu v2.3.1 | `argos-bin/cmd/web/tools/spec.go` | ProjectDiscovery repositories; MIT. [Nuclei](https://github.com/projectdiscovery/nuclei/blob/dev/LICENSE.md), [httpx](https://github.com/projectdiscovery/httpx/blob/main/LICENSE.md), [katana](https://github.com/projectdiscovery/katana/blob/main/LICENSE.md), [subfinder](https://github.com/projectdiscovery/subfinder/blob/main/LICENSE.md), [dnsx](https://github.com/projectdiscovery/dnsx/blob/main/LICENSE.md), [interactsh](https://github.com/projectdiscovery/interactsh/blob/main/LICENSE.md), [tlsx](https://github.com/projectdiscovery/tlsx/blob/main/LICENSE.md), [naabu](https://github.com/projectdiscovery/naabu/blob/dev/LICENSE.md) |
| Nuclei templates v10.4.0 | `argos-bin/cmd/web/tools/spec.go` | [ProjectDiscovery nuclei-templates](https://github.com/projectdiscovery/nuclei-templates/blob/main/LICENSE); review individual template metadata and restrictions as well. |
| gau v2.2.4 | `argos-bin/cmd/web/tools/spec.go` | [MIT](https://github.com/lc/gau/blob/master/LICENSE) |
| dalfox v3.2.0 | `argos-bin/cmd/web/tools/spec.go` | [MIT](https://github.com/hahwul/dalfox/blob/main/LICENSE) |
| ffuf v2.2.1 | `argos-bin/cmd/web/tools/spec.go` | [MIT](https://github.com/ffuf/ffuf/blob/master/LICENSE) |
| sqlmap 1.9 | `argos-bin/cmd/web/tools/spec.go` | [GNU GPL v2 or later](https://github.com/sqlmapproject/sqlmap/wiki/License) |
| Schemathesis 3.39.11 | `argos-bin/cmd/web/tools/spec.go` | [MIT](https://github.com/schemathesis/schemathesis/blob/master/LICENSE); its Python dependencies have their own terms. |
| gitleaks v8.21.2 | `argos-bin/cmd/web/tools/spec.go` | [MIT](https://github.com/gitleaks/gitleaks/blob/master/LICENSE) |
| Trivy v0.58.2 | `argos-bin/cmd/web/tools/spec.go` | [Apache License 2.0](https://github.com/aquasecurity/trivy/blob/main/LICENSE) |
| Semgrep Community Edition v1.99.0 | `argos-bin/cmd/web/tools/spec.go` | [LGPL-2.1](https://github.com/semgrep/semgrep/blob/develop/LICENSE); review the license of any separately obtained rule set. |
| CodeQL CLI v2.20.7 | `argos-bin/cmd/web/tools/spec.go` | [GitHub CodeQL Terms and Conditions](https://github.com/github/codeql-cli-binaries/blob/main/LICENSE.md). The CLI is not covered by the MIT license on CodeQL query sources. It is disabled by default; set `ARGOS_CODEQL_USE_ALLOWED=true` only after confirming that the target and use are allowed by the terms. Private or closed-source analysis requires an applicable commercial license. |

Semgrep and Schemathesis are installed from PyPI on demand; their transitive Python packages retain their own licenses and notices. Versions are pinned in the Go source. This list records the direct tools and upstream license references; it is not a machine-generated inventory of each tool's transitive dependencies. The CI SBOM describes the Argos repository build and does not include tools installed later in a user's cache.

## Other bundled material

- Chromium seccomp profile in `argos-config/runtime/chromium-seccomp.json`: adapted from [Playwright v1.64.0](https://github.com/microsoft/playwright/blob/v1.64.0/utils/docker/seccomp_profile.json), Copyright Microsoft Corporation, Apache License 2.0 (`argos-config/runtime/LICENSE.playwright`). Argos additionally permits the `chroot` syscall required by Chromium inside its user namespace when the container drops all capabilities. The browser retains its own sandbox, and workers retain no host network or Docker socket access.

- Inter variable font in `packages/app/public/assets/Inter-var.woff2`: Copyright 2016 The Inter Project Authors; SIL Open Font License 1.1. The complete notice is included in the installer at `third-party-licenses/Inter-OFL.txt`; see the [upstream license](https://github.com/rsms/inter/blob/master/LICENSE.txt).
- Adapted cybersecurity skills are under `argos-config/skills/library/` and use Apache License 2.0; see the accompanying `LICENSE-2.0.txt` and `NOTICE.md`.
- Pixel source SVGs in `docs/design-reference/streamline-pixel/` and generated icon paths in `packages/ui/src/components/pixel-icons.data.ts` are attributed to Streamline under CC BY 4.0 in the root [NOTICE](NOTICE). The [Iconify collection metadata](https://raw.githubusercontent.com/iconify/icon-sets/master/json/streamline-pixel.json) identifies the 662-icon `streamline-pixel` set and its license; other Streamline sets can have different terms.
- OpenCode-derived code and its MIT attribution are described in the root [NOTICE](NOTICE).
