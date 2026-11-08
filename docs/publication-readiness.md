# Source publication verification — 2026-11-08

This record covers a source prerelease for a local operator. It does not establish a supported binary release, autonomous pentesting accuracy, or parity with another product.

## Publication artifact

The publication candidate is a separate repository at `.artifacts/public-repository`, on branch `main`, created as a single initial commit from the current clean source tree. Its final revision, tree, source-file digest, archive hashes and file count are recorded in `.artifacts/publication-manifest.json`. The portable outputs are `.artifacts/argos-public-source.bundle` and `.artifacts/argos-public-source.zip`.

The candidate is a single-commit snapshot of the current source tree. Generated executables, build output, local tool configuration, private audit data and verification logs are excluded. Upstream licenses and notices are preserved. Binary formats are protected from line-ending conversion.

The original private repository retains historical material that must not be made public. Removing files from its latest tree does not remove their historical copies. Publish the verified candidate to an empty repository; retain the original as a private backup. Do not merge the original Git ancestry back into the publication candidate. No remote history, repository name or visibility was changed during these checks.

## Local checks

Verification used Windows, Node 24.15.0, Bun 1.3.14, pnpm 11.8.0 and the Go toolchain selected by `argos-bin/go.mod`. Tests that require HTTP listeners or temporary Git repositories were run outside the filesystem/network sandbox. They use controlled fixtures, not third-party audit targets.

These results were recorded for the earlier source snapshot. They were not re-run for this regenerated single-commit candidate; re-run the matrix before publishing. The brand scan for the regenerated candidate is recorded in `.artifacts/publication-manifest.json`.

| Check | Result |
| --- | --- |
| App unit tests | 718 passed |
| Shared UI unit / DOM tests | 28 / 18 passed |
| Browser regression and accessibility tests | 17 passed, including primary routes, keyboard navigation, settings, responsive layout and chat interactions; API responses are mocked |
| Core | 1,601 passed, 17 explicitly skipped |
| Desktop | 117 passed |
| Argos runtime | 2,751 passed, 48 explicitly skipped, 1 todo, 0 failed |
| Server contracts | 4 passed |
| LLM | 275 passed, 30 explicitly skipped |
| HTTP recorder / SQLite adapter | 66 / 14 passed |
| Runtime playbook and lint-rule tests | 24 passed |
| Type checking | All 11 package targets passed |
| Server bundles / Electron production bundle | Both Node/WSL bundles and the desktop build completed successfully |
| Go | All packages passed an uncached run |
| Architecture / finding-rule synchronization | Passed |
| Workflow validation | Both workflows passed actionlint; shell blocks and benchmark report guard were checked separately |
| Dependency lock | Frozen, offline lockfile verification passed |
| Secret scan | Not re-run for the regenerated candidate; `secretScanner` is `null` in the manifest |

The local evidence is stored under `.artifacts/release-audit-2026-11-07/` and `.artifacts/release-audit-2026-11-08/`. Those directories are ignored and are not part of the public source. Some Bun runs print an `EPERM` directory-discovery diagnostic despite exiting successfully; these diagnostics remain in the logs. Native watcher, PTY, optional-provider and unsupported file-symlink cases are recorded as omissions rather than passing tests. Directory-link tests still run on Windows using junctions; Linux CI retains file-symlink coverage.

The browser suite checks automatically detectable accessibility issues; it does not replace a manual assistive-technology audit. A successful bundle compilation does not verify a signed installer or each third-party scanner. Fresh remote CI and native platform installation checks remain necessary for binary releases.

## Material corrections

- Recovered corrupted images and audio from verified historical bytes, repaired the public branding, and checked decoding and UI/public mirrors.
- Packaging includes every referenced WASM file and fails when a required file is absent. Both server build results are checked. Server freshness includes LLM sources, dependency manifests, patches and the lockfile; requested worker builds go through Docker's build cache instead of trusting the package version alone.
- The session API uses the real execution layer for explicit resume. A failed run-status query produces a recoverable error in the session view.
- HTTP retest has no direct host-network fallback. Without a controller-supplied isolated executor it reports `checked: false`, performs no HTTP request and preserves the finding. Scope and PoC safety checks precede any supplied executor.
- Fixed empty Gemini/Vertex assistant messages and preserved retry classification when the provider SDK wraps a streamed timeout.
- Updated stale test fixtures to use current provenance, authentication, service-context and CLI contracts. Test examples use reserved domains, TEST-NET addresses and generic local paths.
- CI now covers backend packages, UI DOM/browser tests, runtime playbooks and all package type checks. Its benchmark gate rejects a missing, unmeasured, unchecked or failed report.

## Known limits

The production dependency audit on 2026-11-08 reports **zero critical, high or low advisories and two moderate advisories**, affecting `glob` ([GHSA-3g3m-2fjr-6pw4](https://github.com/advisories/GHSA-3g3m-2fjr-6pw4)) and `minimatch` ([GHSA-g3hv-75wg-m249](https://github.com/advisories/GHSA-g3hv-75wg-m249)). Their patched major versions change matcher APIs used by transitive consumers; they were not forced through an incompatible global override. The compatible `provider-utils` patch was installed and unused KaTeX dependencies were removed. See [SECURITY.md](../SECURITY.md) for the remaining dependency risk.

Effect remains on the documented beta release. The native ARM64 browser has not been verified on ARM64 hardware. Retest transport integration, signed installers, a supported update feed and a complete binary dependency license inventory remain release work. No speedup or AI-agent accuracy claim follows from this verification.

## Maintainer publication gate

Before publishing, verify the final candidate manifest and its secret-scan results, choose an empty remote for the sanitized repository, and review the public repository description and default branch. Private vulnerability reporting must be enabled and checked once a public repository exists; the corresponding API returned 404 for the current private repository. Do not promise a working private report form before that check. Publication and remote changes require the maintainer's explicit approval.
