# Source prerelease verification

This is a historical local verification record, not a claim that a later revision has passed CI or the same checks. Re-run the relevant checks for the exact revision intended for publication; the workflow configuration alone does not establish a successful remote run.

The verification recorded on 2026-10-29 used Windows, the private Debian 13 Slim `ArgosRuntime` WSL2 distro, Docker Desktop, and Linux amd64 worker containers.

The distro uses the non-root `argos` account. Argos 0.1.0 and Node 24.21.0 were provisioned with the package checksums. Docker, the immutable worker image, and the sandboxed Chromium preflight passed from WSL. The Electron application and its active server were not restarted during verification.

## Recorded evidence (2026-10-29)

- Application tests: 694 passed; shared UI tests: 28 passed.
- Desktop suite: 216 passed after the seccomp and container execution corrections; the final packaging checks also cover runtime reinstallation with unchanged version numbers.
- Core under CI settings: 1,568 passed, 16 explicitly skipped, zero failures. A separate native Windows run crashed in Bun's native watcher module; that run is not counted as successful. WSL desktop servers disable the file watcher.
- Go tests passed, including focused sandbox and worker tests after the runtime fixes.
- Live Linux integrations run inside WSL passed for the HTTP scanner worker and Chromium worker. Both exercised an authorized local HTTP fixture and denied out-of-scope traffic or excluded routes. These tests create their own fixture and preserve controller session and operation metadata.
- Type checking and architecture dependency rules passed. Root lint reported no errors and 921 existing warnings; design auditing still reports advisory token inconsistencies.
- The full desktop production build passed with a reproducible `electron-vite` dependency patch. Its original CommonJS shim injector mistook import-like text inside the embedded server for a module import; the patch inserts the shim at the beginning of the chunk, preserving a shebang if present.
- Production dependency audit reported two low-severity advisories and no high or critical advisories at verification time.
- Gitleaks uses the default rules plus exact-value, exact-path exceptions for reviewed synthetic test credentials, public OAuth client identifiers, SDK field names, and historical documentation placeholders. A different synthetic AWS key inserted into the same test path was detected as a negative control.

## Publication and support limits

This is a source prerelease. Signed installers, a supported update feed, a complete binary dependency license inventory, and fresh platform CI results remain release requirements. The integration tests above do not measure AI-agent accuracy or every third-party scanner.

The amd64 browser passed with Chromium sandboxing enabled, a non-root container user, all container capabilities dropped, a read-only filesystem and no direct container network. Its scoped seccomp profile follows Playwright's published Docker profile and also permits `chroot` inside the browser user namespace. It does not use an unconfined seccomp profile or disable the Chromium sandbox at runtime.

ARM64 workers are cross-built. Browser preflight under amd64 emulation failed, so that artifact reports the ARM64 browser as unavailable. Native ARM64 browser support requires verification on ARM64 hardware.

The working repository retains its original history, including copied `docs/design-reference/` material that contained a third-party website delivery token. Publishing that history would expose the removed material again. Use a separately verified, sanitized publication candidate that preserves upstream attribution.

The intended publication candidate is `.artifacts/public-repository` on branch `dev`, with a portable Git bundle at `.artifacts/argos-public-source.bundle`. The fresh publication record belongs in `docs/publication-readiness.md`; it must identify the final revision and checks before publication. The historical results above do not verify that candidate. No change to remote history or repository visibility is authorized by this verification record.
