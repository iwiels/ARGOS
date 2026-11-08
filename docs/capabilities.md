# Capabilities and limits

This table distinguishes native capabilities, third-party integrations, and features that are not implemented. It is maintained against the code.

| Capability | Status | Notes |
|---|---|---|
| Findings pipeline (ingest, fingerprint dedupe, report reconciliation, lifecycle) | Native | `packages/core/src/security/` — `ingest.ts`, `report-reconcile.ts`, `agent-findings-reconcile.ts` |
| Scanner report import | Native | `packages/core/src/security/finding-import.ts` — eight documented formats, preview before persistence, bounded parsing, and batch idempotency; an imported status never counts as remediation verification |
| Finding validation | Native | `packages/core/src/security/validation.ts` — state machine (`detected` → `validating` → `confirmed`/`rejected`) driven by a generic `verifier` callback; there is no per-vulnerability-type automatic verifier |
| Finding retest | Evaluation engine present; desktop HTTP execution blocked | `packages/core/src/security/retest.ts` — PoC matchers and passive header/TLS checks require a trusted, isolated HTTP executor. The current desktop API does not supply one, so retest returns `checked: false` and preserves the finding's status. Connecting retest to the scope gateway remains pending. |
| CVSS v3.1 scoring | Native | `packages/core/src/security/cvss.ts` — deterministic, implemented from the FIRST specification; the caller supplies the 8-vector, the engine computes the score |
| Tamper-evident audit log | Native | `packages/core/src/audit/service.ts` — SHA-256 hash chain over audit entries; keyless, so it detects edits and gaps, not a writer with direct database access |
| Compliance and control mapping | Native | `packages/core/src/compliance/` — maps findings to **NIST CSF v2.0**, **ISO/IEC 27001:2022**, **SOC 2**, **NIS2**, and **DORA**. PCI DSS shows reference IDs and heuristic finding signals only; it is not an assessment or evidence of compliance. |
| Governance panel | Native | `packages/app/src/pages/governance.tsx` — audit-chain integrity and per-agent activity |
| Multi-agent team protocol | Native | `argos-config/AGENTS.md` + `argos-config/agent/*.md` — shared-memory finding contract across the agent team |
| Authenticated browser hunting (`web.browse`) | Conditional runtime capability | Enabled only after the pinned worker passes its Chromium sandbox preflight. Browser traffic uses the isolated scope gateway. Verified locally on Windows/WSL2 amd64; the ARM64 browser remains disabled in packages built under amd64 emulation. |
| Report exports | Native | `packages/core/src/security/export/` and `packages/core/src/security/pdf.ts` — SARIF v2.1.0, DefectDojo, JUnit XML, HTML, CycloneDX SBOM, HAR, CSV, Markdown, and PDF |
| Security scanners | Third-party integrations; container runtime required | The Go module contains wrappers for Nuclei, httpx, katana, ffuf, sqlmap, dalfox, schemathesis, tlsx, naabu, gitleaks, Trivy, Semgrep, subfinder, dnsx, gau, and interactsh-client. Desktop scans require the package-pinned worker image and scope gateway. A missing runtime blocks scans. Individual scanners are downloaded on demand and retain their own licenses; container integration tests do not establish that every third-party scanner works on every target. |
| Intercepting proxy (manual request tampering) | Not implemented | No proxy server or manual request editor is included |
| Cross-file / semantic code analysis (CodeQL) | Implemented, disabled by default | `code.semantic` and the CodeQL component of `code.analyze` require `ARGOS_CODEQL_USE_ALLOWED=true` after the operator confirms the target and use are permitted by GitHub's terms. Without that setting, `code.analyze` can still report its Semgrep results. See [third-party notices](../THIRD_PARTY_NOTICES.md). |
| Remote DNS out-of-band service | Not implemented | Argos has a local HTTP callback collector; DNS callbacks require separately configured infrastructure |
| L3-L4 multi-agent autonomy | Not implemented | The current runtime does not provide continuous autonomous red-team campaigns |
| SBOM of the audited target | Third-party integration (partial) | `code.sbom` invokes Trivy for a local repository or filesystem and returns a CycloneDX artifact and SHA-256. Container-image input is unavailable in the isolated worker. This target inventory is separate from the audit report's CycloneDX export and the CI SBOM of Argos itself. |

---

## Architecture

Argos is organized as a monorepo featuring an Electron desktop shell, a SolidJS renderer, an Effect-TS backend runtime sidecar, and a Go toolchain for the security scanners:

```
argos-bin/                  # Go MCP servers; the desktop Linux profile enables orchestration and web when preflight passes
argos-config/               # Agent, command and skill definitions that drive the audit team
packages/
├── desktop/                # Electron main process, preload scripts, native IPC
├── app/                    # SolidJS frontend application (renderer process)
├── ui/                     # Shared UI design system and components
├── argos/                  # Server entry point & CLI runtime (built to dist/node/node.js)
├── server/                 # HTTP API route handlers and endpoints
├── core/                   # Security engine, database (SQLite/Drizzle), session runner
├── llm/                    # Multi-provider LLM integrations (OpenAI, Anthropic, Ollama, etc.)
├── plugin/                 # Argos plugin contracts
├── sdk/js/                 # Generated API client SDK
├── http-recorder/          # Test fixture recording utilities
├── effect-drizzle-sqlite/  # Drizzle ORM adapter for Effect-TS
└── script/                 # Build and release tooling
```

### Dependency Chain

```
desktop (@argos/desktop)
   ├── app (@argos/app) → ui (@argos/ui)
   └── argos (WSL2 sidecar on Windows, local server on Linux)
          └── server (@argos/server)
                 └── core (@argos/core)
                        ├── effect-drizzle-sqlite (@argos/effect-drizzle-sqlite)
                        └── llm (@argos/llm)
```

`argos-bin` sits outside this chain: it is a separate Go module compiled to standalone executables (`argos-web`, `argos-lan`, `argos-es`) that Argos reaches as external MCP server processes, not as in-process imports. Linux packages also contain `argos-runner`, an early-access client for an existing Argos server and preconfigured session. The desktop enables orchestration and conditionally enables web auditing after container preflight; LAN and Elasticsearch are outside this desktop profile. Windows provisions a private Debian Slim WSL2 distro named `ArgosRuntime`. `argos-config` defines the agents, commands and skills the runtime loads. See the [source publication verification](publication-readiness.md) for tested coverage and remaining release limits.

---

## Benchmark evidence

The versioned light-mode baseline dated 2026-10-21 records 100% precision and recall on 18 measurable vectors of a fixed 44-vector fixture, and 40.9% recall across the full catalog. Nine more vectors require heavy third-party scanners and 17 are unsupported. These are baseline values, not a fresh result for every revision. This benchmark does not measure the AI-agent workflow, compliance mapping, or finding retest. See [method and limits](benchmark.md).

The [OWASP APTS mapping](apts-mapping.md) is Argos's own architecture self-assessment, not an external certification.
