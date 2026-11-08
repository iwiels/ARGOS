# Security Policy

The Argos project takes security and responsible disclosure seriously. As a security operations and auditing tool, maintaining trust, safety, and operational integrity across the platform is paramount.

---

## Supported Versions

This repository does not currently publish a formal version-support matrix or guaranteed backport policy. Check release notes for the versions covered by a published security fix.

---

## Scope

The following components within the Argos repository are in-scope for security evaluations:

- **`packages/*`**: All TypeScript/JavaScript monorepo packages, including `@argos/desktop`, `@argos/app`, `@argos/core`, `@argos/server`, `@argos/llm`, `@argos/ui`, and `@argos/sdk`.
- **`argos-bin/`**: Native Go binary utilities and orchestrator helpers.
- **`argos-config/`**: Default configurations, prompts, and security policies.

### Out of Scope

- Vulnerabilities in upstream third-party LLM providers (e.g., Anthropic, OpenAI) or external API gateways.
- Issues caused by untrusted, user-supplied custom plugins or arbitrary script execution explicitly invoked by the user in terminal sessions.
- Denial of service against local Electron instances caused by local resource starvation or OS-level restrictions.

---

## Reporting a Vulnerability

**Please do NOT disclose security vulnerabilities publicly via GitHub issues, discussions, or social media.**

To report a vulnerability responsibly:

1. Submit a private report through the [GitHub Security Advisory form](https://github.com/iwiels/ARGOS/security/advisories/new). Private vulnerability reporting was enabled and verified for this public repository on 2026-11-08.
2. If the form is unavailable, you may open a non-sensitive request asking maintainers to enable private reporting or publish a private contact route. Include no vulnerability details, credentials, target information, or customer evidence in that request. A GitHub profile is not itself a private messaging channel.

When changing repository visibility, repository owners must recheck the form's availability. Before accepting sensitive security reports, configure and verify private reporting or publish an alternative private contact route here.

### Report Contents

Please include the following details in your report:

- Type of vulnerability and affected component (`packages/core`, `desktop`, `argos-bin`, etc.).
- Step-by-step reproduction instructions or proof-of-concept (PoC).
- Potential impact and threat vector.
- Suggested mitigations or patches if known.

---

## Response & Remediation

The project does not publish guaranteed acknowledgment or remediation timelines. Keep reports private while maintainers assess impact and coordinate any disclosure.

---

## Known Dependency Risk

- **`effect@4.0.0-beta.74`**: `@argos/core` uses a beta release of Effect-TS. `packages/core/src/fs-util.ts` contains a Node filesystem workaround for an interface method missing from the installed platform adapter. No migration release date or special security-response SLA is published.

- **`glob` cancellation and `minimatch` pattern amplification**: This source prerelease retains known availability risks in `glob@13.0.5` and transitive `glob@10.5.0`, and in `minimatch@10.2.5` and transitive `minimatch@9.0.9`. The first corrected versions are [glob 14.0.2](https://github.com/isaacs/node-glob/security/advisories/GHSA-3g3m-2fjr-6pw4) and [minimatch 11.0.1](https://github.com/isaacs/minimatch/security/advisories/GHSA-g3hv-75wg-m249). These are major-version migrations, not compatible patch updates for every consumer.

  Argos's direct `Glob.scan`/`scanSync` use includes configuration, skill discovery, and filesystem helpers. Its wrapper in `packages/core/src/util/glob.ts` does not expose `AbortSignal`, so the specific cancellation-bypass condition is not established through that wrapper. This does not establish that transitive consumers are unaffected. Direct `Glob.match` uses the default minimatch optimization level, but glob 13 enables level 2 internally, where attacker-controlled patterns can trigger the amplification issue. Avoid accepting arbitrary, untrusted glob patterns as a safe resource-bounded operation.

  A standalone override to minimatch 11 would break older glob consumers: their processor expects `RegExp` pattern objects, while minimatch 11 uses a nonrecursive `Matcher` and removes the `makeRe` API. Migration requires upgrading those consumers together, validating matching and traversal behavior, and checking the transitive dependency graph. See the upstream [minimatch 11 design](https://raw.githubusercontent.com/isaacs/minimatch/v11.0.1/README.md) and [glob 14 processor](https://raw.githubusercontent.com/isaacs/node-glob/v14.0.2/src/processor.ts). Until that migration is verified, this prerelease does not claim a clean dependency audit.
