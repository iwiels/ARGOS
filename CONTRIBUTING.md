# Contributing to Argos

Thank you for your interest in contributing to **Argos**! We welcome bug reports, documentation enhancements, feature proposals, and pull requests from the security and open-source communities.

Please review this guide before submitting contributions.

---

## Code of Conduct

All contributors and maintainers are expected to abide by our [Code of Conduct](CODE_OF_CONDUCT.md) (Contributor Covenant v2.1). Please keep discussions respectful, constructive, and inclusive.

---

## DCO and contribution terms

A DCO sign-off or CLA is not currently required. Contributions are submitted under the license identified by the repository's `LICENSE` and applicable notices. If you choose to use `git commit -s`, Git publishes the name and email in the sign-off; use an address you intend to make public.

## Commit Message Conventions

Contributors are encouraged to use [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/); CI does not enforce this format.

```text
<type>(<scope>): <short description>

[optional body]

[optional footer(s)]
```

### Allowed Types

- `feat`: A new user-facing or platform feature
- `fix`: A bug fix
- `docs`: Documentation updates
- `refactor`: Code reorganization with no functional or behavioral changes
- `perf`: Performance optimizations
- `test`: Adding or correcting tests
- `build`: Changes to build systems, bundlers, or external dependencies
- `ci`: Changes to CI/CD workflows and automation scripts
- `chore`: Maintenance tasks, tooling updates, or miscellaneous tasks

### Scopes

Common scopes correspond to monorepo packages or subsystems:
`desktop`, `app`, `ui`, `core`, `server`, `llm`, `sdk`, `argos-bin`, `deps`.

---

## Local Development Setup

### Prerequisites

- **Node.js**: >= 22.13.0; CI uses Node 22. The pinned pnpm 11 does not support Node 20; see [pnpm compatibility](https://pnpm.io/installation#compatibility).
- **pnpm**: 11.x (`pnpm@11.8.0`)
- **Bun**: 1.3.14 recommended, matching CI
- **Go**: the version declared in `argos-bin/go.mod` (currently `1.26.3`)

### Getting Started

1. Fork and clone the repository:
   ```bash
   git clone https://github.com/<your-username>/argos-auditor.git
   cd argos-auditor
   ```
2. Install workspace dependencies:
   ```bash
   pnpm install --frozen-lockfile
   ```
3. Start development:
   - Run Desktop (Electron): `pnpm dev`
   - Run Web App (SolidJS): `pnpm dev:web`

For desktop runtime requirements and packaging with the Docker worker, see [Installation](docs/installation.md).

---

## Running Verification & Tests

Before opening a pull request, verify that all linters, types, and test suites pass locally:

```bash
# Install the browser used by the frontend smoke and regression tests
pnpm --filter @argos/app exec playwright install chromium

# Run unit, UI DOM, mocked browser, architecture, and Go tests
pnpm test:all

# Lint and type-check workspace packages
pnpm lint
pnpm typecheck:all

# Verify generated finding rules and audit design tokens
pnpm check:rules
pnpm audit:design
```

On Linux, Playwright may also need system libraries; `pnpm --filter @argos/app exec playwright install --with-deps chromium` installs those dependencies on supported systems.

For focused checks, use `pnpm test:unit`, `pnpm test:ui:dom`, `pnpm test:browser`, or `pnpm test:go`. `pnpm test` runs only the renderer and shared UI subset; `pnpm typecheck` checks the desktop dependency graph. The browser suite starts its own Vite frontend and mocks the API, so a passing result does not verify the live audit server, installed scanners, or packaged Electron application.

---

## Security-sensitive changes

- Network tools must enforce the engagement scope before sending traffic and include tests for allowed and blocked targets.
- Keep phase gates and operator approvals for active or potentially destructive behavior.
- Document third-party services and data leaving the operator's machine.
- Do not add secrets, real customer evidence, or non-synthetic targets to source, fixtures, or history.

## Pull Request Guidelines

1. **Create a Feature Branch**: Keep changes focused on a single topic:
   ```bash
   git checkout -b feat/cvss-severity-matrix
   ```
2. **Include Tests**: If adding or fixing functionality, include accompanying tests.
3. **No Secrets**: Never commit API keys, personal access tokens, or sensitive test data.
4. **Follow the Template**: Complete the pull request checklist and describe changes clearly.
