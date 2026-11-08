# Argos Desktop Agent Instructions

## Project Overview

This is the **Argos Desktop** application — an Electron-based AI security operations platform built with SolidJS. Licensed under MIT, see NOTICE.

### Architecture

- **argos-bin/** (Go module): Security tooling compiled to standalone executables — `argos-web`, `argos-lan`, `argos-es` — that Argos drives as external MCP servers. Owns scope enforcement, sandboxed execution, and the wrappers around third-party scanners
- **argos-config/**: Runtime agent, command, and skill definitions (the audit team playbooks) that the server loads at runtime; data, not compiled code
- **packages/desktop/** (`@argos/desktop`): Electron main process, preload scripts, and build config
- **packages/app/** (`@argos/app`): SolidJS frontend (renderer process)
- **packages/ui/** (`@argos/ui`): Shared UI components
- **packages/sdk/js/** (`@argos/sdk`): Generated API client SDK
- **packages/argos/** (`argos`): Core server, built via its own `script/build-desktop.ts` to `dist/node/node.js`, loaded by the sidecar
- **packages/server/** (`@argos/server`): API route handlers
- **packages/core/** (`@argos/core`): Security engine (findings ingest/validation/retest, CVSS v3.1, SARIF export, compliance derivation, hash-chained audit log), database (SQLite/Drizzle), file system, session management
- **packages/llm/** (`@argos/llm`): LLM provider integrations
- **packages/plugin/** (`@argos/plugin`): Plugin system (type-only contract; no runtime import path currently exercises it)
- **packages/http-recorder/** (`@argos/http-recorder`): HTTP request recording, used by the recorded-fixture tests under `packages/core/test` that exercise the argos server
- **packages/effect-drizzle-sqlite/** (`@argos/effect-drizzle-sqlite`): Drizzle ORM adapter
- **packages/script/** (`@argos/script`): Build scripts

### Key Patterns

- Renderer process communicates with main process via `window.api` (defined in `src/preload`)
- Main process registers IPC handlers in `src/main/ipc.ts`
- Frontend uses SolidJS with `createStore` (preferred over multiple `createSignal`)
- Uses Effect-TS for async operations in server code
- Desktop sidecar runs the server in-process via `virtual:argos-server` Vite plugin
- `electron.vite.config.ts` resolves `virtual:argos-server` to `../argos/dist/node/node.js`
- The CLI/terminal command surface (`opencode` binary / `argos` package run from a shell) shares this codebase but is a separate entry point (`packages/argos/src/index.ts`) from the desktop server entry (`src/node.ts`) — code reachable only from the CLI entry does not ship in the desktop installer
- `argos-bin` is a separate Go module: Argos reaches it over MCP as child processes, never as in-process imports. Changes there need `go build` + Go tests, not the TypeScript toolchain
- Third-party scanners (nuclei, httpx, katana, sqlmap, dalfox, semgrep, trivy, gitleaks, …) are downloaded on demand from GitHub Releases with pinned versions and SHA-256 verification — see `argos-bin/cmd/web/tools/spec.go` and `download.go`. Do not assume they are installed locally
- `argos-config/agent/*.md` and `argos-config/command/*.md` are the contract between the runtime and the LLM team: findings reach the app panels only through `argos_memory_save` with an exact `argos_session_id`
- `argos-config/templates/nuclei/` holds the Argos nuclei packs (`registry.json` + one dir per pack). The Go side resolves them from `ARGOS_NUCLEI_PACKS_DIR` → `$OPENCODE_CONFIG_DIR/templates/nuclei` → `<exe>/../argos-config/templates/nuclei`; `web.templates` lists them and `web.scan` accepts `packs`. Argos metadata travels in `info.metadata` (`argos-pack`, `argos-evidence`, `argos-requires-auth`, `argos-severity-floor`, `argos-owasp`) and is consumed by `parse.go`
- Two session layers with different owners: `packages/argos/src/session/*` is the agent runtime (prompt, LLM loop, compaction), `packages/core/src/session/*` is the engagement record (store, budget, kill-switch, audit). Dependency is one-way (`argos → core`), enforced by `.arch-rules.json` — see `docs/adr/0008-sesion-runtime-vs-engagement.md`

### Dependency Chain

```
@argos/desktop → @argos/app → @argos/ui
@argos/desktop → argos (via sidecar, loaded as virtual module)
argos → @argos/server → @argos/core → @argos/effect-drizzle-sqlite, @argos/llm
```

`argos-bin` sits outside this chain (standalone executables over MCP); `argos-config` is loaded as data at runtime.

## Development

### Local Dev

- Todos los paquetes y dependencias internas usan el scope `@argos/*`.
- **App (renderer)**: `bun dev` from `packages/app` → opens `http://localhost:4444`

### Building

```bash
bun --cwd packages/desktop build        # Build Electron app
bun --cwd packages/desktop package:win  # Package for Windows
bun --cwd packages/desktop package:mac  # Package for macOS
bun --cwd packages/desktop package:linux # Package for Linux
```

### Server Build

The server is built separately via `bun run packages/argos/script/build-desktop.ts` which outputs `packages/argos/dist/node/node.js`. This file is loaded by the Electron sidecar at runtime.

### Linting

```bash
oxlint  # Run linter
```

### Type Checking

```bash
bun --cwd packages/desktop typecheck
```

## Debugging

- NEVER try to restart the app, or the server process, EVER.
- For local UI/CSS changes, use the app dev server directly
- Open `http://localhost:5173` to verify UI changes (electron-vite dev server port)

## Conventions

- Use `createStore` over multiple `createSignal` calls
- Always prefer parallel tool calls when applicable
- Follow existing code patterns in the file you're editing
- Never add comments unless explicitly asked

## Dependency Management

- Use `pnpm` for all dependency management tasks at the root level.
- All internal workspace packages use the canonical `@argos/*` scope (`@argos/desktop`, `@argos/app`, `@argos/core`, `@argos/server`, `@argos/ui`, `@argos/llm`, `@argos/sdk`, `@argos/plugin`, `@argos/script`, `@argos/http-recorder`, `@argos/effect-drizzle-sqlite`).
- When resolving CJS/ESM interop errors (e.g., `does not provide an export named 'default'`) for dependencies in the Electron renderer, use the `vite-plugin-cjs-interop` configuration in `packages/desktop/electron.vite.config.ts`.
- Ensure you set `client: true` in the `cjsInterop` configuration since the renderer runs in a browser context.

## Known Risks

- **`effect@4.0.0-beta.74`**: the entire `packages/core` backend runs on a beta release of Effect-TS, not a stable version. This is an accepted, documented risk for now — no stable release combination exists yet that provides the APIs the codebase depends on. Revisit once Effect ships a stable 4.x and re-evaluate migrating off the beta line (tracked as a v1.1 backlog item).
  - **Known consequence**: version gaps between the beta core and its companion packages are real, not theoretical. Example: `effect@4.0.0-beta.74`'s `FileSystem` interface declares `realPath`, but `@effect/platform-node@4.0.0`'s concrete Node implementation doesn't implement it — calling it silently resolves to a no-op. Worked around locally in [fs-util.ts](packages/core/src/fs-util.ts) by resolving `realPath` directly against Node's `fs/promises` instead of the upstream platform layer. This is a local patch over an upstream gap, not a real fix — remove it once `@effect/platform-node` catches up to the interface it's implementing.
