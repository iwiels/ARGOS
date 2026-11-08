# Argos Desktop

Electron shell for the Argos application. The desktop package owns the main process, preload bridge, native integrations, packaging, and the Argos server sidecar.

## Development

From the repository root, install dependencies with `pnpm install`, then run:

```bash
pnpm dev
```

## Build and package

```bash
pnpm --filter @argos/desktop prebuild
pnpm --filter @argos/desktop build
pnpm --filter @argos/desktop package:win
pnpm --filter @argos/desktop package:mac
pnpm --filter @argos/desktop package:linux
```

Installers are written to `packages/desktop/dist/`. Windows currently produces an NSIS installer. Release signing requires the maintainer's platform signing credentials; this repository does not include certificates or signing secrets.

The desktop package includes the root license and notices plus the runtime configuration. Review [the repository license](../../LICENSE), [attribution notices](../../NOTICE), and [third-party tool terms](../../THIRD_PARTY_NOTICES.md) before redistribution.

## Linux-first web audit runtime

Windows runs the web MCP and scanner workers in the selected WSL 2 distribution. Linux runs the same workers natively. Both require Docker Engine in that Linux runtime; Argos does not fall back to running scanners on the host.

To create a distributable package with web auditing enabled, build the versioned Linux worker image before packaging. Docker Buildx must be installed and available to the build process:

```powershell
$env:ARGOS_BUILD_LINUX_WORKER_IMAGE = "1"
$env:ARGOS_REQUIRE_LINUX_WORKER_IMAGE = "1"
pnpm --filter @argos/desktop package:win
```

```bash
ARGOS_BUILD_LINUX_WORKER_IMAGE=1 ARGOS_REQUIRE_LINUX_WORKER_IMAGE=1 pnpm --filter @argos/desktop package:linux
```

The package records the worker image ID and the SHA-256 of its archive. WSL verifies both before loading the image. Builds without these flags can still package the Argos server, but omit the web-audit profile and keep web scans unavailable.
