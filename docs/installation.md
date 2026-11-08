# Installation and runtime requirements

Argos is currently distributed as source code. The repository's CI is configured to build packages for validation, but it does not publish tagged installers or a supported auto-update feed. Inspect the workflow results for the revision you use; CI artifacts are not stable releases.

## Windows

The Windows desktop keeps the Electron interface and runs the Argos server in a private WSL 2 distribution named `ArgosRuntime`, based on a pinned Debian Slim rootfs. You do not need to install Ubuntu or another personal Linux distribution; Argos does not adopt or modify your existing WSL distributions. The compressed base rootfs is about 30 MB, and first launch also downloads the Argos runtime and its dependencies.

`ArgosRuntime` is a separate distro filesystem, not a separate VM or security boundary: WSL 2 distributions share a Linux kernel. WSL itself does not isolate scanner processes; Argos keeps scans disabled unless the required container worker and scope controls are available.

1. Install WSL without adding a general-purpose distro: `wsl --install --no-distribution`. Restart Windows if requested, then run `wsl --update`.
2. Start Argos. It downloads and verifies the architecture-matched Debian Slim rootfs, imports `ArgosRuntime` as WSL 2, and provisions the version-matched Linux server there. The distro uses a non-sudo `argos` account and is stored in Argos's application data directory.
3. To enable container-based web audits, use Docker Desktop with its WSL 2 engine and enable **Settings > Resources > WSL Integration > ArgosRuntime** after Argos creates the distro. If Docker is unavailable, Argos reports the setup step and blocks audits; it never falls back to scanners running on Windows or directly on the host.

Argos does not install Docker Desktop or run privileged Windows package-management commands. It installs only the userland packages needed by its private Debian runtime. Current CI does not provision WSL 2 or run a full Windows audit, so treat Windows installer support as unverified until a Windows/WSL end-to-end job passes.

Browser authentication profiles require protected OS storage. On Linux, configure GNOME Keyring/Secret Service or KWallet before saving a profile; Argos disables profile storage when Electron cannot use a supported secure backend.

## Linux

Linux runs the server natively and requires GNU glibc 2.28 or newer; musl-based distributions such as Alpine are outside the initial support guarantee. The desktop probes Docker Engine but does not install system packages or start a privileged daemon. Web scanning requires a package containing the pinned worker image, a working Docker Engine accessible to the desktop user, and a passing runtime preflight. A default source build without the worker keeps web scanning disabled. Browser scanning requires its additional Chromium sandbox preflight to pass. LAN scanning and Elasticsearch are outside this desktop runtime profile.

CI is configured to smoke-test Linux MCP server startup on Ubuntu 24.04, Debian stable, and Fedora current, and build the Linux desktop package on Ubuntu. These jobs do not install third-party scanners or run full audits on every distro; they are startup checks, not a full desktop compatibility guarantee. See the [verification record](release-verification.md) for the separately recorded local integration results and their limits.

## macOS

macOS retains its native server and packaging flow. Web and browser scanning stay disabled until the pinned worker image and scope-enforcing gateway are shipped; Docker availability alone does not enable audits. Current CI does not build or test the macOS package, so treat macOS release support as unverified until a macOS smoke test passes.

## Build from source

Use Node.js 22.13.0 or newer, `pnpm@11.8.0` as pinned in `package.json`, Bun 1.3.14 to match CI, and the Go version declared in `argos-bin/go.mod` (currently 1.26.3). The pinned pnpm 11 does not support Node 20; see [pnpm compatibility](https://pnpm.io/installation#compatibility).

```bash
git clone https://github.com/iwiels/argos-auditor.git
cd argos-auditor
pnpm install --frozen-lockfile
pnpm dev
```

To build the desktop on the operating system you are packaging for, run these steps from the repository root:

```bash
pnpm --filter @argos/desktop prebuild
pnpm --filter @argos/desktop build
```

Then choose one matching package command:

```bash
pnpm --filter @argos/desktop package:win
pnpm --filter @argos/desktop package:mac
pnpm --filter @argos/desktop package:linux
```

The output is written to `packages/desktop/dist/`. The default channel is `dev`. These commands do not publish packages or configure an update feed. macOS packaging is configured for signing and notarization and may require the corresponding credentials.

To include the worker needed by web auditing on Linux or Windows/WSL2, install Docker with Buildx first and make builds for the target Linux architecture available, natively or through emulation. `prebuild` selects the host architecture; the worker builder processes the Linux binary directories present under `argos-bin/bin/`. Before running `prebuild`, set both build flags in the same shell:

```bash
export ARGOS_BUILD_LINUX_WORKER_IMAGE=1
export ARGOS_REQUIRE_LINUX_WORKER_IMAGE=1
```

In PowerShell, use:

```powershell
$env:ARGOS_BUILD_LINUX_WORKER_IMAGE = "1"
$env:ARGOS_REQUIRE_LINUX_WORKER_IMAGE = "1"
```

Then run `prebuild`, `build`, and the matching package command above. `prebuild` builds the Go binaries, prepares the Linux server payload, and builds the worker images when requested. It downloads pinned runtime assets and browser dependencies, so the first build needs network access and Docker storage. `ARGOS_REQUIRE_LINUX_WORKER_IMAGE=1` makes a missing worker package an error. The build records browser availability per architecture; an image built under emulation can package successfully with browser scanning disabled. Installing Docker alone does not add the worker to an existing package.

Before scanning, configure the model provider you intend to use and verify that every target is authorized and inside the engagement scope. See [Privacy and telemetry](../PRIVACY.md) for information about data sent to model providers and optional telemetry.
