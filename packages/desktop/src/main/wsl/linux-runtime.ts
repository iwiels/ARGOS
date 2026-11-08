import { join } from "node:path"
import { LINUX_NODE_ARCHIVES, LINUX_NODE_VERSION } from "../../shared/linux-runtime"
import { ARGOS_WSL_READY_MARKER } from "./startup"

export type LinuxRuntimeManifest = {
  version: string
  platform: "linux"
  architecture: "amd64" | "arm64"
  profile: string[]
  node: { version: string; asset: string; sha256: string }
  nodePty: { package: string; version: string }
  jsoncParser: { package: "jsonc-parser"; version: string }
  server: string
  config: string
  toolsDirectory: string
  web?: "web"
  runner?: "argos-runner"
  worker?: {
    archive: "worker.tar"
    archiveSha256: string
    imageId: string
    browserAvailable?: boolean
    browserRuntimeVersion?: string
  }
}

export type ScannerAvailability = {
  available: boolean
  path: string | null
  reason: string | null
}

export function dockerRuntimeAvailability(cliPath: string | null, serverVersion: string | null): ScannerAvailability {
  if (!cliPath) {
    return {
      available: false,
      path: null,
      reason:
        "Docker CLI is unavailable in this Linux runtime. On Windows, install and start Docker Desktop and enable Settings > Resources > WSL Integration for ArgosRuntime. On Linux, install and start Docker Engine manually. Argos will not run privileged installation commands.",
    }
  }
  if (!serverVersion) {
    return {
      available: false,
      path: cliPath,
      reason:
        "The Docker CLI is installed, but it cannot reach a running Docker daemon. On Windows, start Docker Desktop and enable Settings > Resources > WSL Integration for ArgosRuntime. On Linux, start Docker Engine in this runtime and probe again.",
    }
  }
  return { available: true, path: cliPath, reason: null }
}

export function webAuditRuntimeAvailability(
  dockerAvailable: boolean,
  workerImageAvailable = false,
  webBinaryAvailable = false,
): ScannerAvailability {
  const reason = !dockerAvailable
    ? "Docker Engine is unavailable, so isolated web audits cannot run. On Windows with WSL, install and start Docker Desktop and enable Settings > Resources > WSL Integration for ArgosRuntime. On Linux, install and start Docker Engine. Argos will not fall back to host scanners."
    : !workerImageAvailable
      ? "The pinned Argos worker image is not verified in this Docker Engine; web audits remain disabled. Rebuild the worker runtime or reinstall a package that includes it."
      : !webBinaryAvailable
        ? "The Linux Argos web MCP binary is not included in this runtime package. Rebuild the worker runtime or reinstall a package that includes it."
        : null
  return {
    available: reason === null,
    path: webBinaryAvailable ? "web" : null,
    reason,
  }
}

export function linuxRuntimeToolAvailability(
  cachedScanners: Record<string, ScannerAvailability>,
  docker: ScannerAvailability,
  workerImageAvailable = false,
  webBinaryAvailable = false,
  browserWorkerAvailable = false,
): Record<string, ScannerAvailability> {
  const tools: Record<string, ScannerAvailability> = { ...cachedScanners, docker }
  const workerReady = docker.available && workerImageAvailable
  if (!workerReady) {
    for (const [name, availability] of Object.entries(cachedScanners)) {
      if (!availability.available) continue
      tools[name] = {
        available: false,
        path: availability.path,
        reason:
          "The scanner binary is cached, but the pinned Argos worker image is not verified in this Docker Engine.",
      }
    }
  }
  tools["argos-worker"] = workerReady
    ? { available: true, path: "docker-image", reason: null }
    : {
        available: false,
        path: null,
        reason:
          "The version-pinned Argos worker image is not installed and verified. Rebuild the worker runtime or reinstall a package that includes it.",
      }
  tools["argos-web"] = webAuditRuntimeAvailability(docker.available, workerReady, webBinaryAvailable)
  tools["chrome-devtools"] = {
    available: false,
    path: null,
    reason: "Chrome DevTools MCP is disabled until browser traffic uses the same isolated scope gateway as scanners.",
  }
  tools["web.browse"] = browserWorkerAvailable && workerReady && webBinaryAvailable
    ? { available: true, path: "argos-web", reason: null }
    : {
        available: false,
        path: null,
        reason: !docker.available
          ? docker.reason ?? "Docker Engine is unavailable."
          : !workerReady
            ? "Browser auditing is disabled until the pinned Argos worker image is verified in Docker."
          : !webBinaryAvailable
            ? "Browser auditing is disabled because the Linux Argos web MCP binary is unavailable."
            : "The pinned Argos worker image does not have a passing Playwright browser preflight.",
      }
  return tools
}

export function workerImageAvailability(
  docker: ScannerAvailability,
  expectedImageId: string | null | undefined,
  actualImageId: string | null | undefined,
  failureReason?: string | null,
): ScannerAvailability {
  if (!docker.available) return { available: false, path: null, reason: docker.reason }
  if (failureReason) return { available: false, path: null, reason: failureReason }
  if (!expectedImageId || !/^sha256:[a-f0-9]{64}$/.test(expectedImageId)) {
    return { available: false, path: null, reason: "The Linux runtime package does not pin an Argos worker image ID." }
  }
  if (actualImageId !== expectedImageId) {
    return {
      available: false,
      path: null,
      reason: "The Docker worker image does not match the package-pinned image ID.",
    }
  }
  return { available: true, path: expectedImageId, reason: null }
}

export function nativeRuntimeToolAvailability(
  docker: ScannerAvailability,
  workerImageAvailable = false,
  webBinaryAvailable = false,
  browserWorkerAvailable = false,
): Record<string, ScannerAvailability> {
  return linuxRuntimeToolAvailability({}, docker, workerImageAvailable, webBinaryAvailable, browserWorkerAvailable)
}

export function glibcRuntimeIssue(version: string | null) {
  if (!version) return "GNU glibc was not detected; Alpine/musl and unknown libc runtimes are unsupported."
  const match = version.match(/(\d+)\.(\d+)/)
  if (!match) return `Could not parse GNU glibc version: ${version}`
  const major = Number(match[1])
  const minor = Number(match[2])
  if (major < 2 || (major === 2 && minor < 28)) {
    return `GNU glibc ${match[1]}.${match[2]} is too old; Linux runtime requires glibc 2.28 or newer.`
  }
  return null
}

const scannerToolExecutables: Record<string, string> = {
  nuclei: "nuclei",
  httpx: "httpx",
  katana: "katana",
  subfinder: "subfinder",
  dnsx: "dnsx",
  "interactsh-client": "interactsh-client",
  gau: "gau",
  dalfox: "dalfox",
  ffuf: "ffuf",
  sqlmap: "sqlmap.py",
  schemathesis: "venv/bin/schemathesis",
  tlsx: "tlsx",
  naabu: "naabu",
  gitleaks: "gitleaks",
  trivy: "trivy",
  semgrep: "venv/bin/semgrep",
  codeql: "codeql",
}

export function missingLinuxMcpPaths(
  paths: { argos?: string | null },
  isExecutable: (path: string) => boolean = Boolean,
) {
  return !paths.argos || !isExecutable(paths.argos) ? ["argos"] : []
}

export function linuxScannerAvailabilityFromCache(
  architecture: "amd64" | "arm64",
  toolsDirectory: string,
  isAvailable: (path: string) => boolean,
): Record<string, ScannerAvailability> {
  const cached = Object.fromEntries(
    Object.entries(scannerToolExecutables).flatMap(([name, executable]) => {
      const path = join(toolsDirectory, name, executable)
      return isAvailable(path) ? [[name, path]] : []
    }),
  )
  return scannerToolAvailability(architecture, cached)
}

const scannerTools = [
  "nuclei",
  "httpx",
  "katana",
  "subfinder",
  "dnsx",
  "interactsh-client",
  "gau",
  "dalfox",
  "ffuf",
  "sqlmap",
  "schemathesis",
  "tlsx",
  "naabu",
  "gitleaks",
  "trivy",
  "semgrep",
  "codeql",
] as const

export function validateLinuxRuntimeManifest(
  value: unknown,
  expectedVersion: string,
  expectedArchitecture: "amd64" | "arm64",
): LinuxRuntimeManifest {
  if (!value || typeof value !== "object") throw new Error("Linux Argos package manifest is invalid")
  const manifest = value as Partial<LinuxRuntimeManifest>
  if (manifest.version !== expectedVersion) {
    throw new Error(
      `Linux Argos package version ${manifest.version ?? "missing"} does not match desktop ${expectedVersion}`,
    )
  }
  if (manifest.platform !== "linux") throw new Error("Linux Argos package has an invalid platform")
  if (manifest.architecture !== expectedArchitecture) {
    throw new Error(
      `Linux Argos package architecture ${manifest.architecture ?? "missing"} does not match ${expectedArchitecture}`,
    )
  }
  const node = manifest.node
  const expectedNode = LINUX_NODE_ARCHIVES[expectedArchitecture]
  if (
    !node ||
    node.version !== LINUX_NODE_VERSION ||
    node.asset !== expectedNode.asset ||
    node.sha256 !== expectedNode.sha256
  ) {
    throw new Error("Linux Argos package has an invalid Node runtime pin")
  }
  if (!manifest.profile?.includes("argos")) {
    throw new Error("Linux Argos package does not include the Argos server profile")
  }
  if (manifest.runner !== undefined && manifest.runner !== "argos-runner") {
    throw new Error("Linux Argos package runner binary is invalid")
  }
  if (manifest.profile.includes("argos-runner") && manifest.runner !== "argos-runner") {
    throw new Error("Linux Argos package profile is missing the runner binary")
  }
  if (!manifest.server || !manifest.config || !manifest.nodePty?.version) {
    throw new Error("Linux Argos package is missing a required runtime component")
  }
  if (manifest.jsoncParser?.package !== "jsonc-parser" || !manifest.jsoncParser.version) {
    throw new Error("Linux Argos package is missing its JSONC parser dependency")
  }
  if (manifest.profile.includes("argos-web")) {
    if (manifest.web !== "web") throw new Error("Linux Argos package is missing the web MCP binary")
    if (!manifest.worker) throw new Error("Linux Argos web profile is missing its worker package")
  }
  if (manifest.worker) {
    if (manifest.worker.archive !== "worker.tar") throw new Error("Linux Argos worker archive name is invalid")
    if (!/^[a-f0-9]{64}$/.test(manifest.worker.archiveSha256)) {
      throw new Error("Linux Argos worker archive checksum is invalid")
    }
    if (!/^sha256:[a-f0-9]{64}$/.test(manifest.worker.imageId)) {
      throw new Error("Linux Argos worker image ID must be a sha256 digest")
    }
    if (manifest.worker.browserAvailable !== undefined && typeof manifest.worker.browserAvailable !== "boolean") {
      throw new Error("Linux Argos worker browser capability must be a boolean")
    }
    if (
      manifest.worker.browserAvailable === true &&
      !/^\d+\.\d+\.\d+$/.test(manifest.worker.browserRuntimeVersion ?? "")
    ) {
      throw new Error("Linux Argos worker browser runtime version is invalid")
    }
  }
  return manifest as LinuxRuntimeManifest
}

export function createLinuxFirstMcpConfig(runtimeDirectory: string, includeWeb = false, includeBrowser = false) {
  const mcp = {
    argos: {
      type: "local",
      command: [`${runtimeDirectory}/orquestador`, "--mcp"],
      enabled: true,
    },
    ...(includeWeb
      ? {
          "argos-web": {
            type: "local",
            command: [`${runtimeDirectory}/web`, "--mcp"],
            enabled: true,
            env: {
              ARGOS_REQUIRE_CONTAINER_AUDIT: "1",
              ...(includeBrowser ? { ARGOS_BROWSER_WORKER_AVAILABLE: "1" } : {}),
            },
          },
        }
      : {}),
  }
  return {
    $schema: "https://opencode.ai/config.json",
    mcp,
    default_agent: "security-orchestrator",
    experimental: { mcp_timeout: 300_000 },
    tool_output: { max_lines: 8_000, max_bytes: 200 * 1024 },
  }
}

export function scannerToolAvailability(
  architecture: "amd64" | "arm64",
  cached: Record<string, string | null | undefined>,
): Record<(typeof scannerTools)[number], ScannerAvailability> {
  return Object.fromEntries(
    scannerTools.map((name) => {
      if (name === "codeql" && architecture === "arm64") {
        return [name, { available: false, path: null, reason: "The pinned CodeQL release publishes Linux amd64 only." }]
      }
      if (name === "naabu" && architecture === "arm64") {
        return [
          name,
          { available: false, path: null, reason: "Pinned Naabu v2.3.1 does not publish a Linux arm64 binary." },
        ]
      }
      const path = cached[name] ?? null
      if (path) return [name, { available: true, path, reason: null }]
      return [
        name,
        {
          available: false,
          path: null,
          reason: "Not cached; Argos checks the pinned release and SHA-256 on first use.",
        },
      ]
    }),
  ) as Record<(typeof scannerTools)[number], ScannerAvailability>
}
export function buildWslProvisioningScript(
  hostPayloadDirectory: string,
  manifest: LinuxRuntimeManifest,
  expectedManifestSha256: string,
) {
  const nodeArch = manifest.architecture === "amd64" ? "x64" : "arm64"
  const nodeRoot = shellQuote(`node-v${manifest.node.version}-linux-${nodeArch}`)
  const ptyPackage = shellQuote(`${manifest.nodePty.package}@${manifest.nodePty.version}`)
  const jsoncParserPackage = shellQuote(`${manifest.jsoncParser.package}@${manifest.jsoncParser.version}`)
  const manifestSha = shellQuote(expectedManifestSha256)
  const nodeUrl = shellQuote(`https://nodejs.org/download/release/v${manifest.node.version}/${manifest.node.asset}`)
  const runtimeBinaries = ["orquestador", ...(manifest.web ? [manifest.web] : []), ...(manifest.runner ? [manifest.runner] : [])]
  const runtimeFiles = [
    '"$payload/manifest.json"',
    '"$payload/manifest.sha256"',
    ...runtimeBinaries.map((name) => `"$payload/${name}"`),
  ]
  const workerSetup = manifest.worker
    ? [
        `worker_image_id=${shellQuote(manifest.worker.imageId)}`,
        `worker_archive=${shellQuote(manifest.worker.archive)}`,
        `ensure_worker_image() {`,
        `  local runtime_dir="$1" actual`,
        `  command -v docker >/dev/null 2>&1 || return 0`,
        `  docker info >/dev/null 2>&1 || return 0`,
        `  actual="$(docker image inspect --format '{{.Id}}' "$worker_image_id" 2>/dev/null || true)"`,
        `  [ "$actual" = "$worker_image_id" ] && return 0`,
        `  docker load --input "$runtime_dir/$worker_archive"`,
        `  actual="$(docker image inspect --format '{{.Id}}' "$worker_image_id" 2>/dev/null || true)"`,
        `  if [ "$actual" != "$worker_image_id" ]; then printf '%s\\n' "Loaded Argos worker image does not match $worker_image_id" >&2; return 1; fi`,
        `}`,
      ]
    : []
  const workerArchiveVerification = manifest.worker
    ? [
        `printf '%s  %s\\n' ${shellQuote(manifest.worker.archiveSha256)} "$tmp/${manifest.worker.archive}" | sha256sum -c -`,
      ]
    : []
  const existingChecks = [
    '[ -x "$destination/node/bin/node" ]',
    ...runtimeBinaries.map((name) => `[ -x "$destination/${name}" ]`),
    `"$destination/node/bin/node" -e 'require(process.argv[1])' "$destination/server/node_modules/${manifest.nodePty.package}" >/dev/null 2>&1`,
    `"$destination/node/bin/node" -e 'require(process.argv[1])' "$destination/server/node_modules/${manifest.jsoncParser.package}" >/dev/null 2>&1`,
  ]
  const workerCopy = manifest.worker ? [`cp "$payload/${manifest.worker.archive}" "$tmp"/`] : []
  const executableSetup = runtimeBinaries.map((name) => `chmod 755 "$tmp/${name}"`)
  return [
    "set -euo pipefail",
    `payload="$(wslpath -u ${shellQuote(hostPayloadDirectory)})"`,
    `runtime_root="$HOME/.local/share/argos/runtime"`,
    `destination="$runtime_root/${manifest.version}"`,
    `manifest_sha=${manifestSha}`,
    `checksums_sha="$(sha256sum "$payload/manifest.sha256" | cut -d ' ' -f1)"`,
    ...workerSetup,
    `if [ -d "$destination" ] && printf '%s  manifest.json\\n' "$manifest_sha" | (cd "$destination" && sha256sum -c -) >/dev/null 2>&1 && printf '%s  manifest.sha256\\n' "$checksums_sha" | (cd "$destination" && sha256sum -c -) >/dev/null 2>&1 && (cd "$destination" && sha256sum -c manifest.sha256 >/dev/null 2>&1) && ${existingChecks.join(" && ")}; then`,
    `  if [ "$("$destination/node/bin/node" --version)" = "v${manifest.node.version}" ]; then`,
    ...(manifest.worker ? [`    ensure_worker_image "$destination"`] : []),
    `    exit 0`,
    `  fi`,
    `fi`,
    `mkdir -p "$runtime_root"`,
    `tmp="$runtime_root/.install-${manifest.version}-$$"`,
    `mkdir "$tmp"`,
    `cp ${runtimeFiles.join(" ")} "$tmp"/`,
    ...workerCopy,
    ...workerArchiveVerification,
    `cp -a "$payload/server" "$payload/config" "$tmp"/`,
    `printf '%s  manifest.json\\n' "$manifest_sha" | (cd "$tmp" && sha256sum -c -)`,
    `(cd "$tmp" && sha256sum -c manifest.sha256)`,
    ...executableSetup,
    `node_archive="$tmp/${manifest.node.asset}"`,
    `curl --fail --location --silent --show-error ${nodeUrl} --output "$node_archive"`,
    `printf '%s  %s\\n' ${shellQuote(manifest.node.sha256)} "$node_archive" | sha256sum -c -`,
    `mkdir -p "$tmp/node"`,
    `tar -xJf "$node_archive" -C "$tmp/node" --strip-components=1 ${nodeRoot}/bin/node ${nodeRoot}/bin/npm ${nodeRoot}/bin/npx ${nodeRoot}/lib/node_modules/npm`,
    `rm -f "$node_archive"`,
    `"$tmp/node/bin/node" "$tmp/node/lib/node_modules/npm/bin/npm-cli.js" install --prefix "$tmp/server" --no-save --ignore-scripts --no-audit --no-fund ${ptyPackage} ${jsoncParserPackage}`,
    `"$tmp/node/bin/node" -e 'require(process.argv[1])' "$tmp/server/node_modules/${manifest.nodePty.package}"`,
    `"$tmp/node/bin/node" -e 'require(process.argv[1])' "$tmp/server/node_modules/${manifest.jsoncParser.package}"`,
    `test "$("$tmp/node/bin/node" --version)" = "v${manifest.node.version}"`,
    `if [ -e "$destination" ]; then mv "$destination" "$destination.invalid.$(date +%s).$$"; fi`,
    `mv "$tmp" "$destination"`,
    ...(manifest.worker ? [`ensure_worker_image "$destination"`] : []),
  ].join("\n")
}

export function buildWslRootfsBootstrapScript() {
  return [
    "set -eu",
    `if [ ! -e ${ARGOS_WSL_READY_MARKER} ]; then`,
    "  export DEBIAN_FRONTEND=noninteractive",
    "  apt-get update",
    "  apt-get install -y --no-install-recommends bash ca-certificates coreutils curl grep passwd tar xz-utils",
    "  if ! getent passwd argos >/dev/null 2>&1; then useradd --create-home --uid 1000 --user-group --shell /bin/bash argos; fi",
    "  mkdir -p /var/lib/argos /home/argos",
    "  chown -R argos:argos /home/argos",
    "  cat > /etc/wsl.conf <<'ARGOS_WSL_CONF'",
    "[boot]",
    "systemd=false",
    "[interop]",
    "appendWindowsPath=false",
    "[user]",
    "default=argos",
    "ARGOS_WSL_CONF",
    `  touch ${ARGOS_WSL_READY_MARKER}`,
    "  apt-get clean",
    "  rm -rf /var/lib/apt/lists/*",
    "fi",
    "if [ -S /var/run/docker.sock ]; then",
    "  docker_gid=$(stat -c '%g' /var/run/docker.sock)",
    "  docker_group=$(getent group \"$docker_gid\" | cut -d: -f1 || true)",
    "  if [ -z \"$docker_group\" ]; then docker_group=argos-docker-$docker_gid; groupadd --gid \"$docker_gid\" \"$docker_group\"; fi",
    "  if ! id -G argos | tr ' ' '\\n' | grep -Fxq \"$docker_gid\"; then usermod -aG \"$docker_group\" argos; fi",
    "fi",
  ].join("\n")
}

function shellQuote(value: string) {
  return `'${value.replace(/'/g, `'"'"'`)}'`
}
