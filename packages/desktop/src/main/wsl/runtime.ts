import { spawn } from "node:child_process"
import { createHash } from "node:crypto"
import { createReadStream, createWriteStream, existsSync } from "node:fs"
import { mkdir, readFile, rm, writeFile } from "node:fs/promises"
import { Readable } from "node:stream"
import { pipeline } from "node:stream/promises"
import { join } from "node:path"
import * as pty from "@lydell/node-pty"
import type { WslDistroProbe, WslInstalledDistro, WslOnlineDistro, WslRuntimeCheck } from "../../preload/types"
import { requireWslDistroName, wslTerminalArgs } from "./policy"
import {
  buildWslProvisioningScript,
  buildWslRootfsBootstrapScript,
  dockerRuntimeAvailability,
  glibcRuntimeIssue,
  scannerToolAvailability,
  type ScannerAvailability,
  validateLinuxRuntimeManifest,
} from "./linux-runtime"
import {
  argosWslRootfsArtifact,
  argosWslRootfsSource,
  ARGOS_WSL_DISTRO_NAME,
  ARGOS_WSL_READY_MARKER,
  buildWslImportArgs,
  parseDebianRootfsOciManifest,
  selectArgosRuntimeDistro,
  validateDebianRootfsOciConfig,
  wslArchitectureToGoArch,
} from "./startup"

export type WslCommandLine = {
  stream: "stdout" | "stderr"
  text: string
}

export type WslCommandResult = {
  code: number | null
  signal: NodeJS.Signals | null
  stdout: string
  stderr: string
}

export type RunWslOptions = {
  signal?: AbortSignal
  /**
   * Ceiling on how long we wait for the child process to exit. When the
   * LXSS service or a specific distro wedges (e.g. Ubuntu-24.04 with a
   * pending first-run prompt), `wsl.exe` never returns and any command
   * that doesn't specify a timeout hangs the entire startup flow. Default
   * is 20s — enough for slow cold-starts, short enough to fail fast on
   * a wedge. Callers can override for longer-running jobs.
   */
  timeoutMs?: number
}

const DEFAULT_WSL_TIMEOUT_MS = 20_000
const DEFAULT_WSL_PROBE_TIMEOUT_MS = 60_000
const DEFAULT_WSL_INSTALL_TIMEOUT_MS = 15 * 60_000
const DEFAULT_WSL_ROOTFS_DOWNLOAD_TIMEOUT_MS = 5 * 60_000
const MANAGED_DISTRO_METADATA = { schemaVersion: 1, distro: ARGOS_WSL_DISTRO_NAME } as const

export function wslArgs(args: string[], distro?: string | null, user?: string | null) {
  return [...(distro ? ["-d", distro] : []), ...(user ? ["--user", user] : []), "--exec", ...args]
}

export function runWsl(args: string[], opts: RunWslOptions = {}) {
  return runCommand("wsl", args, opts)
}

export function buildManagedDistroCheckArgs() {
  return wslArgs(["/bin/sh", "-lc", `test -f ${ARGOS_WSL_READY_MARKER}`], ARGOS_WSL_DISTRO_NAME, "root")
}

async function isArgosManagedWslDistro(opts?: RunWslOptions) {
  const result = await runWsl(buildManagedDistroCheckArgs(), {
    ...opts,
    timeoutMs: opts?.timeoutMs ?? DEFAULT_WSL_PROBE_TIMEOUT_MS,
  }).catch(() => null)
  return result?.code === 0
}

async function writeManagedDistroMetadata(path: string) {
  await writeFile(path, `${JSON.stringify(MANAGED_DISTRO_METADATA)}\n`, {
    encoding: "utf8",
    flag: "wx",
  }).catch(async (error: NodeJS.ErrnoException) => {
    if (error.code !== "EEXIST") throw error
    const existing = JSON.parse(await readFile(path, "utf8")) as { schemaVersion: number; distro: string }
    if (existing.schemaVersion !== 1 || existing.distro !== ARGOS_WSL_DISTRO_NAME) throw error
  })
}

function runPowerShell(command: string, opts: RunWslOptions = {}) {
  return runCommand(
    "powershell.exe",
    ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", command],
    opts,
  )
}

function runCommand(command: string, args: string[], opts: RunWslOptions = {}) {
  return new Promise<WslCommandResult>((resolve, reject) => {
    const child = spawn(command, args, {
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: true,
      signal: opts.signal,
    })

    // Guard every wsl.exe invocation with a timeout. When the distro or
    // the LXSS service is wedged (Ubuntu first-run state, Windows update
    // pending, etc.) wsl.exe produces no output and never exits; without
    // this the whole sidecar spawn flow stalls the app forever.
    const timeoutMs = opts.timeoutMs ?? DEFAULT_WSL_TIMEOUT_MS
    const timeoutId = setTimeout(() => {
      try {
        child.kill()
      } catch {
        /* ignore */
      }
      reject(new Error(`${command} ${args.join(" ")} timed out after ${timeoutMs}ms`))
    }, timeoutMs)

    let stdout = ""
    let stderr = ""
    const stdoutDecoder = createOutputDecoder()
    const stderrDecoder = createOutputDecoder()

    const append = (stream: WslCommandLine["stream"], chunk: string) => {
      if (!chunk) return
      if (stream === "stdout") {
        stdout += chunk
        return
      }
      stderr += chunk
    }

    child.stdout.on("data", (chunk: Buffer) => {
      append("stdout", stdoutDecoder.decode(chunk))
    })
    child.stdout.on("end", () => {
      append("stdout", stdoutDecoder.flush())
    })

    child.stderr.on("data", (chunk: Buffer) => {
      append("stderr", stderrDecoder.decode(chunk))
    })
    child.stderr.on("end", () => {
      append("stderr", stderrDecoder.flush())
    })

    child.once("error", (error) => {
      clearTimeout(timeoutId)
      reject(error)
    })
    child.once("close", (code, signal) => {
      clearTimeout(timeoutId)
      resolve({ code, signal, stdout, stderr })
    })
  })
}

function runInteractiveCommand(command: string, args: string[], opts: RunWslOptions = {}, defaultTimeoutMs: number) {
  return new Promise<WslCommandResult>((resolve, reject) => {
    const child = pty.spawn(command, args, {
      name: "xterm-color",
      cols: 80,
      rows: 24,
      cwd: process.cwd(),
      env: process.env,
      useConpty: true,
    })

    let settled = false
    let stdout = ""

    const cleanup = () => {
      clearTimeout(timeoutId)
      abortCleanup?.()
    }

    const timeoutMs = opts.timeoutMs ?? defaultTimeoutMs
    const timeoutId = setTimeout(() => {
      try {
        child.kill()
      } catch {
        /* ignore */
      }
      if (settled) return
      settled = true
      cleanup()
      reject(new Error(`${command} ${args.join(" ")} timed out after ${timeoutMs}ms`))
    }, timeoutMs)

    const abortHandler = () => {
      try {
        child.kill()
      } catch {
        /* ignore */
      }
      if (settled) return
      settled = true
      cleanup()
      reject(new DOMException("Aborted", "AbortError"))
    }
    const abortCleanup = opts.signal
      ? (() => {
          opts.signal?.addEventListener("abort", abortHandler, { once: true })
          return () => opts.signal?.removeEventListener("abort", abortHandler)
        })()
      : undefined

    child.onData((data: string) => {
      stdout += data
    })
    child.onExit((event: { exitCode: number }) => {
      if (settled) return
      settled = true
      cleanup()
      resolve({ code: event.exitCode, signal: null, stdout, stderr: "" })
    })
  })
}

function createOutputDecoder() {
  let decoder: TextDecoder | undefined
  return {
    decode(chunk: Buffer) {
      decoder ??= new TextDecoder(detectOutputEncoding(chunk))
      return decoder.decode(chunk, { stream: true })
    },
    flush() {
      return decoder?.decode() ?? ""
    },
  }
}

function detectOutputEncoding(chunk: Uint8Array) {
  if (chunk[0] === 0xff && chunk[1] === 0xfe) return "utf-16le"
  const pairs = Math.floor(chunk.length / 2)
  if (pairs < 2) return "utf-8"
  const oddZeroes = Array.from({ length: pairs }).filter((_, index) => chunk[index * 2 + 1] === 0).length
  const evenZeroes = Array.from({ length: pairs }).filter((_, index) => chunk[index * 2] === 0).length
  return oddZeroes >= Math.ceil(pairs / 3) && evenZeroes * 2 <= oddZeroes ? "utf-16le" : "utf-8"
}

export function runWslInDistro(args: string[], distro?: string | null, opts?: RunWslOptions) {
  return runWsl(wslArgs(args, distro), opts)
}

export function runWslSh(script: string, distro?: string | null, opts?: RunWslOptions) {
  return runWslInDistro(["sh", "-lc", script], distro, opts)
}

export async function probeWslRuntime(opts?: RunWslOptions): Promise<WslRuntimeCheck> {
  const version = await runWsl(["--version"], opts).catch((error) => ({
    code: 1,
    signal: null,
    stdout: "",
    stderr: error instanceof Error ? error.message : String(error),
  }))

  if (version.code !== 0) {
    return {
      available: false,
      version: null,
      error: summarize(version.stderr || version.stdout) || "WSL is unavailable",
    }
  }

  return {
    available: true,
    version: firstLine(version.stdout),
    error: null,
  }
}

export async function listInstalledWslDistros(opts?: RunWslOptions) {
  const result = await runWsl(["--list", "--verbose"], opts)
  if (result.code !== 0) {
    throw new Error(summarize(result.stderr || result.stdout) || "Failed to list installed WSL distros")
  }
  return parseInstalledDistros(result.stdout)
}

export async function listOnlineWslDistros(opts?: RunWslOptions) {
  const result = await runWsl(["--list", "--online"], opts)
  if (result.code !== 0) {
    throw new Error(summarize(result.stderr || result.stdout) || "Failed to list online WSL distros")
  }
  return parseOnlineDistros(result.stdout)
}

export async function installWslRuntimeElevated(opts?: RunWslOptions) {
  const script = [
    "$ErrorActionPreference = 'Stop'",
    "$process = Start-Process -FilePath 'wsl.exe' -Verb RunAs -ArgumentList @('--install','--no-distribution') -Wait -PassThru",
    "if ($null -ne $process.ExitCode) { exit $process.ExitCode }",
  ].join("; ")
  return runPowerShell(script, withTimeout(opts, DEFAULT_WSL_INSTALL_TIMEOUT_MS))
}

export async function installWslDistro(name: string, opts?: RunWslOptions) {
  return runInteractiveCommand(
    resolveSystem32Command("wsl.exe"),
    ["--install", "-d", name, "--web-download", "--no-launch"],
    withTimeout(opts, DEFAULT_WSL_INSTALL_TIMEOUT_MS),
    DEFAULT_WSL_INSTALL_TIMEOUT_MS,
  )
}

export async function ensureArgosWslDistro(
  userDataDirectory: string,
  architecture: "amd64" | "arm64",
  opts?: RunWslOptions,
) {
  const stateDirectory = join(userDataDirectory, "wsl")
  const metadataPath = join(stateDirectory, "managed-distro.json")
  const installDirectory = join(stateDirectory, "ArgosRuntime")
  const artifact = argosWslRootfsArtifact(architecture)
  const distros = await listInstalledWslDistros(opts)
  const installed = selectArgosRuntimeDistro(distros)
  const namedDistro = distros.find((item) => item.name === ARGOS_WSL_DISTRO_NAME)
  let metadata: { schemaVersion: number; distro: string } | null = null

  if (existsSync(metadataPath)) {
    try {
      metadata = JSON.parse(await readFile(metadataPath, "utf8")) as { schemaVersion: number; distro: string }
    } catch {
      throw new Error(`Argos's managed WSL metadata is invalid: ${metadataPath}`)
    }
    if (metadata?.schemaVersion !== 1 || metadata.distro !== ARGOS_WSL_DISTRO_NAME) {
      throw new Error(`Argos's managed WSL metadata is incompatible: ${metadataPath}`)
    }
  }

  if (namedDistro && !metadata) {
    if (!(await isArgosManagedWslDistro(opts))) {
      throw new Error(
        `A WSL distribution named ${ARGOS_WSL_DISTRO_NAME} already exists and is not registered as Argos-managed. Argos will not modify or replace it. Rename that distribution or remove it yourself, then restart Argos.`,
      )
    }
    await mkdir(stateDirectory, { recursive: true })
    await writeManagedDistroMetadata(metadataPath)
  }
  if (namedDistro && !installed) {
    throw new Error(
      `${ARGOS_WSL_DISTRO_NAME} is registered as Argos-managed but is not running WSL 2. Convert it with: wsl --set-version "${ARGOS_WSL_DISTRO_NAME}" 2`,
    )
  }

  await mkdir(stateDirectory, { recursive: true })
  const importedNew = !installed
  if (importedNew) {
    await writeManagedDistroMetadata(metadataPath)

    const rootfsArchive = join(stateDirectory, `debian-trixie-${architecture}.tar.gz`)
    await downloadVerifiedWslRootfs(rootfsArchive, artifact, opts)
    await mkdir(installDirectory, { recursive: true })
    const imported = await runWsl(buildWslImportArgs(installDirectory, rootfsArchive), {
      ...opts,
      timeoutMs: opts?.timeoutMs ?? DEFAULT_WSL_INSTALL_TIMEOUT_MS,
    })
    if (imported.code !== 0) {
      throw new Error(summarize(imported.stderr || imported.stdout) || `Could not import ${ARGOS_WSL_DISTRO_NAME}`)
    }
    await rm(rootfsArchive, { force: true })
  }

  const bootstrap = await runWsl(
    wslArgs(["/bin/sh", "-lc", buildWslRootfsBootstrapScript()], ARGOS_WSL_DISTRO_NAME, "root"),
    { ...opts, timeoutMs: opts?.timeoutMs ?? DEFAULT_WSL_INSTALL_TIMEOUT_MS },
  )
  if (bootstrap.code !== 0) {
    throw new Error(
      summarize(bootstrap.stderr || bootstrap.stdout) || `Could not prepare the private ${ARGOS_WSL_DISTRO_NAME} runtime`,
    )
  }
  if (importedNew) {
    const terminated = await runWsl(["--terminate", ARGOS_WSL_DISTRO_NAME], opts)
    if (terminated.code !== 0) {
      throw new Error(summarize(terminated.stderr || terminated.stdout) || `Could not restart ${ARGOS_WSL_DISTRO_NAME}`)
    }
  }
  return { name: ARGOS_WSL_DISTRO_NAME, architecture, installDirectory }
}

async function downloadVerifiedWslRootfs(
  destination: string,
  artifact: ReturnType<typeof argosWslRootfsArtifact>,
  opts?: RunWslOptions,
) {
  const source = argosWslRootfsSource(artifact.architecture)
  const imageManifest = await fetchVerifiedWslJson(
    source.manifestUrl,
    artifact.imageManifestSha256,
    opts,
  )
  const { configSha256, rootfsSha256 } = parseDebianRootfsOciManifest(imageManifest)
  const imageConfig = await fetchVerifiedWslJson(source.configUrl, configSha256, opts)
  validateDebianRootfsOciConfig(imageConfig, artifact.architecture)
  const matchesExpectedChecksum = async () =>
    existsSync(destination) && (await sha256File(destination)) === rootfsSha256
  if (await matchesExpectedChecksum()) return
  await rm(destination, { force: true })
  const response = await fetch(source.rootfsUrl, { signal: wslDownloadSignal(opts) })
  if (!response.ok || !response.body || new URL(response.url).hostname !== "raw.githubusercontent.com") {
    throw new Error(`Could not download the pinned Debian WSL rootfs (HTTP ${response.status})`)
  }
  try {
    await pipeline(
      Readable.fromWeb(response.body as import("node:stream/web").ReadableStream<Uint8Array>),
      createWriteStream(destination, { flags: "wx" }),
    )
  } catch (error) {
    await rm(destination, { force: true })
    throw error
  }
  if (!(await matchesExpectedChecksum())) {
    await rm(destination, { force: true })
    throw new Error("The downloaded Debian WSL rootfs failed SHA-256 verification")
  }
}

async function fetchVerifiedWslJson(url: string, expectedSha256: string, opts?: RunWslOptions) {
  const response = await fetch(url, { signal: wslDownloadSignal(opts) })
  if (!response.ok || new URL(response.url).hostname !== "raw.githubusercontent.com") {
    throw new Error(`Could not download the pinned Debian WSL manifest (HTTP ${response.status})`)
  }
  const content = Buffer.from(await response.arrayBuffer())
  if (createHash("sha256").update(content).digest("hex") !== expectedSha256) {
    throw new Error("The Debian WSL manifest failed SHA-256 verification")
  }
  try {
    return JSON.parse(content.toString("utf8")) as unknown
  } catch {
    throw new Error("The pinned Debian WSL manifest is not valid JSON")
  }
}

function wslDownloadSignal(opts?: RunWslOptions) {
  const signals = [AbortSignal.timeout(DEFAULT_WSL_ROOTFS_DOWNLOAD_TIMEOUT_MS)]
  if (opts?.signal) signals.push(opts.signal)
  return AbortSignal.any(signals)
}

async function sha256File(path: string) {
  const hash = createHash("sha256")
  for await (const chunk of createReadStream(path)) hash.update(chunk)
  return hash.digest("hex")
}

export async function installWslOpencode(version: string, distro: string, opts?: RunWslOptions) {
  return runInteractiveCommand(
    resolveSystem32Command("wsl.exe"),
    wslArgs(
      ["bash", "-lc", `curl -fsSL https://opencode.ai/install | bash -s -- --version ${shellEscape(version)}`],
      distro,
    ),
    withTimeout(opts, DEFAULT_WSL_INSTALL_TIMEOUT_MS),
    DEFAULT_WSL_INSTALL_TIMEOUT_MS,
  )
}

export type ProbeWslDistroOptions = RunWslOptions & {
  wslVersion?: number | null
  packageVersion?: string
  workerImageId?: string
  browserWorkerExpected?: boolean
}

export function buildWslCommandAvailabilityScript() {
  return [
    "for tool in bash curl tar sha256sum wslpath xz grep cut date; do",
    '  if command -v "$tool" >/dev/null 2>&1; then printf "%s=yes\\n" "$tool"; else printf "%s=no\\n" "$tool"; fi',
    "done",
  ]
}

export async function probeWslDistro(name: string, opts?: ProbeWslDistroOptions): Promise<WslDistroProbe> {
  const executable = await runWslInDistro(["/bin/true"], name, opts).catch((error) => ({
    code: 1,
    signal: null,
    stdout: "",
    stderr: error instanceof Error ? error.message : String(error),
  }))
  if (executable.code !== 0) {
    return {
      name,
      canExecute: false,
      hasBash: false,
      hasCurl: false,
      error: summarize(executable.stderr || executable.stdout) || "Cannot execute commands in distro",
      wslVersion: opts?.wslVersion ?? null,
      architecture: null,
      glibcVersion: null,
      nodeVersion: null,
      packageVersion: null,
      tools: {},
    }
  }

  const expectedVersion = opts?.packageVersion ?? ""
  const script = [
    ...buildWslCommandAvailabilityScript(),
    'docker_path="$(command -v docker 2>/dev/null || true)"',
    'docker_version=; if [ -n "$docker_path" ]; then docker_version=$(docker info --format "{{.ServerVersion}}" 2>/dev/null || true); fi',
    `docker_worker_image_id=; if [ -n "$docker_version" ] && [ -n ${shellEscape(opts?.workerImageId ?? "")} ]; then docker_worker_image_id=$(docker image inspect --format "{{.Id}}" ${shellEscape(opts?.workerImageId ?? "")} 2>/dev/null || true); fi`,
    ...(opts?.browserWorkerExpected && opts.workerImageId
      ? [
          `browser_worker_preflight=; if [ "$docker_worker_image_id" = ${shellEscape(opts.workerImageId)} ]; then browser_worker_preflight=$(docker run --rm --pull=never --init --network=none --read-only --user=65532:65532 --cap-drop=ALL --security-opt=no-new-privileges --security-opt="seccomp=$HOME/.local/share/argos/runtime/${expectedVersion}/config/runtime/chromium-seccomp.json" --pids-limit=256 --cpus=2 --memory=1g --tmpfs /tmp:rw,nosuid,nodev,noexec,size=128m ${shellEscape(opts.workerImageId)} /usr/local/bin/argos-browser-worker --preflight 2>/dev/null || true); fi`,
          `case "$browser_worker_preflight" in *'"status":"ready"'*) browser_worker=yes ;; *) browser_worker=no ;; esac`,
        ]
      : [`browser_worker=no`]),
    'printf "docker_path=%s\\n" "$docker_path"',
    'printf "docker_version=%s\\n" "$docker_version"',
    'printf "docker_worker_image_id=%s\\n" "$docker_worker_image_id"',
    'printf "browser_worker=%s\\n" "$browser_worker"',
    'printf "arch=%s\\n" "$(uname -m 2>/dev/null || true)"',
    'printf "glibc=%s\\n" "$(getconf GNU_LIBC_VERSION 2>/dev/null || true)"',
    `if [ -n ${shellEscape(expectedVersion)} ] && [ -x "$HOME/.local/share/argos/runtime/${expectedVersion}/node/bin/node" ]; then node_version=$("$HOME/.local/share/argos/runtime/${expectedVersion}/node/bin/node" --version); elif command -v node >/dev/null 2>&1; then node_version=$(node --version); else node_version=; fi`,
    'printf "node=%s\\n" "$node_version"',
    `package_manifest="$HOME/.local/share/argos/runtime/${expectedVersion}/manifest.json"`,
    'if [ -f "$package_manifest" ]; then package_version=$(grep -m1 -o \'"version"[[:space:]]*:[[:space:]]*"[^"]*"\' "$package_manifest" | cut -d \'"\' -f4); else package_version=; fi',
    'printf "package=%s\\n" "$package_version"',
    'tools_dir="$HOME/.argos/tools"',
    'for entry in "nuclei:nuclei" "httpx:httpx" "katana:katana" "subfinder:subfinder" "dnsx:dnsx" "interactsh-client:interactsh-client" "gau:gau" "dalfox:dalfox" "ffuf:ffuf" "sqlmap:sqlmap.py" "schemathesis:venv/bin/schemathesis" "tlsx:tlsx" "naabu:naabu" "gitleaks:gitleaks" "trivy:trivy" "semgrep:venv/bin/semgrep" "codeql:codeql"; do name=${entry%%:*}; binary=${entry#*:}; path="$tools_dir/$name/$binary"; if [ -e "$path" ]; then printf "tool\\t%s\\t%s\\n" "$name" "$path"; fi; done',
  ].join("\n")
  const result = await runWslSh(script, name, opts).catch((error) => ({
    code: 1,
    signal: null,
    stdout: "",
    stderr: error instanceof Error ? error.message : String(error),
  }))
  if (result.code !== 0) {
    return {
      name,
      canExecute: true,
      hasBash: false,
      hasCurl: false,
      error: summarize(result.stderr || result.stdout) || "Cannot inspect distro runtime requirements",
      wslVersion: opts?.wslVersion ?? null,
      architecture: null,
      glibcVersion: null,
      nodeVersion: null,
      packageVersion: null,
      tools: {},
    }
  }

  const values = new Map<string, string>()
  const cachedTools: Record<string, string> = {}
  for (const line of result.stdout.split(/\r?\n/g)) {
    if (line.startsWith("tool\t")) {
      const [, tool, path] = line.split("\t")
      if (tool && path) cachedTools[tool] = path
      continue
    }
    const separator = line.indexOf("=")
    if (separator > 0) values.set(line.slice(0, separator), line.slice(separator + 1).trim())
  }
  const hasBash = values.get("bash") === "yes"
  const hasCurl = values.get("curl") === "yes"
  const hasTar = values.get("tar") === "yes"
  const hasSha256sum = values.get("sha256sum") === "yes"
  const hasWslpath = values.get("wslpath") === "yes"
  const hasXz = values.get("xz") === "yes"
  const hasGrep = values.get("grep") === "yes"
  const hasCut = values.get("cut") === "yes"
  const hasDate = values.get("date") === "yes"
  const architectureRaw = values.get("arch") ?? ""
  let architecture: "amd64" | "arm64" | null = null
  try {
    architecture = wslArchitectureToGoArch(architectureRaw)
  } catch {
    architecture = null
  }
  const glibcVersion = values.get("glibc") || null
  const glibcIssue = glibcRuntimeIssue(glibcVersion)
  const dependencies = [
    ...(!hasBash ? ["bash"] : []),
    ...(!hasCurl ? ["curl"] : []),
    ...(!hasTar ? ["tar"] : []),
    ...(!hasSha256sum ? ["sha256sum"] : []),
    ...(!hasWslpath ? ["wslpath"] : []),
    ...(!hasXz ? ["xz-utils (xz)"] : []),
    ...(!hasGrep ? ["grep"] : []),
    ...(!hasCut ? ["cut"] : []),
    ...(!hasDate ? ["date"] : []),
    ...(glibcIssue ? [glibcIssue] : []),
    ...(!architecture
      ? [`Linux architecture ${architectureRaw || "unknown"} is not supported; use amd64 or arm64`]
      : []),
  ]
  const knownTools = scannerToolAvailability("amd64", {})
  const tools: Record<string, ScannerAvailability> = architecture
    ? scannerToolAvailability(architecture, cachedTools)
    : Object.fromEntries(
        Object.keys(knownTools).map((tool) => [
          tool,
          { available: false, path: null, reason: "Unsupported Linux architecture." },
        ]),
      )

  tools.docker = dockerRuntimeAvailability(values.get("docker_path") || null, values.get("docker_version") || null)
  if (opts?.workerImageId) {
    const imageMatches = values.get("docker_worker_image_id") === opts.workerImageId
    tools["argos-worker"] = imageMatches
      ? { available: true, path: opts.workerImageId, reason: null }
      : {
          available: false,
          path: null,
          reason: tools.docker.available
            ? "Docker Engine is ready, but the Argos worker image does not match the package-pinned image ID."
            : tools.docker.reason,
        }
  }
  const browserWorkerReady =
    opts?.browserWorkerExpected === true &&
    values.get("docker_worker_image_id") === opts.workerImageId &&
    values.get("browser_worker") === "yes"
  tools["web.browse"] = browserWorkerReady
    ? { available: true, path: "argos-web", reason: null }
    : {
        available: false,
        path: null,
        reason: !opts?.browserWorkerExpected
          ? "The pinned Linux package does not include a browser worker for this architecture."
          : !tools.docker?.available
            ? tools.docker.reason ?? "Docker Engine is unavailable."
            : !tools["argos-worker"]?.available
              ? "The pinned Argos worker image is unavailable in this Docker Engine."
              : "Chromium failed the isolated Docker preflight; browser auditing is blocked.",
      }

  return {
    name,
    canExecute: true,
    hasBash,
    hasCurl,
    error: dependencies.length ? `Missing runtime requirements: ${dependencies.join(", ")}` : null,
    wslVersion: opts?.wslVersion ?? null,
    architecture,
    glibcVersion,
    nodeVersion: values.get("node") || null,
    packageVersion: values.get("package") || null,
    tools,
  }
}

export async function provisionWslArgosPackage(
  distro: string,
  payloadDirectory: string,
  expectedVersion: string,
  architecture: "amd64" | "arm64",
  opts?: RunWslOptions,
) {
  const manifestText = await readFile(join(payloadDirectory, "manifest.json"), "utf8")
  const manifest = validateLinuxRuntimeManifest(JSON.parse(manifestText), expectedVersion, architecture)
  const manifestSha256 = createHash("sha256").update(manifestText).digest("hex")
  const script = buildWslProvisioningScript(payloadDirectory, manifest, manifestSha256)
  const result = await runWslInDistro(
    ["bash", "-c", script],
    distro,
    withTimeout(opts, DEFAULT_WSL_INSTALL_TIMEOUT_MS),
  )
  if (result.code !== 0) {
    throw new Error(
      summarize(result.stderr || result.stdout) || `Could not provision Argos ${expectedVersion} in ${distro}`,
    )
  }
  return { directory: `$HOME/.local/share/argos/runtime/${manifest.version}`, manifest, manifestSha256 }
}
export async function resolveWslOpencode(distro: string, opts?: RunWslOptions) {
  return firstLine(
    (
      await runWslSh(
        'if [ -x "$HOME/.argos/bin/argos" ]; then printf "%s\\n" "$HOME/.argos/bin/argos"; elif [ -x "$HOME/.opencode/bin/opencode" ]; then printf "%s\\n" "$HOME/.opencode/bin/opencode"; fi',
        distro,
        opts,
      )
    ).stdout,
  )
}

export async function readWslCommandVersion(command: string, distro: string, opts?: RunWslOptions) {
  const result = await runWslSh(`${shellEscape(command)} --version 2>/dev/null || true`, distro, opts)
  return firstLine(result.stdout)
}

export function openWslTerminal(distro?: string | null) {
  const safeDistro = distro ? requireWslDistroName("distro", distro) : undefined
  return new Promise<void>((resolve, reject) => {
    const child = spawn("cmd.exe", wslTerminalArgs(safeDistro), {
      detached: true,
      stdio: "ignore",
      windowsHide: true,
    })
    child.once("error", reject)
    child.once("spawn", () => {
      child.unref()
      resolve()
    })
  })
}

function parseInstalledDistros(output: string) {
  return output.split(/\r?\n/g).flatMap((line) => {
    const trimmed = line.trim()
    if (!trimmed) return []
    const match = line.match(/^\s*(\*)?\s*(.*?)\s{2,}\S+\s+(\d+)\s*$/)
    if (!match) return []
    const [, marker, name, version] = match
    if (!name || /^name$/i.test(name)) return []
    return [
      {
        name: name.trim(),
        version: Number.isNaN(Number.parseInt(version, 10)) ? null : Number.parseInt(version, 10),
        isDefault: marker === "*",
      } satisfies WslInstalledDistro,
    ]
  })
}

function parseOnlineDistros(output: string) {
  return output.split(/\r?\n/g).flatMap((line) => {
    const trimmed = line.trim()
    if (!trimmed) return []
    const match = trimmed.match(/^([A-Za-z0-9._-]+)\s{2,}(.+)$/)
    if (!match) return []
    const [, name, label] = match
    if (/^name$/i.test(name)) return []
    return [{ name, label: label.trim() } satisfies WslOnlineDistro]
  })
}

function firstLine(value: string) {
  return (
    value
      .split(/\r?\n/g)
      .map((line) => line.trim())
      .find(Boolean) ?? null
  )
}

export function summarize(value: string) {
  return value
    .split(/\r?\n/g)
    .map((line) => line.trim())
    .filter(Boolean)
    .join("\n")
}

export function shellEscape(value: string) {
  return `'${value.replace(/'/g, `'"'"'`)}'`
}

function resolveSystem32Command(command: string) {
  const root = process.env.SystemRoot ?? process.env.windir
  if (!root) return command
  const resolved = join(root, "System32", command)
  return existsSync(resolved) ? resolved : command
}

function withTimeout(opts: RunWslOptions | undefined, timeoutMs: number): RunWslOptions {
  return {
    ...opts,
    timeoutMs: opts?.timeoutMs ?? timeoutMs,
  }
}
