import { spawn, spawnSync } from "node:child_process"
import { createHash } from "node:crypto"
import { accessSync, constants, existsSync, readFileSync } from "node:fs"
import { readFile } from "node:fs/promises"
import { homedir } from "node:os"
import { delimiter, dirname, join } from "node:path"
import { fileURLToPath } from "node:url"
import { app, utilityProcess } from "electron"
import type { Details } from "electron"
import { staticAppEnv } from "./app-env"
import { getLogger } from "./logging"
import { getUserShell, loadShellEnv } from "./shell-env"
import { getStore } from "./store"
import { startAuthVaultBridge } from "./auth-vault"
import { authVaultEnvironment, authVaultNoProxy } from "./auth-vault-http"
import { DEFAULT_SERVER_URL_KEY } from "./store-keys"
import {
  dockerRuntimeAvailability,
  linuxRuntimeToolAvailability,
  linuxScannerAvailabilityFromCache,
  missingLinuxMcpPaths,
  nativeRuntimeToolAvailability,
  validateLinuxRuntimeManifest,
  workerImageAvailability,
  type LinuxRuntimeManifest,
} from "./wsl/linux-runtime"

export type HealthCheck = { wait: Promise<void> }

type SidecarMessage =
  | { type: "ready" }
  | { type: "stopped" }
  | { type: "error"; error: { message: string; stack?: string } }

export type SidecarListener = { stop: () => Promise<void> }

const SIDECAR_SERVICE_NAME = "argos server"
const SIDECAR_START_STALL_TIMEOUT = 60_000
const SIDECAR_STOP_TIMEOUT = 6_000

type SpawnLocalServerOptions = {
  userDataPath: string
  onStdout?: (message: string) => void
  onStderr?: (message: string) => void
  onExit?: (code: number) => void
}

export function getDefaultServerUrl(): string | null {
  const value = getStore().get(DEFAULT_SERVER_URL_KEY)
  return typeof value === "string" ? value : null
}

export function setDefaultServerUrl(url: string | null) {
  if (url) {
    getStore().set(DEFAULT_SERVER_URL_KEY, url)
    return
  }

  getStore().delete(DEFAULT_SERVER_URL_KEY)
}

const BINARY_DIR = "argos-bin"
const CONFIG_DIR = "argos-config"

function readEnv(name: string) {
  return process.env[name]
}

function writeEnv(env: Record<string, string>, name: string, value: string) {
  env[name] = value
}

function resolveArgosMcpEnv(): Record<string, string> {
  const env: Record<string, string> = {}

  if (process.platform === "linux") {
    for (const name of [
      "ARGOS_SANDBOX_IMAGE",
      "ARGOS_WEB_MCP_PATH",
      "ARGOS_WORKER_IMAGE_ARCHIVE",
      "ARGOS_WORKER_IMAGE_ARCHIVE_SHA256",
      "ARGOS_WORKER_IMAGE_ERROR",
      "ARGOS_BROWSER_WORKER_AVAILABLE",
      "ARGOS_BROWSER_WORKER_EXPECTED",
    ]) {
      delete process.env[name]
    }
  }

  const ext = process.platform === "win32" ? ".exe" : ""

  const targetOs = process.platform === "win32" ? "windows" : process.platform
  const targetArch = process.arch === "x64" ? "amd64" : process.arch
  const rootDir = dirname(fileURLToPath(import.meta.url))
  const repoRoot = join(rootDir, "..", "..", "..", "..")
  const binDirs = [
    join(repoRoot, BINARY_DIR, "bin", `${targetOs}-${targetArch}`),
    join(repoRoot, BINARY_DIR, "bin"),
  ]
  const packagedBinDirs = process.resourcesPath
    ? [
        join(process.resourcesPath, BINARY_DIR, "bin", `${targetOs}-${targetArch}`),
        join(process.resourcesPath, BINARY_DIR, "bin"),
      ]
    : []
  const nativeLinuxWorker =
    process.platform === "linux" ? resolveNativeLinuxWorker(repoRoot, targetArch) : null
  if (nativeLinuxWorker?.manifest.worker) {
    writeEnv(env, "ARGOS_SANDBOX_IMAGE", nativeLinuxWorker.manifest.worker.imageId)
    const webBinary = join(nativeLinuxWorker.payloadDirectory, "web")
    if (existsSync(webBinary)) writeEnv(env, "ARGOS_WEB_MCP_PATH", webBinary)
    writeEnv(env, "ARGOS_WORKER_IMAGE_ARCHIVE", nativeLinuxWorker.archivePath)
    writeEnv(env, "ARGOS_WORKER_IMAGE_ARCHIVE_SHA256", nativeLinuxWorker.manifest.worker.archiveSha256)
    if (nativeLinuxWorker.manifest.worker.browserAvailable) writeEnv(env, "ARGOS_BROWSER_WORKER_EXPECTED", "1")
    if (nativeLinuxWorker.error) writeEnv(env, "ARGOS_WORKER_IMAGE_ERROR", nativeLinuxWorker.error)
  }

  interface McpDef {
    name: string
    envVar: string
    binaryName: string
    flag?: string
  }
  const mcpDefs: McpDef[] = [
    {
      name: "argos",
      envVar: "ARGOS_MCP_PATH",
      binaryName: `orquestador${ext}`,
      flag: "--mcp",
    },
    {
      name: "argos-lan",
      envVar: "ARGOS_LAN_MCP_PATH",
      binaryName: `lan${ext}`,
      flag: "--mcp",
    },
    {
      name: "argos-web",
      envVar: "ARGOS_WEB_MCP_PATH",
      binaryName: `web${ext}`,
      flag: "--mcp",
    },
    {
      name: "argos-es",
      envVar: "ARGOS_ES_MCP_PATH",
      binaryName: `es${ext}`,
      flag: "--mcp",
    },
  ]

  const configDir = (app.isPackaged && process.resourcesPath
    ? join(process.resourcesPath, CONFIG_DIR)
    : join(repoRoot, CONFIG_DIR))

  if (existsSync(configDir)) {
    env.ARGOS_CONFIG_DIR = configDir
    env.OPENCODE_CONFIG_DIR = configDir
    writeEnv(env, "ARGOS_BROWSER_SECCOMP_PROFILE", join(configDir, "runtime", "chromium-seccomp.json"))
  }

  writeEnv(env, "ARGOS_NODE", process.execPath)

  const mcpEntries: Record<string, unknown> = {}
  let hasContent = false

  for (const def of mcpDefs) {
    if (def.name === "argos-lan" || def.name === "argos-es") continue
    if (def.name === "argos-web" && (process.platform !== "linux" || !nativeLinuxWorker?.manifest.profile.includes("argos-web"))) continue
    let binPath: string | null = null

    const fromEnv = readEnv(def.envVar)
    if (fromEnv) {
      binPath = fromEnv
    } else {
      const dirs = app.isPackaged ? [...packagedBinDirs, ...binDirs] : binDirs
      searchLoop: for (const dir of dirs) {
        const fullPath = join(dir, def.binaryName)
        if (existsSync(fullPath)) {
          writeEnv(env, def.envVar, fullPath)
          binPath = fullPath
          break searchLoop
        }
      }
    }

    if (binPath) {
      const entry: Record<string, unknown> = {
        type: "local",
        command: def.flag ? [binPath, def.flag] : [binPath],
        enabled: true,
      }
      if (def.name === "argos-web") {
        entry.env = {
          ARGOS_REQUIRE_CONTAINER_AUDIT: "1",
          ...(process.env.ARGOS_BROWSER_WORKER_AVAILABLE === "1" ? { ARGOS_BROWSER_WORKER_AVAILABLE: "1" } : {}),
        }
      }
      mcpEntries[def.name] = entry
      hasContent = true
    }
  }

  const npxPath = process.platform === "linux" || process.platform === "darwin" ? null : "npx"
  if (npxPath) {
    mcpEntries["chrome-devtools"] = {
      type: "local",
      command: [npxPath, "-y", "chrome-devtools-mcp@1.6.0"],
      enabled: true,
    }
    hasContent = true
  }

  if (hasContent) {
    const config: Record<string, unknown> = {
      $schema: "https://opencode.ai/config.json",
      mcp: mcpEntries,
      experimental: {
        mcp_timeout: 300_000,
      },
      tool_output: {
        max_lines: 8_000,
        max_bytes: 200 * 1024,
      },
    }

    if (configDir && existsSync(join(configDir, "agent", "security-orchestrator.md"))) {
      config.default_agent = "security-orchestrator"
    }

    env.ARGOS_CONFIG_CONTENT = JSON.stringify(config)
    env.OPENCODE_CONFIG_CONTENT = JSON.stringify(config)
  }

  return env
}

export function linuxFirstRuntimePreflight() {
  const requiredPaths = {
    argos: process.env.ARGOS_MCP_PATH,
  }
  const missing = missingLinuxMcpPaths(requiredPaths, (path) => {
    if (!path) return false
    try {
      accessSync(path, constants.X_OK)
      return true
    } catch {
      return false
    }
  })
  if (missing.length) {
    const architecture = process.arch === "x64" ? "amd64" : process.arch === "arm64" ? "arm64" : process.arch
    throw new Error(
      `Argos Linux runtime for linux/${architecture} is missing executable MCPs: ${missing.join(", ")}. Reinstall Argos or rebuild its Linux runtime package, then relaunch.`,
    )
  }

  const architecture = process.arch === "x64" ? "amd64" : process.arch === "arm64" ? "arm64" : null
  if (!architecture) throw new Error(`Argos Linux runtime does not support ${process.arch}`)
  const toolsDirectory = process.env.ARGOS_TOOLS_DIR ?? join(homedir(), ".argos", "tools")
  const cachedScanners = linuxScannerAvailabilityFromCache(architecture, toolsDirectory, (path) => {
    try {
      accessSync(path, constants.X_OK)
      return true
    } catch {
      return false
    }
  })
  const docker = probeDockerRuntime()
  const worker = probeDockerWorker(docker)
  const browser = probeDockerBrowserWorker(docker, worker, process.env.ARGOS_BROWSER_WORKER_EXPECTED === "1")
  const tools = linuxRuntimeToolAvailability(
    cachedScanners,
    docker,
    worker.available,
    isExecutable(process.env.ARGOS_WEB_MCP_PATH),
    browser.available,
  )
  tools["web.browse"] = browser
  return tools
}

export function nativeRuntimePreflight() {
  const docker = probeDockerRuntime()
  const worker = probeDockerWorker(docker)
  const browser = probeDockerBrowserWorker(docker, worker, process.env.ARGOS_BROWSER_WORKER_EXPECTED === "1")
  const tools = nativeRuntimeToolAvailability(
    docker,
    worker.available,
    isExecutable(process.env.ARGOS_WEB_MCP_PATH),
    browser.available,
  )
  tools["web.browse"] = browser
  return tools
}

function isExecutable(path: string | undefined) {
  if (!path) return false
  try {
    accessSync(path, constants.X_OK)
    return true
  } catch {
    return false
  }
}

function probeDockerRuntime() {
  const cliPath = findExecutableOnPath("docker")
  if (!cliPath) return dockerRuntimeAvailability(null, null)
  const result = spawnSync(cliPath, ["info", "--format", "{{.ServerVersion}}"], {
    encoding: "utf8",
    timeout: 3_000,
    windowsHide: true,
  })
  const serverVersion = result.status === 0 ? result.stdout.trim() || null : null
  return dockerRuntimeAvailability(cliPath, serverVersion)
}

function probeDockerWorker(docker: ReturnType<typeof probeDockerRuntime>) {
  const expectedImageId = process.env.ARGOS_SANDBOX_IMAGE
  const failureReason = process.env.ARGOS_WORKER_IMAGE_ERROR
  if (!docker.available || !docker.path || !expectedImageId) {
    return workerImageAvailability(docker, expectedImageId, null, failureReason)
  }
  const result = spawnSync(docker.path, ["image", "inspect", "--format", "{{.Id}}", expectedImageId], {
    encoding: "utf8",
    timeout: 3_000,
    windowsHide: true,
  })
  const actualImageId = result.status === 0 ? result.stdout.trim() || null : null
  return workerImageAvailability(docker, expectedImageId, actualImageId, failureReason)
}

function probeDockerBrowserWorker(
  docker: ReturnType<typeof probeDockerRuntime>,
  worker: ReturnType<typeof probeDockerWorker>,
  expected: boolean,
) {
  if (!expected) {
    return {
      available: false,
      path: null,
      reason: "The pinned Linux package does not include a browser worker for this architecture.",
    }
  }
  if (!worker.available || !docker.path) {
    return { available: false, path: null, reason: worker.reason ?? docker.reason ?? "Docker worker is unavailable." }
  }
  const result = spawnSync(
    docker.path,
    [
      "run",
      "--rm",
      "--pull=never",
      "--init",
      "--network=none",
      "--read-only",
      "--user=65532:65532",
      "--cap-drop=ALL",
      "--security-opt=no-new-privileges",
      `--security-opt=seccomp=${process.env.ARGOS_BROWSER_SECCOMP_PROFILE ?? ""}`,
      "--pids-limit=256",
      "--cpus=2",
      "--memory=1g",
      "--tmpfs",
      "/tmp:rw,nosuid,nodev,noexec,size=128m",
      process.env.ARGOS_SANDBOX_IMAGE ?? "",
      "/usr/local/bin/argos-browser-worker",
      "--preflight",
    ],
    { encoding: "utf8", timeout: 45_000, windowsHide: true },
  )
  if (result.status !== 0 || !result.stdout.includes('"status":"ready"')) {
    const detail = [result.error?.message, result.stderr?.trim()].filter(Boolean).join(": ").slice(-1_000)
    return {
      available: false,
      path: null,
      reason: `Chromium failed the isolated Docker preflight${detail ? `: ${detail}` : "."}`,
    }
  }
  return { available: true, path: "argos-web", reason: null }
}

export async function ensureNativeLinuxWorkerImage() {
  if (process.platform !== "linux") return
  const docker = probeDockerRuntime()
  if (!docker.available || !docker.path) return

  const imageId = process.env.ARGOS_SANDBOX_IMAGE
  const archivePath = process.env.ARGOS_WORKER_IMAGE_ARCHIVE
  const expectedArchiveSha256 = process.env.ARGOS_WORKER_IMAGE_ARCHIVE_SHA256
  if (!imageId || !archivePath || !expectedArchiveSha256) return

  let archive: Buffer
  try {
    archive = await readFile(archivePath)
  } catch (error) {
    setWorkerImageError(`The pinned Argos worker archive could not be read: ${error instanceof Error ? error.message : String(error)}`)
    return
  }
  const archiveSha256 = createHash("sha256").update(archive).digest("hex")
  if (archiveSha256 !== expectedArchiveSha256) {
    setWorkerImageError("The pinned Argos worker image archive failed SHA-256 verification.")
    return
  }

  const inspect = await runProcess(docker.path, ["image", "inspect", "--format", "{{.Id}}", imageId], 3_000)
  if (inspect.code === 0 && inspect.stdout.trim() === imageId) {
    clearWorkerImageError()
    return
  }

  const load = await runProcess(docker.path, ["load", "--input", archivePath], 120_000)
  if (load.code !== 0) {
    const detail = [load.error, load.stderr.trim()].filter(Boolean).join("\n").slice(-2_000)
    setWorkerImageError(`Could not load the Argos worker image${detail ? `: ${detail}` : ""}`)
    return
  }

  const verified = await runProcess(docker.path, ["image", "inspect", "--format", "{{.Id}}", imageId], 3_000)
  if (verified.code !== 0 || verified.stdout.trim() !== imageId) {
    setWorkerImageError("Loaded Docker image does not match the package-pinned Argos worker image ID.")
    return
  }
  clearWorkerImageError()
}

function runProcess(command: string, args: string[], timeoutMs: number) {
  return new Promise<{ code: number | null; stdout: string; stderr: string; error: string | null }>((resolve) => {
    const child = spawn(command, args, { stdio: ["ignore", "pipe", "pipe"], windowsHide: true })
    let stdout = ""
    let stderr = ""
    let settled = false
    const finish = (code: number | null, error: string | null = null) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      resolve({ code, stdout, stderr, error })
    }
    const timer = setTimeout(() => {
      child.kill()
      finish(null, `${command} timed out after ${timeoutMs}ms`)
    }, timeoutMs)
    child.stdout.setEncoding("utf8")
    child.stderr.setEncoding("utf8")
    child.stdout.on("data", (chunk: string) => {
      stdout = (stdout + chunk).slice(-2_000)
    })
    child.stderr.on("data", (chunk: string) => {
      stderr = (stderr + chunk).slice(-2_000)
    })
    child.once("error", (error) => finish(null, error.message))
    child.once("close", (code) => finish(code))
  })
}

function setWorkerImageError(message: string) {
  process.env.ARGOS_WORKER_IMAGE_ERROR = message
}

function clearWorkerImageError() {
  delete process.env.ARGOS_WORKER_IMAGE_ERROR
}

function resolveNativeLinuxWorker(repoRoot: string, architecture: string) {
  if (architecture !== "amd64" && architecture !== "arm64") return null
  const payloadCandidates = [
    ...(process.resourcesPath ? [join(process.resourcesPath, "argos-bin", "bin", `linux-${architecture}`)] : []),
    join(repoRoot, "argos-bin", "bin", `linux-${architecture}`),
  ]
  const payloadDirectory = payloadCandidates.find((candidate) => existsSync(join(candidate, "manifest.json")))
  if (!payloadDirectory) return null

  let manifest: LinuxRuntimeManifest
  try {
    manifest = validateLinuxRuntimeManifest(
      JSON.parse(readFileSync(join(payloadDirectory, "manifest.json"), "utf8")),
      app.getVersion(),
      architecture,
    )
  } catch {
    return null
  }
  if (!manifest.profile.includes("argos-web") || !manifest.worker || manifest.web !== "web") return null

  const archivePath = join(payloadDirectory, manifest.worker.archive)
  if (!existsSync(archivePath)) {
    return { payloadDirectory, manifest, archivePath, error: "The pinned Argos worker image archive is missing from the Linux package." }
  }
  if (!existsSync(join(payloadDirectory, "web"))) {
    return { payloadDirectory, manifest, archivePath, error: "The Linux Argos web MCP binary is missing from the package." }
  }
  return { payloadDirectory, manifest, archivePath, error: null }
}

function findExecutableOnPath(name: string) {
  for (const directory of (process.env.PATH ?? "").split(delimiter).filter(Boolean)) {
    const candidate = join(directory, name)
    try {
      accessSync(candidate, constants.X_OK)
      return candidate
    } catch {
      continue
    }
  }
  return null
}

export function preferAppEnv(userDataPath: string) {
  const shell = process.platform === "win32" ? null : getUserShell()
  if (shell) Object.assign(process.env, loadShellEnv(shell, getLogger()))
  Object.assign(process.env, resolveArgosMcpEnv(), staticAppEnv(userDataPath))
}

export async function spawnLocalServer(
  hostname: string,
  port: number,
  password: string,
  options: SpawnLocalServerOptions,
) {
  const sidecar = join(dirname(fileURLToPath(import.meta.url)), "sidecar.js")
  const authVault = await startAuthVaultBridge().catch((error) => {
    options.onStderr?.(`secure auth vault unavailable: ${serializeError(error).message}`)
    return undefined
  })
  const vaultBypass = authVault ? authVaultNoProxy(authVault) : "127.0.0.1"
  let child: ReturnType<typeof utilityProcess.fork>
  try {
    child = utilityProcess.fork(sidecar, [], {
      cwd: process.cwd(),
      env: {
        ...createSidecarEnv(),
        ARGOS_AUTH_VAULT_URLS: "[]",
        ARGOS_AUTH_VAULT_TOKEN: "",
        NO_PROXY: [process.env.NO_PROXY, vaultBypass].filter(Boolean).join(","),
        no_proxy: [process.env.no_proxy, vaultBypass].filter(Boolean).join(","),
        ...(authVault ? authVaultEnvironment(authVault) : {}),
      },
      serviceName: SIDECAR_SERVICE_NAME,
      stdio: "pipe",
    })
  } catch (error) {
    await authVault?.close().catch(() => undefined)
    throw error
  }
  let exited = false
  let vaultClosed: Promise<void> | undefined
  const closeVault = () => {
    if (!vaultClosed) vaultClosed = authVault?.close() ?? Promise.resolve()
    return vaultClosed
  }
  const exit = defer<number>()

  const onProcessGone = (_event: unknown, details: Details) => {
    if (details.type !== "Utility" || details.name !== SIDECAR_SERVICE_NAME) return
    options.onStderr?.(`utility process gone reason=${details.reason} exitCode=${details.exitCode}`)
  }

  app.on("child-process-gone", onProcessGone)
  child.once("exit", (code) => {
    exited = true
    app.off("child-process-gone", onProcessGone)
    void closeVault().catch((error) => options.onStderr?.(`secure auth vault close failed: ${serializeError(error).message}`))
    options.onExit?.(code)
    exit.resolve(code)
  })
  child.on("error", (error) => options.onStderr?.(`utility process error: ${serializeError(error).message}`))

  child.stdout?.on("data", (chunk: Buffer) => options.onStdout?.(chunk.toString("utf8").trimEnd()))
  child.stderr?.on("data", (chunk: Buffer) => options.onStderr?.(chunk.toString("utf8").trimEnd()))

  await new Promise<void>((resolve, reject) => {
    let done = false
    let timeout: NodeJS.Timeout

    const fail = (error: Error) => {
      if (done) return
      done = true
      cleanup()
      reject(error)
    }

    const refreshTimeout = () => {
      clearTimeout(timeout)
      timeout = setTimeout(() => {
        fail(new Error(`Sidecar did not become ready within ${SIDECAR_START_STALL_TIMEOUT}ms: ${sidecar}`))
      }, SIDECAR_START_STALL_TIMEOUT)
    }

    const onMessage = (message: SidecarMessage) => {
      if (message.type === "ready") {
        if (done) return
        done = true
        cleanup()
        resolve()
        return
      }
      if (message.type === "error") {
        fail(Object.assign(new Error(message.error.message), { stack: message.error.stack }))
      }
    }
    const onExit = (code: number) => {
      fail(new Error(`Sidecar exited before ready with code ${code}`))
    }
    const cleanup = () => {
      clearTimeout(timeout)
      child.off("message", onMessage)
      child.off("exit", onExit)
    }

    child.on("message", onMessage)
    child.on("exit", onExit)
    refreshTimeout()
    child.postMessage({
      type: "start",
      hostname,
      port,
      userDataPath: options.userDataPath,
    })
  }).catch(async (error) => {
    if (!exited) child.kill()
    await closeVault().catch(() => undefined)
    throw error
  })

  const wait = (async () => {
    const url = `http://${hostname}:${port}`
    let healthy = false
    const gone = exit.promise.then((code) => {
      if (healthy) return
      throw new Error(`Sidecar exited before health check passed with code ${code}`)
    })

    const ready = async () => {
      const deadline = Date.now() + SIDECAR_START_STALL_TIMEOUT
      while (Date.now() < deadline) {
        await new Promise((resolve) => setTimeout(resolve, 100))
        if (await checkHealth(url, password)) {
          healthy = true
          return
        }
      }
      throw new Error(`Health check did not pass within ${SIDECAR_START_STALL_TIMEOUT}ms`)
    }

    await Promise.race([ready(), gone])
  })()

  let stopping: Promise<void> | undefined

  return {
    listener: {
      stop: () => {
        if (stopping) return stopping
        if (exited) return Promise.resolve()
        child.postMessage({ type: "stop" })
        stopping = Promise.race([
          exit.promise.then(() => undefined),
          delay(SIDECAR_STOP_TIMEOUT).then(() => {
            if (!exited) child.kill()
          }),
        ])
        return stopping.then(closeVault)
      },
    },
    health: { wait },
  }
}

export async function checkHealth(url: string, password?: string | null): Promise<boolean> {
  let healthUrl: URL
  try {
    healthUrl = new URL("/global/health", url)
  } catch {
    return false
  }

  const headers = new Headers()
  if (password) {
    const auth = Buffer.from(`opencode:${password}`).toString("base64")
    headers.set("authorization", `Basic ${auth}`)
  }

  try {
    const res = await fetch(healthUrl, {
      method: "GET",
      headers,
      signal: AbortSignal.timeout(3000),
    })
    return res.ok
  } catch {
    return false
  }
}

function createSidecarEnv(): Record<string, string> {
  const env = Object.fromEntries(
    Object.entries(process.env).flatMap(([key, value]) => (value === undefined ? [] : [[key, value]])),
  )
  delete env.DEBUG
  if (process.platform === "linux") delete env.LD_PRELOAD
  if (!app.isPackaged) {
    env.ARGOS_DISABLE_CHANNEL_DB = "1"
    env.OPENCODE_DISABLE_CHANNEL_DB = "1"
  }
  return env
}

function delay(ms: number) {
  return new Promise<void>((resolve) => setTimeout(resolve, ms))
}

function serializeError(error: unknown) {
  if (error instanceof Error) return { message: error.message, stack: error.stack }
  return { message: String(error) }
}

function defer<T>() {
  let resolve!: (value: T) => void
  let reject!: (error: Error) => void
  const promise = new Promise<T>((res, rej) => {
    resolve = res
    reject = rej
  })
  return { promise, resolve, reject }
}
