import { spawn } from "node:child_process"
import { existsSync } from "node:fs"
import { readFile } from "node:fs/promises"
import { randomUUID } from "node:crypto"
import { createServer } from "node:net"
import { dirname, join, resolve } from "node:path"
import { fileURLToPath } from "node:url"
import { app } from "electron"
import { startAuthVaultBridge } from "../auth-vault"
import { authVaultEnvironment, authVaultNoProxy } from "../auth-vault-http"
import { checkHealth } from "../server"
import {
  createLinuxFirstMcpConfig,
  linuxRuntimeToolAvailability,
  validateLinuxRuntimeManifest,
} from "./linux-runtime"
import {
  ensureArgosWslDistro,
  listInstalledWslDistros,
  probeWslDistro,
  probeWslRuntime,
  provisionWslArgosPackage,
  shellEscape,
  wslArgs,
  type WslCommandLine,
} from "./runtime"
import { ARGOS_WSL_DISTRO_NAME, pollWslHealth, wslArchitectureToGoArch } from "./startup"

export type WslSidecar = {
  listener: {
    stop: () => Promise<void>
    onExit: (cb: (code: number | null, signal: NodeJS.Signals | null) => void) => void
  }
  url: string
  username: string | null
  password: string
  distro: string
  wslVersion: string | null
  architecture: "amd64" | "arm64"
  packageVersion: string
  tools: NonNullable<Awaited<ReturnType<typeof probeWslDistro>>["tools"]>
}

export async function spawnPrimaryWslSidecar(
  opts: { onLine?: (line: WslCommandLine) => void; healthTimeoutMs?: number } = {},
) {
  const runtime = await probeWslRuntime()
  if (!runtime.available) {
    throw new Error(
      `Argos requires WSL 2 on Windows. ${runtime.error ?? "Install WSL with wsl --install, restart Windows if prompted, then launch Argos again."}`,
    )
  }
  const architecture = wslArchitectureToGoArch(process.arch)
  const managed = await ensureArgosWslDistro(app.getPath("userData"), architecture).catch((error) => {
    throw new Error(`Argos could not prepare its private WSL runtime: ${error instanceof Error ? error.message : String(error)}`)
  })
  return spawnWslSidecar(managed.name, { ...opts, managedRuntime: true })
}

export async function spawnWslSidecar(
  distro: string,
  opts: { onLine?: (line: WslCommandLine) => void; healthTimeoutMs?: number; managedRuntime?: boolean } = {},
): Promise<WslSidecar> {
  const appVersion = app.getVersion()
  const distroInfo = (await listInstalledWslDistros()).find((item) => item.name === distro)
  if (!distroInfo || distroInfo.version !== 2) {
    throw new Error(`Argos requires ${distro} to run as WSL 2. Set it with: wsl --set-version "${distro}" 2`)
  }

  const probe = await probeWslDistro(distro, { wslVersion: distroInfo.version, packageVersion: appVersion })
  if (!probe.canExecute) throw new Error(probe.error ?? `Cannot execute commands in ${distro}`)
  if (!probe.architecture) {
    throw new Error(probe.error ?? `Argos has no Linux runtime for the architecture in ${distro}`)
  }
  if (probe.error) {
    throw new Error(
      `The WSL 2 distribution ${distro} is not ready for the Linux runtime: ${probe.error}. Install the missing userland tools in the distro, then retry.`,
    )
  }
  const architecture = wslArchitectureToGoArch(probe.architecture)
  const payloadDirectory = resolveLinuxPayloadDirectory(architecture)
  const packageInfo = await provisionWslArgosPackage(distro, payloadDirectory, appVersion, architecture)
  const toolsProbe = await probeWslDistro(distro, {
    wslVersion: distroInfo.version,
    packageVersion: appVersion,
    workerImageId: packageInfo.manifest.worker?.imageId,
    browserWorkerExpected: packageInfo.manifest.worker?.browserAvailable === true,
    timeoutMs: 60_000,
  })
  const tools = runtimeToolsFromProbe(toolsProbe, packageInfo.manifest)

  const port = await allocatePort()
  const password = randomUUID()
  const authVault = await startAuthVaultBridge({ wslHost: true }).catch((error) => {
    opts.onLine?.({
      stream: "stderr",
      text: `Authenticated browser profiles are unavailable: ${error instanceof Error ? error.message : String(error)}`,
    })
    return undefined
  })
  const authVaultBypass = authVault ? authVaultNoProxy(authVault) : "127.0.0.1"
  const username = "opencode"
  const runtimeDirectory = `__ARGOS_RUNTIME__`
  const configTemplate = JSON.stringify(
    createLinuxFirstMcpConfig(
      runtimeDirectory,
      packageInfo.manifest.profile.includes("argos-web"),
      Boolean(toolsProbe.tools?.["web.browse"]?.available),
    ),
  )
  const configScript = [
    `export ARGOS_CONFIG_TEMPLATE=${shellEscape(configTemplate)}`,
    `export ARGOS_CONFIG_CONTENT="$("$ARGOS_NODE" -e 'const config=JSON.parse(process.env.ARGOS_CONFIG_TEMPLATE);const root=process.env.ARGOS_RUNTIME_DIR;for(const entry of Object.values(config.mcp))entry.command=entry.command.map((part)=>part.replaceAll("__ARGOS_RUNTIME__",root));process.stdout.write(JSON.stringify(config))')"`,
    `export OPENCODE_CONFIG_CONTENT="$ARGOS_CONFIG_CONTENT"`,
  ]
  const script = [
    "set -euo pipefail",
    'cd "$HOME" || cd /',
    "export WSLENV=",
    "export ARGOS_WSL_RUNTIME=1",
    "export ARGOS_EXPERIMENTAL_DISABLE_FILEWATCHER=true",
    "export OPENCODE_EXPERIMENTAL_DISABLE_FILEWATCHER=true",
    "export ARGOS_DISABLE_EMBEDDED_WEB_UI=true",
    "export OPENCODE_DISABLE_EMBEDDED_WEB_UI=true",
    "export ARGOS_CLIENT=desktop",
    "export OPENCODE_CLIENT=desktop",
    `export ARGOS_SERVER_USERNAME=${shellEscape(username)}`,
    `export OPENCODE_SERVER_USERNAME=${shellEscape(username)}`,
    `export ARGOS_SERVER_PASSWORD=${shellEscape(password)}`,
    `export OPENCODE_SERVER_PASSWORD=${shellEscape(password)}`,
    `export ARGOS_RUNTIME_DIR="$HOME/.local/share/argos/runtime/${packageInfo.manifest.version}"`,
    `export ARGOS_NODE="$ARGOS_RUNTIME_DIR/node/bin/node"`,
    `export ARGOS_CONFIG_DIR="$ARGOS_RUNTIME_DIR/config"`,
    `export ARGOS_BROWSER_SECCOMP_PROFILE="$ARGOS_CONFIG_DIR/runtime/chromium-seccomp.json"`,
    `export OPENCODE_CONFIG_DIR="$ARGOS_CONFIG_DIR"`,
    `export ARGOS_MCP_PATH="$ARGOS_RUNTIME_DIR/orquestador"`,
    ...(packageInfo.manifest.web ? [`export ARGOS_WEB_MCP_PATH="$ARGOS_RUNTIME_DIR/${packageInfo.manifest.web}"`] : []),
    ...(packageInfo.manifest.worker
      ? [`export ARGOS_SANDBOX_IMAGE=${shellEscape(packageInfo.manifest.worker.imageId)}`]
      : []),
    `export ARGOS_TOOLS_DIR="$HOME/.argos/tools"`,
    `export ARGOS_NUCLEI_PACKS_DIR="$ARGOS_CONFIG_DIR/templates/nuclei"`,
    `export ARGOS_PORT=${port}`,
    `export ARGOS_AUTH_VAULT_NO_PROXY=${shellEscape(authVaultBypass)}`,
    'export NO_PROXY="${NO_PROXY:+$NO_PROXY,}$ARGOS_AUTH_VAULT_NO_PROXY"',
    'export no_proxy="$NO_PROXY"',
    ...Object.entries(
      authVault
        ? authVaultEnvironment(authVault)
        : { ARGOS_AUTH_VAULT_URLS: "[]", ARGOS_AUTH_VAULT_TOKEN: "" },
    ).map(([name, value]) => `export ${name}=${shellEscape(value)}`),
    `export XDG_DATA_HOME="$HOME/.local/share/argos/data"`,
    `export XDG_CONFIG_HOME="$HOME/.config/argos"`,
    `export XDG_CACHE_HOME="$HOME/.cache/argos"`,
    `export XDG_STATE_HOME="$HOME/.local/state/argos"`,
    `export PATH="$ARGOS_RUNTIME_DIR/node/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"`,
    ...configScript,
    `exec "$ARGOS_NODE" "$ARGOS_RUNTIME_DIR/${packageInfo.manifest.server}"`,
  ].join("\n")
  const child = spawn("wsl", wslArgs(["bash", "-se"], distro, opts.managedRuntime ? "argos" : undefined), {
    stdio: ["pipe", "pipe", "pipe"],
    windowsHide: true,
  })
  child.stdin.end(script)
  child.once("exit", () => {
    void authVault?.close().catch(() => undefined)
  })

  const recentOutput: string[] = []
  const emit = (line: WslCommandLine) => {
    if (!line.text.trim()) return
    recentOutput.push(`[${line.stream}] ${line.text}`)
    if (recentOutput.length > 12) recentOutput.shift()
    opts.onLine?.(line)
  }
  forwardLines(child.stdout, "stdout", emit)
  forwardLines(child.stderr, "stderr", emit)

  const exit = new Promise<never>((_, reject) => {
    child.once("error", reject)
    child.once("exit", (code, signal) => reject(new Error(startupFailure(code, signal, recentOutput))))
  })
  const url = `http://127.0.0.1:${port}`
  const startup = new AbortController()
  const health = pollWslHealth(() => checkHealth(url, password), startup.signal)
  const timeoutMs = opts.healthTimeoutMs ?? 60_000
  let timeout: ReturnType<typeof setTimeout>
  const timedOut = new Promise<never>(
    (_, reject) =>
      (timeout = setTimeout(
        () => reject(new Error(`Sidecar for ${distro} health check timed out after ${timeoutMs}ms`)),
        timeoutMs,
      )),
  )

  await Promise.race([health, exit, timedOut])
    .catch(async (error) => {
      child.kill()
      await authVault?.close().catch(() => undefined)
      throw error
    })
    .finally(() => {
      clearTimeout(timeout)
      startup.abort()
    })
  return {
    listener: {
      stop: async () => {
        child.kill()
        await authVault?.close().catch(() => undefined)
      },
      onExit: (cb) => child.once("exit", cb),
    },
    url,
    username,
    password,
    distro,
    wslVersion: (await probeWslRuntime()).version,
    architecture,
    packageVersion: packageInfo.manifest.version,
    tools,
  }
}

function runtimeToolsFromProbe(
  probe: Awaited<ReturnType<typeof probeWslDistro>>,
  manifest: { profile: string[] },
) {
  return linuxRuntimeToolAvailability(
    Object.fromEntries(
      Object.entries(probe.tools ?? {}).filter(([name]) => name !== "docker" && name !== "argos-worker"),
    ),
    probe.tools?.docker ?? { available: false, path: null, reason: "Docker Engine probe did not return a result." },
    Boolean(probe.tools?.["argos-worker"]?.available),
    manifest.profile.includes("argos-web"),
    Boolean(probe.tools?.["web.browse"]?.available),
  )
}

export async function probePrimaryWslRuntimeTools() {
  if (process.platform !== "win32") return null
  const architecture = wslArchitectureToGoArch(process.arch)
  const payloadDirectory = resolveLinuxPayloadDirectory(architecture)
  const manifest = validateLinuxRuntimeManifest(
    JSON.parse(await readFile(join(payloadDirectory, "manifest.json"), "utf8")),
    app.getVersion(),
    architecture,
  )
  const probe = await probeWslDistro(ARGOS_WSL_DISTRO_NAME, {
    packageVersion: app.getVersion(),
    workerImageId: manifest.worker?.imageId,
    browserWorkerExpected: manifest.worker?.browserAvailable === true,
    timeoutMs: 60_000,
  })
  return runtimeToolsFromProbe(probe, manifest)
}

function resolveLinuxPayloadDirectory(architecture: "amd64" | "arm64") {
  const root = app.isPackaged ? process.resourcesPath : resolve(dirname(fileURLToPath(import.meta.url)), "../../../..")
  if (!root) throw new Error("Argos Linux runtime resources are unavailable")
  const payload = join(root, "argos-bin", "bin", `linux-${architecture}`)
  if (!existsSync(join(payload, "manifest.json"))) {
    throw new Error(`Argos Linux runtime package for linux/${architecture} is not included in this desktop build`)
  }
  return payload
}

function allocatePort() {
  return new Promise<number>((resolve, reject) => {
    const server = createServer()
    server.on("error", reject)
    server.listen(0, "127.0.0.1", () => {
      const address = server.address()
      if (typeof address !== "object" || !address) {
        server.close()
        reject(new Error("Failed to get port"))
        return
      }
      server.close(() => resolve(address.port))
    })
  })
}

function forwardLines(
  stream: NodeJS.ReadableStream,
  source: WslCommandLine["stream"],
  onLine: (line: WslCommandLine) => void,
) {
  let pending = ""
  stream.setEncoding("utf8")
  stream.on("data", (chunk: string) => {
    pending += chunk
    const lines = pending.split(/\r?\n/g)
    pending = lines.pop() ?? ""
    lines.forEach((text) => onLine({ stream: source, text }))
  })
  stream.on("end", () => {
    if (pending) onLine({ stream: source, text: pending })
  })
}

function startupFailure(code: number | null, signal: NodeJS.Signals | null, recentOutput: string[]) {
  const suffix = recentOutput.length ? `\n${recentOutput.join("\n")}` : ""
  return `WSL server exited before becoming healthy (code=${code ?? "null"} signal=${signal ?? "null"})${suffix}`
}
