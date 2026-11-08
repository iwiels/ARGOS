import { expect, test } from "bun:test"
import { readFileSync } from "node:fs"
import { join } from "node:path"
import {
  buildWslProvisioningScript,
  buildWslRootfsBootstrapScript,
  glibcRuntimeIssue,
  linuxScannerAvailabilityFromCache,
  missingLinuxMcpPaths,
  createLinuxFirstMcpConfig,
  dockerRuntimeAvailability,
  webAuditRuntimeAvailability,
  linuxRuntimeToolAvailability,
  scannerToolAvailability,
  validateLinuxRuntimeManifest,
  workerImageAvailability,
} from "./linux-runtime"

const manifest = {
  version: "0.1.0",
  platform: "linux",
  architecture: "amd64",
  profile: ["argos"],
  node: {
    version: "24.21.0",
    asset: "node-v24.21.0-linux-x64.tar.xz",
    sha256: "fd8e59d5a511510f6a298afb548f18c7d2b1be404d8b4a27d94fbe49f56cb2d6",
  },
  nodePty: { package: "@lydell/node-pty", version: "1.2.0-beta.12" },
  jsoncParser: { package: "jsonc-parser", version: "3.3.1" },
  server: "server/wsl.js",
  config: "config",
  toolsDirectory: "$HOME/.argos/tools",
}

test("preflights glibc compatibility for the pinned official Node runtime", () => {
  expect(glibcRuntimeIssue("glibc 2.27")).toContain("2.28 or newer")
  expect(glibcRuntimeIssue("glibc 2.28")).toBeNull()
  expect(glibcRuntimeIssue(null)).toContain("Alpine/musl")
})

test("bootstraps only the managed Debian runtime with a non-sudo Argos user", () => {
  const script = buildWslRootfsBootstrapScript()
  expect(script).toContain("apt-get install -y --no-install-recommends")
  expect(script).toContain("default=argos")
  expect(script).toContain("systemd=false")
  expect(script).toContain("usermod -aG")
  expect(script).not.toContain("sudo")
  expect(script).not.toContain("wsl --set-default")
})

test("accepts only the matching Linux Argos package version and architecture", () => {
  expect(validateLinuxRuntimeManifest(manifest, "0.1.0", "amd64")).toEqual(manifest)
  expect(() => validateLinuxRuntimeManifest(manifest, "0.1.1", "amd64")).toThrow("package version")
  expect(() => validateLinuxRuntimeManifest(manifest, "0.1.0", "arm64")).toThrow("architecture")
  expect(() => validateLinuxRuntimeManifest({ ...manifest, jsoncParser: undefined }, "0.1.0", "amd64")).toThrow(
    "JSONC parser dependency",
  )
  expect(() => validateLinuxRuntimeManifest({ ...manifest, profile: [] }, "0.1.0", "amd64")).toThrow(
    "Argos server profile",
  )
})

test("validates and provisions the Linux headless runner as a checksummed runtime binary", () => {
  const runnerManifest = { ...manifest, profile: ["argos", "argos-runner"], runner: "argos-runner" }
  expect(validateLinuxRuntimeManifest(runnerManifest, "0.1.0", "amd64")).toMatchObject({
    profile: ["argos", "argos-runner"],
    runner: "argos-runner",
  })
  expect(() =>
    validateLinuxRuntimeManifest({ ...runnerManifest, runner: "other-binary" }, "0.1.0", "amd64"),
  ).toThrow("runner binary")

  const script = buildWslProvisioningScript("/tmp/argos-runtime", runnerManifest, "b".repeat(64))
  expect(script).toContain('"$payload/argos-runner" "$tmp"/')
  expect(script).toContain('chmod 755 "$tmp/argos-runner"')
  expect(script).toContain('[ -x "$destination/argos-runner" ]')
})

test("keeps Linux web scanning disabled until the isolated container gateway exists", () => {
  const config = createLinuxFirstMcpConfig("/home/argos/.local/share/argos/runtime/0.1.0") as {
    mcp: Record<string, { command: string[]; enabled: boolean }>
  }
  expect(Object.keys(config.mcp)).toEqual(["argos"])
  expect(config.mcp.argos.command).toEqual(["/home/argos/.local/share/argos/runtime/0.1.0/orquestador", "--mcp"])
  expect(config.mcp["argos-web"]).toBeUndefined()
  expect(config.mcp["chrome-devtools"]).toBeUndefined()
  expect(config.mcp["argos-lan"]).toBeUndefined()
  expect(config.mcp["argos-es"]).toBeUndefined()
})

test("adds the web MCP only to a Linux runtime package with the scanner worker", () => {
  const config = createLinuxFirstMcpConfig("/home/argos/runtime/0.1.0", true) as {
    mcp: Record<string, { command: string[]; enabled: boolean }>
  }
  expect(config.mcp["argos-web"]).toEqual({
    type: "local",
    command: ["/home/argos/runtime/0.1.0/web", "--mcp"],
    enabled: true,
    env: { ARGOS_REQUIRE_CONTAINER_AUDIT: "1" },
  })
})

test("keeps MCPs without an active isolated runtime disabled in the shared config", () => {
  const config = JSON.parse(readFileSync(new URL("../../../../../argos-config/argos.jsonc", import.meta.url), "utf8"))
  for (const name of ["argos-web", "argos-lan", "argos-es", "chrome-devtools"]) {
    expect(config.mcp[name]?.enabled, `${name} must stay disabled until its isolated runtime is active`).toBe(false)
  }
})

test("reports Docker CLI and daemon availability separately from scanner readiness", () => {
  expect(dockerRuntimeAvailability(null, null)).toMatchObject({
    available: false,
    reason: expect.stringContaining("Docker Engine"),
  })
  expect(dockerRuntimeAvailability(null, null).reason).toContain("WSL Integration for ArgosRuntime")
  expect(dockerRuntimeAvailability("/usr/bin/docker", null).reason).toContain("WSL Integration for ArgosRuntime")
  expect(dockerRuntimeAvailability("/usr/bin/docker", null)).toMatchObject({
    available: false,
    path: "/usr/bin/docker",
    reason: expect.stringContaining("daemon"),
  })
  expect(dockerRuntimeAvailability("/usr/bin/docker", "27.5.1")).toEqual({
    available: true,
    path: "/usr/bin/docker",
    reason: null,
  })
  expect(webAuditRuntimeAvailability(false).reason).toContain("Docker Engine")
  expect(webAuditRuntimeAvailability(true).reason).toContain("worker image")
  expect(webAuditRuntimeAvailability(true).available).toBe(false)
  expect(webAuditRuntimeAvailability(true, true, true)).toEqual({ available: true, path: "web", reason: null })
  expect(
    linuxRuntimeToolAvailability(
      { nuclei: { available: true, path: "/tools/nuclei", reason: null } },
      dockerRuntimeAvailability("/usr/bin/docker", "27.5.1"),
    ),
  ).toMatchObject({
    nuclei: { available: false, path: "/tools/nuclei", reason: expect.stringContaining("pinned Argos worker image") },
    docker: { available: true },
    "argos-web": { available: false, reason: expect.stringContaining("worker image") },
    "chrome-devtools": { available: false, reason: expect.stringContaining("scope gateway") },
    "web.browse": { available: false, reason: expect.stringContaining("worker image") },
  })
  expect(
    linuxRuntimeToolAvailability(
      { nuclei: { available: true, path: "/tools/nuclei", reason: null } },
      dockerRuntimeAvailability("/usr/bin/docker", "27.5.1"),
      true,
      true,
    ),
  ).toMatchObject({
    nuclei: { available: true, path: "/tools/nuclei", reason: null },
    "argos-worker": { available: true },
    "argos-web": { available: true, path: "web" },
  })
})

test("reports a worker image ready only when Docker confirms the manifest-pinned image ID", () => {
  const docker = dockerRuntimeAvailability("/usr/bin/docker", "27.5.1")
  const imageId = `sha256:${"c".repeat(64)}`
  expect(workerImageAvailability(docker, imageId, imageId)).toEqual({
    available: true,
    path: imageId,
    reason: null,
  })
  expect(workerImageAvailability(docker, imageId, `sha256:${"d".repeat(64)}`).reason).toContain("does not match")
  expect(workerImageAvailability(dockerRuntimeAvailability(null, null), imageId, null).reason).toContain(
    "Docker Engine",
  )
})

test("reports web.browse only when the pinned worker contains a usable browser runtime", () => {
  const docker = dockerRuntimeAvailability("/usr/bin/docker", "27.5.1")
  const withoutBrowser = linuxRuntimeToolAvailability({}, docker, true, true, false)
  expect(withoutBrowser["web.browse"]).toMatchObject({
    available: false,
    reason: expect.stringContaining("browser preflight"),
  })
  const withBrowser = linuxRuntimeToolAvailability({}, docker, true, true, true)
  expect(withBrowser["web.browse"]).toEqual({ available: true, path: "argos-web", reason: null })
})

test("blocks a native Linux startup when a required Argos MCP binary is missing", () => {
  expect(missingLinuxMcpPaths({})).toEqual(["argos"])
  expect(missingLinuxMcpPaths({ argos: "/opt/argos/orquestador" })).toEqual([])
})

test("reports the native Linux scanner cache path for each pinned tool", () => {
  const toolsDirectory = join("home", "user", ".argos", "tools")
  const tools = linuxScannerAvailabilityFromCache("amd64", toolsDirectory, (path) =>
    path.endsWith(join("httpx", "httpx")),
  )
  expect(tools.httpx).toEqual({ available: true, path: join(toolsDirectory, "httpx", "httpx"), reason: null })
  expect(tools.nuclei).toMatchObject({ available: false, reason: expect.stringContaining("first use") })
})

test("reports cached, first-use and architecture-limited scanner availability", () => {
  const amd64 = scannerToolAvailability("amd64", { nuclei: "/home/argos/tools/nuclei/nuclei" })
  expect(amd64.nuclei).toEqual({
    available: true,
    path: "/home/argos/tools/nuclei/nuclei",
    reason: null,
  })
  expect(amd64.httpx).toMatchObject({ available: false, reason: expect.stringContaining("first use") })
  const arm64 = scannerToolAvailability("arm64", {
    naabu: "/home/argos/tools/naabu/naabu",
    codeql: "/home/argos/tools/codeql/codeql",
  })
  expect(arm64.naabu).toEqual({ available: false, path: null, reason: expect.stringContaining("v2.3.1") })
  expect(arm64.codeql).toEqual({
    available: false,
    path: null,
    reason: expect.stringContaining("amd64"),
  })
})

test("provisions the versioned runtime in user space and verifies every download", () => {
  const script = buildWslProvisioningScript(
    "C:\\Program Files\\Argos\\resources\\linux-amd64",
    manifest,
    "b".repeat(64),
  )
  expect(script).toContain("sha256sum -c manifest.sha256")
  expect(script).not.toContain('[ -x "$destination/lan" ]')
  expect(script).toContain('"$payload/orquestador" "$tmp"/')
  expect(script).not.toContain('"$payload/web"')
  expect(script).not.toContain('cp -a "$payload"/. "$tmp"/')
  expect(script).toContain('chmod 755 "$tmp/orquestador"')
  expect(script).not.toContain('"$tmp/web"')
  expect(script).toContain("nodejs.org/download/release/v24.21.0/node-v24.21.0-linux-x64.tar.xz")
  expect(script).toContain("npm-cli.js")
  expect(script).toContain("jsonc-parser@3.3.1")
  expect(script).toContain('"$destination/server/node_modules/jsonc-parser"')
  expect(script).toContain("require(process.argv[1])")
  expect(script.split("\n").length).toBeGreaterThan(10)
  expect(script).toContain('destination="$runtime_root/0.1.0"')
  expect(script.toLowerCase()).not.toContain("sudo")
})

test("requires a versioned worker archive and immutable image ID for the target architecture", () => {
  const worker = {
    archive: "worker.tar",
    archiveSha256: "a".repeat(64),
    imageId: `sha256:${"b".repeat(64)}`,
  }
  const webProfile = { ...manifest, profile: ["argos", "argos-web"], web: "web" }
  expect(validateLinuxRuntimeManifest({ ...webProfile, worker }, "0.1.0", "amd64")).toMatchObject({ worker })
  expect(() => validateLinuxRuntimeManifest({ ...webProfile, worker: undefined }, "0.1.0", "amd64")).toThrow(
    "worker package",
  )
  expect(() =>
    validateLinuxRuntimeManifest(
      { ...webProfile, worker: { ...worker, imageId: "argos/worker:latest" } },
      "0.1.0",
      "amd64",
    ),
  ).toThrow("worker image ID")
  expect(() =>
    validateLinuxRuntimeManifest({ ...webProfile, worker: { ...worker, archiveSha256: "invalid" } }, "0.1.0", "amd64"),
  ).toThrow("worker archive checksum")
  expect(
    validateLinuxRuntimeManifest(
      { ...webProfile, worker: { ...worker, browserAvailable: true, browserRuntimeVersion: "1.64.0" } },
      "0.1.0",
      "amd64",
    ).worker,
  ).toMatchObject({ browserAvailable: true })
  expect(() =>
    validateLinuxRuntimeManifest(
      { ...webProfile, worker: { ...worker, browserAvailable: "yes" } },
      "0.1.0",
      "amd64",
    ),
  ).toThrow("browser capability")
  expect(() =>
    validateLinuxRuntimeManifest(
      { ...webProfile, worker: { ...worker, browserAvailable: true, browserRuntimeVersion: "next" } },
      "0.1.0",
      "amd64",
    ),
  ).toThrow("browser runtime version")
})

test("requires the worker gateway and marks argos-web browser-ready only after preflight", () => {
  const config = createLinuxFirstMcpConfig("/home/argos/runtime/0.1.0", true, true) as {
    mcp: Record<string, { env?: Record<string, string> }>
  }
  expect(config.mcp["argos-web"].env).toEqual({
    ARGOS_REQUIRE_CONTAINER_AUDIT: "1",
    ARGOS_BROWSER_WORKER_AVAILABLE: "1",
  })
  const scannerOnly = createLinuxFirstMcpConfig("/home/argos/runtime/0.1.0", true, false) as {
    mcp: Record<string, { env?: Record<string, string> }>
  }
  expect(scannerOnly.mcp["argos-web"].env).toEqual({ ARGOS_REQUIRE_CONTAINER_AUDIT: "1" })
})

test("loads and verifies the pinned worker image before WSL runtime provisioning completes", () => {
  const workerManifest = {
    ...manifest,
    profile: ["argos", "argos-web"],
    web: "web",
    worker: {
      archive: "worker.tar",
      archiveSha256: "a".repeat(64),
      imageId: `sha256:${"b".repeat(64)}`,
    },
  }
  const script = buildWslProvisioningScript(
    "C:\\Program Files\\Argos\\resources\\linux-amd64",
    workerManifest,
    "b".repeat(64),
  )
  expect(script).toContain("sha256sum -c -")
  expect(script).toContain("a".repeat(64))
  expect(script).toContain('docker load --input "$runtime_dir/$worker_archive"')
  expect(script).toContain(`worker_image_id='sha256:${"b".repeat(64)}'`)
  expect(script).toContain("docker image inspect --format '{{.Id}}' \"$worker_image_id\"")
})
