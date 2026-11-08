import { createHash } from "node:crypto"
import { cpSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join, relative, resolve, sep } from "node:path"
import { spawnSync } from "node:child_process"
import { fileURLToPath } from "node:url"
import { LINUX_NODE_ARCHIVES, LINUX_NODE_VERSION } from "../src/shared/linux-runtime"

const scriptDir = fileURLToPath(new URL(".", import.meta.url))
const root = join(scriptDir, "..", "..", "..")
const goBinRoot = join(root, "argos-bin", "bin")
const dockerfile = join(root, "argos-bin", "worker", "Dockerfile")
const argosPackage = JSON.parse(readFileSync(join(root, "packages", "argos", "package.json"), "utf8")) as {
  version: string
}
const desktopPackage = JSON.parse(readFileSync(join(root, "packages", "desktop", "package.json"), "utf8")) as {
  version: string
}
const browserPackage = JSON.parse(readFileSync(join(root, "argos-bin", "worker", "browser", "package.json"), "utf8")) as {
  dependencies: Record<string, string>
}

if (argosPackage.version !== desktopPackage.version) {
  throw new Error(`Desktop version ${desktopPackage.version} does not match Argos server ${argosPackage.version}`)
}
if (!existsSync(dockerfile)) throw new Error("Argos worker Dockerfile is missing")
run("docker", ["info"])

let builder = "argos-worker-runtime"
const existingBuilder = spawnSync("docker", ["buildx", "inspect", builder], { encoding: "utf8", windowsHide: true })
if (existingBuilder.status === 0 && !/^Driver:\s*docker-container\s*$/m.test(existingBuilder.stdout)) {
  builder = `argos-worker-runtime-${process.pid}`
}
if (existingBuilder.status !== 0 || builder !== "argos-worker-runtime") {
  run("docker", ["buildx", "create", "--name", builder, "--driver", "docker-container"])
}
run("docker", ["buildx", "inspect", builder, "--bootstrap"])

const architectures = (["amd64", "arm64"] as const).filter((architecture) => {
  const targetDir = join(goBinRoot, `linux-${architecture}`)
  return existsSync(join(targetDir, "orquestador")) && existsSync(join(targetDir, "web"))
})
if (architectures.length === 0) throw new Error("Build the Linux orquestador and web binaries before the worker image")

const temporaryDirectory = mkdtempSync(join(tmpdir(), "argos-worker-build-"))
const revision = process.env.GITHUB_SHA || "local"

try {
  for (const architecture of architectures) {
    const targetDir = join(goBinRoot, `linux-${architecture}`)
    const archive = join(temporaryDirectory, `worker-${architecture}.tar`)
    const image = `argos/worker:${argosPackage.version}-${architecture}`
    run("docker", [
      "buildx",
      "build",
      "--builder",
      builder,
      "--platform",
      `linux/${architecture}`,
      "--file",
      dockerfile,
      "--build-arg",
      `ARGOS_WORKER_VERSION=${argosPackage.version}`,
      "--build-arg",
      `ARGOS_WORKER_REVISION=${revision}`,
      "--build-arg",
      `ARGOS_NODE_VERSION=${LINUX_NODE_VERSION}`,
      "--build-arg",
      `ARGOS_NODE_SHA256_AMD64=${LINUX_NODE_ARCHIVES.amd64.sha256}`,
      "--build-arg",
      `ARGOS_NODE_SHA256_ARM64=${LINUX_NODE_ARCHIVES.arm64.sha256}`,
      "--build-arg",
      `ARGOS_PLAYWRIGHT_VERSION=${browserPackage.dependencies["playwright-core"]}`,
      "--tag",
      image,
      "--output",
      `type=docker,name=${image},dest=${archive}`,
      join(root, "argos-bin"),
    ])
    run("docker", ["load", "--input", archive])
    const inspection = run("docker", ["image", "inspect", "--format", "{{.Id}}", image])
    const imageId = inspection.stdout.trim()
    if (!/^sha256:[a-f0-9]{64}$/.test(imageId)) {
      throw new Error(`Docker returned an invalid image ID for ${architecture}`)
    }
    const browserPreflight = spawnSync(
      "docker",
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
        `--security-opt=seccomp=${join(root, "argos-config", "runtime", "chromium-seccomp.json")}`,
        "--pids-limit=256",
        "--cpus=2",
        "--memory=1g",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev,noexec,size=128m",
        imageId,
        "/usr/local/bin/argos-browser-worker",
        "--preflight",
      ],
      { encoding: "utf8", windowsHide: true, timeout: 45_000 },
    )
    const browserAvailable = browserPreflight.status === 0 && browserPreflight.stdout.includes('"status":"ready"')
    const probeVersion = spawnSync(
      "docker",
      [
        "run",
        "--rm",
        "--pull=never",
        "--network=none",
        "--read-only",
        "--user=65532:65532",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        imageId,
        "/usr/local/bin/argos-worker-probe",
        "--version",
      ],
      { encoding: "utf8", windowsHide: true, timeout: 10_000 },
    )
    if (probeVersion.status !== 0 || probeVersion.stdout.trim() !== `argos-worker-probe ${argosPackage.version}`) {
      const reason = probeVersion.error?.message || probeVersion.stderr?.trim() || `exit ${probeVersion.status}`
      throw new Error(`Argos worker probe package check failed for linux/${architecture}: ${reason}`)
    }
    cpSync(archive, join(targetDir, "worker.tar"))
    writeFileSync(
      join(targetDir, "worker-image.json"),
      `${JSON.stringify(
        {
          version: argosPackage.version,
          architecture,
          imageId,
          browserAvailable,
          browserRuntimeVersion: browserPackage.dependencies["playwright-core"],
        },
        null,
        2,
      )}\n`,
    )
    if (!browserAvailable) {
      const reason = browserPreflight.error?.message || browserPreflight.stderr?.trim() || `exit ${browserPreflight.status}`
      process.stderr.write(`Playwright browser preflight failed for linux/${architecture}: ${reason}\n`)
    }
  }
} finally {
  removeBuildDirectory(temporaryDirectory)
}

function removeBuildDirectory(directory: string) {
  const allowedRoot = resolve(tmpdir())
  const target = resolve(directory)
  const fromRoot = relative(allowedRoot, target)
  if (!fromRoot || fromRoot === ".." || fromRoot.startsWith(`..${sep}`) || resolve(allowedRoot, fromRoot) !== target) {
    throw new Error("Refusing to remove a worker build directory outside the OS temporary directory")
  }
  rmSync(target, { recursive: true, force: true })
}

function run(command: string, args: string[]) {
  const result = spawnSync(command, args, { encoding: "utf8", windowsHide: true })
  if (result.error || result.status !== 0) {
    const detail = [result.error?.message, result.stderr?.trim()].filter(Boolean).join("\n")
    throw new Error(`${command} ${args.join(" ")} failed${detail ? `:\n${detail}` : ""}`)
  }
  return result
}
