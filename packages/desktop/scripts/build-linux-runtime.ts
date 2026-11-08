import { createHash } from "node:crypto"
import { cpSync, existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs"
import { dirname, join, relative, sep } from "node:path"
import { fileURLToPath } from "node:url"
import { LINUX_NODE_ARCHIVES, LINUX_NODE_VERSION } from "../src/shared/linux-runtime"
import { copyServerRuntimeAssets } from "./linux-runtime-assets"

const scriptDir = fileURLToPath(new URL(".", import.meta.url))
const root = join(scriptDir, "..", "..", "..")
const goBinRoot = join(root, "argos-bin", "bin")
const configRoot = join(root, "argos-config")
const serverBundle = join(root, "packages", "argos", "dist", "wsl", "wsl.js")
const argosPackage = JSON.parse(readFileSync(join(root, "packages", "argos", "package.json"), "utf8")) as {
  version: string
  dependencies: Record<string, string>
}
const desktopPackage = JSON.parse(readFileSync(join(root, "packages", "desktop", "package.json"), "utf8")) as {
  version: string
  devDependencies: Record<string, string>
}
const browserPackage = JSON.parse(readFileSync(join(root, "argos-bin", "worker", "browser", "package.json"), "utf8")) as {
  dependencies: Record<string, string>
}
const browserRuntimeVersion = browserPackage.dependencies["playwright-core"]

if (argosPackage.version !== desktopPackage.version) {
  throw new Error(`Desktop version ${desktopPackage.version} does not match Argos server ${argosPackage.version}`)
}
if (!argosPackage.dependencies["jsonc-parser"]) {
  throw new Error("Argos server package is missing its pinned jsonc-parser dependency")
}
if (!existsSync(serverBundle))
  throw new Error("Linux Argos server bundle is missing; run the Argos desktop build first")
if (!existsSync(configRoot)) throw new Error("argos-config directory is missing")

for (const goarch of ["amd64", "arm64"] as const) {
  const targetDir = join(goBinRoot, `linux-${goarch}`)
  const binaries = ["orquestador"]
  if (!binaries.every((name) => existsSync(join(targetDir, name)))) continue

  const runnerBinary = join(targetDir, "argos-runner")
  const hasRunner = existsSync(runnerBinary)
  const webBinary = join(targetDir, "web")
  const workerArchive = join(targetDir, "worker.tar")
  const workerMetadata = join(targetDir, "worker-image.json")
  const hasWorkerArchive = existsSync(workerArchive)
  const hasWorkerMetadata = existsSync(workerMetadata)
  if (hasWorkerArchive !== hasWorkerMetadata) {
    throw new Error(`Linux worker package for ${goarch} is incomplete; rebuild the worker image package`)
  }
  let worker: {
    archive: "worker.tar"
    archiveSha256: string
    imageId: string
    browserAvailable: boolean
    browserRuntimeVersion: string
  } | undefined
  if (hasWorkerArchive) {
    if (!existsSync(webBinary)) throw new Error(`Linux web MCP binary for ${goarch} is missing`)
    const metadata = JSON.parse(readFileSync(workerMetadata, "utf8")) as {
      version?: string
      architecture?: string
      imageId?: string
      browserAvailable?: boolean
      browserRuntimeVersion?: string
    }
    if (metadata.version !== argosPackage.version || metadata.architecture !== goarch) {
      if (process.env.ARGOS_REQUIRE_LINUX_WORKER_IMAGE === "1") {
        throw new Error(`Linux worker package for ${goarch} does not match Argos ${argosPackage.version}`)
      }
      process.stderr.write(
        `[linux-runtime] Ignoring stale Linux worker package for ${goarch} (built for ${metadata.version ?? "unknown"}); ` +
          `run "pnpm --filter @argos/desktop build:worker-runtime" to rebuild it for ${argosPackage.version}.\n`,
      )
    } else {
      if (!metadata.imageId || !/^sha256:[a-f0-9]{64}$/.test(metadata.imageId)) {
        throw new Error(`Linux worker package for ${goarch} has an invalid immutable image ID`)
      }
      if (metadata.browserRuntimeVersion !== browserRuntimeVersion) {
        throw new Error(`Linux worker package for ${goarch} has an unsupported browser runtime version`)
      }
      worker = {
        archive: "worker.tar",
        archiveSha256: createHash("sha256").update(readFileSync(workerArchive)).digest("hex"),
        imageId: metadata.imageId,
        browserAvailable: metadata.browserAvailable === true,
        browserRuntimeVersion: metadata.browserRuntimeVersion,
      }
    }
  } else if (process.env.ARGOS_REQUIRE_LINUX_WORKER_IMAGE === "1") {
    throw new Error(`Linux worker package for ${goarch} is required; set ARGOS_BUILD_LINUX_WORKER_IMAGE=1 and rebuild`)
  }

  const serverDir = join(targetDir, "server")
  const configDir = join(targetDir, "config")
  mkdirSync(serverDir, { recursive: true })
  const serverAssets = copyServerRuntimeAssets(dirname(serverBundle), serverDir)
  cpSync(configRoot, configDir, { recursive: true, force: true })

  const manifest = {
    version: argosPackage.version,
    platform: "linux",
    architecture: goarch,
    profile: ["argos", ...(worker ? ["argos-web"] : []), ...(hasRunner ? ["argos-runner"] : [])],
    node: {
      version: LINUX_NODE_VERSION,
      ...LINUX_NODE_ARCHIVES[goarch],
    },
    nodePty: {
      package: "@lydell/node-pty",
      version: desktopPackage.devDependencies["@lydell/node-pty"],
    },
    jsoncParser: {
      package: "jsonc-parser",
      version: argosPackage.dependencies["jsonc-parser"],
    },
    server: "server/wsl.js",
    config: "config",
    toolsDirectory: "$HOME/.argos/tools",
    ...(hasRunner ? { runner: "argos-runner" } : {}),
    ...(worker ? { web: "web", worker } : {}),
  }
  writeFileSync(join(targetDir, "manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`)

  const checkedFiles = [
    ...binaries.map((name) => join(targetDir, name)),
    ...(hasRunner ? [runnerBinary] : []),
    ...(worker ? [webBinary, workerArchive] : []),
    ...serverAssets,
    ...listFiles(configDir),
  ]
  const checksums = checkedFiles
    .map((path) => {
      const name = relative(targetDir, path).split(sep).join("/")
      const digest = createHash("sha256").update(readFileSync(path)).digest("hex")
      return `${digest}  ${name}`
    })
    .join("\n")
  writeFileSync(join(targetDir, "manifest.sha256"), `${checksums}\n`)
}

if (process.env.ARGOS_REQUIRE_LINUX_WORKER_IMAGE === "1") {
  const packaged = ["amd64", "arm64"].some((goarch) => existsSync(join(goBinRoot, `linux-${goarch}`, "manifest.json")))
  if (!packaged) throw new Error("No Linux Argos runtime package was built")
}

function listFiles(directory: string): string[] {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const path = join(directory, entry.name)
    if (entry.isDirectory()) return listFiles(path)
    return entry.isFile() ? [path] : []
  })
}
