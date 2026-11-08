import { spawnSync } from "node:child_process"
import { existsSync, mkdirSync, readFileSync } from "node:fs"
import { join } from "node:path"
import { fileURLToPath } from "node:url"
import { goBuildTargetsFor } from "./go-build-targets"

const __dirname = fileURLToPath(new URL(".", import.meta.url))
const rootDir = join(__dirname, "..", "..", "..")
const goDir = join(rootDir, "argos-bin")
const outDir = join(goDir, "bin")
const argosPackage = JSON.parse(readFileSync(join(rootDir, "packages", "argos", "package.json"), "utf8")) as {
  version: string
}

if (!existsSync(join(goDir, "go.mod"))) {
  process.exit(0)
}

const targets = goBuildTargetsFor(process.platform, process.arch)
let failed = false

for (const target of targets) {
  const targetDir = join(outDir, `${target.goos}-${target.goarch}`)
  mkdirSync(targetDir, { recursive: true })
  for (const command of target.commands) {
    const ext = target.goos === "windows" ? ".exe" : ""
    const output = join(targetDir, `${command}${ext}`)
    const buildArgs = ["build", "-trimpath"]
    if (command === "argos-runner") buildArgs.push("-ldflags", `-X main.version=${argosPackage.version}`)
    buildArgs.push("-o", output, join(goDir, "cmd", command))
    const result = spawnSync("go", buildArgs, {
      cwd: goDir,
      env: { ...process.env, CGO_ENABLED: "0", GOOS: target.goos, GOARCH: target.goarch },
      encoding: "utf8",
    })
    if (result.status !== 0) {
      failed = true
      console.error(`[build-go] Failed: GOOS=${target.goos} GOARCH=${target.goarch} ${command}`)
      if (result.error) console.error(result.error)
      if (result.stderr) console.error(result.stderr)
    }
  }
}

if (failed) process.exitCode = 1
