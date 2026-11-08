import { execSync } from "node:child_process"
import { existsSync, readdirSync, statSync } from "node:fs"
import { dirname, join, resolve } from "node:path"
import { fileURLToPath } from "node:url"

const __dirname = dirname(fileURLToPath(import.meta.url))
const root = resolve(__dirname, "..", "..", "..")

const SERVER_PACKAGES = ["argos", "server", "core", "llm", "effect-drizzle-sqlite", "plugin", "sdk/js"]
const SERVER_SOURCE_DIRS = [...SERVER_PACKAGES.map((name) => `packages/${name}/src`), "packages/argos/script", "patches"]
const SERVER_SOURCE_FILES = ["package.json", "pnpm-lock.yaml", "pnpm-workspace.yaml", ...SERVER_PACKAGES.map((name) => `packages/${name}/package.json`)]
const SERVER_BUNDLES = [join(root, "packages/argos/dist/node/node.js"), join(root, "packages/argos/dist/wsl/wsl.js")]

function latestSourceMtime(dir: string): number {
  if (!existsSync(dir)) return 0
  let latest = 0
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === "node_modules" || entry.name === "dist" || entry.name.startsWith(".")) continue
    const full = join(dir, entry.name)
    if (entry.isDirectory()) {
      latest = Math.max(latest, latestSourceMtime(full))
    } else if (entry.isFile()) {
      latest = Math.max(latest, statSync(full).mtimeMs)
    }
  }
  return latest
}

/** Rebuild the Electron sidecar server bundle when server sources are newer. */
export function ensureServerBundle() {
  const bundleMtime = Math.min(...SERVER_BUNDLES.map((bundle) => (existsSync(bundle) ? statSync(bundle).mtimeMs : 0)))
  const latestMtime = Math.max(
    ...SERVER_SOURCE_DIRS.map((dir) => latestSourceMtime(join(root, dir))),
    ...SERVER_SOURCE_FILES.map((file) => statSync(join(root, file), { throwIfNoEntry: false })?.mtimeMs ?? 0),
  )
  if (latestMtime > bundleMtime) {
    console.log("[server-bundle] Server sources are newer than dist/node/node.js — rebuilding server bundle…")
    execSync("bun run script/build-desktop.ts", { cwd: join(root, "packages/argos"), stdio: "inherit" })
    return true
  }
  console.log("[server-bundle] Server bundle is up to date")
  return false
}
