import { copyFileSync, mkdirSync, readdirSync, readFileSync } from "node:fs"
import path from "node:path"

export const copyServerRuntimeAssets = (sourceDirectory: string, targetDirectory: string) => {
  const names = readdirSync(sourceDirectory, { withFileTypes: true })
    .filter((entry) => entry.isFile() && (entry.name === "wsl.js" || entry.name.endsWith(".wasm")))
    .map((entry) => entry.name)
    .sort()

  if (!names.includes("wsl.js")) throw new Error("Linux Argos server bundle is missing")
  const bundle = readFileSync(path.join(sourceDirectory, "wsl.js"), "utf8")
  const required = Array.from(bundle.matchAll(/["']\.\/([^"'\\\s/]+\.wasm)["']/g), (match) => match[1])
  for (const name of required) {
    if (!names.includes(name)) throw new Error(`Linux Argos server asset is missing: ${name}. Rebuild the server bundle.`)
  }

  mkdirSync(targetDirectory, { recursive: true })
  for (const name of names) copyFileSync(path.join(sourceDirectory, name), path.join(targetDirectory, name))

  return names.map((name) => path.join(targetDirectory, name))
}
