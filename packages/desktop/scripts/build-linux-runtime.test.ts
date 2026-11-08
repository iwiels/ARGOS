import { expect, test } from "bun:test"
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs"
import os from "node:os"
import path from "node:path"
import { copyServerRuntimeAssets } from "./linux-runtime-assets"

const root = path.resolve(import.meta.dir, "../../..")
const wslOutput = path.join(root, "packages", "argos", "dist", "wsl")
const wslBundle = path.join(wslOutput, "wsl.js")

test("copies the WSL server bundle with its emitted WASM files", () => {
  const temporary = mkdtempSync(path.join(os.tmpdir(), "argos-runtime-assets-"))
  const source = path.join(temporary, "source")
  const target = path.join(temporary, "target")
  const files = ["wsl.js", "tree-sitter-a1.wasm", "tree-sitter-b2.wasm", "wsl.js.map"]
  try {
    mkdirSync(source)
    for (const file of files) writeFileSync(path.join(source, file), file)

    const copied = copyServerRuntimeAssets(source, target).map((file) => path.basename(file))

    expect(copied).toEqual(["tree-sitter-a1.wasm", "tree-sitter-b2.wasm", "wsl.js"])
    expect(existsSync(path.join(target, "tree-sitter-a1.wasm"))).toBe(true)
    expect(existsSync(path.join(target, "tree-sitter-b2.wasm"))).toBe(true)
    expect(existsSync(path.join(target, "wsl.js.map"))).toBe(false)
  } finally {
    rmSync(temporary, { recursive: true, force: true })
  }
})

test("rejects a runtime when a WASM file referenced by the bundle is missing", () => {
  const temporary = mkdtempSync(path.join(os.tmpdir(), "argos-runtime-missing-asset-"))
  const source = path.join(temporary, "source")
  const target = path.join(temporary, "target")
  try {
    mkdirSync(source)
    writeFileSync(path.join(source, "wsl.js"), 'module.exports = "./tree-sitter-missing.wasm";')

    expect(() => copyServerRuntimeAssets(source, target)).toThrow("tree-sitter-missing.wasm")
    expect(existsSync(target)).toBe(false)
  } finally {
    rmSync(temporary, { recursive: true, force: true })
  }
})

const assertWasmAssetsArePackaged = () => {
  const wasmAssets = readdirSync(wslOutput).filter((name) => name.endsWith(".wasm"))
  expect(wasmAssets.length).toBeGreaterThan(0)

  for (const architecture of ["amd64", "arm64"]) {
    const runtime = path.join(root, "argos-bin", "bin", `linux-${architecture}`)
    const manifestPath = path.join(runtime, "manifest.sha256")
    if (!existsSync(manifestPath)) continue

    const server = path.join(runtime, "server")
    const checksums = readFileSync(manifestPath, "utf8")
    for (const asset of wasmAssets) {
      expect(existsSync(path.join(server, asset))).toBe(true)
      expect(checksums).toContain(`server/${asset}`)
    }
  }
}

if (existsSync(wslBundle)) {
  test("packages and verifies every generated WSL server WASM asset", assertWasmAssetsArePackaged)
} else {
  test.skip("packages and verifies every generated WSL server WASM asset", () => {})
}
