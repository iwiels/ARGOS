#!/usr/bin/env bun

import path from "path"
import { fileURLToPath } from "url"

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)
const dir = path.resolve(__dirname, "..")

process.chdir(dir)

const generated = await import("./generate.ts")

const nodeResult = await Bun.build({
  target: "node",
  entrypoints: ["./src/node.ts"],
  outdir: "./dist/node",
  format: "esm",
  sourcemap: "linked",
  external: ["jsonc-parser", "@lydell/node-pty", "chromium-bidi"],
  define: {
    OPENCODE_MODELS_DEV: generated.modelsData,
    OPENCODE_CHANNEL: "'dev'",
  },
  files: {
    "opencode-web-ui.gen.ts": "",
  },
})
if (!nodeResult.success) {
  throw new Error(nodeResult.logs.map((log) => log.message).join("\n"))
}

const wslResult = await Bun.build({
  target: "node",
  entrypoints: ["./src/wsl.ts"],
  outdir: "./dist/wsl",
  format: "esm",
  sourcemap: "linked",
  external: ["jsonc-parser", "@lydell/node-pty", "chromium-bidi"],
  define: {
    OPENCODE_MODELS_DEV: generated.modelsData,
    OPENCODE_CHANNEL: "'dev'",
  },
  files: {
    "opencode-web-ui.gen.ts": "",
  },
})
if (!wslResult.success) {
  throw new Error(wslResult.logs.map((log) => log.message).join("\n"))
}

console.log("Build complete")
