import { execSync } from "node:child_process"
import { ensureServerBundle } from "./ensure-server-bundle"

ensureServerBundle()

execSync(`tsx ./scripts/copy-icons.ts ${process.env.ARGOS_CHANNEL ?? process.env.OPENCODE_CHANNEL ?? "dev"}`, {
  stdio: "inherit",
})
execSync(`tsx ./scripts/build-go-binaries.ts`, { stdio: "inherit" })
execSync(`tsx ./scripts/build-linux-runtime.ts`, { stdio: "inherit" })
execSync(`tsx ./scripts/build-core-scripts.ts`, { stdio: "inherit" })
