import { execSync } from "node:child_process"
import { resolveChannel } from "./utils"
import { ensureServerBundle } from "./ensure-server-bundle"

ensureServerBundle()

const channel = resolveChannel()
execSync(`tsx ./scripts/copy-icons.ts ${channel}`, { stdio: "inherit" })
execSync(`tsx ./scripts/copy-metainfo.ts ${channel}`, { stdio: "inherit" })
execSync(`tsx ./scripts/build-go-binaries.ts`, { stdio: "inherit" })
if (process.env.ARGOS_BUILD_LINUX_WORKER_IMAGE === "1") {
  execSync(`tsx ./scripts/build-worker-runtime.ts`, { stdio: "inherit" })
}
execSync(`tsx ./scripts/build-linux-runtime.ts`, { stdio: "inherit" })
execSync(`tsx ./scripts/build-core-scripts.ts`, { stdio: "inherit" })
