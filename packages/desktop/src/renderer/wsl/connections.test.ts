import { describe, expect, test } from "bun:test"
import type { WslServersState } from "@argos/app/wsl/types"
import { availableStartupServer, primaryServerConnection, readyWslConnections } from "./connections"

const state = (kind: "starting" | "ready" | "failed" | "stopped"): WslServersState => ({
  runtime: null,
  installed: [],
  online: [],
  distroProbes: {},
  opencodeChecks: {},
  pendingRestart: false,
  job: null,
  servers: [
    {
      config: { id: "wsl:Debian", distro: "Debian" },
      runtime: runtime(kind),
    },
  ],
})

function runtime(kind: "starting" | "ready" | "failed" | "stopped") {
  if (kind === "ready") return { kind, url: "http://127.0.0.1:4096", username: "opencode", password: "secret" }
  if (kind === "failed") return { kind, message: "boom" }
  return { kind }
}

describe("WSL desktop connections", () => {
  test("attaches the actual WSL runtime to the primary sidecar without changing its saved key", () => {
    const connection = primaryServerConnection({
      runtime: "wsl2",
      distro: "Ubuntu-24.04",
      url: "http://127.0.0.1:4321",
      username: "opencode",
      password: "secret",
    })

    expect(connection).toMatchObject({
      type: "sidecar",
      variant: "base",
      runtime: { kind: "wsl2", distro: "Ubuntu-24.04" },
      displayName: "WSL 2 · Ubuntu-24.04",
    })
  })

  test("publishes a WSL server only after it reports ready", () => {
    expect(readyWslConnections(state("starting"))).toEqual([])
    expect(readyWslConnections(state("failed"))).toEqual([])
    expect(readyWslConnections(state("stopped"))).toEqual([])
    expect(readyWslConnections(state("ready"))).toEqual([
      expect.objectContaining({ displayName: "Debian", label: "WSL" }),
    ])
  })

  test("does not block desktop startup on a configured WSL default", () => {
    const key = "wsl:Debian"
    expect(availableStartupServer(key, undefined)).toBe("sidecar")
    expect(availableStartupServer(key, state("starting"))).toBe("sidecar")
    expect(availableStartupServer(key, state("ready"))).toBe(key)
  })
})




