import { expect, test } from "bun:test"
import { clearWslDistroState, requireWslIpcString, wslServerIdToRestart, wslTerminalArgs } from "./policy"
import {
  expectOpencodeVersion,
  pendingRestartAfterWslInstall,
  pollWslHealth,
  wslServerIdsToStartOnInitialize,
} from "./startup"
import { createWslServersController, type WslServerConfig } from "./servers"

let persistedServers: WslServerConfig[] = []
let releaseOpencodeResolve: (() => void) | undefined

test("starts every configured WSL server on initialization", () => {
  expect(
    wslServerIdsToStartOnInitialize([
      { id: "wsl:Debian", distro: "Debian" },
      { id: "wsl:Ubuntu-24.04", distro: "Ubuntu-24.04" },
    ]),
  ).toEqual(["wsl:Debian", "wsl:Ubuntu-24.04"])
})

test("rejects an update that did not install the desktop version", () => {
  expect(() => expectOpencodeVersion("0.1.0", "0.1.0")).not.toThrow()
  expect(() => expectOpencodeVersion("1.14.35", "0.1.0")).toThrow(
    "Argos update finished but Debian still reports 1.14.35; expected 0.1.0",
  )
})

test("restarts an existing distro server after updating Argos", () => {
  expect(
    wslServerIdToRestart(
      [
        {
          config: { id: "wsl:Debian", distro: "Debian" },
          runtime: { kind: "ready", url: "", username: null, password: null },
        },
      ],
      "Debian",
    ),
  ).toBe("wsl:Debian")
  expect(wslServerIdToRestart([], "Debian")).toBeUndefined()
})

test("clears cached distro probes when removing a WSL server", () => {
  expect(
    clearWslDistroState(
      { Debian: { name: "Debian", canExecute: true, hasBash: true, hasCurl: true, error: null } },
      {
        Debian: {
          distro: "Debian",
          resolvedPath: "/home/luke/.opencode/bin/opencode",
          version: "0.1.0",
          expectedVersion: "0.1.0",
          matchesDesktop: true,
          error: null,
        },
      },
      "Debian",
    ),
  ).toEqual({ distroProbes: {}, opencodeChecks: {} })
})

test("opens terminals for distro names containing spaces", () => {
  expect(wslTerminalArgs("Ubuntu Preview")).toEqual(["/c", "start", "", "wsl", "-d", "Ubuntu Preview"])
})

test("stops health polling when sidecar startup settles", async () => {
  const abort = new AbortController()
  let checks = 0
  const polling = pollWslHealth(
    async () => {
      checks++
      return false
    },
    abort.signal,
    1,
  )

  await new Promise((resolve) => setTimeout(resolve, 5))
  abort.abort()
  await polling
  const settled = checks
  await new Promise((resolve) => setTimeout(resolve, 5))
  expect(checks).toBe(settled)
})

test("validates WSL IPC identifiers at the module boundary", () => {
  expect(requireWslIpcString("distro", "Debian")).toBe("Debian")
  expect(() => requireWslIpcString("distro", "")).toThrow("Invalid distro")
  expect(() => requireWslIpcString("server id", undefined)).toThrow("Invalid server id")
})

test("derives a required Windows restart from the post-install runtime probe", () => {
  expect(pendingRestartAfterWslInstall({ available: false, version: null, error: "WSL unavailable" })).toBe(true)
  expect(pendingRestartAfterWslInstall({ available: true, version: "WSL version: 2.6.1", error: null })).toBe(false)
})

test("ignores stale background Argos checks after removing a WSL server", async () => {
  persistedServers = []
  releaseOpencodeResolve = undefined
  const controller = createWslServersController(
    "0.1.0",
    async () => ({
      listener: {
        stop: () => undefined,
        onExit: () => undefined,
      },
      url: "http://127.0.0.1:4096",
      username: "opencode",
      password: "secret",
    }),
    testControllerOptions(),
  )

  await controller.addServer("Debian")
  await waitFor(() => !!releaseOpencodeResolve)
  await controller.removeServer("wsl:Debian")
  releaseOpencodeResolve?.()
  await new Promise((resolve) => setTimeout(resolve, 0))

  expect(controller.getState().servers).toEqual([])
  expect(controller.getState().opencodeChecks).toEqual({})
})

test("ignores stale startup Argos checks after removing a WSL server", async () => {
  persistedServers = [{ id: "wsl:Debian", distro: "Debian" }]
  releaseOpencodeResolve = undefined
  const controller = createWslServersController(
    "0.1.0",
    async () => new Promise<never>(() => undefined),
    testControllerOptions(),
  )

  await controller.initialize()
  await waitFor(() => !!releaseOpencodeResolve)
  await controller.removeServer("wsl:Debian")
  releaseOpencodeResolve?.()
  await new Promise((resolve) => setTimeout(resolve, 0))

  expect(controller.getState().servers).toEqual([])
  expect(controller.getState().opencodeChecks).toEqual({})
})

async function waitFor(check: () => boolean) {
  for (let attempt = 0; attempt < 20; attempt++) {
    if (check()) return
    await new Promise((resolve) => setTimeout(resolve, 0))
  }
  throw new Error("Timed out waiting for condition")
}

function testControllerOptions() {
  return {
    readServers: () => persistedServers,
    writeServers: (servers: WslServerConfig[]) => {
      persistedServers = servers
    },
    readCommandVersion: async () => "0.1.0",
    resolveOpencode: async () => {
      await new Promise<void>((resolve) => {
        releaseOpencodeResolve = resolve
      })
      return "/home/me/.opencode/bin/opencode"
    },
  }
}




