import { afterEach, describe, expect, test } from "bun:test"
import {
  authVaultEnvironment,
  createAuthVaultBridge,
  authVaultNoProxy,
  wslHostAddresses,
  type AuthVaultBackend,
} from "./auth-vault-http"

const bridges: Array<{ close: () => Promise<void> }> = []
const profileID = `auth_${"a".repeat(32)}`

afterEach(async () => {
  await Promise.all(bridges.splice(0).map((bridge) => bridge.close()))
})

function memoryBackend(available = true) {
  const data = new Map<string, string>()
  const backend: AuthVaultBackend = {
    isAvailable: () => available,
    get: (id) => {
      const value = data.get(id)
      return value?.startsWith("enc:") ? value.slice(4).split("").reverse().join("") : null
    },
    set: (id, value) => data.set(id, `enc:${value.split("").reverse().join("")}`),
    delete: (id) => data.delete(id),
  }
  return { backend, data }
}

async function createBridge(backend: AuthVaultBackend) {
  const bridge = await createAuthVaultBridge({ hosts: ["127.0.0.1"], backend })
  bridges.push(bridge)
  return bridge
}

describe("desktop auth vault bridge", () => {
  test("passes the private endpoint list and token to a sidecar", () => {
    expect(authVaultEnvironment({ urls: ["http://127.0.0.1:1234", "http://172.30.96.1:2345"], token: "secret-token" })).toEqual({
      ARGOS_AUTH_VAULT_URLS: '["http://127.0.0.1:1234","http://172.30.96.1:2345"]',
      ARGOS_AUTH_VAULT_TOKEN: "secret-token",
    })
  })

  test("bypasses configured proxies for the local vault endpoints", () => {
    expect(authVaultNoProxy({ urls: ["http://127.0.0.1:1234", "http://172.30.96.1:2345"] })).toBe("127.0.0.1,172.30.96.1")
  })

  test("selects only routable IPv4 addresses on WSL host interfaces", () => {
    expect(
      wslHostAddresses({
        "vEthernet (WSL)": [
          { address: "172.30.96.1", family: "IPv4", internal: false },
          { address: "8.8.8.8", family: "IPv4", internal: false },
          { address: "fe80::1", family: "IPv6", internal: false },
        ],
        Ethernet: [{ address: "192.168.1.20", family: "IPv4", internal: false }],
        "vEthernet (WSL Test)": [{ address: "127.0.0.1", family: "IPv4", internal: true }],
      }),
    ).toEqual(["172.30.96.1"])
  })

  test("stores encrypted material and serves it only to the authenticated runtime", async () => {
    const { backend, data } = memoryBackend()
    const bridge = await createBridge(backend)
    const endpoint = `${bridge.urls[0]}/v1/secrets/${profileID}`
    const authorization = `Bearer ${bridge.token}`

    const stored = await fetch(endpoint, {
      method: "PUT",
      headers: { authorization, "content-type": "application/json" },
      body: JSON.stringify({ value: "cookie=session-secret" }),
    })
    expect(stored.status).toBe(204)
    expect(data.get(profileID)).toBe("enc:terces-noisses=eikooc")

    const unauthorized = await fetch(endpoint)
    expect(unauthorized.status).toBe(401)

    const loaded = await fetch(endpoint, { headers: { authorization } })
    expect(loaded.status).toBe(200)
    expect(await loaded.json()).toEqual({ value: "cookie=session-secret" })

    const removed = await fetch(endpoint, {
      method: "DELETE",
      headers: { authorization },
    })
    expect(removed.status).toBe(204)
    expect(data.has(profileID)).toBe(false)
  })

  test("fails closed when secure storage is unavailable", async () => {
    const { backend, data } = memoryBackend(false)
    const bridge = await createBridge(backend)
    const authorization = `Bearer ${bridge.token}`
    const response = await fetch(`${bridge.urls[0]}/v1/secrets/${profileID}`, {
      method: "PUT",
      headers: { authorization, "content-type": "application/json" },
      body: JSON.stringify({ value: "must-not-persist" }),
    })

    expect(response.status).toBe(503)
    expect(data.size).toBe(0)
  })

  test("rejects malformed IDs, payloads, and oversized secrets", async () => {
    const { backend } = memoryBackend()
    const bridge = await createBridge(backend)
    const headers = { authorization: `Bearer ${bridge.token}`, "content-type": "application/json" }

    expect((await fetch(`${bridge.urls[0]}/v1/secrets/%2Fetc`, { headers })).status).toBe(400)
    expect(
      (
        await fetch(`${bridge.urls[0]}/v1/secrets/${profileID}`, {
          method: "PUT",
          headers,
          body: JSON.stringify({ value: 42 }),
        })
      ).status,
    ).toBe(400)
    expect(
      (
        await fetch(`${bridge.urls[0]}/v1/secrets/${profileID}`, {
          method: "PUT",
          headers,
          body: JSON.stringify({ value: "x".repeat(600_000) }),
        })
      ).status,
    ).toBe(413)
  })
})
