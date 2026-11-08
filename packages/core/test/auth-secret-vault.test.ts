import { describe, expect, test } from "bun:test"
import { makeClient, clientFromEnvironment } from "../src/security/auth-secret-vault"

const profileID = `auth_${"a".repeat(32)}`

describe("auth secret vault client", () => {
  test("uses authenticated local endpoints and retries only unreachable bridge addresses", async () => {
    const requests: Array<{ url: string; method: string; authorization: string | null; body?: string }> = []
    const client = makeClient({
      urls: ["http://127.0.0.1:1234", "http://172.30.96.1:2345"],
      token: "vault-token",
      fetcher: async (input, init) => {
        const url = String(input)
        if (url.startsWith("http://127.0.0.1:")) throw new Error("connection refused")
        requests.push({
          url,
          method: init?.method ?? "GET",
          authorization: new Headers(init?.headers).get("authorization"),
          body: typeof init?.body === "string" ? init.body : undefined,
        })
        if (init?.method === "GET") return new Response(JSON.stringify({ value: "cookie=session-secret" }), { status: 200 })
        return new Response(null, { status: 204 })
      },
    })

    await client.put(profileID, "cookie=session-secret")
    expect(await client.get(profileID)).toBe("cookie=session-secret")
    await client.delete(profileID)
    expect(requests.map((request) => request.method)).toEqual(["PUT", "GET", "DELETE"])
    expect(requests.every((request) => request.authorization === "Bearer vault-token")).toBe(true)
    expect(requests[0].body).toBe(JSON.stringify({ value: "cookie=session-secret" }))
  })

  test("returns null for an unknown profile reference", async () => {
    const client = makeClient({
      urls: ["http://127.0.0.1:1234"],
      token: "vault-token",
      fetcher: async () => new Response(null, { status: 404 }),
    })

    expect(await client.get(`auth_${"b".repeat(32)}`)).toBeNull()
  })

  test("rejects a nonlocal endpoint before sending the vault token", async () => {
    let sent = false
    const client = makeClient({
      urls: ["http://vault.example.com"],
      token: "vault-token",
      fetcher: async () => {
        sent = true
        return new Response(null, { status: 204 })
      },
    })

    await expect(client.get(profileID)).rejects.toThrow("secure vault is unavailable")
    expect(sent).toBe(false)
  })

  test("reports when the desktop did not provide a vault bridge", async () => {
    const client = clientFromEnvironment({})
    await expect(client.get(profileID)).rejects.toThrow("secure vault is unavailable")
  })
})
