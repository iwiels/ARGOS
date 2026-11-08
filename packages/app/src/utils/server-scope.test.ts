import { describe, expect, test } from "bun:test"
import { SessionRouteKey, SessionStateKey, ServerScope, migrateLegacySessionStateKeys } from "./server-scope"

describe("SessionRouteKey.fromRoute", () => {
  test("joins dir and sessionID with slash", () => {
    expect(SessionRouteKey.fromRoute("/home/user", "abc") as string).toBe("/home/user/abc")
  })

  test("omits slash when no sessionID", () => {
    expect(SessionRouteKey.fromRoute("/home/user") as string).toBe("/home/user")
  })

  test("handles undefined dir", () => {
    expect(SessionRouteKey.fromRoute(undefined, "abc") as string).toBe("/abc")
  })

  test("handles undefined dir without sessionID", () => {
    expect(SessionRouteKey.fromRoute(undefined) as string).toBe("")
  })
})

describe("SessionRouteKey.fromLegacy", () => {
  test("returns the key as-is", () => {
    expect(SessionRouteKey.fromLegacy("foo/bar") as string).toBe("foo/bar")
  })
})

describe("SessionStateKey", () => {
  test("from composes scope and route with null byte separator", () => {
    const scope = "remote" as ServerScope
    const route = SessionRouteKey.fromRoute("/dir", "id1")
    const key = SessionStateKey.from(scope, route)
    expect(key as string).toBe(`remote\u0000/dir/id1`)
  })

  test("route extracts route part after last null byte", () => {
    const key = `remote\u0000/dir/id1`
    expect(SessionStateKey.route(key).toString()).toBe("/dir/id1")
  })

  test("route handles no null byte", () => {
    expect(SessionStateKey.route("bare-key").toString()).toBe("bare-key")
  })

  test("scope extracts scope before first null byte", () => {
    const key = `remote\u0000/dir/id1`
    expect(SessionStateKey.scope(key) as string).toBe("remote")
  })

  test("scope returns local when no null byte", () => {
    expect(SessionStateKey.scope("bare-key") as string).toBe("local")
  })
})

describe("ServerScope.fromServerKey", () => {
  test("returns local for sidecar", () => {
    expect(ServerScope.fromServerKey("sidecar" as any) as string).toBe("local")
  })

  test("returns local when key matches canonicalLocalServer", () => {
    expect(ServerScope.fromServerKey("my-server" as never, "my-server" as any) as string).toBe("local")
  })

  test("returns the key itself for remote servers", () => {
    expect(ServerScope.fromServerKey("remote-host" as any) as string).toBe("remote-host")
  })
})

describe("migrateLegacySessionStateKeys", () => {
  test("returns non-object input as-is", () => {
    expect(migrateLegacySessionStateKeys(null)).toBe(null)
    expect(migrateLegacySessionStateKeys("str")).toBe("str")
    expect(migrateLegacySessionStateKeys([1, 2])).toEqual([1, 2])
  })

  test("returns object with null bytes unchanged", () => {
    const input = { "local\u0000/dir/s1": "value" }
    expect(migrateLegacySessionStateKeys(input)).toBe(input)
  })

  test("migrates legacy keys into scoped keys", () => {
    const input = { "dir/s1": "value" }
    const result = migrateLegacySessionStateKeys(input) as Record<string, unknown>
    const expected = `local\u0000dir/s1`
    expect(result).toHaveProperty(expected, "value")
    expect(Object.keys(result)).toHaveLength(1)
  })

  test("does not overwrite existing scoped keys", () => {
    const scoped = `local\u0000dir/s1`
    const input = { "dir/s1": "legacy", [scoped]: "scoped" }
    const result = migrateLegacySessionStateKeys(input) as Record<string, unknown>
    expect(result[scoped]).toBe("scoped")
  })
})
