import { describe, expect, test } from "bun:test"
import {
  authProfileMetadata,
  createAuthProfileRecord,
  parseAuthProfileRecord,
  validateAuthProfileInput,
} from "./auth-profile-record"

const id = `auth_${"a".repeat(32)}`
const input = {
  sessionID: "ses_security_test",
  name: "Administrator",
  username: "operator",
  password: "test-secret",
  successSelector: "[data-testid='signed-in']",
}

describe("protected authentication profile records", () => {
  test("creates the versioned record consumed by the Go browser worker", () => {
    expect(createAuthProfileRecord(input, id)).toEqual({
      id,
      version: 1,
      ...input,
      userSelector: undefined,
      passwordSelector: undefined,
      submitSelector: undefined,
    })
  })

  test("parses saved browser state and returns metadata without secrets", () => {
    const raw = JSON.stringify({
      ...createAuthProfileRecord(input, id),
      storageState: { cookies: [{ name: "sid", value: "secret-cookie" }], origins: [] },
      unexpected: "discarded",
    })
    const profile = parseAuthProfileRecord(raw, id)
    expect(profile?.storageState).toEqual({ cookies: [{ name: "sid", value: "secret-cookie" }], origins: [] })
    expect(profile).not.toHaveProperty("unexpected")
    expect(authProfileMetadata(profile!)).toEqual({
      id,
      name: "Administrator",
      username: "operator",
      hasBrowserSession: true,
    })
    expect(authProfileMetadata(profile!)).not.toHaveProperty("password")
    expect(authProfileMetadata(profile!)).not.toHaveProperty("storageState")
  })

  test("rejects a mismatched reference, malformed state, and oversized record", () => {
    const record = createAuthProfileRecord(input, id)
    expect(parseAuthProfileRecord(JSON.stringify(record), `auth_${"b".repeat(32)}`)).toBeNull()
    expect(
      parseAuthProfileRecord(JSON.stringify({ ...record, storageState: [] }), id),
    ).toBeNull()
    expect(parseAuthProfileRecord(JSON.stringify({ ...record, note: "x".repeat(600_000) }), id)).toBeNull()
  })

  test("validates profile names, session binding and secret size", () => {
    expect(() => validateAuthProfileInput(input)).not.toThrow()
    expect(() => validateAuthProfileInput({ ...input, sessionID: "bad/session" })).toThrow("Invalid authentication profile")
    expect(() => validateAuthProfileInput({ ...input, password: "" })).toThrow("Invalid authentication profile")
    expect(() => validateAuthProfileInput({ ...input, password: "x".repeat(4097) })).toThrow("Invalid authentication profile")
  })
})
