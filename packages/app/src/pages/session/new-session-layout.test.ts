import { describe, expect, test } from "bun:test"
import { shouldUseV2NewSessionPage } from "./new-session-layout"

describe("shouldUseV2NewSessionPage", () => {
  test("uses the v2 layout for new-session pages and false when sessionID exists", () => {
    expect(shouldUseV2NewSessionPage({})).toBe(true)
    expect(shouldUseV2NewSessionPage({ sessionID: "ses_123" })).toBe(false)
  })
})



