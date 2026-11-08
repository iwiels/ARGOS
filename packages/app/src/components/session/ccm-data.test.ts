import { describe, expect, test } from "bun:test"
import { STATUS_META, STATUS_ORDER, driftWorsened, statusLabelKey, statusMeta } from "./ccm-data"

describe("STATUS_ORDER", () => {
  test("covers the four compliance statuses in canonical order", () => {
    expect(STATUS_ORDER).toEqual(["deficient", "partial", "compliant", "unassessed"])
  })
})

describe("STATUS_META", () => {
  test("provides an i18n label key and styling for every status", () => {
    for (const status of STATUS_ORDER) {
      const meta = STATUS_META[status]
      expect(meta.labelKey).toMatch(/^ccm\.status\./)
      expect(meta.badge).toBeTruthy()
      expect(meta.bar).toMatch(/^var\(/)
    }
  })

  test("statusMeta falls back to unassessed for unknown statuses", () => {
    expect(statusMeta("exploited").labelKey).toBe("ccm.status.unassessed")
  })

  test("statusLabelKey returns the i18n key of the resolved status (always defined via fallback)", () => {
    expect(statusLabelKey("deficient")).toBe("ccm.status.deficient")
    expect(statusLabelKey("unknown-status")).toBe("ccm.status.unassessed")
  })
})

describe("driftWorsened", () => {
  test("returns true when the control moved to a worse state", () => {
    expect(driftWorsened("compliant", "deficient")).toBe(true)
    expect(driftWorsened("compliant", "partial")).toBe(true)
    expect(driftWorsened("partial", "deficient")).toBe(true)
  })

  test("returns false for improvements and same-state transitions", () => {
    expect(driftWorsened("deficient", "compliant")).toBe(false)
    expect(driftWorsened("partial", "compliant")).toBe(false)
    expect(driftWorsened("compliant", "compliant")).toBe(false)
  })

  test("handles unknown statuses as unassessed (lowest rank)", () => {
    expect(driftWorsened("unknown", "deficient")).toBe(true)
    expect(driftWorsened("deficient", "unknown")).toBe(false)
  })
})
