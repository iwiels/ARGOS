import { describe, expect, test } from "bun:test"
import { persistFindingStatusChange } from "./finding-status-action"

describe("persistFindingStatusChange", () => {
  test("does not apply the local status when the server did not persist it", async () => {
    let applied = false

    const saved = await persistFindingStatusChange(
      async () => false,
      () => (applied = true),
    )

    expect(saved).toBe(false)
    expect(applied).toBe(false)
  })

  test("does not apply the local status when saving throws", async () => {
    let applied = false

    const saved = await persistFindingStatusChange(
      async () => {
        throw new Error("HTTP 503")
      },
      () => (applied = true),
    )

    expect(saved).toBe(false)
    expect(applied).toBe(false)
  })

  test("applies the local status only after the server confirms persistence", async () => {
    let applied = false

    const saved = await persistFindingStatusChange(
      async () => true,
      () => (applied = true),
    )

    expect(saved).toBe(true)
    expect(applied).toBe(true)
  })
})
