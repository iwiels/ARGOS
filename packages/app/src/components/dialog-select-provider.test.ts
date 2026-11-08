import { describe, expect, test } from "bun:test"

describe("DialogSelectProvider module", () => {
  test("component source file exists", async () => {
    const file = Bun.file(import.meta.dir + "/dialog-select-provider.tsx")
    expect(await file.exists()).toBe(true)
  })

  test("contains expected export: DialogSelectProvider", async () => {
    const content = await Bun.file(import.meta.dir + "/dialog-select-provider.tsx").text()
    expect(content).toContain("DialogSelectProvider")
    expect(content).toContain("export const DialogSelectProvider")
  })
})
