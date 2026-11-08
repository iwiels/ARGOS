import { describe, expect, test } from "bun:test"

describe("DialogConnectProvider module", () => {
  test("component source file exists", async () => {
    const file = Bun.file(import.meta.dir + "/dialog-connect-provider.tsx")
    expect(await file.exists()).toBe(true)
  })

  test("contains expected export: DialogConnectProvider", async () => {
    const content = await Bun.file(import.meta.dir + "/dialog-connect-provider.tsx").text()
    expect(content).toContain("export function DialogConnectProvider")
  })
})
