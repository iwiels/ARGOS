import { describe, expect, test } from "bun:test"
import * as fc from "fast-check"
import { normalizePaste, pasteMode } from "./paste"

describe("normalizePaste property tests", () => {
  test("idempotence: applying twice is same as once", () => {
    fc.assert(
      fc.property(fc.string(), (text) => {
        const once = normalizePaste(text)
        expect(normalizePaste(once)).toBe(once)
      }),
    )
  })

  test("invariance: text without \\r is unchanged", () => {
    fc.assert(
      fc.property(
        fc.string().filter((s) => !s.includes("\r")),
        (text) => {
          expect(normalizePaste(text)).toBe(text)
        },
      ),
    )
  })

  test("replaces \\r\\n and \\r with \\n", () => {
    expect(normalizePaste("line1\r\nline2\rline3")).toBe("line1\nline2\nline3")
    expect(normalizePaste("\r\n")).toBe("\n")
    expect(normalizePaste("\r")).toBe("\n")
  })
})

describe("pasteMode property tests", () => {
  test("invariance: returns one of the known modes", () => {
    fc.assert(
      fc.property(fc.string({ maxLength: 200 }), (text) => {
        const mode = pasteMode(text)
        expect(["native", "manual"]).toContain(mode)
      }),
    )
  })

  test("short single-line text is native", () => {
    expect(pasteMode("hello world")).toBe("native")
    expect(pasteMode("short")).toBe("native")
  })

  test("multiline text is manual", () => {
    expect(pasteMode("line1\nline2")).toBe("manual")
  })

  test("very long text is manual", () => {
    expect(pasteMode("x".repeat(8001))).toBe("manual")
  })
})
