import { describe, expect, test } from "bun:test"
import * as fc from "fast-check"
import { stream } from "./markdown-stream"

describe("markdown stream", () => {
  test("heals incomplete emphasis while streaming", () => {
    expect(stream("hello **world", true)).toEqual([{ raw: "hello **world", src: "hello **world**", mode: "live" }])
    expect(stream("say `code", true)).toEqual([{ raw: "say `code", src: "say `code`", mode: "live" }])
  })

  test("keeps incomplete links non-clickable until they finish", () => {
    expect(stream("see [docs](https://example.com/gu", true)).toEqual([
      { raw: "see [docs](https://example.com/gu", src: "see docs", mode: "live" },
    ])
  })

  test("splits an unfinished trailing code fence from stable content", () => {
    expect(stream("before\n\n```ts\nconst x = 1", true)).toEqual([
      { raw: "before\n\n", src: "before\n\n", mode: "live" },
      { raw: "```ts\nconst x = 1", src: "```ts\nconst x = 1", mode: "live" },
    ])
  })

  test("keeps reference-style markdown as one block", () => {
    expect(stream("[docs][1]\n\n[1]: https://example.com", true)).toEqual([
      {
        raw: "[docs][1]\n\n[1]: https://example.com",
        src: "[docs][1]\n\n[1]: https://example.com",
        mode: "live",
      },
    ])
  })
})

describe("stream property tests", () => {
  test("invariance: not-live always produces a single full block", () => {
    fc.assert(
      fc.property(fc.string(), (text) => {
        const blocks = stream(text, false)
        expect(blocks).toHaveLength(1)
        expect(blocks[0]?.mode).toBe("full")
        expect(blocks[0]?.raw).toBe(text)
        expect(blocks[0]?.src).toBe(text)
      }),
    )
  })

  test("invariance: all blocks have valid shape", () => {
    fc.assert(
      fc.property(fc.string({ maxLength: 500 }), (text) => {
        const blocks = stream(text, true)
        for (const block of blocks) {
          expect(block).toHaveProperty("raw")
          expect(block).toHaveProperty("src")
          expect(["full", "live"]).toContain(block.mode)
        }
      }),
    )
  })

  test("invariance: concatenated raw text equals original input", () => {
    fc.assert(
      fc.property(fc.string({ maxLength: 300 }), (text) => {
        const blocks = stream(text, false)
        const joined = blocks.map((b) => b.raw).join("")
        expect(joined).toBe(text)
      }),
    )
  })
})

