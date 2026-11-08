import { describe, expect, test } from "bun:test"
import * as fc from "fast-check"
import { base64Decode, base64Encode, checksum, sampledChecksum } from "./encode"

describe("base64 round-trip property", () => {
  test("base64 encode/decode round-trip for any string", () => {
    fc.assert(
      fc.property(fc.string(), (str) => {
        expect(base64Decode(base64Encode(str))).toBe(str)
      }),
    )
  })

  test("base64 handles empty string", () => {
    expect(base64Encode("")).toBe("")
    expect(base64Decode("")).toBe("")
  })

  test("base64 handles ascii strings", () => {
    fc.assert(
      fc.property(fc.string({ minLength: 1 }), (str) => {
        expect(base64Decode(base64Encode(str))).toBe(str)
      }),
    )
  })
})

describe("base64 idempotence", () => {
  test("double encoding is not idempotent but round-trip is", () => {
    fc.assert(
      fc.property(fc.string({ minLength: 1 }), (str) => {
        const encoded = base64Encode(str)
        expect(encoded).not.toBe(str)
        expect(base64Decode(encoded)).toBe(str)
      }),
    )
  })
})

describe("checksum properties", () => {
  test("empty content returns undefined", () => {
    expect(checksum("")).toBeUndefined()
    expect(checksum("   ")).toBeTruthy()
  })

  test("same content produces same checksum", () => {
    fc.assert(
      fc.property(fc.string({ minLength: 1, maxLength: 100 }), (str) => {
        expect(checksum(str)).toBe(checksum(str))
      }),
    )
  })

  test("different content likely produces different checksum", () => {
    fc.assert(
      fc.property(fc.string({ minLength: 1, maxLength: 50 }), fc.string({ minLength: 1, maxLength: 50 }), (a, b) => {
        fc.pre(a !== b)
        expect(checksum(a)).not.toBe(checksum(b))
      }),
    )
  })
})

describe("sampledChecksum properties", () => {
  test("small content equals regular checksum", () => {
    fc.assert(
      fc.property(fc.string({ maxLength: 100 }), (str) => {
        expect(sampledChecksum(str)).toBe(checksum(str))
      }),
    )
  })

  test("empty content returns undefined", () => {
    expect(sampledChecksum("")).toBeUndefined()
  })

  test("large content produces length-prefixed result", () => {
    const largeContent = "x".repeat(600_000)
    const result = sampledChecksum(largeContent)
    expect(result).toMatch(/^600000:/)
  })
})
