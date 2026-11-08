import { describe, expect, test } from "bun:test"
import { booleanValue, numberValue, responseItems, safeJson, stringValue } from "./api-utils"

describe("stringValue", () => {
  test("trims and returns non-empty strings", () => {
    expect(stringValue("  hello  ")).toBe("hello")
  })

  test("returns undefined for empty, whitespace-only and non-string values", () => {
    expect(stringValue("")).toBeUndefined()
    expect(stringValue("   ")).toBeUndefined()
    expect(stringValue(42)).toBeUndefined()
    expect(stringValue(null)).toBeUndefined()
    expect(stringValue(undefined)).toBeUndefined()
  })
})

describe("numberValue", () => {
  test("returns numbers as-is and rejects non-numbers", () => {
    expect(numberValue(3)).toBe(3)
    expect(numberValue(0)).toBe(0)
    expect(numberValue("3")).toBeUndefined()
    expect(numberValue(null)).toBeUndefined()
  })
})

describe("booleanValue", () => {
  test("returns the boolean or false fallback", () => {
    expect(booleanValue(true)).toBe(true)
    expect(booleanValue(false)).toBe(false)
    expect(booleanValue(1)).toBe(false)
    expect(booleanValue(undefined)).toBe(false)
  })
})

describe("responseItems", () => {
  test("passes arrays through, unwraps data/findings objects", () => {
    expect(responseItems([1, 2])).toEqual([1, 2])
    expect(responseItems({ data: [1, 2] })).toEqual([1, 2])
    expect(responseItems({ findings: [3] })).toEqual([3])
    expect(responseItems({ other: "x" })).toBeUndefined()
    expect(responseItems(null)).toBeUndefined()
  })
})

describe("safeJson", () => {
  const jsonResponse = (body: string, contentType = "application/json") =>
    new Response(body, { headers: { "content-type": contentType } })

  test("parses JSON objects and arrays", async () => {
    expect(await safeJson(jsonResponse('{"a":1}'))).toEqual({ a: 1 })
    expect(await safeJson(jsonResponse("[1,2]"))).toEqual([1, 2])
  })

  test("rejects HTML/XML content types without parsing", async () => {
    expect(await safeJson(jsonResponse("<html>error</html>", "text/html"))).toBeUndefined()
    expect(await safeJson(jsonResponse("<?xml?>", "application/xml"))).toBeUndefined()
  })

  test("returns undefined for empty or non-JSON bodies", async () => {
    expect(await safeJson(jsonResponse(""))).toBeUndefined()
    expect(await safeJson(jsonResponse("not json"))).toBeUndefined()
    expect(await safeJson(jsonResponse("hello world"))).toBeUndefined()
  })

  test("returns undefined for malformed JSON", async () => {
    expect(await safeJson(jsonResponse("{broken"))).toBeUndefined()
  })
})
