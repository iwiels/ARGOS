import { describe, expect, test } from "bun:test"
import { errorDescriptionKey } from "./error-description"

describe("errorDescriptionKey", () => {
  test("returns startup key for localServerStartup errors", () => {
    expect(errorDescriptionKey({ localServerStartup: true })).toBe("error.page.description.localServerStartup")
  })

  test("returns generic key for other errors", () => {
    expect(errorDescriptionKey({})).toBe("error.page.description")
    expect(errorDescriptionKey({ serverVersionMismatch: true })).toBe("error.page.description")
  })

  test("returns generic key for null/undefined", () => {
    // The function receives null/undefined but accesses properties on it,
    // so it falls through to the generic key
    expect(errorDescriptionKey(null)).toBe("error.page.description")
    expect(errorDescriptionKey(undefined)).toBe("error.page.description")
  })

  test("returns generic key for primitive values", () => {
    expect(errorDescriptionKey("string")).toBe("error.page.description")
    expect(errorDescriptionKey(42)).toBe("error.page.description")
    expect(errorDescriptionKey(true)).toBe("error.page.description")
  })
})
