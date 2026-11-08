import { describe, expect, test } from "bun:test"
import {
  cleanHeading,
  errorRowFor,
  reasoningHeading,
  resolveStreamErrorKind,
  unwrapErrorMessage,
} from "./message-timeline-helpers"

describe("reasoningHeading", () => {
  test("extracts ATX heading (# Heading)", () => {
    expect(reasoningHeading("# My Heading")).toBe("My Heading")
  })

  test("extracts setext heading (underlined)", () => {
    expect(reasoningHeading("Setext Title\n=====")).toBe("Setext Title")
  })

  test("extracts bold heading (**bold**)", () => {
    expect(reasoningHeading("**Bold Heading**")).toBe("Bold Heading")
  })

  test("extracts HTML h2 heading", () => {
    expect(reasoningHeading("<h2>HTML Heading</h2>")).toBe("HTML Heading")
  })

  test("strips markdown formatting from heading", () => {
    expect(reasoningHeading("# `code` and [link](http://x.com)")).toBe("code and link")
  })

  test("returns undefined for plain text without headings", () => {
    expect(reasoningHeading("Just some plain text")).toBeUndefined()
  })

  test("normalizes line endings", () => {
    expect(reasoningHeading("# Heading\r\nMore text")).toBe("Heading")
  })
})

describe("cleanHeading", () => {
  test("removes inline code backticks", () => {
    expect(cleanHeading("`code`")).toBe("code")
  })

  test("removes markdown links keeping text", () => {
    expect(cleanHeading("[text](url)")).toBe("text")
  })

  test("removes bold/italic/tilde markers", () => {
    expect(cleanHeading("**bold** __under__ *italic* ~~strike~~")).toBe("bold under italic strike")
  })

  test("trims whitespace", () => {
    expect(cleanHeading("  hello  ")).toBe("hello")
  })
})

describe("unwrapErrorMessage", () => {
  test("returns plain text as-is", () => {
    expect(unwrapErrorMessage("something went wrong")).toBe("something went wrong")
  })

  test("strips Error: prefix only for JSON extraction", () => {
    const json = JSON.stringify({ message: "ok" })
    expect(unwrapErrorMessage(`Error: ${json}`)).toBe("ok")
  })

  test("unwraps JSON error object", () => {
    const input = JSON.stringify({ error: { type: "TypeError", message: "bad input" } })
    expect(unwrapErrorMessage(input)).toBe("TypeError: bad input")
  })

  test("unwraps nested JSON string", () => {
    const inner = JSON.stringify({ error: { message: "nested" } })
    const outer = JSON.stringify(inner)
    expect(unwrapErrorMessage(outer)).toBe("nested")
  })

  test("extracts JSON from surrounding text", () => {
    const json = JSON.stringify({ message: "extracted" })
    expect(unwrapErrorMessage(`prefix ${json} suffix`)).toBe("extracted")
  })

  test("returns original message when no JSON found", () => {
    expect(unwrapErrorMessage("no json here")).toBe("no json here")
    expect(unwrapErrorMessage("Error: no json here")).toBe("Error: no json here")
  })

  test("handles error with only type", () => {
    const input = JSON.stringify({ error: { type: "TimeoutError" } })
    expect(unwrapErrorMessage(input)).toBe("TimeoutError")
  })

  test("handles error with only code", () => {
    const input = JSON.stringify({ error: { code: "E001" } })
    expect(unwrapErrorMessage(input)).toBe("E001")
  })

  test("handles message field", () => {
    const input = JSON.stringify({ message: "from message field" })
    expect(unwrapErrorMessage(input)).toBe("from message field")
  })

  test("handles error string field", () => {
    const input = JSON.stringify({ error: "string error" })
    expect(unwrapErrorMessage(input)).toBe("string error")
  })
})

describe("resolveStreamErrorKind", () => {
  test("maps APIError 503 to queueFull", () => {
    expect(
      resolveStreamErrorKind({
        name: "APIError",
        data: { message: "boom", statusCode: 503, isRetryable: true },
      }),
    ).toEqual({ kind: "queueFull", retryable: true, statusCode: 503 })
  })

  test("maps APIError 529 to queueFull", () => {
    expect(
      resolveStreamErrorKind({ name: "APIError", data: { statusCode: 529, isRetryable: true } }),
    ).toEqual({ kind: "queueFull", retryable: true, statusCode: 529 })
  })

  test("maps APIError 429 to rateLimit", () => {
    expect(
      resolveStreamErrorKind({ name: "APIError", data: { statusCode: 429, isRetryable: false } }),
    ).toEqual({ kind: "rateLimit", retryable: false, statusCode: 429 })
  })

  test("maps APIError 500 to server", () => {
    expect(
      resolveStreamErrorKind({ name: "APIError", data: { statusCode: 500, isRetryable: true } }),
    ).toEqual({ kind: "server", retryable: true, statusCode: 500 })
  })

  test("maps APIError 401 to auth and never retryable", () => {
    expect(
      resolveStreamErrorKind({ name: "APIError", data: { statusCode: 401, isRetryable: true } }),
    ).toEqual({ kind: "auth", retryable: false, statusCode: 401 })
  })

  test("falls back to retryable for 5xx when isRetryable is missing", () => {
    expect(resolveStreamErrorKind({ name: "APIError", data: { message: "x", statusCode: 503 } })).toEqual({
      kind: "queueFull",
      retryable: true,
      statusCode: 503,
    })
  })

  test("respects isRetryable false on 5xx", () => {
    expect(
      resolveStreamErrorKind({ name: "APIError", data: { statusCode: 503, isRetryable: false } }),
    ).toEqual({ kind: "queueFull", retryable: false, statusCode: 503 })
  })

  test("maps ProviderAuthError to auth", () => {
    expect(resolveStreamErrorKind({ name: "ProviderAuthError", data: { message: "x" } })).toEqual({
      kind: "auth",
      retryable: false,
    })
  })

  test("maps ContextOverflowError to contextOverflow", () => {
    expect(resolveStreamErrorKind({ name: "ContextOverflowError", data: { message: "x" } })).toEqual({
      kind: "contextOverflow",
      retryable: false,
    })
  })

  test("maps StructuredOutputError to structuredOutput", () => {
    expect(resolveStreamErrorKind({ name: "StructuredOutputError", data: { message: "x", retries: 3 } })).toEqual({
      kind: "structuredOutput",
      retryable: false,
    })
  })

  test("maps UnknownError to generic without retry", () => {
    expect(resolveStreamErrorKind({ name: "UnknownError", data: { message: "x" } })).toEqual({
      kind: "generic",
      retryable: false,
    })
  })

  test("maps APIError without status to generic", () => {
    expect(resolveStreamErrorKind({ name: "APIError", data: { message: "x", isRetryable: false } })).toEqual({
      kind: "generic",
      retryable: false,
    })
  })

  test("handles non-object input", () => {
    expect(resolveStreamErrorKind(undefined)).toEqual({ kind: "generic", retryable: false })
    expect(resolveStreamErrorKind("boom")).toEqual({ kind: "generic", retryable: false })
  })
})

describe("errorRowFor", () => {
  test("carries the error object with unwrapped text", () => {
    const error = {
      name: "APIError",
      data: { message: "Streaming response failed; [503] The request queue is full.", statusCode: 503, isRetryable: true },
    }
    expect(errorRowFor(error)).toEqual({ error, text: "Streaming response failed; [503] The request queue is full." })
  })

  test("unwraps JSON error payloads", () => {
    const error = { name: "UnknownError", data: { message: JSON.stringify({ error: { message: "boom" } }) } }
    expect(errorRowFor(error)?.text).toBe("boom")
  })

  test("returns undefined for non-objects", () => {
    expect(errorRowFor(undefined)).toBeUndefined()
    expect(errorRowFor("boom")).toBeUndefined()
  })
})
