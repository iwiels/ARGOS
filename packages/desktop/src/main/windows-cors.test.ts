import { describe, expect, test } from "bun:test"
import { mergeAllowedHeaders, RENDERER_ALLOWED_HEADERS } from "./cors-headers"

const has = (list: string[], name: string) => list.some((h) => h.toLowerCase() === name.toLowerCase())

describe("mergeAllowedHeaders", () => {
  test("permite el ticket de PTY", () => {
    // Su ausencia rompía la terminal: el preflight de
    // /pty/{id}/connect-token quedaba bloqueado aunque el servidor
    // respondiera correctamente.
    expect(has(mergeAllowedHeaders(undefined), "x-opencode-ticket")).toBe(true)
    expect(has(RENDERER_ALLOWED_HEADERS, "x-opencode-ticket")).toBe(true)
  })

  test("conserva headers que sólo envía el servidor", () => {
    // Regresión: antes se REEMPLAZABA la cabecera del servidor por la lista
    // local, así que cualquier header nuevo del servidor desaparecía.
    const merged = mergeAllowedHeaders("content-type,authorization,x-opencode-ticket,x-future-header")
    expect(has(merged, "x-future-header")).toBe(true)
    expect(has(merged, "x-opencode-ticket")).toBe(true)
  })

  test("acepta la cabecera como string o como array", () => {
    const fromString = mergeAllowedHeaders("a-header, b-header")
    const fromArray = mergeAllowedHeaders(["a-header", "b-header"])
    expect(has(fromString, "a-header")).toBe(true)
    expect(has(fromString, "b-header")).toBe(true)
    expect(has(fromArray, "a-header")).toBe(true)
    expect(has(fromArray, "b-header")).toBe(true)
  })

  test("no duplica, comparando sin distinguir mayúsculas", () => {
    const merged = mergeAllowedHeaders(["Content-Type", "content-type", "X-OpenCode-Ticket"])
    const lower = merged.map((h) => h.toLowerCase())
    expect(new Set(lower).size).toBe(lower.length)
  })

  test("siempre incluye la lista local aunque el servidor no mande nada", () => {
    const merged = mergeAllowedHeaders(undefined)
    for (const header of RENDERER_ALLOWED_HEADERS) {
      expect(has(merged, header)).toBe(true)
    }
  })
})
