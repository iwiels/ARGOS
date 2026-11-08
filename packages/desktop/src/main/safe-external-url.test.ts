import { describe, expect, test } from "bun:test"
import { isSafeExternalUrl } from "./safe-external-url"

describe("isSafeExternalUrl", () => {
  test("permite http y https", () => {
    expect(isSafeExternalUrl("https://docs.example.com/guia")).toBe(true)
    expect(isSafeExternalUrl("http://intranet.local/pagina")).toBe(true)
  })

  test("rechaza esquemas que el shell puede ejecutar o usar para phishing", () => {
    // file:, ms-msdt:, search-ms: y similares son vectores conocidos de
    // ejecución de comandos / phishing en Windows vía shell.openExternal.
    expect(isSafeExternalUrl("file:///C:/Windows/System32/calc.exe")).toBe(false)
    expect(isSafeExternalUrl("ms-msdt:A1")).toBe(false)
    expect(isSafeExternalUrl("search-ms:query=algo")).toBe(false)
    expect(isSafeExternalUrl("smb://servidor/recurso")).toBe(false)
    expect(isSafeExternalUrl("javascript:alert(1)")).toBe(false)
    expect(isSafeExternalUrl("data:text/html,hola")).toBe(false)
    expect(isSafeExternalUrl("vbscript:msgbox")).toBe(false)
  })

  test("rechaza entradas no-string o no parseables", () => {
    expect(isSafeExternalUrl(undefined)).toBe(false)
    expect(isSafeExternalUrl(null)).toBe(false)
    expect(isSafeExternalUrl(42)).toBe(false)
    expect(isSafeExternalUrl("")).toBe(false)
    expect(isSafeExternalUrl("no es una url")).toBe(false)
    expect(isSafeExternalUrl("https://")).toBe(false)
  })
})
