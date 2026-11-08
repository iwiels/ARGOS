import { describe, expect, test } from "bun:test"
import { readdirSync, readFileSync, statSync, writeFileSync } from "node:fs"
import { join, relative } from "node:path"

const SRC = join(import.meta.dir, "..")
const ALLOWLIST_PATH = join(import.meta.dir, "hardcoded-strings.allowlist.json")

/**
 * Guardrail: user-facing copy must go through language.t().
 *
 * `hardcoded-strings.allowlist.json` freezes the existing hardcoded debt
 * (mostly Spanish copy that predates this check). The test fails on ANY delta:
 * adding a hardcoded string breaks it — migrate to language.t() instead of
 * regenerating the allowlist. Regenerating is only allowed intentionally with:
 *
 *   UPDATE_ALLOWLIST=1 bun test src/i18n/hardcoded-strings.test.ts
 */
// Text nodes: `>Copy here</tag>`. The closing-tag requirement keeps out TS
// generics like `Promise<T>` and `ReturnType<X>`.
const TEXT_NODE = />([^{}<>]*[A-Za-zÁÉÍÓÚáéíóúñÑ][^{}<>]*)<\//g
// Static user-facing attributes (no {expression}).
const ATTR = /(?:title|placeholder|aria-label)="([^"]*[A-Za-zÁÉÍÓÚáéíóúñÑ][^"]*)"/g

function walk(dir: string, out: string[] = []) {
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry)
    if (full.includes("node_modules")) continue
    if (statSync(full).isDirectory()) {
      walk(full, out)
      continue
    }
    if (full.endsWith(".tsx") && !full.endsWith(".test.tsx") && !full.endsWith(".stories.tsx")) {
      out.push(full)
    }
  }
  return out
}

// Keys are normalized so prettier reflows (line breaks, indentation) do not
// churn the golden file: only the collapsed text matters.
const collapse = (value: string) => value.replace(/\s+/g, " ").trim()

function collect() {
  const violations: string[] = []
  for (const file of walk(SRC)) {
    const content = readFileSync(file, "utf8")
    const rel = relative(SRC, file).replace(/\\/g, "/")
    for (const match of content.matchAll(TEXT_NODE)) {
      const value = match[1].trim()
      if (value.length < 3 || value.includes("{") || value.includes("}")) continue
      if (/^[A-Z][A-Z0-9 ._-]{0,12}$/.test(value)) continue // all-caps markers like "OK", "N/A"
      violations.push(`${rel}:text:${collapse(value)}`)
    }
    for (const match of content.matchAll(ATTR)) {
      const value = match[1].trim()
      if (value.length < 2 || value.includes("{") || value.includes("}")) continue
      const attr = match[0].slice(0, match[0].indexOf("="))
      violations.push(`${rel}:${attr}=${collapse(value)}`)
    }
  }
  return violations.sort()
}

describe("i18n hardcoded strings", () => {
  test("no hardcoded user-facing strings outside the allowlist", () => {
    const violations = collect()

    if (process.env.UPDATE_ALLOWLIST) {
      writeFileSync(ALLOWLIST_PATH, JSON.stringify(violations, null, 2) + "\n")
      return
    }

    const baseline = JSON.parse(readFileSync(ALLOWLIST_PATH, "utf8")) as string[]
    expect(violations).toEqual(baseline)
  })
})
