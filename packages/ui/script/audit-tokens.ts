#!/usr/bin/env bun

import { readFileSync, readdirSync, statSync, existsSync } from "node:fs"
import { join } from "node:path"

const dir = import.meta.dir
const read = (f: string) => readFileSync(join(dir, f), "utf8").replace(/\r\n/g, "\n")

const tokensJson = JSON.parse(read("tokens.json")) as Record<string, string>
const colorsCss = read("../src/styles/tailwind/colors.css")
const themeCss = read("../src/styles/theme.css")

function blockDefs(selector: string): Set<string> {
  const i = themeCss.indexOf(selector)
  if (i < 0) return new Set()
  const start = themeCss.indexOf("{", i)
  const end = themeCss.indexOf("\n  }", start)
  const block = themeCss.slice(start + 1, end)
  return new Set([...block.matchAll(/^\s*--([a-z0-9-]+):/gm)].map((m) => m[1]))
}

const darkDefs = new Set([
  ...blockDefs(":root {\n"),
  ...blockDefs(':root,\n  [data-color-scheme="dark"]'),
])
const lightDefs = blockDefs('.light,\n  [data-color-scheme="light"]')

const txtNames = new Set<string>(Object.keys(tokensJson))

const cssTokens = new Map<string, string>()
for (const line of colorsCss.split("\n")) {
  const m = line.trim().match(/^--color-([a-z0-9-]+):\s*(.+)$/)
  if (m) cssTokens.set(m[1], m[2])
}

let errors = 0

const missingInCss = [...txtNames].filter((n) => !cssTokens.has(n))
if (missingInCss.length > 0) {
  errors++
  console.error(`❌ [sync] ${missingInCss.length} tokens en tokens.json sin mapping en colors.css:`)
  console.error(`   ${missingInCss.join(", ")}`)
}

const undefinedDark: string[] = []
const fallbackOnly: string[] = []
const lightOnly: string[] = []
for (const [token, value] of cssTokens) {
  const m = value.match(/var\(--([a-z0-9-]+)/)
  if (!m) continue
  const target = m[1]
  if (darkDefs.has(target)) continue
  if (lightDefs.has(target)) {
    lightOnly.push(`${token} -> var(--${target})`)
    continue
  }
  if (value.includes(",")) fallbackOnly.push(`${token} -> var(--${target}, ...)`)
  else undefinedDark.push(`${token} -> var(--${target})`)
}
if (undefinedDark.length > 0) {
  errors++
  console.error(`❌ [runtime] ${undefinedDark.length} mappings sin definición en theme.css (dark o light):`)
  for (const t of undefinedDark) console.error(`   ${t}`)
}
if (lightOnly.length > 0) {
  errors++
  console.error(`❌ [runtime] ${lightOnly.length} mappings definidos solo en light (rotos en dark):`)
  for (const t of lightOnly) console.error(`   ${t}`)
}
if (fallbackOnly.length > 0) {
  console.warn(`⚠️ [runtime] ${fallbackOnly.length} mappings con fallback pero sin definición primaria:`)
  for (const t of fallbackOnly) console.warn(`   ${t}`)
}

const generatedNames = new Set([...txtNames].map((n) => `--color-${n}`))
const cssNames = new Set([...cssTokens.keys()].map((n) => `--color-${n}`))
if (
  generatedNames.size !== cssNames.size ||
  [...generatedNames].some((n) => !cssNames.has(n)) ||
  [...cssNames].some((n) => !generatedNames.has(n))
) {
  errors++
  console.error("❌ [drift] colors.css NO está sincronizado con tokens.json.")
  console.error("   Ejecuta: bun --cwd packages/ui generate:tailwind")
}

// ── Deuda de color: mappings --color-* definidos sin NINGÚN uso en source ──
function collectSources(dir: string, out: string[], exclude: RegExp): void {
  if (!existsSync(dir)) return
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry)
    const st = statSync(full)
    const norm = full.replace(/\\/g, "/")
    if (st.isDirectory()) collectSources(full, out, exclude)
    else if (/\.(ts|tsx|css)$/.test(entry) && !exclude.test(norm)) out.push(norm)
  }
}

const sources: string[] = []
collectSources(
  join(dir, "..", "src"),
  sources,
  /\/styles\/(theme\.css|utilities\.css|index\.css|base\.css|animations\.css|tailwind\/index\.css|tailwind\/colors\.css|tailwind\/utilities\.css)$/,
)
collectSources(join(dir, "..", "..", "app", "src"), sources, /$^/)
const corpus = sources.map((f) => readFileSync(f, "utf8").replace(/\r\n/g, "\n"))

// Match preciso: el nombre del token usado como var(--color-X)/var(--X) o como
// clase de color Tailwind (text-X, bg-X, border-X, fill-X, ring-X, …). Evita
// falsos positivos por colisiones de substring (p.ej. "white" en "whitespace").
const COLOR_CLASS_PREFIX =
  "(?:text|bg|border|fill|stroke|ring|from|to|via|decoration|divide|shadow|outline|accent|caret)-"
function tokenUsed(name: string, source: string): boolean {
  return new RegExp(`(?:--color-|--|${COLOR_CLASS_PREFIX})${name}(?:/|\\$|[^a-z0-9-])`).test(source)
}

const deadMappings: string[] = []
for (const name of txtNames) {
  if (!corpus.some((c) => tokenUsed(name, c))) deadMappings.push(name)
}
if (deadMappings.length > 0) {
  // Error (no warning): un mapping sin NINGÚN uso en source es deuda muerta que
  // infla tokens.json/colors.css. Si sync-tokens lo resucita desde theme.css,
  // este chequeo lo bloquea en pre-commit.
  errors++
  console.error(`❌ [debt] ${deadMappings.length} mappings de color sin uso en source (tokens.json):`)
  for (const n of deadMappings) console.error(`   ${n}`)
  console.error(
    "   Pódalos de tokens.json (y de theme.css solo si su token crudo no se usa directo) y ejecuta: bun --cwd packages/ui generate:tailwind",
  )
} else {
  console.log("✅ [debt] Todos los mappings de color tienen uso en source.")
}

if (errors > 0) {
  console.error(`\n${errors} error(es) de auditoría de tokens.`)
  process.exit(1)
}
console.log("✅ Auditoría de tokens OK")
