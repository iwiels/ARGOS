#!/usr/bin/env bun

import { readFileSync, readdirSync, statSync, writeFileSync } from "node:fs"
import { join } from "node:path"

const distDir = join(import.meta.dir, "..", "dist", "assets")
const baselineFile = join(import.meta.dir, "dist-baseline.json")
const themeCssFile = join(import.meta.dir, "..", "..", "ui", "src", "styles", "theme.css")
const tolerance = 0.15

const themeTokens = new Set<string>()
try {
  const themeCss = readFileSync(themeCssFile, "utf8")
  for (const m of themeCss.matchAll(/^\s*--([a-z0-9-]+)\s*:/gm)) themeTokens.add(m[1].toLowerCase())
} catch {}

const runtimePrefixes = ["kb-", "animated-number-", "text-reveal-", "tool-motion-", "diffs-", "inline-input-v2-", "question-prompt-", "sticky-accordion-", "session-title-", "main-left", "list-divider-inset", "active-bg", "inactive-bg", "alpha-"]

let errors = 0
const cssFiles = readdirSync(distDir).filter((f) => f.endsWith(".css"))

if (cssFiles.length === 0) {
  console.error("❌ No hay CSS compilado en dist/assets. Ejecuta primero: bun --cwd packages/app build")
  process.exit(1)
}

const cssText = cssFiles.map((f) => readFileSync(join(distDir, f), "utf8")).join("\n")

const defined = new Set<string>()
for (const m of cssText.matchAll(/--([a-z0-9-]+)\s*:/gi)) defined.add(m[1].toLowerCase())

const broken = new Set<string>()
const fallbackOnly: string[] = []
for (const m of cssText.matchAll(/var\(--([a-z0-9-]+)([^)]*)\)/gi)) {
  const name = m[1].toLowerCase()
  if (defined.has(name) || themeTokens.has(name)) continue
  if (runtimePrefixes.some((p) => name.startsWith(p))) continue
  if (m[2].trim().startsWith(",")) {
    fallbackOnly.push(m[1])
    continue
  }
  broken.add(m[1])
}

if (broken.size > 0) {
  errors++
  console.error(`❌ [postbuild] ${broken.size} var(--x) rotas en el CSS compilado (sin definición ni runtime):`)
  for (const v of [...broken].sort()) console.error(`   var(--${v})`)
}
if (fallbackOnly.length > 0) {
  console.warn(`⚠️ [postbuild] ${fallbackOnly.length} vars con fallback (var(--x, fb)) pero sin definición:`)
  for (const v of [...new Set(fallbackOnly)].sort()) console.warn(`   var(--${v})`)
}

const totalBytes = cssFiles.reduce((sum, f) => sum + statSync(join(distDir, f)).size, 0)
const totalKb = totalBytes / 1024

let baseline: number | null = null
try {
  baseline = JSON.parse(readFileSync(baselineFile, "utf8")).cssKb
} catch {}

if (baseline === null) {
  writeFileSync(baselineFile, JSON.stringify({ cssKb: Math.round(totalKb), generatedBy: "verify-dist.ts" }, null, 2))
  console.log(`📦 Baseline de CSS creado: ${Math.round(totalKb)} KB → ${baselineFile}`)
} else {
  const limit = baseline * (1 + tolerance)
  if (totalKb > limit) {
    errors++
    console.error(`❌ [postbuild] CSS compilado: ${totalKb.toFixed(1)} KB, excede baseline ${baseline} KB +${tolerance * 100}%`)
    console.error("   Si el crecimiento es intencional, actualiza script/dist-baseline.json")
  } else {
    console.log(`📦 CSS compilado: ${totalKb.toFixed(1)} KB (baseline ${baseline} KB, +${((totalKb / baseline - 1) * 100).toFixed(1)}%)`)
  }
}

if (errors > 0) {
  console.error(`\n${errors} error(es) de verificación postbuild.`)
  process.exit(1)
}
console.log("✅ Postbuild OK")
