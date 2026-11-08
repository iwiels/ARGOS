#!/usr/bin/env bun

import { readFileSync, writeFileSync } from "node:fs"

const css = readFileSync(import.meta.dir + "/../src/styles/theme.css", "utf8").replace(/\r\n/g, "\n")

const LAYOUT_PREFIXES = [
  "font-",
  "font-size-",
  "font-weight-",
  "font-family-",
  "font-feature-",
  "line-height-",
  "letter-spacing-",
  "paragraph-spacing-",
  "spacing-",
  "breakpoint-",
  "container-",
  "radius-",
  "shadow-",
  "color-scheme",
  "text-mix-blend-mode",
]

// ⚠️ tokens.json es la fuente de la capa de mapeo --color-* (→ colors.css).
// Regenerarlo desde theme.css RESUCITA los mappings muertos que audit:tailwind
// ya podó. Si necesitas re-sincronizar, corre audit:tailwind después y poda los
// tokens que reporte como [debt] (o revisa si el token crudo se usa directo).
const tokens: Record<string, string> = {}
for (const line of css.split("\n")) {
  const m = line.match(/^  --([a-z0-9-]+):\s*(.+?);\s*$/)
  if (!m) continue
  const [name, value] = [m[1], m[2]]
  if (name in tokens) continue
  if (LAYOUT_PREFIXES.some((p) => name.startsWith(p))) continue
  tokens[name] = value
}

writeFileSync(import.meta.dir + "/tokens.json", JSON.stringify(tokens, null, 2) + "\n")
console.log(`tokens.json regenerado: ${Object.keys(tokens).length} tokens desde theme.css`)
