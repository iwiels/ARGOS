#!/usr/bin/env bun
// WCAG 2.2 contrast audit for the Argos design tokens.
// Verifies the real text/background pairs (dark + light) against AA thresholds:
//   - text / button labels / severity fg / syntax: 4.5:1
//   - icons (non-text UI components):              3:1
// Fails (exit 1) on any violation so it can run in pre-commit.
//
// Inheritance model: light block inherits from dark (:root) exactly like CSS —
// any token not overridden by [data-color-scheme="light"] keeps the dark value.

import { readFileSync } from "node:fs"
import { join } from "node:path"

const dir = import.meta.dir
const themeCss = readFileSync(join(dir, "..", "src", "styles", "theme.css"), "utf8")

// ── Parsing ──────────────────────────────────────────────────────────────────
const darkStart = themeCss.indexOf('data-color-scheme="dark"')
const lightStart = themeCss.indexOf('data-color-scheme="light"')
if (darkStart < 0 || lightStart < 0) {
  console.error("❌ No se encontraron los bloques de tema en theme.css")
  process.exit(1)
}

function extractTokens(block: string): Record<string, string> {
  const tokens: Record<string, string> = {}
  for (const m of block.matchAll(/--([a-z0-9-]+):\s*([^;]+);/g)) {
    tokens[m[1]] = m[2].replace(/\s+/g, " ").trim()
  }
  return tokens
}

const shared = extractTokens(themeCss.slice(0, darkStart)) // palette :root (grey-*, green-500, black-*, white)
const dark = extractTokens(themeCss.slice(darkStart, lightStart))
const light = { ...dark, ...extractTokens(themeCss.slice(lightStart)) } // light hereda de :root (dark)

const COLOR_RE = /^(#[0-9a-fA-F]{3,8}|rgba?\([^)]*\)|var\(--[a-z0-9-]+\))$/

function resolveAll(theme: Record<string, string>): Record<string, string | null> {
  const resolved: Record<string, string | null> = {}
  const stack: string[] = []
  const resolve = (name: string): string | null => {
    if (name in resolved) return resolved[name]
    if (stack.includes(name)) return (resolved[name] = null) // cycle
    stack.push(name)
    let v = theme[name] ?? shared[name]
    let out: string | null = null
    if (v != null) {
      v = v.trim()
      const vm = /^var\(--([a-z0-9-]+)\)$/.exec(v)
      out = vm ? resolve(vm[1]) : COLOR_RE.test(v) ? v : null
    }
    stack.pop()
    return (resolved[name] = out)
  }
  for (const k of Object.keys(theme)) resolve(k)
  return resolved
}

// ── Color math (WCAG 2.x relative luminance + contrast) ─────────────────────
function rgbArr(color: string): [number, number, number] {
  if (color.startsWith("#")) {
    let h = color.slice(1)
    if (h.length === 3) h = h.split("").map((c) => c + c).join("")
    return [parseInt(h.slice(0, 2), 16), parseInt(h.slice(2, 4), 16), parseInt(h.slice(4, 6), 16)]
  }
  const m = /rgba?\((\d+),\s*(\d+),\s*(\d+)/.exec(color)
  return [+m![1], +m![2], +m![3]]
}

function luminance(color: string): number {
  const lin = (c: number) => {
    c /= 255
    return c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4)
  }
  const [r, g, b] = rgbArr(color)
  return 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b)
}

function contrast(fg: string, bg: string): number | null {
  const lf = luminance(fg)
  const lb = luminance(bg)
  if (Number.isNaN(lf) || Number.isNaN(lb)) return null
  const [hi, lo] = lf >= lb ? [lf, lb] : [lb, lf]
  return (hi + 0.05) / (lo + 0.05)
}

const RGBA_RE = /^rgba\((\d+),\s*(\d+),\s*(\d+),\s*([\d.]+)\)$/

function compositeOver(rgba: string, bg: string): string | null {
  const m = RGBA_RE.exec(rgba)
  if (!m) return null
  const a = parseFloat(m[4])
  if (a >= 1) return `rgb(${m[1]}, ${m[2]}, ${m[3]})`
  const [br, bgG, bb] = rgbArr(bg)
  const mix = (f: number, b: number) => Math.round(f * a + b * (1 - a))
  return `#${[mix(+m[1], br), mix(+m[2], bgG), mix(+m[3], bb)]
    .map((x) => x.toString(16).padStart(2, "0"))
    .join("")}`
}

function resolveColor(resolved: Record<string, string | null>, name: string, baseBg: string): string | null {
  const raw = resolved[name]
  if (!raw || raw.startsWith("var(")) return null
  if (RGBA_RE.test(raw)) {
    const base = resolved[baseBg]
    if (base && base.startsWith("#")) return compositeOver(raw, base)
    return null
  }
  return raw
}

// ── Matriz de pares a auditar ────────────────────────────────────────────────
type Kind = "text" | "icon" | "button" | "severity" | "syntax" | "avatar"
const THRESHOLD: Record<Kind, number> = { text: 4.5, icon: 3.0, button: 4.5, severity: 4.5, syntax: 4.5, avatar: 4.5 }

const BACKGROUNDS = ["bg-base", "bg-surface", "bg-elevated", "surface-raised-base"]
const TEXT = ["text-primary", "text-secondary", "text-tertiary", "text-link", "text-accent"]
const ICONS = ["icon", "icon-muted", "icon-weak", "icon-strong", "icon-weaker", "icon-interactive-base", "icon-warning-base", "icon-base", "icon-weak-base"]
const SEVERITIES = ["critical", "high", "medium", "low", "info"]
const SYNTAX = ["syntax-comment", "syntax-string", "syntax-keyword", "syntax-property", "syntax-type", "syntax-constant", "syntax-variable", "syntax-operator", "syntax-primitive", "syntax-punctuation", "syntax-success", "syntax-warning", "syntax-critical", "syntax-info", "syntax-diff-add", "syntax-diff-delete"]
const AVATAR_BGS = ["avatar-bg-gray", "avatar-bg-orange", "avatar-bg-yellow", "avatar-bg-cyan", "avatar-bg-green", "avatar-bg-red", "avatar-bg-pink", "avatar-bg-blue", "avatar-bg-purple"]

interface Pair {
  label: string
  fg: string
  bg: string
  kind: Kind
}

function pairs(): Pair[] {
  const out: Pair[] = []
  for (const fg of TEXT) for (const bg of BACKGROUNDS) out.push({ label: `${fg} on ${bg}`, fg, bg, kind: "text" })
  out.push({ label: "accent-fg on accent (botón primario)", fg: "accent-fg", bg: "accent", kind: "button" })
  out.push({ label: "text-on-critical on danger", fg: "text-on-critical", bg: "danger", kind: "button" })
  for (const fg of ICONS) for (const bg of BACKGROUNDS) out.push({ label: `${fg} on ${bg}`, fg, bg, kind: "icon" })
  for (const s of SEVERITIES) {
    out.push({ label: `severity-fg-${s} on severity-bg-${s} (sobre bg-base)`, fg: `severity-fg-${s}`, bg: `severity-bg-${s}`, kind: "severity" })
    out.push({ label: `severity-fg-${s} on severity-bg-${s} (sobre bg-elevated)`, fg: `severity-fg-${s}`, bg: `severity-bg-${s}`, kind: "severity" })
  }
  for (const fg of ["state-fg-success", "state-fg-warning", "state-fg-danger"]) {
    for (const bg of ["bg-base", "bg-elevated"]) out.push({ label: `${fg} on ${bg}`, fg, bg, kind: "text" })
  }
  for (const fg of SYNTAX) for (const bg of ["bg-base", "bg-elevated"]) out.push({ label: `${fg} on ${bg}`, fg, bg, kind: "syntax" })
  for (const bg of AVATAR_BGS) out.push({ label: `avatar-fg on ${bg} (proyecto)`, fg: "avatar-fg", bg, kind: "avatar" })
  // text-invert-* se renderizan dentro de tooltips/popovers (bg-surface) y
  // context-items (bg-elevated). En light heredaban blanco de :root -> invisibles.
  for (const fg of ["text-invert-strong", "text-invert-base"]) {
    for (const bg of ["bg-surface", "bg-elevated"]) out.push({ label: `${fg} on ${bg} (tooltip)`, fg, bg, kind: "text" })
  }
  out.push({ label: "text-invert-weak on bg-surface (tooltip)", fg: "text-invert-weak", bg: "bg-surface", kind: "text" })
  return out
}

// ── Ejecución ────────────────────────────────────────────────────────────────
function auditTheme(name: string, theme: Record<string, string>): number {
  const resolved = resolveAll(theme)
  let fails = 0
  const lines: string[] = []
  const unresolved: string[] = []

  for (const p of pairs()) {
    let fgColor: string | null
    let bgColor: string | null
    if (p.kind === "severity") {
      const base = p.label.includes("bg-elevated") ? "bg-elevated" : "bg-base"
      bgColor = resolveColor(resolved, p.bg, base)
      fgColor = bgColor ? resolved[p.fg] : null
    } else {
      bgColor = resolveColor(resolved, p.bg, "bg-base")
      fgColor = resolved[p.fg]
    }
    if (!fgColor || !bgColor) {
      unresolved.push(p.label)
      continue
    }
    let fg: string = fgColor
    const bg: string = bgColor
    if (RGBA_RE.test(fg) && bg.startsWith("#")) fg = compositeOver(fg, bg) ?? fg
    const ratio = contrast(fg, bg)
    if (ratio == null) continue
    const need = THRESHOLD[p.kind]
    const pass = ratio >= need
    if (!pass) fails++
    lines.push(
      `${pass ? "✅" : "❌"} [${name}] ${p.label}: ${ratio.toFixed(2)}:1 (requiere ${need}:1)${pass ? "" : ` <- ${fg} / ${bg}`}`,
    )
  }

  console.log(`\n═══ TEMA ${name.toUpperCase()} ═══`)
  for (const l of lines) console.log(l)
  console.log(`→ ${fails} fallos en ${name}`)
  if (unresolved.length > 0) {
    // Un par de la matriz sin color resoluble es un punto ciego real -> falla fuerte.
    console.log(`❌ ${unresolved.length} pares sin resolver (revisar matriz o tokens):`)
    for (const u of unresolved) console.log(`   ${u}`)
    return fails + unresolved.length
  }
  return fails
}

const failDark = auditTheme("dark", dark)
const failLight = auditTheme("light", light)
const total = failDark + failLight

console.log(`\n${total} violación(es) AA.`)
if (total > 0) process.exit(1)
console.log("✅ Contraste WCAG AA OK en ambos temas")
