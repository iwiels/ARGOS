/**
 * Generador de PDF nativo del informe de auditoría (ARG-043).
 *
 * ── Por qué un writer propio y no Chromium ──────────────────────────────────
 * El repo ya tiene `playwright-core` como dependencia, pero `playwright-core`
 * no distribuye ningún navegador: hay que descargar Chromium aparte (~150 MB)
 * y el instalador de escritorio no lo lleva. Sumado a que el PDF de Chromium
 * incrusta un timestamp de creación y un `/ID` aleatorio (con lo que el
 * artefacto no es determinista ni reproducible), el camino de Playwright no
 * cumple el requisito de "mismos datos → mismo contenido".
 *
 * Por eso el PDF se escribe acá: un writer propio, sin dependencias nuevas,
 * que además da control exacto sobre la metadata (`dc:*`, `pdf:Keywords`,
 * `xmp:CreateDate`), la portada, el índice con números de página y el hash
 * del contenido. El renderer es inyectable (`PdfRenderer`) para poder testear
 * el pipeline completo con un stub.
 *
 * ── Determinismo ────────────────────────────────────────────────────────────
 * El único valor no determinista es `generatedAt`, que va declarado como
 * metadata (`/CreationDate`, `xmp:CreateDate`). Los ids de objeto son
 * secuenciales y el `/ID` del trailer se deriva del hash del contenido, así
 * que dos emisiones del mismo informe con la misma fecha dan el mismo archivo.
 */

import { createHash } from "node:crypto"
import { deflateSync, inflateSync } from "node:zlib"
import { exportHtml } from "./export/html"
import { reportContentHash, toPdfDate, type ReportDocument, type ReportFinding } from "./export/model"

// ── Geometría de la página (A4) ──────────────────────────────────────────────

const PAGE_WIDTH = 595.28
const PAGE_HEIGHT = 841.89
const MARGIN = 56
const CONTENT_WIDTH = PAGE_WIDTH - MARGIN * 2
const TOP_Y = PAGE_HEIGHT - MARGIN
const BOTTOM_Y = MARGIN + 28
const FOOTER_Y = 38

type RGB = [number, number, number]

const COLOR_TEXT: RGB = [0.09, 0.11, 0.16]
const COLOR_MUTED: RGB = [0.42, 0.46, 0.55]
const COLOR_RULE: RGB = [0.82, 0.85, 0.9]
const COLOR_CRITICAL: RGB = [0.86, 0.16, 0.16]
const COLOR_HIGH: RGB = [0.94, 0.45, 0.09]
const COLOR_MEDIUM: RGB = [0.85, 0.66, 0.05]
const COLOR_LOW: RGB = [0.2, 0.5, 0.94]
const COLOR_INFO: RGB = [0.42, 0.47, 0.56]
const COLOR_ACCENT: RGB = [0.09, 0.45, 0.68]
const COLOR_PANEL: RGB = [0.96, 0.97, 0.99]

// ── Fuentes base-14 y sus anchos ─────────────────────────────────────────────

type FontKey = "regular" | "bold" | "mono"

/** Anchos AFM de Helvetica para el rango ASCII 32..126 (unidades de 1/1000 em). */
const HELVETICA_WIDTHS = [
  278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278, 556, 556, 556, 556, 556, 556, 556,
  556, 556, 556, 278, 278, 584, 584, 584, 556, 1015, 667, 667, 722, 722, 667, 611, 778, 722, 278, 500, 667, 556, 833,
  722, 778, 667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 278, 278, 278, 469, 556, 333, 556, 556, 500, 556,
  556, 278, 556, 556, 222, 222, 500, 222, 833, 556, 556, 556, 556, 333, 500, 278, 556, 500, 722, 500, 500, 500, 334,
  260, 334, 584,
]

/** Anchos AFM de Helvetica-Bold para el rango ASCII 32..126. */
const HELVETICA_BOLD_WIDTHS = [
  278, 333, 474, 556, 556, 889, 722, 238, 333, 333, 389, 584, 278, 333, 278, 278, 556, 556, 556, 556, 556, 556, 556,
  556, 556, 556, 333, 333, 584, 584, 584, 611, 975, 722, 722, 722, 722, 667, 611, 778, 722, 278, 556, 722, 611, 833,
  722, 778, 667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 333, 278, 333, 584, 556, 333, 556, 611, 556, 611,
  556, 333, 611, 611, 278, 278, 556, 278, 889, 611, 611, 611, 611, 389, 556, 333, 611, 556, 778, 556, 556, 500, 389,
  280, 389, 584,
]

const MONO_WIDTH = 600

/** Las letras acentuadas tienen el ancho de su letra base en Helvetica. */
function latinBase(code: number): number | undefined {
  if (code >= 0xc0 && code <= 0xc5) return 0x41 // À-Å
  if (code === 0xc6) return 0x41 // Æ
  if (code === 0xc7) return 0x43 // Ç
  if (code >= 0xc8 && code <= 0xcb) return 0x45 // È-Ë
  if (code >= 0xcc && code <= 0xcf) return 0x49 // Ì-Ï
  if (code === 0xd1) return 0x4e // Ñ
  if (code >= 0xd2 && code <= 0xd6) return 0x4f // Ò-Ö
  if (code === 0xd8) return 0x4f // Ø
  if (code >= 0xd9 && code <= 0xdc) return 0x55 // Ù-Ü
  if (code === 0xdd) return 0x59 // Ý
  if (code === 0xdf) return 0x73 // ß
  if (code >= 0xe0 && code <= 0xe5) return 0x61 // à-å
  if (code === 0xe7) return 0x63 // ç
  if (code >= 0xe8 && code <= 0xeb) return 0x65 // è-ë
  if (code >= 0xec && code <= 0xef) return 0x69 // ì-ï
  if (code === 0xf1) return 0x6e // ñ
  if (code >= 0xf2 && code <= 0xf6) return 0x6f // ò-ö
  if (code === 0xf8) return 0x6f // ø
  if (code >= 0xf9 && code <= 0xfc) return 0x75 // ù-ü
  if (code === 0xfd || code === 0xff) return 0x79 // ý ÿ
  return undefined
}

function charWidth(font: FontKey, code: number): number {
  if (font === "mono") return MONO_WIDTH
  const table = font === "bold" ? HELVETICA_BOLD_WIDTHS : HELVETICA_WIDTHS
  const index = code - 32
  if (index >= 0 && index < table.length) return table[index]
  const base = latinBase(code)
  if (base !== undefined) return charWidth(font, base)
  return 556
}

/** Caracteres fuera de WinAnsi que aparecen en la copia del informe. */
const UNICODE_TO_WINANSI: Record<string, string> = {
  "–": "\x96",
  "—": "\x97",
  "‘": "\x91",
  "’": "\x92",
  "“": "\x93",
  "”": "\x94",
  "•": "\x95",
  "…": "\x85",
  "€": "\x80",
  "™": "\x99",
  "→": "->",
  "←": "<-",
  "≤": "\xa3",
  "≥": "\xb3",
  "×": "\xd7",
  "÷": "\xf7",
  "·": "\xb7",
  "°": "\xb0",
  "„": "\x84",
  "«": "\xab",
  "»": "\xbb",
}

/** Convierte a WinAnsi (Latin-1 con las sustituciones de Windows-1252). */
function toWinAnsi(text: string): string {
  let out = ""
  for (const char of text) {
    const mapped = UNICODE_TO_WINANSI[char]
    if (mapped !== undefined) {
      out += mapped
      continue
    }
    const code = char.codePointAt(0) ?? 63
    if (code < 0x20) {
      out += " "
      continue
    }
    if (code <= 0xff) {
      out += String.fromCharCode(code)
      continue
    }
    out += "?"
  }
  return out
}

function measureText(text: string, font: FontKey, size: number): number {
  let total = 0
  for (const char of toWinAnsi(text)) total += charWidth(font, char.charCodeAt(0))
  return (total * size) / 1000
}

function wrapText(text: string, font: FontKey, size: number, maxWidth: number): string[] {
  const lines: string[] = []
  for (const paragraph of text.split(/\r?\n/)) {
    const words = paragraph.split(/\s+/).filter(Boolean)
    if (words.length === 0) {
      lines.push("")
      continue
    }
    let current = ""
    const flush = () => {
      lines.push(current)
      current = ""
    }
    for (const word of words) {
      const candidate = current.length === 0 ? word : `${current} ${word}`
      if (measureText(candidate, font, size) <= maxWidth) {
        current = candidate
        continue
      }
      if (current.length > 0) flush()
      if (measureText(word, font, size) <= maxWidth) {
        current = word
        continue
      }
      // Palabra más ancha que la caja: se parte en trozos.
      let chunk = ""
      for (const char of word) {
        if (chunk.length > 0 && measureText(chunk + char, font, size) > maxWidth) {
          lines.push(chunk)
          chunk = char
          continue
        }
        chunk += char
      }
      current = chunk
    }
    if (current.length > 0) lines.push(current)
  }
  return lines
}

// ── Metadata del PDF ─────────────────────────────────────────────────────────

export interface PdfMetadata {
  title: string
  author: string
  subject: string
  description: string
  keywords: string[]
  creator: string
  producer: string
  createdAt: Date
}

export function buildPdfMetadata(document: ReportDocument): PdfMetadata {
  const { meta } = document
  const target = meta.target ?? meta.clientName
  return {
    title: meta.title,
    author: meta.leadAuditor,
    subject: meta.classification,
    description: [
      `Informe de auditoría de seguridad — ${meta.clientName}${meta.clientLegalName ? ` (${meta.clientLegalName})` : ""}.`,
      `Alcance: ${meta.scope}.`,
      `Sesión: ${meta.sessionID}.`,
      `Metodología: ${meta.methodology}.`,
    ].join(" "),
    keywords: [
      meta.engagement ?? "argos-engagement",
      `session:${meta.sessionID}`,
      `target:${target}`,
      meta.classification,
      `findings:${document.summary.totalFindings}`,
    ].filter(Boolean),
    creator: meta.leadAuditor,
    producer: `${meta.engine ?? "argos-security-operations"}${meta.engineVersion ? ` ${meta.engineVersion}` : ""}`,
    createdAt: meta.generatedAt,
  }
}

export interface PdfArtifact {
  bytes: Uint8Array
  /** sha256 del archivo PDF final. */
  sha256: string
  /** sha256 del contenido del informe (independiente del formato y del reloj). */
  contentHash: string
  pageCount: number
  metadata: PdfMetadata
}

export interface PdfRenderInput {
  document: ReportDocument
  metadata: PdfMetadata
  /** HTML equivalente del informe — lo consume un renderer basado en navegador. */
  html: string
  /** Hash del contenido del informe. */
  contentHash: string
}

export interface PdfRenderer {
  readonly name: string
  render(input: PdfRenderInput): Promise<Uint8Array>
}

// ── Layout ───────────────────────────────────────────────────────────────────

interface LaidPage {
  ops: string[]
}

const SEVERITY_COLOR: Record<string, RGB> = {
  critical: COLOR_CRITICAL,
  high: COLOR_HIGH,
  medium: COLOR_MEDIUM,
  low: COLOR_LOW,
  info: COLOR_INFO,
}

const SEVERITY_LABEL: Record<string, string> = {
  critical: "CRÍTICO",
  high: "ALTO",
  medium: "MEDIO",
  low: "BAJO",
  info: "INFO",
}

function escapePdfString(value: string): string {
  let out = ""
  for (const char of toWinAnsi(value)) {
    const code = char.charCodeAt(0)
    if (char === "\\" || char === "(" || char === ")") {
      out += `\\${char}`
      continue
    }
    if (code < 0x20 || code > 0x7e) {
      out += `\\${code.toString(8).padStart(3, "0")}`
      continue
    }
    out += char
  }
  return out
}

function colorOp(color: RGB, stroke = false): string {
  const [r, g, b] = color
  return `${r.toFixed(3)} ${g.toFixed(3)} ${b.toFixed(3)} ${stroke ? "RG" : "rg"}`
}

/** Dibuja una línea de texto en una posición absoluta. */
function drawText(page: LaidPage, text: string, x: number, y: number, font: FontKey, size: number, color: RGB): void {
  if (text.length === 0) return
  const resource = font === "bold" ? "/F2" : font === "mono" ? "/F3" : "/F1"
  page.ops.push(
    `${colorOp(color)} BT ${resource} ${size} Tf 1 0 0 1 ${x.toFixed(2)} ${y.toFixed(2)} Tm (${escapePdfString(text)}) Tj ET`,
  )
}

function drawRect(page: LaidPage, x: number, y: number, width: number, height: number, color: RGB): void {
  page.ops.push(`${colorOp(color)} ${x.toFixed(2)} ${y.toFixed(2)} ${width.toFixed(2)} ${height.toFixed(2)} re f`)
}

function drawLine(page: LaidPage, x1: number, y1: number, x2: number, y2: number, color: RGB, width = 0.6): void {
  page.ops.push(
    `${colorOp(color, true)} ${width} w ${x1.toFixed(2)} ${y1.toFixed(2)} m ${x2.toFixed(2)} ${y2.toFixed(2)} l S`,
  )
}

function severityColor(severity: string): RGB {
  return SEVERITY_COLOR[severity] ?? COLOR_INFO
}

interface TextOptions {
  font?: FontKey
  size?: number
  color?: RGB
  x?: number
  leading?: number
  maxWidth?: number
  indent?: number
}

class PageBuilder {
  readonly pages: LaidPage[] = []
  private current: LaidPage
  y = TOP_Y

  constructor() {
    this.current = { ops: [] }
    this.pages.push(this.current)
  }

  get pageIndex(): number {
    return this.pages.length - 1
  }

  get page(): LaidPage {
    return this.current
  }

  newPage(): void {
    this.current = { ops: [] }
    this.pages.push(this.current)
    this.y = TOP_Y
  }

  ensure(space: number): void {
    if (this.y - space < BOTTOM_Y) this.newPage()
  }

  text(value: string, options: TextOptions = {}): void {
    const font = options.font ?? "regular"
    const size = options.size ?? 10
    const color = options.color ?? COLOR_TEXT
    const x = options.x ?? MARGIN
    const leading = options.leading ?? size * 1.42
    const maxWidth = options.maxWidth ?? CONTENT_WIDTH
    const indent = options.indent ?? 0
    for (const line of wrapText(value, font, size, Math.max(maxWidth - indent, 40))) {
      this.ensure(leading)
      this.y -= leading
      drawText(this.current, line, x + indent, this.y, font, size, color)
    }
  }

  paragraph(value: string, options: TextOptions = {}): void {
    this.text(value, options)
    this.y -= (options.leading ?? (options.size ?? 10) * 1.42) * 0.35
  }

  space(amount: number): void {
    this.y -= amount
  }

  rule(color: RGB = COLOR_RULE): void {
    this.ensure(10)
    this.y -= 6
    drawLine(this.current, MARGIN, this.y, PAGE_WIDTH - MARGIN, this.y, color)
    this.y -= 6
  }

  heading(value: string, options: { size?: number; color?: RGB; pageBreak?: boolean } = {}): void {
    if (options.pageBreak) {
      this.newPage()
    } else {
      this.ensure(40)
      this.y -= 12
    }
    const size = options.size ?? 15
    this.text(value, { font: "bold", size, color: options.color ?? COLOR_TEXT })
    this.y -= 4
    this.rule()
    this.y -= 4
  }

  /** Píldora de severidad con fondo. Devuelve el ancho dibujado. */
  badge(label: string, x: number, y: number, color: RGB): number {
    const width = measureText(label, "bold", 8) + 12
    const height = 13
    drawRect(this.current, x, y - height + 3, width, height, color)
    drawText(this.current, label, x + 6, y - height + 7, "bold", 8, [1, 1, 1])
    return width
  }
}

// ── Portada ──────────────────────────────────────────────────────────────────

interface CoverImage {
  width: number
  height: number
  rgb: Uint8Array
  alpha?: Uint8Array
}

function buildCover(builder: PageBuilder, document: ReportDocument, contentHash: string): CoverImage | undefined {
  const { meta, summary } = document
  const page = builder.page

  // Banda de clasificación arriba de todo.
  drawRect(page, 0, PAGE_HEIGHT - 96, PAGE_WIDTH, 96, [0.11, 0.14, 0.22])
  drawText(page, meta.classification.toUpperCase(), MARGIN, PAGE_HEIGHT - 44, "bold", 12, [1, 1, 1])
  drawText(
    page,
    `Emitido ${meta.generatedAt.toISOString().replace("T", " ").slice(0, 19)} UTC`,
    MARGIN,
    PAGE_HEIGHT - 64,
    "mono",
    9,
    [0.72, 0.78, 0.9],
  )

  builder.y = PAGE_HEIGHT - 150

  const image = decodeLogo(meta.clientLogoDataUrl)
  if (image) {
    const maxWidth = 180
    const maxHeight = 60
    const scale = Math.min(maxWidth / image.width, maxHeight / image.height, 1)
    const width = image.width * scale
    const height = image.height * scale
    builder.y -= height
    page.ops.push(
      `q ${width.toFixed(2)} 0 0 ${height.toFixed(2)} ${MARGIN.toFixed(2)} ${builder.y.toFixed(2)} cm /Logo Do Q`,
    )
    builder.y -= 18
  }

  builder.text(meta.title, { font: "bold", size: 24, leading: 28 })
  builder.space(6)
  builder.text(meta.clientLegalName ? `${meta.clientName} — ${meta.clientLegalName}` : meta.clientName, {
    size: 13,
    color: COLOR_MUTED,
  })
  builder.space(10)
  builder.rule()
  builder.space(6)

  const rows: Array<[string, string]> = [
    ["Alcance autorizado", meta.scope],
    ["Auditor responsable", meta.leadAuditor],
    ["Metodología", meta.methodology],
    ["Sesión", meta.sessionID],
    ["Riesgo global", summary.globalRisk.toUpperCase()],
    ["Hallazgos", String(summary.totalFindings)],
    ["CVSS v3.1 promedio", summary.averageCvss.toFixed(1)],
    ["Fecha de emisión", meta.generatedAt.toISOString()],
  ]
  for (const [label, value] of rows) {
    builder.ensure(16)
    builder.y -= 15
    drawText(page, label.toUpperCase(), MARGIN, builder.y, "bold", 7.5, COLOR_MUTED)
    drawText(page, value, MARGIN + 140, builder.y, "regular", 10, COLOR_TEXT)
  }

  builder.space(16)
  builder.rule()
  builder.space(4)
  builder.text("Hash del contenido del informe (sha256)", { font: "bold", size: 8, color: COLOR_MUTED })
  builder.y -= 13
  drawText(page, contentHash, MARGIN, builder.y, "mono", 8.5, COLOR_ACCENT)
  builder.y -= 14
  builder.text(
    "Este hash identifica el contenido firmado del informe. El hash del artefacto PDF (sha256 del archivo) se devuelve junto con la descarga.",
    { size: 8, color: COLOR_MUTED },
  )

  return image
}

// ── Índice ───────────────────────────────────────────────────────────────────

interface TocResult {
  pages: LaidPage[]
  /** Página (base 0) de la primera hoja del índice. */
  firstPage: number
}

function buildToc(
  document: ReportDocument,
  findingPages: number[],
  bodyOffset: number,
  sectionPages: Array<{ title: string; page: number }>,
): TocResult {
  const pages: LaidPage[] = []
  let page: LaidPage = { ops: [] }
  let y = TOP_Y

  const nextPage = () => {
    pages.push(page)
    page = { ops: [] }
    y = TOP_Y
  }

  const line = (
    label: string,
    pageNumber: number,
    options: { bold?: boolean; indent?: number; size?: number } = {},
  ) => {
    const size = options.size ?? 9.5
    const indent = options.indent ?? 0
    const labelWidth = measureText(label, options.bold ? "bold" : "regular", size)
    const numberText = String(pageNumber)
    const numberWidth = measureText(numberText, "regular", size)
    if (y - size * 1.5 < BOTTOM_Y) nextPage()
    y -= size * 1.5
    drawText(page, label, MARGIN + indent, y, options.bold ? "bold" : "regular", size, COLOR_TEXT)
    const dotsStart = MARGIN + indent + labelWidth + 4
    const dotsEnd = PAGE_WIDTH - MARGIN - numberWidth - 4
    if (dotsEnd > dotsStart) {
      const dotWidth = measureText(".", "regular", size)
      const count = Math.floor((dotsEnd - dotsStart) / dotWidth)
      if (count > 0) drawText(page, ".".repeat(count), dotsStart, y, "regular", size, COLOR_RULE)
    }
    drawText(page, numberText, PAGE_WIDTH - MARGIN - numberWidth, y, "regular", size, COLOR_TEXT)
  }

  drawText(page, "Índice", MARGIN, y, "bold", 18, COLOR_TEXT)
  y -= 12
  drawLine(page, MARGIN, y, PAGE_WIDTH - MARGIN, y, COLOR_RULE)
  y -= 14

  for (const section of sectionPages) {
    line(section.title, bodyOffset + section.page + 1)
  }
  y -= 8

  drawText(page, "Hallazgos", MARGIN, y, "bold", 11, COLOR_TEXT)
  y -= 6
  document.findings.forEach((finding, index) => {
    const severity = SEVERITY_LABEL[finding.severity] ?? finding.severity.toUpperCase()
    line(`[${severity}] ${finding.title}`, bodyOffset + findingPages[index] + 1, { indent: 10, size: 9 })
  })

  pages.push(page)
  return { pages, firstPage: 0 }
}

// ── Cuerpo del informe ───────────────────────────────────────────────────────

interface BodyResult {
  pages: LaidPage[]
  /** Página (base 0, dentro del cuerpo) en la que arranca cada hallazgo. */
  findingPages: number[]
  sections: Array<{ title: string; page: number }>
}

function buildBody(document: ReportDocument): BodyResult {
  const builder = new PageBuilder()
  const { meta, summary, findings } = document
  const findingPages: number[] = []
  const sections: Array<{ title: string; page: number }> = []

  // ── Resumen ejecutivo ──
  builder.heading("Resumen ejecutivo")
  sections.push({ title: "Resumen ejecutivo", page: builder.pageIndex })

  builder.text(
    `La auditoría de seguridad ${meta.engagement ? `del engagement ${meta.engagement} ` : ""}identificó ${summary.totalFindings} hallazgos sobre ${summary.targets.length} objetivo(s) evaluados, con un riesgo global ${summary.globalRisk.toUpperCase()}.`,
    { size: 10.5 },
  )
  builder.space(8)

  const kpis: Array<[string, string, RGB]> = [
    ["Hallazgos", String(summary.totalFindings), COLOR_TEXT],
    ["Críticos", String(summary.counts.critical), COLOR_CRITICAL],
    ["Altos", String(summary.counts.high), COLOR_HIGH],
    ["Medios", String(summary.counts.medium), COLOR_MEDIUM],
    ["Bajos", String(summary.counts.low), COLOR_LOW],
    ["CVSS prom.", summary.averageCvss.toFixed(1), COLOR_ACCENT],
  ]
  const kpiWidth = CONTENT_WIDTH / kpis.length
  const kpiTop = builder.y - 12
  kpis.forEach(([label, value, color], index) => {
    const x = MARGIN + index * kpiWidth
    drawRect(builder.page, x + 3, kpiTop - 42, kpiWidth - 6, 46, COLOR_PANEL)
    drawText(builder.page, value, x + 10, kpiTop - 22, "bold", 17, color)
    drawText(builder.page, label.toUpperCase(), x + 10, kpiTop - 36, "bold", 7, COLOR_MUTED)
  })
  builder.y = kpiTop - 56

  // Distribución por severidad.
  builder.text("Distribución por severidad", { font: "bold", size: 9.5, color: COLOR_MUTED })
  builder.y -= 8
  const total = Math.max(summary.totalFindings, 1)
  let barX = MARGIN
  for (const severity of ["critical", "high", "medium", "low", "info"]) {
    const count = summary.counts[severity as keyof typeof summary.counts] ?? 0
    if (count === 0) continue
    const width = (count / total) * CONTENT_WIDTH
    drawRect(builder.page, barX, builder.y - 12, width, 12, severityColor(severity))
    barX += width
  }
  builder.y -= 22
  builder.text(
    `Críticos ${summary.counts.critical} · Altos ${summary.counts.high} · Medios ${summary.counts.medium} · Bajos ${summary.counts.low} · Info ${summary.counts.info}`,
    { size: 8.5, color: COLOR_MUTED },
  )

  // ── Objetivos evaluados ──
  builder.heading("Objetivos evaluados", { pageBreak: true })
  sections.push({ title: "Objetivos evaluados", page: builder.pageIndex })
  if (summary.targets.length === 0) {
    builder.text("No se registraron objetivos en esta auditoría.", { color: COLOR_MUTED })
  }
  for (const target of summary.targets) {
    builder.ensure(18)
    builder.y -= 15
    drawText(builder.page, target.url, MARGIN, builder.y, "mono", 9, COLOR_TEXT)
    const counts = `total ${target.total} · crit ${target.counts.critical} · alto ${target.counts.high} · medio ${target.counts.medium}`
    drawText(builder.page, counts, PAGE_WIDTH - MARGIN - 200, builder.y, "regular", 8.5, COLOR_MUTED)
  }

  // ── Detalle de hallazgos ──
  builder.heading("Detalle de hallazgos", { pageBreak: true })
  sections.push({ title: "Detalle de hallazgos", page: builder.pageIndex })
  if (findings.length === 0) {
    builder.text("No se identificaron hallazgos en esta auditoría.", { color: COLOR_MUTED })
  }

  findings.forEach((finding, index) => {
    findingPages.push(renderFinding(builder, finding, index))
  })

  // ── Emisión ──
  builder.heading("Control de emisión y aprobaciones", { pageBreak: true })
  sections.push({ title: "Control de emisión y aprobaciones", page: builder.pageIndex })
  builder.text(
    `Este informe ha sido generado por el motor de ciberseguridad ${meta.engine ?? "argos-security-operations"}${meta.engineVersion ? ` v${meta.engineVersion}` : ""} y validado automáticamente.`,
    { size: 10 },
  )
  builder.space(6)
  const approvals: Array<[string, string, string]> = [
    ["Auditor responsable", meta.leadAuditor, meta.generatedAt.toISOString()],
    ["Receptor de seguridad", meta.clientName, ""],
  ]
  if (meta.clientLegalName) approvals.push(["Razón social del receptor", meta.clientLegalName, ""])
  for (const [role, who, when] of approvals) {
    builder.ensure(18)
    builder.y -= 15
    drawText(builder.page, role, MARGIN, builder.y, "bold", 8.5, COLOR_MUTED)
    drawText(builder.page, who, MARGIN + 150, builder.y, "regular", 10, COLOR_TEXT)
    drawText(builder.page, when, MARGIN + 330, builder.y, "mono", 8.5, COLOR_MUTED)
  }

  return { pages: builder.pages, findingPages, sections }
}

function renderFinding(builder: PageBuilder, finding: ReportFinding, index: number): number {
  const color = severityColor(finding.severity)
  const severity = SEVERITY_LABEL[finding.severity] ?? finding.severity.toUpperCase()

  builder.ensure(110)
  builder.space(8)
  const startPage = builder.pageIndex

  const badgeWidth = measureText(severity, "bold", 8) + 12
  builder.y -= 13
  drawRect(builder.page, MARGIN, builder.y - 3, 3, 13, color)
  drawText(builder.page, finding.id, MARGIN + 10, builder.y, "mono", 8, COLOR_MUTED)
  builder.badge(severity, PAGE_WIDTH - MARGIN - badgeWidth, builder.y + 6, color)
  if (finding.cvssScore !== undefined) {
    drawText(
      builder.page,
      `CVSS ${finding.cvssScore.toFixed(1)}`,
      PAGE_WIDTH - MARGIN - badgeWidth - 62,
      builder.y + 1,
      "bold",
      8.5,
      COLOR_TEXT,
    )
  }

  builder.y -= 18
  for (const lineText of wrapText(`${index + 1}. ${finding.title}`, "bold", 12, CONTENT_WIDTH - 20)) {
    builder.ensure(18)
    builder.y -= 15
    drawText(builder.page, lineText, MARGIN + 10, builder.y, "bold", 12, COLOR_TEXT)
  }

  builder.y -= 4
  const metaLine = [
    finding.cwe,
    finding.target ? `objetivo ${finding.target}` : undefined,
    `estado ${finding.status}`,
    finding.feedback ? `triage ${finding.feedback.verdict} (${finding.feedback.actor})` : undefined,
    finding.sourceTool ? `origen ${finding.sourceTool}` : undefined,
  ]
    .filter(Boolean)
    .join("  ·  ")
  if (metaLine) {
    builder.ensure(14)
    builder.y -= 12
    drawText(builder.page, metaLine, MARGIN + 10, builder.y, "mono", 8, COLOR_MUTED)
  }

  if (finding.feedback?.reason) {
    builder.ensure(30)
    builder.y -= 5
    builder.text("Motivo del triage", { font: "bold", size: 8.5, color: COLOR_ACCENT })
    builder.paragraph(finding.feedback.reason, { size: 9, indent: 10 })
  }

  if (finding.cvssVector) {
    builder.ensure(14)
    builder.y -= 12
    drawText(builder.page, finding.cvssVector, MARGIN + 10, builder.y, "mono", 7.5, COLOR_MUTED)
  }

  if (finding.evidence) {
    builder.y -= 8
    builder.text("Evidencia técnica", { font: "bold", size: 8.5, color: COLOR_ACCENT })
    builder.paragraph(finding.evidence, { font: "mono", size: 7.5, indent: 10 })
  }

  if (finding.curlCommand) {
    builder.y -= 4
    builder.text("Reproducción (cURL)", { font: "bold", size: 8.5, color: COLOR_ACCENT })
    builder.paragraph(finding.curlCommand, { font: "mono", size: 7.5, indent: 10 })
  }

  if (finding.httpRequest) {
    builder.y -= 4
    builder.text("Petición HTTP", { font: "bold", size: 8.5, color: COLOR_ACCENT })
    builder.paragraph(finding.httpRequest, { font: "mono", size: 7.5, indent: 10 })
  }

  if (finding.httpResponse) {
    builder.y -= 4
    builder.text("Respuesta HTTP", { font: "bold", size: 8.5, color: COLOR_ACCENT })
    builder.paragraph(finding.httpResponse, { font: "mono", size: 7.5, indent: 10 })
  }

  if (finding.remediation) {
    builder.y -= 4
    builder.text("Remediación", { font: "bold", size: 8.5, color: COLOR_ACCENT })
    builder.paragraph(finding.remediation, { size: 9, indent: 10 })
  }

  builder.space(8)
  builder.rule()
  return startPage
}

// ── Pie de página ────────────────────────────────────────────────────────────

function drawFooters(pages: LaidPage[], document: ReportDocument, contentHash: string): void {
  const total = pages.length
  pages.forEach((page, index) => {
    const pageNumber = index + 1
    const left = `${document.meta.classification}  ·  sesión ${document.meta.sessionID}`
    const right = `Página ${pageNumber} de ${total}`
    const y = FOOTER_Y
    drawLine(page, MARGIN, y + 12, PAGE_WIDTH - MARGIN, y + 12, COLOR_RULE)
    drawText(page, left, MARGIN, y, "regular", 7, COLOR_MUTED)
    drawText(page, `sha256 ${contentHash}`, MARGIN, y - 9, "mono", 6, COLOR_MUTED)
    const rightWidth = measureText(right, "bold", 7)
    drawText(page, right, PAGE_WIDTH - MARGIN - rightWidth, y, "bold", 7, COLOR_MUTED)
  })
}

// ── Logo: decodificación PNG ────────────────────────────────────────────────

const PNG_SIGNATURE = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]

function decodeLogo(dataUrl: string | undefined): CoverImage | undefined {
  if (!dataUrl) return undefined
  const match = dataUrl.match(/^data:image\/png;base64,(.*)$/i)
  if (!match) return undefined
  try {
    return decodePng(Buffer.from(match[1], "base64"))
  } catch {
    // Un logo ilegible no puede tumbar el informe: la portada sigue sin logo.
    return undefined
  }
}

function decodePng(bytes: Buffer): CoverImage | undefined {
  for (let index = 0; index < PNG_SIGNATURE.length; index++) {
    if (bytes[index] !== PNG_SIGNATURE[index]) return undefined
  }
  let offset = 8
  let width = 0
  let height = 0
  let bitDepth = 0
  let colorType = 0
  let interlace = 0
  let palette: Buffer | undefined
  const idat: Buffer[] = []

  while (offset + 8 <= bytes.length) {
    const length = bytes.readUInt32BE(offset)
    const type = bytes.toString("ascii", offset + 4, offset + 8)
    const dataStart = offset + 8
    const dataEnd = dataStart + length
    if (dataEnd > bytes.length) break
    if (type === "IHDR") {
      width = bytes.readUInt32BE(dataStart)
      height = bytes.readUInt32BE(dataStart + 4)
      bitDepth = bytes[dataStart + 8]!
      colorType = bytes[dataStart + 9]!
      interlace = bytes[dataStart + 12]!
    } else if (type === "PLTE") {
      palette = bytes.subarray(dataStart, dataEnd)
    } else if (type === "IDAT") {
      idat.push(bytes.subarray(dataStart, dataEnd))
    } else if (type === "IEND") {
      break
    }
    offset = dataEnd + 4
  }

  if (!width || !height) return undefined
  if (bitDepth !== 8) return undefined
  if (interlace !== 0) return undefined

  const channels =
    colorType === 0 ? 1 : colorType === 2 ? 3 : colorType === 3 ? 1 : colorType === 4 ? 2 : colorType === 6 ? 4 : 0
  if (!channels) return undefined

  const raw = inflateSync(Buffer.concat(idat))
  const stride = width * channels
  const pixels = unfilter(raw, width, height, channels, stride)
  if (!pixels) return undefined

  const rgb = new Uint8Array(width * height * 3)
  const alpha = colorType === 4 || colorType === 6 ? new Uint8Array(width * height) : undefined

  for (let index = 0; index < width * height; index++) {
    const source = index * channels
    if (colorType === 0) {
      const value = pixels[source]
      rgb[index * 3] = value
      rgb[index * 3 + 1] = value
      rgb[index * 3 + 2] = value
    } else if (colorType === 2) {
      rgb[index * 3] = pixels[source]!
      rgb[index * 3 + 1] = pixels[source + 1]!
      rgb[index * 3 + 2] = pixels[source + 2]!
    } else if (colorType === 3) {
      const paletteIndex = pixels[source]
      const base = paletteIndex * 3
      rgb[index * 3] = palette?.[base] ?? 0
      rgb[index * 3 + 1] = palette?.[base + 1] ?? 0
      rgb[index * 3 + 2] = palette?.[base + 2] ?? 0
    } else if (colorType === 4) {
      const value = pixels[source]
      rgb[index * 3] = value
      rgb[index * 3 + 1] = value
      rgb[index * 3 + 2] = value
      if (alpha) alpha[index] = pixels[source + 1]
    } else {
      rgb[index * 3] = pixels[source]!
      rgb[index * 3 + 1] = pixels[source + 1]!
      rgb[index * 3 + 2] = pixels[source + 2]!
      if (alpha) alpha[index] = pixels[source + 3]!
    }
  }

  return { width, height, rgb, alpha }
}

/** Deshace los filtros de línea de PNG (None/Sub/Up/Average/Paeth). */
function unfilter(
  raw: Buffer,
  width: number,
  height: number,
  channels: number,
  stride: number,
): Uint8Array | undefined {
  const out = new Uint8Array(stride * height)
  let position = 0
  for (let row = 0; row < height; row++) {
    const filter = raw[position]
    if (filter === undefined) return undefined
    position++
    const rowStart = row * stride
    const previousStart = rowStart - stride
    for (let index = 0; index < stride; index++) {
      const value = raw[position + index]
      if (value === undefined) return undefined
      const left = index >= channels ? out[rowStart + index - channels] : 0
      const up = row > 0 ? out[previousStart + index] : 0
      const upLeft = row > 0 && index >= channels ? out[previousStart + index - channels] : 0
      let result: number
      switch (filter) {
        case 0:
          result = value
          break
        case 1:
          result = value + left
          break
        case 2:
          result = value + up
          break
        case 3:
          result = value + ((left + up) >> 1)
          break
        case 4:
          result = value + paeth(left, up, upLeft)
          break
        default:
          return undefined
      }
      out[rowStart + index] = result & 0xff
    }
    position += stride
  }
  return out
}

function paeth(a: number, b: number, c: number): number {
  const p = a + b - c
  const pa = Math.abs(p - a)
  const pb = Math.abs(p - b)
  const pc = Math.abs(p - c)
  if (pa <= pb && pa <= pc) return a
  if (pb <= pc) return b
  return c
}

// ── Serialización del PDF ────────────────────────────────────────────────────

class PdfWriter {
  private chunks: Uint8Array[] = []
  private length = 0

  push(data: Uint8Array | string): void {
    const bytes = typeof data === "string" ? new TextEncoder().encode(data) : data
    this.chunks.push(bytes)
    this.length += bytes.length
  }

  get offset(): number {
    return this.length
  }

  toBytes(): Uint8Array {
    const out = new Uint8Array(this.length)
    let cursor = 0
    for (const chunk of this.chunks) {
      out.set(chunk, cursor)
      cursor += chunk.length
    }
    return out
  }
}

interface PdfObject {
  /** Diccionario completo del objeto (sin `/Length`). */
  dict: string
  /** Contenido binario del stream, si el objeto es un stream. */
  stream?: Uint8Array
}

function buildXmp(metadata: PdfMetadata): Uint8Array {
  const title = xmlEscape(metadata.title)
  const author = xmlEscape(metadata.author)
  const subject = xmlEscape(metadata.subject)
  const description = xmlEscape(metadata.description)
  const keywords = xmlEscape(metadata.keywords.join(", "))
  const created = metadata.createdAt.toISOString().replace(/\.\d{3}Z$/, "Z")
  const xml = `<?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?>
<x:xmpmeta xmlns:x="adobe:ns:meta/" x:xmptk="argos-security-operations">
  <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
    <rdf:Description rdf:about="" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:pdf="http://ns.adobe.com/pdf/1.3/" xmlns:xmp="http://ns.adobe.com/xap/1.0/">
      <dc:title><rdf:Alt><rdf:li xml:lang="x-default">${title}</rdf:li></rdf:Alt></dc:title>
      <dc:creator><rdf:Seq><rdf:li>${author}</rdf:li></rdf:Seq></dc:creator>
      <dc:subject><rdf:Bag><rdf:li>${subject}</rdf:li></rdf:Bag></dc:subject>
      <dc:description><rdf:Alt><rdf:li xml:lang="x-default">${description}</rdf:li></rdf:Alt></dc:description>
      <pdf:Keywords>${keywords}</pdf:Keywords>
      <xmp:CreateDate>${created}</xmp:CreateDate>
      <xmp:ModifyDate>${created}</xmp:ModifyDate>
      <xmp:CreatorTool>${xmlEscape(metadata.creator)}</xmp:CreatorTool>
      <pdf:Producer>${xmlEscape(metadata.producer)}</pdf:Producer>
    </rdf:Description>
  </rdf:RDF>
</x:xmpmeta>
<?xpacket end="w"?>`
  return new TextEncoder().encode(xml)
}

function xmlEscape(value: string): string {
  return value.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;")
}

interface OutlineItem {
  title: string
  page: number
  children: OutlineItem[]
}

function countOutlineItems(items: OutlineItem[]): number {
  let total = 0
  for (const item of items) total += 1 + countOutlineItems(item.children)
  return total
}

/** Asigna un número de objeto a cada marcador, en orden de aparición. */
function assignOutlineNumbers(
  items: OutlineItem[],
  start: number,
): { numbers: Map<OutlineItem, number>; next: number } {
  const numbers = new Map<OutlineItem, number>()
  let current = start
  const walk = (list: OutlineItem[]) => {
    for (const item of list) {
      numbers.set(item, current++)
      walk(item.children)
    }
  }
  walk(items)
  return { numbers, next: current }
}

/** Escribe el PDF completo y devuelve los bytes. */
function serializePdf(
  pages: LaidPage[],
  metadata: PdfMetadata,
  contentHash: string,
  logo: CoverImage | undefined,
  outline: OutlineItem[],
): Uint8Array {
  const objects: PdfObject[] = []

  const catalogNumber = 1
  const pagesNumber = 2
  const fontRegular = 3
  const fontBold = 4
  const fontMono = 5
  const infoNumber = 6
  const metadataNumber = 7
  const outlinesNumber = 8

  const { numbers: outlineNumbers, next: afterOutline } = assignOutlineNumbers(outline, 9)

  let nextNumber = afterOutline
  const pageNumbers: number[] = []
  const contentNumbers: number[] = []
  for (let index = 0; index < pages.length; index++) {
    pageNumbers.push(nextNumber++)
    contentNumbers.push(nextNumber++)
  }
  const logoNumber = logo ? nextNumber++ : undefined
  const logoMaskNumber = logo?.alpha ? nextNumber++ : undefined

  const set = (number: number, object: PdfObject) => {
    objects[number - 1] = object
  }

  set(fontRegular, { dict: "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>" })
  set(fontBold, { dict: "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>" })
  set(fontMono, { dict: "<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>" })
  set(infoNumber, {
    dict:
      `<< /Title (${escapePdfString(metadata.title)}) /Author (${escapePdfString(metadata.author)}) ` +
      `/Subject (${escapePdfString(metadata.subject)}) /Keywords (${escapePdfString(metadata.keywords.join(", "))}) ` +
      `/Creator (${escapePdfString(metadata.creator)}) /Producer (${escapePdfString(metadata.producer)}) ` +
      `/CreationDate (${toPdfDate(metadata.createdAt)}) /ModDate (${toPdfDate(metadata.createdAt)}) >>`,
  })
  set(metadataNumber, {
    dict: "/Type /Metadata /Subtype /XML",
    stream: buildXmp(metadata),
  })

  // Marcadores (outlines).
  const outlineItems = flattenOutline(outline)
  if (outlineItems.length === 0) {
    set(outlinesNumber, { dict: "<< /Type /Outlines /Count 0 >>" })
  } else {
    for (const { item, parent } of outlineItems) {
      const number = outlineNumbers.get(item)!
      const siblings = outlineItems.filter((candidate) => candidate.parent === parent)
      const index = siblings.findIndex((candidate) => candidate.item === item)
      const parentNumber = parent ? outlineNumbers.get(parent)! : outlinesNumber
      const previous = index > 0 ? outlineNumbers.get(siblings[index - 1].item)! : undefined
      const next = index < siblings.length - 1 ? outlineNumbers.get(siblings[index + 1].item)! : undefined
      const page = pageNumbers[Math.min(item.page, pageNumbers.length - 1)]
      const children = item.children.length
        ? ` /First ${outlineNumbers.get(item.children[0])!} 0 R /Last ${outlineNumbers.get(item.children[item.children.length - 1])!} 0 R /Count ${countOutlineItems(item.children)}`
        : ""
      set(number, {
        dict:
          `<< /Title (${escapePdfString(item.title)}) /Parent ${parentNumber} 0 R` +
          `${previous ? ` /Prev ${previous} 0 R` : ""}${next ? ` /Next ${next} 0 R` : ""}` +
          ` /Dest [${page} 0 R /XYZ 0 ${TOP_Y} 0]${children} >>`,
      })
    }
    set(outlinesNumber, {
      dict: `<< /Type /Outlines /First ${outlineNumbers.get(outlineItems[0].item)!} 0 R /Last ${outlineNumbers.get(outlineItems[outlineItems.length - 1].item)!} 0 R /Count ${outline.length} >>`,
    })
  }

  // Páginas y sus streams de contenido.
  const kids: string[] = []
  pages.forEach((page, index) => {
    const pageNumber = pageNumbers[index]
    const contentNumber = contentNumbers[index]
    const resources = logoNumber
      ? `/Font << /F1 ${fontRegular} 0 R /F2 ${fontBold} 0 R /F3 ${fontMono} 0 R >> /XObject << /Logo ${logoNumber} 0 R${logoMaskNumber ? ` /LogoMask ${logoMaskNumber} 0 R` : ""} >>`
      : `/Font << /F1 ${fontRegular} 0 R /F2 ${fontBold} 0 R /F3 ${fontMono} 0 R >>`
    set(pageNumber, {
      dict: `<< /Type /Page /Parent ${pagesNumber} 0 R /MediaBox [0 0 ${PAGE_WIDTH} ${PAGE_HEIGHT}] /Resources << ${resources} >> /Contents ${contentNumber} 0 R >>`,
    })
    kids.push(`${pageNumber} 0 R`)
    set(contentNumber, { dict: "", stream: new TextEncoder().encode(page.ops.join("\n")) })
  })

  set(pagesNumber, { dict: `<< /Type /Pages /Kids [${kids.join(" ")}] /Count ${pages.length} >>` })

  // Logo del cliente.
  if (logo && logoNumber) {
    set(logoNumber, {
      dict: `/Type /XObject /Subtype /Image /Width ${logo.width} /Height ${logo.height} /ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /FlateDecode`,
      stream: deflateSync(logo.rgb, { level: 9 }),
    })
    if (logo.alpha && logoMaskNumber) {
      set(logoMaskNumber, {
        dict: `/Type /XObject /Subtype /Image /Width ${logo.width} /Height ${logo.height} /ColorSpace /DeviceGray /BitsPerComponent 8 /Filter /FlateDecode`,
        stream: deflateSync(logo.alpha, { level: 9 }),
      })
    }
  }

  const outlineRef = outlineItems.length > 0 ? ` /Outlines ${outlinesNumber} 0 R /PageMode /UseOutlines` : ""
  set(catalogNumber, {
    dict: `<< /Type /Catalog /Pages ${pagesNumber} 0 R /Metadata ${metadataNumber} 0 R${outlineRef} /Lang (es) >>`,
  })

  // Serialización binaria.
  const writer = new PdfWriter()
  writer.push("%PDF-1.7\n")
  writer.push(new Uint8Array([0x25, 0xe2, 0xe3, 0xcf, 0xd3, 0x0a]))

  const offsets: number[] = []
  for (let index = 0; index < objects.length; index++) {
    const object = objects[index]
    if (!object) continue
    offsets.push(writer.offset)
    writer.push(`${index + 1} 0 obj\n`)
    if (object.stream) {
      writer.push(`<< ${object.dict} /Length ${object.stream.length} >>\nstream\n`)
      writer.push(object.stream)
      writer.push("\nendstream\n")
    } else {
      writer.push(object.dict)
      writer.push("\n")
    }
    writer.push("endobj\n")
  }

  const xrefOffset = writer.offset
  writer.push(`xref\n0 ${objects.length + 1}\n`)
  writer.push("0000000000 65535 f \n")
  for (const offset of offsets) writer.push(`${offset.toString().padStart(10, "0")} 00000 n \n`)

  const id = contentHash.slice(0, 32).toUpperCase()
  writer.push(
    `trailer\n<< /Size ${objects.length + 1} /Root ${catalogNumber} 0 R /Info ${infoNumber} 0 R /ID [<${id}> <${id}>] >>\nstartxref\n${xrefOffset}\n%%EOF\n`,
  )

  return writer.toBytes()
}

interface FlatOutlineItem {
  item: OutlineItem
  parent?: OutlineItem
}

function flattenOutline(items: OutlineItem[], parent?: OutlineItem): FlatOutlineItem[] {
  const out: FlatOutlineItem[] = []
  for (const item of items) {
    out.push({ item, parent })
    out.push(...flattenOutline(item.children, item))
  }
  return out
}

// ── API pública ──────────────────────────────────────────────────────────────

/** Renderer por defecto: el writer determinista de este módulo. */
export const builtinPdfRenderer: PdfRenderer = {
  name: "argos-builtin",
  async render(input: PdfRenderInput): Promise<Uint8Array> {
    return renderBuiltinPdf(input)
  },
}

export function renderBuiltinPdf(input: PdfRenderInput): Uint8Array {
  const { document, metadata, contentHash } = input

  const coverBuilder = new PageBuilder()
  const logo = buildCover(coverBuilder, document, contentHash)
  const coverPages = coverBuilder.pages

  const body = buildBody(document)

  // El índice conoce los números de página del cuerpo, y el número de hojas
  // del índice shift esos números: se itera hasta que converge (en la
  // práctica una sola pasada).
  let tocPages = buildToc(document, body.findingPages, coverPages.length + 1, body.sections).pages
  for (let attempt = 0; attempt < 3; attempt++) {
    const next = buildToc(document, body.findingPages, coverPages.length + tocPages.length, body.sections).pages
    if (next.length === tocPages.length) {
      tocPages = next
      break
    }
    tocPages = next
  }

  const pages = [...coverPages, ...tocPages, ...body.pages]
  drawFooters(pages, document, contentHash)

  const bodyOffset = coverPages.length + tocPages.length
  const detailSection = body.sections.find((section) => section.title === "Detalle de hallazgos")
  const outline: OutlineItem[] = [
    {
      title: metadata.title,
      page: 0,
      children: [
        { title: "Índice", page: coverPages.length, children: [] },
        ...body.sections.map((section) => ({
          title: section.title,
          page: bodyOffset + section.page,
          children:
            section.title === "Detalle de hallazgos" && detailSection
              ? document.findings.map((finding, index) => ({
                  title: `${SEVERITY_LABEL[finding.severity] ?? finding.severity.toUpperCase()} — ${finding.title}`,
                  page: bodyOffset + body.findingPages[index],
                  children: [] as OutlineItem[],
                }))
              : ([] as OutlineItem[]),
        })),
      ],
    },
  ]

  return serializePdf(pages, metadata, contentHash, logo, outline)
}

/**
 * Renderiza el informe de auditoría a PDF.
 *
 * `opts.renderer` permite inyectar un renderer alternativo (por ejemplo uno
 * basado en navegador) sin tocar el resto del pipeline: todo lo que se testea
 * —metadata, portada, índice, hash— vive fuera del writer.
 */
export async function renderReportPdf(
  document: ReportDocument,
  opts?: { renderer?: PdfRenderer; metadata?: Partial<PdfMetadata> },
): Promise<PdfArtifact> {
  const metadata: PdfMetadata = { ...buildPdfMetadata(document), ...opts?.metadata }
  const contentHash = reportContentHash(document)
  const html = exportHtml(document)
  const renderer = opts?.renderer ?? builtinPdfRenderer
  const bytes = await renderer.render({ document, metadata, html, contentHash })
  return {
    bytes,
    sha256: createHash("sha256").update(bytes).digest("hex"),
    contentHash,
    pageCount: countPages(bytes),
    metadata,
  }
}

/** Cuenta las páginas leyendo el árbol `/Type /Page` del PDF generado. */
function countPages(bytes: Uint8Array): number {
  const text = Buffer.from(bytes).toString("latin1")
  const matches = text.match(/\/Type\s*\/Page(?![s])/g)
  return matches ? matches.length : 0
}
