/**
 * Tests del PDF nativo del informe (ARG-043).
 *
 * El render server-side es inyectable (`opts.renderer`), así que el pipeline
 * se puede testear con un stub; pero el writer por defecto es viable en el
 * entorno de test, y estos tests lo usan para verificar de punta a punta lo
 * que el entregable firmado tiene que cumplir: metadata leíble del archivo,
 * portada, índice con números de página y hash verificable.
 */

import { describe, expect, test } from "bun:test"
import { createHash } from "node:crypto"
import { buildReport, reportContentHash, type ReportDocument, type ReportFinding } from "../src/security/export"
import { buildPdfMetadata, renderReportPdf, type PdfRenderer } from "../src/security/pdf"

const FIXED_DATE = new Date(Date.UTC(2024, 4, 17, 9, 30, 0))

const findings: ReportFinding[] = [
  {
    id: "finding-1",
    title: "SQL injection through the request parameter",
    severity: "critical",
    status: "open",
    cwe: "CWE-89",
    owasp: ["A03:2021"],
    target: "https://app.example.com/api/items",
    evidence: "SELECT * FROM items WHERE id = '1' OR 1=1 --'",
    remediation: "Use parameterized queries",
    curlCommand: "curl -s 'https://app.example.com/api/items?id=1'",
    cvssScore: 9.8,
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    sourceTool: "web.scan",
    detectedAt: Date.UTC(2024, 4, 16, 8, 0, 0),
  },
  {
    id: "finding-2",
    title: "Missing security headers",
    severity: "low",
    status: "open",
    target: "https://app.example.com",
    evidence: "No Content-Security-Policy header present",
    remediation: "Add a Content-Security-Policy header",
    cvssScore: 3.1,
    detectedAt: Date.UTC(2024, 4, 16, 8, 5, 0),
  },
]

const document: ReportDocument = buildReport({
  meta: {
    title: "Informe Ejecutivo de Auditoría de Seguridad",
    clientName: "Banco Ejemplo",
    clientLegalName: "Banco Ejemplo S.A.",
    scope: "Auditoría app.example.com",
    classification: "CONFIDENCIAL — TLP:AMBER",
    leadAuditor: "Ana Auditora",
    methodology: "OWASP Testing Guide v4.2",
    sessionID: "ses_123",
    engagement: "eng-2024-05",
    target: "app.example.com",
    generatedAt: FIXED_DATE,
    engine: "argos-security-operations",
    engineVersion: "1.0.0",
  },
  findings,
})

/** Los bytes 0x80..0x9F de WinAnsi no son los de Latin-1. */
const WINANSI_HIGH: Record<number, string> = {
  0x80: "€",
  0x82: "‚",
  0x83: "ƒ",
  0x84: "„",
  0x85: "…",
  0x86: "†",
  0x87: "‡",
  0x88: "ˆ",
  0x89: "‰",
  0x8a: "Š",
  0x8b: "‹",
  0x8c: "Œ",
  0x8e: "Ž",
  0x91: "‘",
  0x92: "’",
  0x93: "“",
  0x94: "”",
  0x95: "•",
  0x96: "–",
  0x97: "—",
  0x98: "˜",
  0x99: "™",
  0x9a: "š",
  0x9b: "›",
  0x9c: "œ",
  0x9e: "ž",
  0x9f: "Ÿ",
}

/** Convierte una cadena de bytes WinAnsi a texto Unicode. */
function winAnsiToUnicode(value: string): string {
  let out = ""
  for (const char of value) {
    const code = char.charCodeAt(0)
    out += WINANSI_HIGH[code] ?? char
  }
  return out
}

/** Decodifica una cadena literal de PDF (escapes octales y de paréntesis). */
function decodePdfString(raw: string): string {
  let out = ""
  for (let index = 0; index < raw.length; index++) {
    const char = raw[index]
    if (char !== "\\") {
      out += char
      continue
    }
    const next = raw[index + 1]
    if (next === undefined) break
    if (/[0-7]/.test(next)) {
      const octal = raw.slice(index + 1, index + 4)
      const match = octal.match(/^[0-7]{1,3}/)
      if (match) {
        out += String.fromCharCode(Number.parseInt(match[0], 8))
        index += match[0].length
        continue
      }
    }
    out += next === "n" ? "\n" : next === "r" ? "\r" : next === "t" ? "\t" : next
    index++
  }
  return winAnsiToUnicode(out)
}

/** Decodifica todos los escapes de cadena del PDF (para buscar texto plano). */
function decodePdfEscapes(text: string): string {
  return winAnsiToUnicode(
    text.replace(/\\([0-7]{1,3})/g, (_match, octal: string) => String.fromCharCode(Number.parseInt(octal, 8))),
  )
}

function pdfText(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("latin1")
}

function infoEntry(text: string, key: string): string | undefined {
  const match = text.match(new RegExp(`/${key}\\s*\\(((?:[^()\\\\]|\\\\.)*)\\)`))
  return match ? decodePdfString(match[1]) : undefined
}

function xmpValue(text: string, tag: string): string | undefined {
  const match = text.match(new RegExp(`<${tag}>([\\s\\S]*?)</${tag}>`))
  if (!match) return undefined
  return new TextDecoder()
    .decode(Buffer.from(match[1], "latin1"))
    .replace(/<[^>]+>/g, "")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .trim()
}

describe("pdf — render server-side", () => {
  test("genera un PDF utilizable con la metadata del informe", async () => {
    const artifact = await renderReportPdf(document)

    expect(artifact.bytes.length).toBeGreaterThan(1024)
    expect(artifact.pageCount).toBeGreaterThan(1)
    expect(artifact.sha256).toBe(createHash("sha256").update(artifact.bytes).digest("hex"))
    expect(artifact.contentHash).toBe(reportContentHash(document))

    const text = pdfText(artifact.bytes)
    expect(text.startsWith("%PDF-1.7")).toBe(true)
    expect(text.trimEnd().endsWith("%%EOF")).toBe(true)

    // Metadata del diccionario Info.
    expect(infoEntry(text, "Title")).toBe("Informe Ejecutivo de Auditoría de Seguridad")
    expect(infoEntry(text, "Author")).toBe("Ana Auditora")
    expect(infoEntry(text, "Subject")).toBe("CONFIDENCIAL — TLP:AMBER")
    expect(infoEntry(text, "Creator")).toBe("Ana Auditora")
    expect(infoEntry(text, "Producer")).toBe("argos-security-operations 1.0.0")
    expect(infoEntry(text, "CreationDate")).toBe("D:20240517093000Z")
    expect(infoEntry(text, "Keywords")).toContain("session:ses_123")
    expect(infoEntry(text, "Keywords")).toContain("target:app.example.com")
    expect(infoEntry(text, "Keywords")).toContain("eng-2024-05")

    // Metadata XMP (dc:*, pdf:Keywords, xmp:CreateDate).
    expect(xmpValue(text, "dc:title")).toBe("Informe Ejecutivo de Auditoría de Seguridad")
    expect(xmpValue(text, "dc:creator")).toBe("Ana Auditora")
    expect(xmpValue(text, "dc:subject")).toBe("CONFIDENCIAL — TLP:AMBER")
    expect(xmpValue(text, "dc:description")).toContain("Banco Ejemplo S.A.")
    expect(xmpValue(text, "pdf:Keywords")).toContain("session:ses_123")
    expect(xmpValue(text, "xmp:CreateDate")).toBe("2024-05-17T09:30:00Z")
  })

  test("la portada lleva los datos del cliente y el hash del contenido", async () => {
    const artifact = await renderReportPdf(document)
    const text = decodePdfEscapes(pdfText(artifact.bytes))

    expect(text).toContain("Banco Ejemplo")
    expect(text).toContain("Banco Ejemplo S.A.")
    expect(text).toContain("CONFIDENCIAL")
    expect(text).toContain("Ana Auditora")
    expect(text).toContain("ses_123")
    // El hash del contenido va impreso en la portada y en el pie de cada página.
    expect(text).toContain(reportContentHash(document))
  })

  test("el índice lista los hallazgos con su severidad y su número de página", async () => {
    const artifact = await renderReportPdf(document)
    const text = decodePdfEscapes(pdfText(artifact.bytes))

    expect(text).toContain("SQL injection")
    expect(text).toContain("CRÍTICO")
    expect(text).toContain("BAJO")
    expect(text).toContain("Índice")
    // La numeración de páginas viaja en el pie.
    expect(text).toContain("Página 1 de")
  })

  test("el mismo informe con la misma fecha produce el mismo archivo", async () => {
    const first = await renderReportPdf(document)
    const second = await renderReportPdf(document)
    expect(first.sha256).toBe(second.sha256)
    expect(Buffer.from(first.bytes).equals(Buffer.from(second.bytes))).toBe(true)
  })

  test("un cambio en los hallazgos cambia el hash del contenido", async () => {
    const mutated = buildReport({
      meta: document.meta,
      findings: [...findings, { id: "finding-3", title: "Nuevo hallazgo", severity: "medium", status: "open" }],
    })
    const artifact = await renderReportPdf(mutated)
    expect(artifact.contentHash).not.toBe(reportContentHash(document))
  })

  test("el renderer es inyectable: un stub reemplaza al writer por defecto", async () => {
    let received: { title: string; contentHash: string; html: string } | undefined
    const stub: PdfRenderer = {
      name: "stub",
      async render(input) {
        received = { title: input.metadata.title, contentHash: input.contentHash, html: input.html }
        return new Uint8Array([0x25, 0x50, 0x44, 0x46, 0x2d, 0x31, 0x2e, 0x37])
      },
    }

    const artifact = await renderReportPdf(document, { renderer: stub })

    expect(artifact.bytes.length).toBe(8)
    expect(artifact.sha256).toBe(createHash("sha256").update(artifact.bytes).digest("hex"))
    expect(artifact.contentHash).toBe(reportContentHash(document))
    expect(received?.title).toBe("Informe Ejecutivo de Auditoría de Seguridad")
    expect(received?.contentHash).toBe(reportContentHash(document))
    expect(received?.html).toContain("<!DOCTYPE html>")
  })

  test("la metadata se puede sobreescribir sin tocar el resto del pipeline", async () => {
    const metadata = buildPdfMetadata(document)
    expect(metadata.title).toBe(document.meta.title)
    expect(metadata.author).toBe(document.meta.leadAuditor)
    expect(metadata.subject).toBe(document.meta.classification)
    expect(metadata.keywords).toContain("session:ses_123")
    expect(metadata.keywords).toContain("target:app.example.com")
    expect(metadata.createdAt).toEqual(FIXED_DATE)
  })
})
