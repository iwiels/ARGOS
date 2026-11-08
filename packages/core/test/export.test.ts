/**
 * Tests de los exportadores profesionales (ARG-044).
 *
 * ── Alcance de la validación de schema ──────────────────────────────────────
 * - SARIF 2.1.0 → contra el JSON Schema oficial de OASIS, vendorizado en
 *   `test/fixtures/schema/sarif-schema-2.1.0.json`.
 * - CycloneDX 1.5 → contra el JSON Schema oficial de CycloneDX, vendorizado en
 *   `test/fixtures/schema/bom-1.5.schema.json`.
 * - JUnit XML → contra las reglas estructurales del `junit.xsd` de Jenkins
 *   (elementos obligatorios, orden de la `sequence` y tipos). El XSD completo
 *   no se vendoriza: requiere un validador XSD (xmllint) que no está en el
 *   toolchain del repo.
 * - DefectDojo → contra el formato de importación documentado (los campos que
 *   el importador `Findings` lee con `.get()` y sus defaults).
 * - HTML → contra la regla estructural del formato: un solo archivo, sin
 *   assets externos.
 */

import { describe, expect, test } from "bun:test"
import { readFileSync } from "node:fs"
import { join } from "node:path"
import { Effect } from "effect"
import { Database } from "@argos/core/database/database"
import { Project } from "@argos/core/project"
import { ProjectTable } from "@argos/core/project/sql"
import { SessionV2 } from "@argos/core/session"
import { SessionTable } from "@argos/core/session/sql"
import { AbsolutePath } from "@argos/core/schema"
import { FindingTable } from "@argos/core/security/sql"
import { recordFeedback } from "../src/security/finding-feedback"
import {
  buildReport,
  exportAll,
  exportCsv,
  exportDefectDojo,
  exportDocument,
  exportHar,
  exportHtml,
  exportJunit,
  exportMarkdown,
  exportSarif,
  exportSbom,
  exportSessions,
  loadReportDocument,
  reportContentHash,
  type ReportDocument,
  type ReportFinding,
} from "../src/security/export"
import { testEffect } from "./lib/effect"
import { validateAgainstSchema } from "./lib/json-schema"

const SCHEMA_DIR = join(import.meta.dir, "fixtures", "schema")

const sarifSchema = JSON.parse(readFileSync(join(SCHEMA_DIR, "sarif-schema-2.1.0.json"), "utf8"))
const cycloneDxSchema = JSON.parse(readFileSync(join(SCHEMA_DIR, "bom-1.5.schema.json"), "utf8"))

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
    vector: "app/handler.py:42",
    evidence: "SELECT * FROM items WHERE id = '1' OR 1=1 --'",
    remediation: "Use parameterized queries",
    httpRequest: "GET /api/items?id=1 HTTP/1.1\nHost: app.example.com",
    httpResponse: "HTTP/1.1 200 OK\nContent-Type: application/json",
    curlCommand: "curl -s 'https://app.example.com/api/items?id=1'",
    tags: ["sqli", "owasp"],
    references: ["https://owasp.org/Top10/A03_2021/"],
    attackTechniqueIds: ["T1190"],
    sourceTool: "web.scan",
    fingerprint: "cwe-89|app/handler.py:42",
    cvssScore: 9.8,
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    epssScore: 0.42,
    cisaKev: true,
    detectedAt: Date.UTC(2024, 4, 16, 8, 0, 0),
    dataflow: [
      { file: "app/handler.py", line: 42, message: "Source: request.args", snippet: "value = request.args['id']" },
      { file: "app/handler.py", line: 45, message: "Sink: cursor.execute(query)" },
    ],
    partialFingerprints: { "matchBasedId/v1": "9f2b1c8d4e7a6b5c" },
  },
  {
    id: "finding-2",
    title: "Missing security headers",
    severity: "low",
    status: "false-positive",
    target: "https://app.example.com",
    evidence: "No Content-Security-Policy header present",
    remediation: "Add a Content-Security-Policy header",
    sourceTool: "web.scan",
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

describe("export — SARIF 2.1.0", () => {
  test("valida contra el JSON Schema oficial de OASIS", () => {
    const document_ = JSON.parse(exportSarif(document))
    const violations = validateAgainstSchema(document_, sarifSchema)
    expect(violations.map((violation) => `${violation.path}: ${violation.message}`)).toEqual([])
  })

  test("lleva la versión, el schema y las taxonomías del hallazgo", () => {
    const log = JSON.parse(exportSarif(document))
    expect(log.version).toBe("2.1.0")
    expect(log.$schema).toContain("sarif-schema-2.1.0.json")
    expect(log.runs).toHaveLength(1)
    expect(log.runs[0].tool.driver.name).toBe("Argos Security Operations Engine")

    const result = log.runs[0].results[0]
    expect(result.ruleId).toBe("ARGOS-CWE-89")
    expect(result.level).toBe("error")
    expect(result.partialFingerprints["argos/v1"]).toBe("cwe-89|app/handler.py:42")
    expect(result.partialFingerprints["matchBasedId/v1"]).toBe("9f2b1c8d4e7a6b5c")
    expect(result.taxa.map((taxon: { id: string }) => taxon.id)).toEqual(["CWE-89", "A03:2021"])
    expect(result.codeFlows[0].threadFlows[0].locations).toHaveLength(2)
    expect(result.properties.cwe).toEqual(["CWE-89"])
  })
})

describe("export — DefectDojo", () => {
  test("cumple el formato de importación documentado", () => {
    const payload = JSON.parse(exportDefectDojo(document))
    expect(Array.isArray(payload)).toBe(true)
    expect(payload).toHaveLength(2)

    const first = payload[0]
    expect(first.title).toBe("SQL injection through the request parameter")
    expect(first.severity).toBe("Critical")
    expect(first.cwe).toBe(89)
    expect(first.date).toBe("2024-05-16")
    expect(first.tags).toContain("sqli")
    expect(first.endpoints).toEqual(["https://app.example.com/api/items"])
    expect(first.hash).toBe(reportContentHash(document))
    expect(first.description).toContain("SELECT * FROM items")
    expect(first.description).toContain("Reproducción (cURL)")
    expect(first.active).toBe(true)
    expect(first.verified).toBe(false)
    expect(first.unique_id_from_tool).toBe("finding-1")

    // El importador de DefectDojo acepta los campos del modelo `Finding`.
    for (const finding of payload) {
      for (const key of [
        "title",
        "description",
        "severity",
        "cwe",
        "date",
        "active",
        "verified",
        "references",
        "tags",
      ]) {
        expect(finding).toHaveProperty(key)
      }
      expect(["Critical", "High", "Medium", "Low", "Info"]).toContain(finding.severity)
      expect(Number.isInteger(finding.cwe)).toBe(true)
      expect(finding.date).toMatch(/^\d{4}-\d{2}-\d{2}$/)
    }
  })
})

describe("export — JUnit XML", () => {
  test("respeta la estructura del junit.xsd", () => {
    const xml = exportJunit(document)
    expect(xml.startsWith('<?xml version="1.0" encoding="UTF-8"?>')).toBe(true)
    expect(xml).toContain(`<testsuites name="Argos Security Operations" tests="2" failures="1"`)
    expect(xml).toContain(`<testsuite name="eng-2024-05"`)
    expect(xml).toContain("<properties>")
    expect(xml).toContain("<testcase ")
    expect(xml).toContain("<failure ")
    expect(xml).toContain("<skipped ")

    // La `sequence` del xsd: properties → testcase* → system-out.
    const propertiesIndex = xml.indexOf("<properties>")
    const testcaseIndex = xml.indexOf("<testcase ")
    const systemOutIndex = xml.indexOf("<system-out>")
    expect(propertiesIndex).toBeGreaterThan(-1)
    expect(testcaseIndex).toBeGreaterThan(propertiesIndex)
    expect(systemOutIndex).toBeGreaterThan(testcaseIndex)
  })

  test("el hallazgo vigente es un failure y el descartado un skipped", () => {
    const xml = exportJunit(document)
    expect(xml).toContain('type="critical"')
    expect(xml).toContain('message="false-positive"')
    expect(xml).toContain("SELECT * FROM items")
  })
})

describe("export — HTML autocontenido", () => {
  test("es un solo archivo sin assets externos", () => {
    const html = exportHtml(document)
    expect(html.startsWith("<!DOCTYPE html>")).toBe(true)
    expect(html).toContain("<style>")
    expect(html).toContain("<script>")
    // Sin referencias a assets externos: ni scripts, ni estilos, ni fuentes remotas.
    expect(html).not.toMatch(/<script[^>]+src=/i)
    expect(html).not.toMatch(/<link[^>]+href=/i)
    expect(html).not.toMatch(/url\(\s*['"]?https?:/i)
    expect(html).not.toMatch(/@import\s+url/i)
    expect(html).toContain("Banco Ejemplo S.A.")
    expect(html).toContain("SQL injection through the request parameter")
  })
})

describe("export — CycloneDX SBOM", () => {
  test("valida contra el JSON Schema oficial de CycloneDX 1.5", () => {
    const bom = JSON.parse(exportSbom(document))
    expect(bom.bomFormat).toBe("CycloneDX")
    expect(bom.specVersion).toBe("1.5")
    const violations = validateAgainstSchema(bom, cycloneDxSchema)
    expect(violations.map((violation) => `${violation.path}: ${violation.message}`)).toEqual([])
  })

  test("los hallazgos viajan como vulnerabilities y el target como component", () => {
    const bom = JSON.parse(exportSbom(document))
    expect(bom.vulnerabilities).toHaveLength(2)
    expect(bom.components).toHaveLength(1)
    expect(bom.vulnerabilities[0].id).toBe("CWE-89")
    expect(bom.vulnerabilities[0].cwes).toEqual([89])
    expect(bom.vulnerabilities[0].ratings[0].score).toBe(9.8)
    expect(bom.vulnerabilities[0].ratings[0].severity).toBe("critical")
    expect(bom.vulnerabilities[0].ratings[0].method).toBe("CVSSv31")
    expect(bom.vulnerabilities[0].affects[0].ref).toBe(bom.components[0]["bom-ref"])
    expect(bom.serialNumber).toMatch(/^urn:uuid:[0-9a-f-]{36}$/)
  })
})

describe("export — HAR", () => {
  test("es un HAR 1.2 válido con las entries derivadas de la evidencia", () => {
    const har = JSON.parse(exportHar(document))
    expect(har.log.version).toBe("1.2")
    expect(har.log.creator.name).toBe("argos-security-operations")
    expect(Array.isArray(har.log.entries)).toBe(true)
    expect(har.log.entries).toHaveLength(1)
    const entry = har.log.entries[0]
    expect(entry.request.method).toBe("GET")
    expect(entry.request.url).toBe("https://app.example.com/api/items?id=1")
    expect(entry.response.status).toBe(200)
    expect(entry.startedDateTime).toBe("2024-05-17T09:30:00Z")
  })

  test("sin evidencia de red sale un HAR vacío pero válido", () => {
    const empty = buildReport({
      meta: document.meta,
      findings: [{ id: "x", title: "sin evidencia", severity: "info", status: "open" }],
    })
    const har = JSON.parse(exportHar(empty))
    expect(har.log.version).toBe("1.2")
    expect(har.log.entries).toEqual([])
    expect(har.log.pages).toEqual([])
  })
})

describe("export — CSV", () => {
  test("una fila por hallazgo con las columnas de ticketing", () => {
    const csv = exportCsv(document)
    const lines = csv.trim().split("\r\n")
    expect(lines[0]).toBe(
      "id,title,severity,status,feedback_verdict,feedback_reason,feedback_actor,feedback_updated_at,cvss_score,cvss_vector,cwe,owasp,target,source_tool,detected_at,fingerprint,tags,references,session,evidence,remediation",
    )
    expect(lines).toHaveLength(3)
    expect(lines[1]).toContain("finding-1")
    expect(lines[1]).toContain("critical")
    expect(lines[1]).toContain("CWE-89")
    expect(lines[1]).toContain("ses_123")
  })

  test("las comas y comillas de la evidencia se escapan (RFC 4180)", () => {
    const quoted = buildReport({
      meta: document.meta,
      findings: [
        {
          id: "finding-3",
          title: 'Header injection "X-Forwarded-For"',
          severity: "medium",
          status: "open",
          evidence: "value = 1, 2, 3\nline2",
        },
      ],
    })
    const csv = exportCsv(quoted)
    const row = csv.trim().split("\r\n")[1]
    expect(row).toContain(`"Header injection ""X-Forwarded-For"""`)
    expect(row).toContain(`"value = 1, 2, 3\nline2"`)
  })
})

describe("export — Markdown", () => {
  test("el informe completo en markdown con su front-matter", () => {
    const markdown = exportMarkdown(document)
    expect(markdown.startsWith("---")).toBe(true)
    expect(markdown).toContain(`content_sha256: "${reportContentHash(document)}"`)
    expect(markdown).toContain("# Informe Ejecutivo de Auditoría de Seguridad")
    expect(markdown).toContain("## 1. Resumen ejecutivo")
    expect(markdown).toContain("## 4. Detalle técnico de vulnerabilidades")
    expect(markdown).toContain("SQL injection through the request parameter")
  })
})

describe("export — punto de entrada único", () => {
  test("exportDocument devuelve el artefacto con su hash y su nombre de archivo", async () => {
    const artifact = await exportDocument(document, "csv", { now: FIXED_DATE })
    expect(artifact.format).toBe("csv")
    expect(artifact.filename).toBe("argos-report-ses_123-2024-05-17.csv")
    expect(artifact.mimeType).toBe("text/csv;charset=utf-8")
    expect(artifact.sha256).toMatch(/^[0-9a-f]{64}$/)
    expect(artifact.contentHash).toBe(reportContentHash(document))
    expect(artifact.text).toBe(exportCsv(document))
  })

  test("exportAll carga los hallazgos de la sesión desde la base de datos", () => {
    const effect = exportAll("ses_123", "sarif", { now: FIXED_DATE })
    expect(effect).toBeDefined()
  })
})

describe("export — sobre la base de datos", () => {
  const database = Database.layerFromPath(":memory:")
  const it = testEffect(database)

  const seed = (sessionID: SessionV2.ID) =>
    Effect.gen(function* () {
      const { db } = yield* Database.Service
      yield* db
        .insert(ProjectTable)
        .values({ id: Project.ID.global, worktree: AbsolutePath.make("/project"), sandboxes: [] })
        .onConflictDoNothing()
        .run()
        .pipe(Effect.orDie)
      yield* db
        .insert(SessionTable)
        .values({
          id: sessionID,
          project_id: Project.ID.global,
          slug: "export-test",
          directory: "/project",
          title: "export test",
          version: "test",
        })
        .onConflictDoNothing()
        .run()
        .pipe(Effect.orDie)
      yield* db
        .insert(FindingTable)
        .values({
          id: `finding-export-${sessionID}`,
          session_id: sessionID,
          project_id: Project.ID.global,
          fingerprint: "cwe-89|app/handler.py:42",
          title: "SQL injection through the request parameter",
          severity: "critical",
          status: "open",
          source: "agent-reviewed",
          source_tool: "argos_memory_save",
          target: "https://app.example.com/api/items",
          cwe: "CWE-89",
          vector: "app/handler.py:42",
          evidence: { text: "SELECT * FROM items WHERE id = '1' OR 1=1 --'" },
          remediation: "Use parameterized queries",
          tags: ["sqli"],
          time_created: Date.UTC(2024, 4, 16, 8, 0, 0),
          time_updated: Date.UTC(2024, 4, 16, 8, 0, 0),
        })
        .onConflictDoNothing()
        .run()
        .pipe(Effect.orDie)
    })

  it.effect("exporta el PDF de los hallazgos persistidos de la sesión", () =>
    Effect.gen(function* () {
      const sessionID = SessionV2.ID.make("ses_export_pdf")
      yield* seed(sessionID)

      const artifact = yield* exportAll(sessionID, "pdf", { now: FIXED_DATE, meta: { clientName: "Banco Ejemplo" } })

      expect(artifact.format).toBe("pdf")
      expect(artifact.bytes).toBeDefined()
      expect(artifact.bytes!.length).toBeGreaterThan(1024)
      expect(artifact.sha256).toMatch(/^[0-9a-f]{64}$/)
      expect(artifact.contentHash).toMatch(/^[0-9a-f]{64}$/)
      expect(artifact.filename).toBe("argos-report-ses_export_pdf-2024-05-17.pdf")
    }),
  )

  it.effect("exporta el SARIF de los hallazgos persistidos de la sesión", () =>
    Effect.gen(function* () {
      const sessionID = SessionV2.ID.make("ses_export_sarif")
      yield* seed(sessionID)

      const artifact = yield* exportAll(sessionID, "sarif", { now: FIXED_DATE })
      const log = JSON.parse(artifact.text!)

      expect(log.version).toBe("2.1.0")
      expect(log.runs[0].results).toHaveLength(1)
      expect(log.runs[0].results[0].ruleId).toBe("ARGOS-CWE-89")
      expect(validateAgainstSchema(log, sarifSchema)).toEqual([])
    }),
  )

  it.effect("conserva el feedback persistido en el informe y su hash de contenido", () =>
    Effect.gen(function* () {
      const sessionID = SessionV2.ID.make("ses_export_feedback")
      yield* seed(sessionID)
      const { db } = yield* Database.Service
      const findingID = `finding-export-${sessionID}`
      const feedback = yield* recordFeedback(db, {
        sessionID,
        findingID,
        verdict: "false-positive",
        reason: "La ruta requiere autenticación y no expone datos.",
      })

      const document = yield* loadReportDocument(sessionID, { now: FIXED_DATE })
      const finding = document.findings[0]

      expect(finding.feedback).toEqual({
        verdict: "false-positive",
        reason: feedback.reason,
        actor: "human",
        updatedAt: feedback.time_updated,
      })
      expect(exportMarkdown(document)).toContain("false-positive")
      expect(exportMarkdown(document)).toContain("La ruta requiere autenticación y no expone datos.")
      expect(exportHtml(document)).toContain("La ruta requiere autenticación y no expone datos.")
      expect(exportCsv(document)).toContain("false-positive")
      const sarif = JSON.parse(exportSarif(document))
      expect(sarif.runs[0].results[0].suppressions[0].justification).toContain("false-positive")
      expect(sarif.runs[0].results[0].properties.argosFeedback.reason).toBe(
        "La ruta requiere autenticación y no expone datos.",
      )
      expect(validateAgainstSchema(sarif, sarifSchema)).toEqual([])
      expect(exportJunit(document)).toContain('<skipped message="false-positive"/>')
      const defectdojo = JSON.parse(exportDefectDojo(document))
      expect(defectdojo[0].active).toBe(false)
      expect(defectdojo[0].description).toContain("La ruta requiere autenticación y no expone datos.")
      expect(reportContentHash(document)).toMatch(/^[0-9a-f]{64}$/)
    }),
  )

  it.effect("consolida varias sesiones del mismo workspace", () =>
    Effect.gen(function* () {
      const first = SessionV2.ID.make("ses_export_multi_a")
      const second = SessionV2.ID.make("ses_export_multi_b")
      yield* seed(first)
      yield* seed(second)

      const artifact = yield* exportSessions([first, second], "csv", { now: FIXED_DATE })
      const rows = artifact.text!.trim().split("\r\n")

      expect(rows).toHaveLength(3)
    }),
  )
})
