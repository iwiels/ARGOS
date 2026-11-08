import { readFileSync } from "node:fs"
import path from "node:path"
import { describe, expect, test } from "bun:test"
import { Effect } from "effect"
import { Database } from "@argos/core/database/database"
import { Project } from "@argos/core/project"
import { ProjectTable } from "@argos/core/project/sql"
import { SessionV2 } from "@argos/core/session"
import { SessionTable } from "@argos/core/session/sql"
import { FindingTable } from "@argos/core/security/sql"
import { parseReportFindingsTable, parseReportTarget, reconcileReportFindings } from "@argos/core/security/report-reconcile"
import { findingFingerprint } from "@argos/core/security/ingest"
import { AbsolutePath } from "@argos/core/schema"
import { eq } from "drizzle-orm"
import { testEffect } from "./lib/effect"

const REPORT = readFileSync(path.join(import.meta.dir, "fixture/example-security-report.md"), "utf8")

describe("parseReportFindingsTable", () => {
  test("parses all 18 rows from the real consolidated findings table", () => {
    const findings = parseReportFindingsTable(REPORT)
    expect(findings).toHaveLength(18)
    expect(findings.map((f) => f.reportId)).toEqual([
      "F-01", "F-02", "F-03", "F-04", "F-05", "F-06", "F-07", "F-08", "F-09",
      "F-10", "F-11", "F-12", "F-13", "F-14", "F-15", "F-16", "F-17", "F-18",
    ])
  })

  test("parses the critical finding with its full fields", () => {
    const [f01] = parseReportFindingsTable(REPORT)
    expect(f01).toMatchObject({
      reportId: "F-01",
      severity: "CRITICO",
      title: "Compromiso activo del CMS — SEO/spam inyectado",
      cwe: "CWE-506",
      status: "validated",
      vector: "templates/example/index.php → todas las paginas",
    })
    expect(f01.cve).toBeUndefined()
  })

  test("does not confuse the risk-analysis table (4 columns) with the findings table", () => {
    const findings = parseReportFindingsTable(REPORT)
    // La tabla de "Analisis de riesgo del top" también tiene filas F-01/F-03/etc,
    // pero con 4 columnas (ID, CVSS, Justificacion) en vez de 7 — no debe duplicar.
    expect(findings.filter((f) => f.reportId === "F-01")).toHaveLength(1)
  })

  test("ignores the markdown separator row and non-table lines", () => {
    const findings = parseReportFindingsTable("| ID | Severidad | Titulo | CWE | CVE | Estado | Vector |\n|---|---|---|---|---|---|---|\nSome prose line\n")
    expect(findings).toHaveLength(0)
  })

  test("returns an empty array for markdown with no findings table", () => {
    expect(parseReportFindingsTable("# Just a heading\n\nSome prose.")).toEqual([])
  })
})

describe("reconcileReportFindings", () => {
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
          slug: "reconcile-test",
          directory: "/project",
          title: "reconcile test",
          version: "test",
        })
        .onConflictDoNothing()
        .run()
        .pipe(Effect.orDie)
    })

  it.effect("backfills all 18 findings from the report into an empty session", () =>
    Effect.gen(function* () {
      const sessionID = SessionV2.ID.make("ses_reconcile_empty")
      yield* seed(sessionID)
      const { db } = yield* Database.Service

      const result = yield* reconcileReportFindings(db, { sessionID, reportMarkdown: REPORT })
      expect(result).toEqual({ total: 18, inserted: 18, skipped: 0 })

      const rows = yield* db.select().from(FindingTable).where(eq(FindingTable.session_id, sessionID)).all().pipe(Effect.orDie)
      expect(rows).toHaveLength(18)
      const critical = rows.find((r) => r.tags.includes("F-01"))
      expect(critical).toMatchObject({ severity: "critical", status: "validated", cwe: "CWE-506" })
    }),
  )

  it.effect("does not duplicate a finding that already exists with a matching fingerprint", () =>
    Effect.gen(function* () {
      const sessionID = SessionV2.ID.make("ses_reconcile_partial")
      yield* seed(sessionID)
      const { db } = yield* Database.Service

      // Pre-existente: mismo title+vector que F-01 en el reporte (ya vino por memory_save).
      yield* db
        .insert(FindingTable)
        .values({
          id: "finding_preexisting",
          session_id: sessionID,
          project_id: Project.ID.global,
          fingerprint: "will-be-overwritten",
          title: "Compromiso activo del CMS — SEO/spam inyectado",
          severity: "critical",
          status: "validated",
          source: "memory",
          source_tool: "argos_memory_save",
          vector: "templates/example/index.php → todas las paginas",
          evidence: {},
          tags: [],
          time_created: Date.now(),
          time_updated: Date.now(),
        })
        .run()
        .pipe(Effect.orDie)
      // Alinear el fingerprint real con lo que el reconciliador calcularía.
      const fp = findingFingerprint({
        title: "Compromiso activo del CMS — SEO/spam inyectado",
        vector: "templates/example/index.php → todas las paginas",
      })
      yield* db.update(FindingTable).set({ fingerprint: fp }).where(eq(FindingTable.id, "finding_preexisting")).run().pipe(Effect.orDie)

      const result = yield* reconcileReportFindings(db, { sessionID, reportMarkdown: REPORT })
      expect(result.total).toBe(18)
      expect(result.inserted).toBe(17)
      expect(result.skipped).toBe(1)

      const rows = yield* db.select().from(FindingTable).where(eq(FindingTable.session_id, sessionID)).all().pipe(Effect.orDie)
      expect(rows).toHaveLength(18)
    }),
  )

  it.effect("is idempotent: running it twice does not create duplicates", () =>
    Effect.gen(function* () {
      const sessionID = SessionV2.ID.make("ses_reconcile_idempotent")
      yield* seed(sessionID)
      const { db } = yield* Database.Service

      yield* reconcileReportFindings(db, { sessionID, reportMarkdown: REPORT })
      const second = yield* reconcileReportFindings(db, { sessionID, reportMarkdown: REPORT })
      expect(second).toEqual({ total: 18, inserted: 0, skipped: 18 })

      const rows = yield* db.select().from(FindingTable).where(eq(FindingTable.session_id, sessionID)).all().pipe(Effect.orDie)
      expect(rows).toHaveLength(18)
    }),
  )

  it.effect("no-ops for a Session that isn't recorded", () =>
    Effect.gen(function* () {
      const { db } = yield* Database.Service
      const result = yield* reconcileReportFindings(db, {
        sessionID: SessionV2.ID.make("ses_missing"),
        reportMarkdown: REPORT,
      })
      expect(result).toEqual({ total: 18, inserted: 0, skipped: 18 })
    }),
  )

  it.effect("deduplicates finding that has target but no vector in ingest and '-' vector in report", () =>
    Effect.gen(function* () {
      const sessionID = SessionV2.ID.make("ses_reconcile_no_vector")
      yield* seed(sessionID)
      const { db } = yield* Database.Service

      const reportWithDashVector = `
# Consolidated Audit Report
**Target:** https://audit-domain.example.com

| ID | Severidad | Titulo | CWE | CVE | Estado | Vector |
|---|---|---|---|---|---|---|
| F-01 | CRITICO | Exposed Database Credential | CWE-798 | — | open | — |
`
      // Pre-ingestado vía memory_save sin vector, pero con target
      const fp = findingFingerprint({
        title: "Exposed Database Credential",
        target: "https://audit-domain.example.com",
      })

      yield* db
        .insert(FindingTable)
        .values({
          id: "finding_ingested_no_vec",
          session_id: sessionID,
          project_id: Project.ID.global,
          fingerprint: fp,
          title: "Exposed Database Credential",
          severity: "critical",
          status: "open",
          source: "memory",
          source_tool: "argos_memory_save",
          target: "https://audit-domain.example.com",
          evidence: {},
          tags: [],
          time_created: Date.now(),
          time_updated: Date.now(),
        })
        .run()
        .pipe(Effect.orDie)

      const result = yield* reconcileReportFindings(db, {
        sessionID,
        reportMarkdown: reportWithDashVector,
      })

      expect(result.total).toBe(1)
      expect(result.skipped).toBe(1)
      expect(result.inserted).toBe(0)

      const rows = yield* db
        .select()
        .from(FindingTable)
        .where(eq(FindingTable.session_id, sessionID))
        .all()
        .pipe(Effect.orDie)
      expect(rows).toHaveLength(1)
      expect(rows[0].target).toBe("https://audit-domain.example.com")
    }),
  )
})

describe("parseReportTarget", () => {
  test("extracts target from **Target:** markdown header", () => {
    expect(parseReportTarget("**Target:** https://example.com/api")).toBe("https://example.com/api")
  })
  test("extracts target from Target: header line", () => {
    expect(parseReportTarget("Target: 192.168.1.1\nSome description")).toBe("192.168.1.1")
  })
  test("returns undefined if no target header is found", () => {
    expect(parseReportTarget("# Audit Report\n\nNo target specified.")).toBeUndefined()
  })
})

