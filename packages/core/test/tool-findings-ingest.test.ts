import { describe, expect } from "bun:test"
import { Effect, Layer } from "effect"
import { eq } from "drizzle-orm"
import { Database } from "@argos/core/database/database"
import { EventV2 } from "@argos/core/event"
import { Project } from "@argos/core/project"
import { ProjectTable } from "@argos/core/project/sql"
import { SessionV2 } from "@argos/core/session"
import { SessionTable } from "@argos/core/session/sql"
import { FindingObservationTable, FindingTable } from "@argos/core/security/sql"
import { ingestToolFindings } from "@argos/core/security/ingest"
import { AbsolutePath } from "@argos/core/schema"
import { testEffect } from "./lib/effect"

const database = Database.layerFromPath(":memory:")
const events = EventV2.layer.pipe(Layer.provide(database))
const it = testEffect(Layer.mergeAll(database, events))

const SESSION_ID = SessionV2.ID.make("ses_tool_findings_test")

const seed = Effect.gen(function* () {
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
      id: SESSION_ID,
      project_id: Project.ID.global,
      slug: "tool-findings-test",
      directory: "/project",
      title: "tool findings test",
      version: "test",
    })
    .onConflictDoNothing()
    .run()
    .pipe(Effect.orDie)
})

const toolPart = (output: unknown, tool = "argos-web_web.scan", callID = "call-tool-findings") => ({
  sessionID: SESSION_ID,
  type: "tool" as const,
  callID,
  tool,
  state: { status: "completed" as const, output: JSON.stringify(output) },
})

const finding = (title: string) => ({
  title,
  severity: "high",
  cwe: "CWE-89",
  target: "https://x.test/item?id=1",
  vector: "https://x.test/item?id=1",
})

const findingsFor = Effect.fn("test.findingsFor")(function* () {
  const { db } = yield* Database.Service
  return yield* db
    .select()
    .from(FindingTable)
    .where(eq(FindingTable.session_id, SESSION_ID))
    .all()
    .pipe(Effect.orDie)
})

const ingestImportedFindings = (db: Parameters<typeof ingestToolFindings>[0], part: Parameters<typeof ingestToolFindings>[1]) =>
  ingestToolFindings(db, part, { source: "import" })

describe("ingestToolFindings", () => {
  it.effect("no promociona directamente los candidatos que devuelve una tool", () =>
    Effect.gen(function* () {
      yield* seed
      yield* ingestToolFindings(
        (yield* Database.Service).db,
        toolPart({ findings: [finding("Scanner candidate")] }),
      )
      expect(yield* findingsFor()).toHaveLength(0)
    }),
  )

  it.effect("persiste hallazgos de un import explícito con su taxonomia", () =>
    Effect.gen(function* () {
      yield* seed
      yield* ingestImportedFindings(
        (yield* Database.Service).db,
        toolPart({
          tool: "web.scan",
          status: "completed",
          findings: [
            {
              source: "web.scan",
              source_tool: "web.scan",
              rule_id: "nuclei:exposed-env-file",
              title: "Exposed .env file",
              severity: "high",
              confidence: "confirmed",
              cwe: "CWE-200",
              owasp: ["A05:2021"],
              target: "https://target.example/.env",
              vector: "https://target.example/.env",
              evidence: { matched_at: "https://target.example/.env" },
              tags: ["secret-exposure", ".env"],
              remediation: "Remove the file from the repository and rotate the credentials.",
            },
          ],
        }),
      )

      const rows = yield* findingsFor()
      expect(rows.length).toBe(1)
      const row = rows[0]
      expect(row.title).toBe("Exposed .env file")
      expect(row.severity).toBe("high")
      expect(row.cwe).toBe("CWE-200")
      expect(row.source_tool).toBe("web.scan")
      expect(row.rule_id).toBe("nuclei:exposed-env-file")
      expect(row.confidence).toBe("confirmed")
      expect(row.tags).toContain("secret-exposure")
      expect(row.owasp).toContain("A05:2021")
      expect(row.remediation).toContain("rotate")
      expect(row.source).toBe("import")
    }),
  )

  it.effect("el Session ID es el de la parte: no hay ambiguedad de campana", () =>
    Effect.gen(function* () {
      yield* seed
      yield* ingestImportedFindings(
        (yield* Database.Service).db,
        toolPart({
          findings: [{ title: "Finding A", severity: "medium", cwe: "CWE-89", target: "https://x.test/a" }],
        }),
      )
      const rows = yield* findingsFor()
      expect(rows.length).toBe(1)
      expect(rows[0].session_id).toBe(SESSION_ID)
    }),
  )

  it.effect("el mismo bug reportado dos veces con titulos distintos queda en una fila", () =>
    Effect.gen(function* () {
      yield* seed
      const finding = (title: string) => ({
        title,
        severity: "high",
        cwe: "CWE-89",
        target: "https://x.test/item?id=1",
        vector: "https://x.test/item?id=1",
      })
      const db = (yield* Database.Service).db
      yield* ingestImportedFindings(db, toolPart({ findings: [finding("SQL Injection")] }))
      yield* ingestImportedFindings(db, toolPart({ findings: [finding("SQL Injection Confirmada (sqlmap)")] }))
      const rows = yield* findingsFor()
      expect(rows.length).toBe(1)
    }),
  )

  it.effect("conserva una observacion por llamada y vuelve idempotente la proyeccion del mismo evento", () =>
    Effect.gen(function* () {
      yield* seed
      const db = (yield* Database.Service).db
      const finding = {
        title: "SQL Injection",
        severity: "high",
        cwe: "CWE-89",
        target: "https://x.test/item",
        vector: "https://x.test/item?id=1",
        evidence: { matched_at: "https://x.test/item?id=1" },
      }
      const output = { findings: [finding] }
      yield* ingestImportedFindings(db, toolPart(output, "argos-web_web.scan", "call-scan-one"))
      yield* ingestImportedFindings(db, toolPart(output, "argos-web_web.scan", "call-scan-one"))
      const first = yield* db
        .select()
        .from(FindingObservationTable)
        .where(eq(FindingObservationTable.session_id, SESSION_ID))
        .all()
      expect(first).toHaveLength(1)
      expect(first[0]).toMatchObject({
        finding_id: (yield* findingsFor())[0].id,
        source_tool: "argos-web_web.scan",
        source_event_id: "import:call-scan-one",
      })
      expect(first[0].snapshot).toContain("SQL Injection")

      yield* ingestImportedFindings(db, toolPart(output, "argos-web_web.scan", "call-scan-two"))
      const all = yield* db
        .select({ sourceEventID: FindingObservationTable.source_event_id })
        .from(FindingObservationTable)
        .where(eq(FindingObservationTable.session_id, SESSION_ID))
        .all()
      expect(all.map((row) => row.sourceEventID).sort()).toEqual(["import:call-scan-one", "import:call-scan-two"])
      expect(yield* findingsFor()).toHaveLength(1)
    }),
  )

  it.effect("una tool que no devuelve findings no rompe nada", () =>
    Effect.gen(function* () {
      yield* seed
      const db = (yield* Database.Service).db
      yield* ingestImportedFindings(db, toolPart({ status: "completed" }))
      yield* ingestImportedFindings(db, toolPart({ findings: [] }))
      yield* ingestImportedFindings(db, {
        sessionID: SESSION_ID,
        type: "tool",
        tool: "bash",
        state: { status: "completed", output: "not json at all" },
      })
      const rows = yield* findingsFor()
      expect(rows.length).toBe(0)
    }),
  )
})
