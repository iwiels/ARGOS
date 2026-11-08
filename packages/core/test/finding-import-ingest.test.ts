import { describe, expect } from "bun:test"
import { eq } from "drizzle-orm"
import { Cause, Effect, Exit } from "effect"
import { EventV2 } from "../src/event"
import { Database } from "../src/database/database"
import { Project } from "../src/project"
import { ProjectTable } from "../src/project/sql"
import { AbsolutePath } from "../src/schema"
import { importFindingDocument } from "../src/security/finding-import"
import { FindingCaseTable, FindingObservationTable, FindingTable } from "../src/security/sql"
import { SessionV2 } from "../src/session"
import { SessionTable } from "../src/session/sql"
import { testEffect } from "./lib/effect"

const sessionID = SessionV2.ID.make("ses_finding_import")
const it = testEffect(Database.layerFromPath(":memory:"))

const seed = Effect.gen(function* () {
  const { db } = yield* Database.Service
  yield* db
    .insert(ProjectTable)
    .values({
      id: Project.ID.global,
      worktree: AbsolutePath.make("/project"),
      sandboxes: [],
    })
    .run()
    .pipe(Effect.orDie)
  yield* db
    .insert(SessionTable)
    .values({
      id: sessionID,
      project_id: Project.ID.global,
      slug: "finding-import",
      directory: "/project",
      title: "finding import",
      version: "test",
    })
    .run()
    .pipe(Effect.orDie)
})

const content = JSON.stringify({
  "template-id": "exposed-env-file",
  "matched-at": "https://target.example/.env",
  info: { name: "Exposed environment file", severity: "high", classification: { "cwe-id": ["CWE-798"] } },
})

describe("finding import persistence", () => {
  it.effect("imports idempotently by batch identity and preserves a new reimport as an observation", () =>
    Effect.gen(function* () {
      yield* seed
      const { db } = yield* Database.Service
      const input = { sessionID, format: "nuclei-jsonl" as const, content, importID: "batch-one" }
      const first = yield* importFindingDocument(db, input)
      const repeated = yield* importFindingDocument(db, input)
      expect(first.importedCount).toBe(1)
      expect(repeated.sourceEventID).toBe(first.sourceEventID)

      const reimport = yield* importFindingDocument(db, { ...input, importID: "batch-two" })
      expect(reimport.sourceEventID).not.toBe(first.sourceEventID)
      const findings = yield* db.select().from(FindingTable).where(eq(FindingTable.session_id, sessionID)).all()
      const observations = yield* db
        .select()
        .from(FindingObservationTable)
        .where(eq(FindingObservationTable.session_id, sessionID))
        .all()
      expect(findings).toHaveLength(1)
      expect(findings[0]).toMatchObject({ source: "import", source_tool: "nuclei", rule_id: "nuclei:exposed-env-file" })
      expect(observations).toHaveLength(2)
      expect(observations.every((row) => row.finding_id === findings[0].id)).toBe(true)
    }),
  )

  it.effect("validates the complete document before persisting any finding", () =>
    Effect.gen(function* () {
      yield* seed
      const { db } = yield* Database.Service
      const error = yield* importFindingDocument(db, {
        sessionID,
        format: "nuclei-jsonl",
        content: `${content}\nnot-json`,
        importID: "invalid-batch",
      }).pipe(Effect.flip)
      expect(error).toMatchObject({ code: "invalid_document", line: 2 })
      expect(yield* db.select().from(FindingTable).where(eq(FindingTable.session_id, sessionID)).all()).toEqual([])
      expect(
        yield* db.select().from(FindingObservationTable).where(eq(FindingObservationTable.session_id, sessionID)).all(),
      ).toEqual([])
    }),
  )

  it.effect("does not claim an empty report was persisted before run records exist", () =>
    Effect.gen(function* () {
      yield* seed
      const { db } = yield* Database.Service
      const error = yield* importFindingDocument(db, {
        sessionID,
        format: "defectdojo-generic-json",
        content: "[]",
        importID: "empty-report",
      }).pipe(Effect.flip)
      expect(error).toMatchObject({ code: "empty_import" })
      expect(yield* db.select().from(FindingTable).where(eq(FindingTable.session_id, sessionID)).all()).toEqual([])
      expect(
        yield* db.select().from(FindingObservationTable).where(eq(FindingObservationTable.session_id, sessionID)).all(),
      ).toEqual([])
    }),
  )

  it.effect("rolls back cases and observations when a finding projection fails", () =>
    Effect.gen(function* () {
      yield* seed
      const { db } = yield* Database.Service
      yield* db.run(
        "CREATE TRIGGER fail_finding_projection BEFORE INSERT ON security_finding WHEN NEW.title = 'Projection failure' BEGIN SELECT RAISE(ABORT, 'projection failed'); END",
      )
      const published: unknown[] = []
      const events = {
        publish: (...args: unknown[]) => Effect.sync(() => published.push(args)),
      } as unknown as EventV2.Interface
      const failure = JSON.stringify({
        "template-id": "projection-failure",
        "matched-at": "https://target.example/failure",
        info: { name: "Projection failure", severity: "high" },
      })

      const exit = yield* importFindingDocument(db, {
        sessionID,
        format: "nuclei-jsonl",
        content: `${content}\n${failure}`,
        importID: "failing-projection",
      }, { events }).pipe(Effect.exit)

      expect(Exit.isFailure(exit)).toBe(true)
      expect(published).toEqual([])
      expect(yield* db.select().from(FindingTable).where(eq(FindingTable.session_id, sessionID)).all()).toEqual([])
      expect(
        yield* db.select().from(FindingObservationTable).where(eq(FindingObservationTable.session_id, sessionID)).all(),
      ).toEqual([])
      expect(yield* db.select().from(FindingCaseTable).all()).toEqual([])
    }),
  )

  it.effect("keeps import notification interruption visible after the commit", () =>
    Effect.gen(function* () {
      yield* seed
      const { db } = yield* Database.Service
      const events = {
        publish: () => Effect.interrupt,
      } as unknown as EventV2.Interface

      const exit = yield* importFindingDocument(
        db,
        { sessionID, format: "nuclei-jsonl", content, importID: "interrupted-notification" },
        { events },
      ).pipe(Effect.exit)

      expect(Exit.isFailure(exit) && Cause.hasInterruptsOnly(exit.cause)).toBe(true)
      expect(yield* db.select().from(FindingTable).where(eq(FindingTable.session_id, sessionID)).all()).toHaveLength(1)
      expect(
        yield* db.select().from(FindingObservationTable).where(eq(FindingObservationTable.session_id, sessionID)).all(),
      ).toHaveLength(1)
    }),
  )
})
