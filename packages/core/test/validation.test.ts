import { describe, expect } from "bun:test"
import { eq } from "drizzle-orm"
import { Effect } from "effect"
import { Database } from "@argos/core/database/database"
import { Project } from "@argos/core/project"
import { ProjectTable } from "@argos/core/project/sql"
import { SessionV2 } from "@argos/core/session"
import { SessionTable } from "@argos/core/session/sql"
import { FindingTable } from "@argos/core/security/sql"
import { validateFinding } from "@argos/core/security/validation"
import { AbsolutePath } from "@argos/core/schema"
import { testEffect } from "./lib/effect"

const SESSION_ID = SessionV2.ID.make("ses_xbow_val")
const database = Database.layerFromPath(":memory:")
const it = testEffect(database)

const seedDatabase = (db: Database.Interface["db"]) =>
  Effect.gen(function* () {
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
        slug: SESSION_ID,
        directory: "/project",
        title: "xbow test",
        version: "test",
      })
      .onConflictDoNothing()
      .run()
      .pipe(Effect.orDie)
    yield* db
      .insert(FindingTable)
      .values({
        id: "find_xbow_1",
        session_id: SESSION_ID,
        project_id: Project.ID.global,
        fingerprint: "fp_xbow_1",
        title: "SQL Injection in parameter id",
        severity: "critical",
        status: "suspected",
        source: "web.sqli",
        target: "http://127.0.0.1:8080/item?id=1",
        evidence: { indicator: "boolean blind" },
        tags: ["sqli"],
        time_created: Date.now(),
        time_updated: Date.now(),
      })
      .run()
      .pipe(Effect.orDie)
  })

describe("Finding Validation Engine (XBOW-style)", () => {
  it.effect("transiciona a 'confirmed' y sincroniza status a 'validated' cuando reproduce", () =>
    Effect.gen(function* () {
      const { db } = yield* Database.Service
      yield* seedDatabase(db)
      const res = yield* validateFinding(db, {
        findingId: "find_xbow_1",
        verifier: async () => ({ confirmed: true, evidence: { dbms: "SQLite", parameter: "id" } }),
      })
      expect(res.validation_status).toBe("confirmed")
      expect(res.status).toBe("validated")
      expect(res.validation_evidence).toBeDefined()
    }),
  )

  it.effect("transiciona a 'rejected' y status a 'false-positive' cuando no reproduce", () =>
    Effect.gen(function* () {
      const { db } = yield* Database.Service
      yield* seedDatabase(db)
      const res = yield* validateFinding(db, {
        findingId: "find_xbow_1",
        verifier: async () => ({ confirmed: false, reason: "endpoint is parameterized" }),
      })
      expect(res.validation_status).toBe("rejected")
      expect(res.status).toBe("false-positive")
    }),
  )

  it.effect("marca 'rejected' con evidencia de error cuando el verificador arroja excepción", () =>
    Effect.gen(function* () {
      const { db } = yield* Database.Service
      yield* seedDatabase(db)
      const result = yield* validateFinding(db, {
        findingId: "find_xbow_1",
        verifier: async () => {
          throw new Error("Network timeout reaching target")
        },
      }).pipe(Effect.exit)

      expect(result._tag).toBe("Failure")

      const rows = yield* db
        .select()
        .from(FindingTable)
        .where(eq(FindingTable.id, "find_xbow_1"))
        .run()
        .pipe(Effect.orDie)
      expect(rows[0].validation_status).toBe("rejected")
      const evidence = typeof rows[0].validation_evidence === "string" ? JSON.parse(rows[0].validation_evidence) : rows[0].validation_evidence
      expect(evidence?.error).toContain("Network timeout reaching target")
    }),
  )
})
