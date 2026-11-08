import { describe, expect } from "bun:test"
import { Effect } from "effect"
import { Database } from "../src/database/database"
import { AbsolutePath } from "../src/schema"
import { ProjectTable } from "../src/project/sql"
import { CaseService } from "../src/security/case-service"
import {
  CaseTransitionHistoryTable,
  CaseObservationTable,
  SecurityCaseTable,
} from "../src/security/sql"
import { SessionTable } from "../src/session/sql"
import { eq } from "drizzle-orm"
import { testEffect } from "./lib/effect"

const database = Database.layerFromPath(":memory:")
const it = testEffect(database)

describe("Case & Observation Longitudinal Management (Etapa 2)", () => {
  it.effect("records observations, creates cases, merges and splits reversibly", () =>
    Effect.gen(function* () {
      const { db } = yield* Database.Service

      // Setup project & sessions
      const projectID = "proj-case-test-1"
      const sessionA = "sess-a"
      const sessionB = "sess-b"

      yield* db
        .insert(ProjectTable)
        .values({
          id: projectID as any,
          name: "Test Project",
          worktree: AbsolutePath.make("/project"),
          sandboxes: [],
          time_created: Date.now(),
          time_updated: Date.now(),
        })
        .run()
        .pipe(Effect.orDie)

      yield* db
        .insert(SessionTable)
        .values([
          {
            id: sessionA as any,
            project_id: projectID as any,
            slug: sessionA,
            directory: "/project" as any,
            title: "Session A",
            version: "1.0",
            time_created: Date.now(),
            time_updated: Date.now(),
          },
          {
            id: sessionB as any,
            project_id: projectID as any,
            slug: sessionB,
            directory: "/project" as any,
            title: "Session B",
            version: "1.0",
            time_created: Date.now(),
            time_updated: Date.now(),
          },
        ])
        .run()
        .pipe(Effect.orDie)

      // 1. Record observation in Session A
      const obs1 = yield* CaseService.recordObservation(db, {
        sessionID: sessionA,
        projectID,
        title: "SQL Injection in /api/users",
        severity: "critical",
        cwe: "CWE-89",
        target: "https://example.com/api/users",
        vector: "id",
        source: "scanner",
        sourceTool: "web.sqli",
        evidence: { payload: "1' OR '1'='1" },
      })

      expect(obs1.isNewCase).toBe(true)

      // 2. Re-observe the same bug in Session B (multi-engagement)
      const obs2 = yield* CaseService.recordObservation(db, {
        sessionID: sessionB,
        projectID,
        title: "SQL Injection in /api/users",
        severity: "critical",
        cwe: "CWE-89",
        target: "https://example.com/api/users",
        vector: "id",
        source: "scanner",
        sourceTool: "web.sqli",
        evidence: { payload: "sleep(5)" },
      })

      expect(obs2.isNewCase).toBe(false)
      expect(obs2.caseID).toBe(obs1.caseID)

      // Verify 2 observations linked to 1 case
      const observations = yield* db
        .select()
        .from(CaseObservationTable)
        .where(eq(CaseObservationTable.case_id, obs1.caseID))
        .all()
        .pipe(Effect.orDie)
      expect(observations).toHaveLength(2)

      // 3. Purging Session A retains the case because Session B still backs it
      yield* CaseService.purgeSession(db, sessionA)

      const remainingObservations = yield* db
        .select()
        .from(CaseObservationTable)
        .where(eq(CaseObservationTable.case_id, obs1.caseID))
        .all()
        .pipe(Effect.orDie)
      expect(remainingObservations).toHaveLength(1)
      expect(remainingObservations[0].session_id).toBe(sessionB)

      const caseAfterPurgeA = yield* db
        .select()
        .from(SecurityCaseTable)
        .where(eq(SecurityCaseTable.id, obs1.caseID))
        .get()
        .pipe(Effect.orDie)
      expect(caseAfterPurgeA).toBeDefined()

      // 4. Purging Session B deletes the case because no sessions back it anymore
      yield* CaseService.purgeSession(db, sessionB)

      const caseAfterPurgeB = yield* db
        .select()
        .from(SecurityCaseTable)
        .where(eq(SecurityCaseTable.id, obs1.caseID))
        .get()
        .pipe(Effect.orDie)
      expect(caseAfterPurgeB).toBeUndefined()
    })
  )
})
