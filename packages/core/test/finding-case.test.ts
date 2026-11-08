import { describe, expect } from "bun:test"
import { eq, sql } from "drizzle-orm"
import { Effect } from "effect"
import { Database } from "../src/database/database"
import { Project } from "../src/project"
import { ProjectTable } from "../src/project/sql"
import { AbsolutePath } from "../src/schema"
import { ingestToolFindings } from "../src/security/ingest"
import {
  deleteOrphanFindingCases,
  countFindingCasesForSession,
  getFindingCaseForSession,
  listFindingCasesForSession,
  listFindingCaseTransitions,
  setFindingCaseStatus,
} from "../src/security/finding-case"
import { FindingCaseTable } from "../src/security/sql"
import { SessionV2 } from "../src/session"
import { SessionTable } from "../src/session/sql"
import { testEffect } from "./lib/effect"

const firstSessionID = SessionV2.ID.make("ses_case_first")
const secondSessionID = SessionV2.ID.make("ses_case_second")
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
  for (const id of [firstSessionID, secondSessionID]) {
    yield* db
      .insert(SessionTable)
      .values({
        id,
        project_id: Project.ID.global,
        slug: id,
        directory: "/project",
        title: "case test",
        version: "test",
      })
      .run()
      .pipe(Effect.orDie)
  }
})

const finding = {
  title: "SQL injection",
  severity: "high",
  status: "open",
  confidence: "possible",
  cwe: "CWE-89",
  target: "https://target.example/items",
  vector: "https://target.example/items?id",
  evidence: { format: "test", parameter: "id" },
  tags: [],
  references: [],
}

describe("finding cases", () => {
  it.effect("links the same project finding identity across sessions while retaining session rows", () =>
    Effect.gen(function* () {
      yield* seed
      const { db } = yield* Database.Service
      const ingest = (sessionID: typeof firstSessionID, callID: string) =>
        ingestToolFindings(
          db,
          {
            sessionID,
            callID,
            type: "tool",
            tool: "web.scan",
            state: { status: "completed", output: JSON.stringify({ findings: [finding] }) },
          },
          { source: "import" },
        )

      yield* ingest(firstSessionID, "run-one")
      yield* ingest(secondSessionID, "run-two")
      yield* ingestToolFindings(
        db,
        {
          sessionID: secondSessionID,
          callID: "run-two-other-case",
          type: "tool",
          tool: "web.scan",
          state: {
            status: "completed",
            output: JSON.stringify({
              findings: [
                {
                  ...finding,
                  title: "Exposed admin panel",
                  target: "https://target.example/admin",
                  vector: "/admin",
                },
              ],
            }),
          },
        },
        { source: "import" },
      )

      const rows = yield* db.all<{ session_id: string; case_id: string }>(
        sql`SELECT session_id, case_id FROM security_finding WHERE session_id IN (${firstSessionID}, ${secondSessionID}) AND title = ${finding.title} ORDER BY session_id`,
      )
      const cases = yield* db.select().from(FindingCaseTable).all()
      expect(rows).toHaveLength(2)
      expect(rows[0].case_id).toBe(rows[1].case_id)
      expect(cases).toHaveLength(2)

      const caseID = rows[0].case_id
      const sessionCases = yield* listFindingCasesForSession(db, {
        projectID: Project.ID.global,
        sessionID: firstSessionID,
      })
      expect(sessionCases).toHaveLength(1)
      expect(sessionCases[0]).toMatchObject({ id: caseID, finding_count: 1, session_count: 2, status: "open" })
      expect(
        yield* countFindingCasesForSession(db, {
          projectID: Project.ID.global,
          sessionID: firstSessionID,
        }),
      ).toBe(1)
      expect(yield* getFindingCaseForSession(db, { sessionID: firstSessionID, caseID })).toMatchObject({
        id: caseID,
        project_id: Project.ID.global,
      })
      expect(yield* getFindingCaseForSession(db, { sessionID: "ses_other_project", caseID })).toBeUndefined()
      const secondSessionCases = yield* listFindingCasesForSession(db, {
        projectID: Project.ID.global,
        sessionID: secondSessionID,
      })
      expect(secondSessionCases).toHaveLength(2)
      expect(
        yield* getFindingCaseForSession(db, {
          sessionID: firstSessionID,
          caseID: secondSessionCases.find((item) => item.id !== caseID)!.id,
        }),
      ).toBeUndefined()

      const expiredRisk = yield* setFindingCaseStatus(db, {
        projectID: Project.ID.global,
        caseID,
        status: "accepted-risk",
        actor: "human",
        now: 1000,
      }).pipe(Effect.flip)
      expect(expiredRisk).toMatchObject({ code: "expiry_required" })

      yield* setFindingCaseStatus(db, {
        projectID: Project.ID.global,
        caseID,
        status: "accepted-risk",
        actor: "human",
        reason: "Temporary exception",
        acceptedRiskUntil: 2000,
        sessionID: firstSessionID,
        now: 1000,
      })
      yield* setFindingCaseStatus(db, {
        projectID: Project.ID.global,
        caseID,
        status: "accepted-risk",
        actor: "human",
        reason: "Temporary exception",
        acceptedRiskUntil: 2000,
        sessionID: firstSessionID,
        now: 1001,
      })
      const transitions = yield* listFindingCaseTransitions(db, { sessionID: firstSessionID, caseID })
      expect(transitions).toHaveLength(1)
      expect(transitions[0]).toMatchObject({ from_status: "open", to_status: "accepted-risk", actor: "human" })
      expect(yield* listFindingCaseTransitions(db, { sessionID: "ses_other_project", caseID })).toHaveLength(0)

      yield* db.delete(SessionTable).where(eq(SessionTable.id, firstSessionID)).run().pipe(Effect.orDie)
      yield* deleteOrphanFindingCases(db)
      expect(yield* db.select().from(FindingCaseTable).where(eq(FindingCaseTable.id, caseID)).get()).toBeDefined()
      yield* db.delete(SessionTable).where(eq(SessionTable.id, secondSessionID)).run().pipe(Effect.orDie)
      yield* deleteOrphanFindingCases(db)
      expect(yield* db.select().from(FindingCaseTable).where(eq(FindingCaseTable.id, caseID)).get()).toBeUndefined()
    }),
  )
})
