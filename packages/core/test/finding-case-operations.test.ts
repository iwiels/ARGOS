import { describe, expect } from "bun:test"
import { and, eq } from "drizzle-orm"
import { Effect } from "effect"
import { Database } from "../src/database/database"
import { Project } from "../src/project"
import { ProjectTable } from "../src/project/sql"
import { AbsolutePath } from "../src/schema"
import { ingestToolFindings } from "../src/security/ingest"
import {
  deleteOrphanFindingCases,
  listFindingCaseOperations,
  mergeFindingCases,
  reverseFindingCaseOperation,
  splitFindingCase,
} from "../src/security/finding-case"
import { FindingCaseOperationTable, FindingCaseTable, FindingTable } from "../src/security/sql"
import { SessionV2 } from "../src/session"
import { SessionTable } from "../src/session/sql"
import { testEffect } from "./lib/effect"

const sessionIDs = ["ses_case_ops_one", "ses_case_ops_two", "ses_case_ops_three"].map((value) =>
  SessionV2.ID.make(value),
)
const it = testEffect(Database.layerFromPath(":memory:"))

const seed = Effect.gen(function* () {
  const { db } = yield* Database.Service
  yield* db
    .insert(ProjectTable)
    .values({ id: Project.ID.global, worktree: AbsolutePath.make("/project"), sandboxes: [] })
    .run()
    .pipe(Effect.orDie)
  for (const id of sessionIDs) {
    yield* db
      .insert(SessionTable)
      .values({
        id,
        project_id: Project.ID.global,
        slug: id,
        directory: "/project",
        title: "case operation test",
        version: "test",
      })
      .run()
      .pipe(Effect.orDie)
  }
})

const finding = (title: string, target: string, vector: string) => ({
  title,
  severity: "high",
  status: "open",
  confidence: "possible",
  cwe: "CWE-89",
  target,
  vector,
  evidence: { format: "test" },
  tags: [],
  references: [],
})

const ingest = (
  db: Database.Interface["db"],
  sessionID: (typeof sessionIDs)[number],
  callID: string,
  item: ReturnType<typeof finding>,
) =>
  ingestToolFindings(
    db,
    {
      sessionID,
      callID,
      type: "tool",
      tool: "web.scan",
      state: { status: "completed", output: JSON.stringify({ findings: [item] }) },
    },
    { source: "import" },
  )

describe("finding case operations", () => {
  it.effect("merges, splits, reverses, and retains audit history while evidence remains", () =>
    Effect.gen(function* () {
      yield* seed
      const { db } = yield* Database.Service
      const first = finding("SQL injection", "https://target.example/items", "/items?id")
      const second = finding("Exposed admin panel", "https://target.example/admin", "/admin")
      yield* ingest(db, sessionIDs[0], "first-sql", first)
      yield* ingest(db, sessionIDs[1], "second-sql", first)
      yield* ingest(db, sessionIDs[0], "first-admin", second)

      const source = yield* db
        .select({ id: FindingCaseTable.id })
        .from(FindingCaseTable)
        .innerJoin(FindingTable, eq(FindingTable.case_id, FindingCaseTable.id))
        .where(eq(FindingTable.title, first.title))
        .get()
      const target = yield* db
        .select({ id: FindingCaseTable.id })
        .from(FindingCaseTable)
        .innerJoin(FindingTable, eq(FindingTable.case_id, FindingCaseTable.id))
        .where(eq(FindingTable.title, second.title))
        .get()
      expect(source).toBeDefined()
      expect(target).toBeDefined()

      const merge = yield* mergeFindingCases(db, {
        projectID: Project.ID.global,
        sessionID: sessionIDs[0],
        sourceCaseID: source!.id,
        targetCaseID: target!.id,
        reason: "Confirmed to be the same underlying issue",
        actor: "human",
        now: 1000,
      })
      expect(merge).toMatchObject({ kind: "merge", source_case_id: source!.id, target_case_id: target!.id })
      expect(merge.finding_ids).toHaveLength(2)
      expect(yield* listFindingCaseOperations(db, { sessionID: sessionIDs[0], caseID: target!.id })).toMatchObject([
        { id: merge.id, kind: "merge", source_case_id: source!.id, target_case_id: target!.id },
      ])
      expect(
        yield* db.select({ id: FindingTable.id }).from(FindingTable).where(eq(FindingTable.case_id, target!.id)).all(),
      ).toHaveLength(3)
      expect(
        (yield* db.select().from(FindingCaseTable).where(eq(FindingCaseTable.id, source!.id)).get())?.merged_into_id,
      ).toBe(target!.id)

      yield* ingest(db, sessionIDs[2], "third-sql", first)
      const thirdSessionFinding = yield* db
        .select()
        .from(FindingTable)
        .where(eq(FindingTable.session_id, sessionIDs[2]))
        .get()
      expect(thirdSessionFinding?.case_id).toBe(target!.id)

      const reverseMerge = yield* reverseFindingCaseOperation(db, {
        projectID: Project.ID.global,
        sessionID: sessionIDs[0],
        caseID: target!.id,
        operationID: merge.id,
        reason: "Separate identity after manual review",
        actor: "human",
        now: 2000,
      })
      expect(reverseMerge.reversed_at).toBe(2000)
      expect(
        (yield* db.select().from(FindingCaseTable).where(eq(FindingCaseTable.id, source!.id)).get())?.merged_into_id,
      ).toBeNull()
      const sourceFindings = yield* db.select().from(FindingTable).where(eq(FindingTable.case_id, source!.id)).all()
      expect(sourceFindings).toHaveLength(3)

      const sessionFinding = yield* db
        .select({ id: FindingTable.id })
        .from(FindingTable)
        .where(and(eq(FindingTable.session_id, sessionIDs[0]), eq(FindingTable.case_id, source!.id)))
        .get()
      const split = yield* splitFindingCase(db, {
        projectID: Project.ID.global,
        sessionID: sessionIDs[0],
        sourceCaseID: source!.id,
        findingIDs: [sessionFinding!.id],
        reason: "Separate this observation for independent remediation",
        actor: "human",
        now: 3000,
      })
      expect(split.operation.kind).toBe("split")
      expect(split.operation.finding_ids).toEqual([sessionFinding!.id])
      expect(
        (yield* db.select().from(FindingTable).where(eq(FindingTable.id, sessionFinding!.id)).get())?.case_id,
      ).toBe(split.caseID)

      const reverseSplit = yield* reverseFindingCaseOperation(db, {
        projectID: Project.ID.global,
        sessionID: sessionIDs[0],
        caseID: split.caseID,
        operationID: split.operation.id,
        reason: "Restore the original grouping",
        actor: "human",
        now: 4000,
      })
      expect(reverseSplit.reversed_at).toBe(4000)
      expect(
        (yield* db.select().from(FindingTable).where(eq(FindingTable.id, sessionFinding!.id)).get())?.case_id,
      ).toBe(source!.id)
      expect(
        (yield* db.select().from(FindingCaseTable).where(eq(FindingCaseTable.id, split.caseID)).get())?.merged_into_id,
      ).toBe(source!.id)

      yield* db.delete(SessionTable).where(eq(SessionTable.id, sessionIDs[0])).run().pipe(Effect.orDie)
      yield* deleteOrphanFindingCases(db)
      expect(yield* db.select().from(FindingCaseOperationTable).all()).toHaveLength(2)
      yield* db.delete(SessionTable).where(eq(SessionTable.id, sessionIDs[1])).run().pipe(Effect.orDie)
      yield* db.delete(SessionTable).where(eq(SessionTable.id, sessionIDs[2])).run().pipe(Effect.orDie)
      yield* deleteOrphanFindingCases(db)
      expect(yield* db.select().from(FindingCaseOperationTable).all()).toHaveLength(0)
      expect(yield* db.select().from(FindingCaseTable).all()).toHaveLength(0)
    }),
  )
})
