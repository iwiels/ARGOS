import { describe, expect } from "bun:test"
import { eq } from "drizzle-orm"
import { NodeHttpServer } from "@effect/platform-node"
import { Audit } from "@argos/core/audit"
import { Database } from "@argos/core/database/database"
import { ingestToolFindings } from "@argos/core/security/ingest"
import { FindingTable } from "@argos/core/security/sql"
import { Project } from "@argos/core/project"
import { ProjectTable } from "@argos/core/project/sql"
import { AbsolutePath } from "@argos/core/schema"
import { SessionV2 } from "@argos/core/session"
import { SessionTable } from "@argos/core/session/sql"
import { SecurityGroup } from "@argos/server/groups/security"
import { SecurityHandler } from "@argos/server/handlers/security"
import { Authorization } from "@argos/server/middleware/authorization"
import { SessionLocationMiddleware } from "@argos/server/middleware/session-location"
import { schemaErrorLayer } from "@argos/server/middleware/schema-error"
import { Effect, Layer } from "effect"
import { HttpClient, HttpClientRequest, HttpRouter } from "effect/unstable/http"
import { HttpApi, HttpApiBuilder } from "effect/unstable/httpapi"
import { testEffect } from "../lib/effect"

const currentSessionID = SessionV2.ID.make("ses_case_operations_api")
const otherSessionID = SessionV2.ID.make("ses_case_operations_other")
const database = Database.layerFromPath(":memory:")
const api = HttpApi.make("server").add(SecurityGroup)
const server = HttpRouter.serve(
  HttpApiBuilder.layer(api).pipe(
    Layer.provide(SecurityHandler),
    Layer.provide([
      schemaErrorLayer,
      Layer.succeed(
        Authorization,
        Authorization.of((effect) => effect),
      ),
      Layer.succeed(
        SessionLocationMiddleware,
        SessionLocationMiddleware.of((effect) =>
          effect as Effect.Effect<Effect.Success<typeof effect>, Effect.Error<typeof effect>>,
        ),
      ),
    ]),
    Layer.provide(Audit.defaultLayer),
    Layer.provide(database),
  ),
  { disableListenLog: true, disableLogger: true },
).pipe(Layer.provideMerge(NodeHttpServer.layerTest))
const it = testEffect(Layer.mergeAll(database, server))

const finding = (title: string, target: string, vector: string) => ({
  title,
  severity: "high",
  status: "open",
  confidence: "possible",
  cwe: "CWE-89",
  target,
  vector,
  evidence: { format: "api-test" },
  tags: [],
  references: [],
})

const ingest = (
  db: Database.Interface["db"],
  sessionID: SessionV2.ID,
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

describe("finding case operations HTTP API", () => {
  it.effect("merges, splits, exposes history, and reverses only visible session findings", () =>
    Effect.gen(function* () {
      const { db } = yield* Database.Service
      yield* db
        .insert(ProjectTable)
        .values({ id: Project.ID.global, worktree: AbsolutePath.make("/project"), sandboxes: [] })
        .run()
        .pipe(Effect.orDie)
      for (const id of [currentSessionID, otherSessionID]) {
        yield* db
          .insert(SessionTable)
          .values({
            id,
            project_id: Project.ID.global,
            slug: id,
            directory: "/project",
            title: "finding case operation API test",
            version: "test",
          })
          .run()
          .pipe(Effect.orDie)
      }
      const sqlFinding = finding("SQL injection", "https://target.example/items", "/items?id")
      const adminFinding = finding("Exposed admin panel", "https://target.example/admin", "/admin")
      yield* ingest(db, currentSessionID, "current-sql", sqlFinding)
      yield* ingest(db, otherSessionID, "other-sql", sqlFinding)
      yield* ingest(db, currentSessionID, "current-admin", adminFinding)
      const sessionFindings = yield* db
        .select({ id: FindingTable.id, caseID: FindingTable.case_id, title: FindingTable.title })
        .from(FindingTable)
        .where(eq(FindingTable.session_id, currentSessionID))
        .all()
      const otherFinding = yield* db
        .select({ id: FindingTable.id, caseID: FindingTable.case_id })
        .from(FindingTable)
        .where(eq(FindingTable.session_id, otherSessionID))
        .get()
      const sourceCaseID = sessionFindings.find((item) => item.title === "SQL injection")?.caseID
      const targetCaseID = sessionFindings.find((item) => item.title === "Exposed admin panel")?.caseID
      expect(sourceCaseID).toBeDefined()
      expect(targetCaseID).toBeDefined()
      expect(otherFinding?.caseID).toBe(sourceCaseID)

      const send = (method: "GET" | "POST", path: string, payload?: unknown) =>
        Effect.gen(function* () {
          const request = HttpClientRequest.make(method)(path)
          const response = yield* HttpClient.execute(
            payload === undefined ? request : HttpClientRequest.bodyJsonUnsafe(payload)(request),
          )
          return { status: response.status, body: (yield* response.json) as Record<string, any> }
        })

      const base = `/api/session/${currentSessionID}/finding-cases`
      const wrongSessionSplit = yield* send("POST", `${base}/${sourceCaseID}/split`, {
        findingIDs: [otherFinding!.id],
        reason: "Must remain session scoped",
      })
      expect(wrongSessionSplit.status).toBe(400)

      const merged = yield* send("POST", `${base}/${sourceCaseID}/merge`, {
        targetCaseID,
        reason: "Confirmed duplicate identity",
      })
      expect(merged.status).toBe(200)
      const mergeID = merged.body.data.id as string

      const history = yield* send("GET", `${base}/${targetCaseID}/operations?limit=100`)
      expect(history.status, JSON.stringify(history.body)).toBe(200)
      expect(history.body.data).toMatchObject([{ id: mergeID, kind: "merge", sourceCaseID, targetCaseID }])

      const toSplit = sessionFindings.find((item) => item.title === "SQL injection")!
      const split = yield* send("POST", `${base}/${targetCaseID}/split`, {
        findingIDs: [toSplit.id],
        reason: "Separate validation path",
      })
      expect(split.status).toBe(200)
      const splitCaseID = split.body.caseID as string
      const splitID = split.body.operation.id as string

      const prematureMergeReverse = yield* send("POST", `${base}/${targetCaseID}/operations/${mergeID}/reverse`, {
        reason: "This must wait for the later split",
      })
      expect(prematureMergeReverse.status).toBe(409)

      const reversedSplit = yield* send("POST", `${base}/${splitCaseID}/operations/${splitID}/reverse`, {
        reason: "Restore the reviewed grouping",
      })
      expect(reversedSplit.status).toBe(200)
      expect(reversedSplit.body.data.reversedReason).toBe("Restore the reviewed grouping")

      const reversedMerge = yield* send("POST", `${base}/${targetCaseID}/operations/${mergeID}/reverse`, {
        reason: "Restore separate findings",
      })
      expect(reversedMerge.status).toBe(200)
      expect(typeof reversedMerge.body.data.reversedAt).toBe("number")
    }),
  )
})
