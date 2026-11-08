import * as http from "node:http"
import { PermissionV1 } from "@argos/core/v1/permission"
import { NodeHttpServer, NodeServices } from "@effect/platform-node"
import { Flag } from "@argos/core/flag/flag"
import { describe, expect } from "bun:test"
import { eq } from "drizzle-orm"
import { Config, Context, Effect, FileSystem, Layer, Path } from "effect"
import { HttpClient, HttpClientRequest, HttpRouter, HttpServer } from "effect/unstable/http"
import * as Socket from "effect/unstable/socket/Socket"
import { WorkspaceV2 } from "@argos/core/workspace"
import { SessionV2 } from "@argos/core/session"
import { Database } from "@argos/core/database/database"
import { AuditLogTable } from "@argos/core/audit/sql"
import { FindingTable } from "@argos/core/security/sql"
import { SessionTable } from "@argos/core/session/sql"
import { ControlPaths } from "../../src/server/routes/instance/httpapi/groups/control"
import { FindingPaths } from "../../src/server/routes/instance/httpapi/groups/finding"
import { InstancePaths } from "../../src/server/routes/instance/httpapi/groups/instance"
import { SessionPaths } from "../../src/server/routes/instance/httpapi/groups/session"
import { ProjectV2 } from "@argos/core/project"
import { QuestionID } from "../../src/question/schema"
import { HttpApiApp } from "../../src/server/routes/instance/httpapi/server"
import { HEADER as FenceHeader } from "../../src/server/shared/fence"
import { resetDatabase } from "../fixture/db"
import { tmpdirScoped } from "../fixture/fixture"
import { testEffect } from "../lib/effect"

// Flip the experimental workspaces flag so EventV2.run actually writes to
// EventSequenceTable (the source of truth the fence middleware reads). Reset
// the database around the test so per-instance state does not leak between
// runs. resetDatabase() already calls disposeAllInstances(), so we don't
// repeat it.
const testStateLayer = Layer.effectDiscard(
  Effect.gen(function* () {
    const originalWorkspaces = Flag.ARGOS_EXPERIMENTAL_WORKSPACES
    Flag.ARGOS_EXPERIMENTAL_WORKSPACES = true
    yield* Effect.promise(() => resetDatabase())
    yield* Effect.addFinalizer(() =>
      Effect.promise(async () => {
        Flag.ARGOS_EXPERIMENTAL_WORKSPACES = originalWorkspaces
        await resetDatabase()
      }),
    )
  }),
)

// Mount the production HttpApi route tree on a real Node HTTP server bound to
// 127.0.0.1:0 and a fetch-based HttpClient that prepends the server URL. This
// keeps the test wired directly through the same route layer production uses.
const servedRoutes: Layer.Layer<never, Config.ConfigError, HttpServer.HttpServer> = HttpRouter.serve(
  HttpApiApp.routes,
  { disableListenLog: true, disableLogger: true },
)

const httpApiServerLayer = servedRoutes.pipe(
  Layer.provide(Socket.layerWebSocketConstructorGlobal),
  Layer.provideMerge(NodeHttpServer.layerTest),
  Layer.provideMerge(NodeServices.layer),
)

const it = testEffect(Layer.mergeAll(testStateLayer, httpApiServerLayer))
const handlerContext = Context.empty() as Context.Context<unknown>

const directoryHeader = (dir: string) => HttpClientRequest.setHeader("x-opencode-directory", dir)

describe("instance HttpApi", () => {
  it.live("serves the OpenAPI document", () =>
    Effect.gen(function* () {
      const response = yield* HttpClient.get("/doc")

      expect(response.status).toBe(200)
      expect(response.headers["content-type"]).toContain("application/json")
      expect(yield* response.json).toMatchObject({
        openapi: expect.any(String),
        info: expect.any(Object),
        paths: expect.objectContaining({
          "/global/health": expect.any(Object),
          "/session": expect.any(Object),
        }),
      })
    }),
  )

  it.live("emits a sync fence header for fixed-workspace mutations", () =>
    Effect.gen(function* () {
      const originalWorkspaceID = Flag.ARGOS_WORKSPACE_ID
      Flag.ARGOS_WORKSPACE_ID = WorkspaceV2.ID.ascending()
      yield* Effect.addFinalizer(() =>
        Effect.sync(() => {
          Flag.ARGOS_WORKSPACE_ID = originalWorkspaceID
        }),
      )

      const dir = yield* tmpdirScoped({ git: true })
      const response = yield* HttpClientRequest.post(SessionPaths.create).pipe(
        directoryHeader(dir),
        HttpClientRequest.bodyJson({ title: "fenced" }),
        Effect.flatMap(HttpClient.execute),
      )

      expect(response.status).toBe(200)
      expect(JSON.parse(response.headers[FenceHeader] ?? "{}")).not.toEqual({})
    }),
  )

  it.live("does not emit sync fence headers for fixed-workspace reads or no-op mutations", () =>
    Effect.gen(function* () {
      const originalWorkspaceID = Flag.ARGOS_WORKSPACE_ID
      Flag.ARGOS_WORKSPACE_ID = WorkspaceV2.ID.ascending()
      yield* Effect.addFinalizer(() =>
        Effect.sync(() => {
          Flag.ARGOS_WORKSPACE_ID = originalWorkspaceID
        }),
      )

      const dir = yield* tmpdirScoped({ git: true })
      const read = yield* HttpClientRequest.get(InstancePaths.path).pipe(directoryHeader(dir), HttpClient.execute)
      const log = yield* HttpClientRequest.post(ControlPaths.log).pipe(
        directoryHeader(dir),
        HttpClientRequest.bodyJson({ service: "fence-test", level: "info", message: "noop" }),
        Effect.flatMap(HttpClient.execute),
      )

      expect(read.status).toBe(200)
      expect(read.headers[FenceHeader]).toBeUndefined()
      expect(log.status).toBe(200)
      expect(log.headers[FenceHeader]).toBeUndefined()
    }),
  )

  it.live("rejects malformed permission and question request ids", () =>
    Effect.gen(function* () {
      const dir = yield* tmpdirScoped({ git: true })
      const request = (path: string, init?: RequestInit) =>
        Effect.promise(() =>
          HttpApiApp.webHandler().handler(
            new Request(`http://localhost${path}`, {
              ...init,
              headers: { "x-opencode-directory": dir, "content-type": "application/json", ...init?.headers },
            }),
            handlerContext,
          ),
        )
      const [permission, questionReply, questionReject] = yield* Effect.all(
        [
          request("/permission/invalid-permission-id/reply", {
            method: "POST",
            body: JSON.stringify({ reply: "once" }),
          }),
          request("/question/invalid-question-id/reply", {
            method: "POST",
            body: JSON.stringify({ answers: [["Yes"]] }),
          }),
          request("/question/invalid-question-id/reject", { method: "POST" }),
        ],
        { concurrency: "unbounded" },
      )

      expect(permission.status).toBe(400)
      expect(questionReply.status).toBe(400)
      expect(questionReject.status).toBe(400)
    }),
  )

  it.live("returns typed not found bodies for missing permission and question requests", () =>
    Effect.gen(function* () {
      const dir = yield* tmpdirScoped({ git: true })
      const request = (path: string, init?: RequestInit) =>
        Effect.promise(() =>
          HttpApiApp.webHandler().handler(
            new Request(`http://localhost${path}`, {
              ...init,
              headers: { "x-opencode-directory": dir, "content-type": "application/json", ...init?.headers },
            }),
            handlerContext,
          ),
        )
      const permissionID = PermissionV1.ID.ascending()
      const questionReplyID = QuestionID.ascending()
      const questionRejectID = QuestionID.ascending()
      const [permission, questionReply, questionReject] = yield* Effect.all(
        [
          request(`/permission/${permissionID}/reply`, {
            method: "POST",
            body: JSON.stringify({ reply: "once" }),
          }),
          request(`/question/${questionReplyID}/reply`, {
            method: "POST",
            body: JSON.stringify({ answers: [["Yes"]] }),
          }),
          request(`/question/${questionRejectID}/reject`, { method: "POST" }),
        ],
        { concurrency: "unbounded" },
      )

      expect(permission.status).toBe(404)
      expect(yield* Effect.promise(() => permission.json())).toEqual({
        _tag: "PermissionNotFoundError",
        requestID: permissionID,
        message: `Permission request not found: ${permissionID}`,
      })
      expect(questionReply.status).toBe(404)
      expect(yield* Effect.promise(() => questionReply.json())).toEqual({
        _tag: "QuestionNotFoundError",
        requestID: questionReplyID,
        message: `Question request not found: ${questionReplyID}`,
      })
      expect(questionReject.status).toBe(404)
      expect(yield* Effect.promise(() => questionReject.json())).toEqual({
        _tag: "QuestionNotFoundError",
        requestID: questionRejectID,
        message: `Question request not found: ${questionRejectID}`,
      })
    }),
  )

  it.live("returns typed not found bodies for missing projects", () =>
    Effect.gen(function* () {
      const dir = yield* tmpdirScoped({ git: true })
      const projectID = ProjectV2.ID.make("project_missing")
      const response = yield* Effect.promise(() =>
        HttpApiApp.webHandler().handler(
          new Request(`http://localhost/project/${projectID}`, {
            method: "PATCH",
            headers: { "x-opencode-directory": dir, "content-type": "application/json" },
            body: JSON.stringify({ name: "Missing" }),
          }),
          handlerContext,
        ),
      )

      expect(response.status).toBe(404)
      expect(yield* Effect.promise(() => response.json())).toEqual({
        _tag: "ProjectNotFoundError",
        projectID,
        message: `Project not found: ${projectID}`,
      })
    }),
  )

  it.live("serves path and VCS read endpoints", () =>
    Effect.gen(function* () {
      const dir = yield* tmpdirScoped({ git: true })
      const fs = yield* FileSystem.FileSystem
      const path = yield* Path.Path
      yield* fs.writeFileString(path.join(dir, "changed.txt"), "hello")

      const [paths, vcs, diff] = yield* Effect.all(
        [
          HttpClientRequest.get(InstancePaths.path).pipe(directoryHeader(dir), HttpClient.execute),
          HttpClientRequest.get(InstancePaths.vcs).pipe(directoryHeader(dir), HttpClient.execute),
          HttpClientRequest.get(InstancePaths.vcsDiff).pipe(
            HttpClientRequest.setUrlParam("mode", "git"),
            directoryHeader(dir),
            HttpClient.execute,
          ),
        ],
        { concurrency: "unbounded" },
      )

      expect(paths.status).toBe(200)
      expect(yield* paths.json).toMatchObject({ directory: dir, worktree: dir })

      expect(vcs.status).toBe(200)
      expect(yield* vcs.json).toMatchObject({ branch: expect.any(String) })

      expect(diff.status).toBe(200)
      expect(yield* diff.json).toContainEqual(
        expect.objectContaining({ file: "changed.txt", additions: 1, status: "added" }),
      )
    }),
  )

  it.live("finding retest over real HTTP fails closed without an isolated executor and is session-scoped", () =>
    Effect.gen(function* () {
      const dir = yield* tmpdirScoped({ git: true })
      const created = yield* HttpClientRequest.post(SessionPaths.create).pipe(
        directoryHeader(dir),
        HttpClientRequest.bodyJson({ title: "finding-retest-http" }),
        Effect.flatMap(HttpClient.execute),
      )
      expect(created.status).toBe(200)
      const session = (yield* created.json) as { id: string; projectID: string }

      let requests = 0
      const { server, port } = yield* Effect.promise(
        () =>
          new Promise<{ server: http.Server; port: number }>((resolve) => {
            const srv = http.createServer((_req, res) => {
              requests++
              res.writeHead(200, { "content-type": "text/plain" })
              res.end("ok")
            })
            srv.listen(0, "127.0.0.1", () => {
              const addr = srv.address()
              resolve({ server: srv, port: typeof addr === "object" && addr ? addr.port : 0 })
            })
          }),
      )
      yield* Effect.addFinalizer(() => Effect.sync(() => server.close()))

      const findingId = `find_http_${Date.now()}_${Math.random().toString(36).slice(2)}`
      yield* Effect.gen(function* () {
        const { db } = yield* Database.Service
        yield* db
          .update(SessionTable)
          .set({ scope_cidrs: ["127.0.0.1/32"] })
          .where(eq(SessionTable.id, SessionV2.ID.make(session.id)))
          .run()
          .pipe(Effect.orDie)
        yield* db
          .insert(FindingTable)
          .values({
            id: findingId,
            session_id: session.id,
            project_id: session.projectID,
            fingerprint: findingId,
            title: "SQL injection en /login",
            severity: "high",
            status: "open",
            source: "agent-reviewed",
            vector: `http://127.0.0.1:${port}/login`,
            target: `http://127.0.0.1:${port}/login`,
            evidence: {},
            tags: [],
            time_created: Date.now(),
            time_updated: Date.now(),
          })
          .run()
          .pipe(Effect.orDie)
      }).pipe(Effect.provide(Database.defaultLayer))

      const retestPath = FindingPaths.retest.replace(":sessionID", session.id).replace(":findingID", findingId)
      const retest = yield* HttpClientRequest.post(retestPath).pipe(directoryHeader(dir), HttpClient.execute)
      const retestBody = yield* retest.text
      expect(retest.status, retestBody).toBe(200)
      const result = JSON.parse(retestBody) as { checked: boolean; newStatus: string }
      expect(result.checked).toBe(false)
      expect(result.newStatus).toBe("open")
      expect(requests).toBe(0)
      expect(result.newStatus).not.toBe("verified")

      // Un findingID real bajo un sessionID que no lo posee no debe re-testearlo ni mutarlo.
      const otherSession = yield* HttpClientRequest.post(SessionPaths.create).pipe(
        directoryHeader(dir),
        HttpClientRequest.bodyJson({ title: "other-session" }),
        Effect.flatMap(HttpClient.execute),
      )
      const other = (yield* otherSession.json) as { id: string }
      const crossPath = FindingPaths.retest.replace(":sessionID", other.id).replace(":findingID", findingId)
      const cross = yield* HttpClientRequest.post(crossPath).pipe(directoryHeader(dir), HttpClient.execute)
      expect(cross.status).toBe(200)
      expect(yield* cross.json).toBeNull()

      const row = yield* Effect.gen(function* () {
        const { db } = yield* Database.Service
        return yield* db
          .select({ status: FindingTable.status })
          .from(FindingTable)
          .where(eq(FindingTable.id, findingId))
          .get()
          .pipe(Effect.orDie)
      }).pipe(Effect.provide(Database.defaultLayer))
      expect(row?.status).toBe("open")

      // GET findings de la sesión: el panel pide esto por cada sesión del árbol.
      const listPath = FindingPaths.list.replace(":sessionID", session.id)
      const listRes = yield* HttpClientRequest.get(listPath).pipe(directoryHeader(dir), HttpClient.execute)
      expect(listRes.status).toBe(200)
      const listBody = (yield* listRes.json) as { findings: Array<{ id: string; title: string }>; total: number }
      expect(listBody.total).toBe(1)
      expect(listBody.findings).toHaveLength(1)
      expect(listBody.findings[0].id).toBe(findingId)
      expect(listBody.findings[0].title).toBe("SQL injection en /login")

      // Una sesión sin hallazgos devuelve lista vacía (no 404).
      const emptyPath = FindingPaths.list.replace(":sessionID", other.id)
      const emptyRes = yield* HttpClientRequest.get(emptyPath).pipe(directoryHeader(dir), HttpClient.execute)
      expect(emptyRes.status).toBe(200)
      const emptyBody = (yield* emptyRes.json) as { findings: unknown[]; total: number }
      expect(emptyBody.total).toBe(0)
      expect(emptyBody.findings).toHaveLength(0)
    }),
  )

  it.live("persists operator finding status transitions in the audit chain", () =>
    Effect.gen(function* () {
      const dir = yield* tmpdirScoped({ git: true })
      const created = yield* HttpClientRequest.post(SessionPaths.create).pipe(
        directoryHeader(dir),
        HttpClientRequest.bodyJson({ title: "finding-status-http" }),
        Effect.flatMap(HttpClient.execute),
      )
      expect(created.status).toBe(200)
      const session = (yield* created.json) as { id: string; projectID: string }
      const findingId = `find_status_${Date.now()}_${Math.random().toString(36).slice(2)}`

      yield* Effect.gen(function* () {
        const { db } = yield* Database.Service
        yield* db
          .insert(FindingTable)
          .values({
            id: findingId,
            session_id: session.id,
            project_id: session.projectID,
            fingerprint: findingId,
            title: "SQL injection in login",
            severity: "high",
            status: "open",
            source: "memory",
            evidence: {},
            tags: [],
            time_created: Date.now(),
            time_updated: Date.now(),
          })
          .run()
          .pipe(Effect.orDie)
      }).pipe(Effect.provide(Database.defaultLayer))

      const statusPath = FindingPaths.status.replace(":sessionID", session.id).replace(":findingID", findingId)
      const response = yield* HttpClientRequest.post(statusPath).pipe(
        directoryHeader(dir),
        HttpClientRequest.bodyJson({ status: "verified" }),
        Effect.flatMap(HttpClient.execute),
      )
      const responseBody = yield* response.text
      expect(response.status, responseBody).toBe(200)
      expect(JSON.parse(responseBody)).toEqual({ ok: true })

      const auditEntries = yield* Effect.gen(function* () {
        const { db } = yield* Database.Service
        return yield* db
          .select()
          .from(AuditLogTable)
          .where(eq(AuditLogTable.target, findingId))
          .all()
          .pipe(Effect.orDie)
      }).pipe(Effect.provide(Database.defaultLayer))

      expect(auditEntries).toHaveLength(1)
      expect(auditEntries[0]).toMatchObject({
        session_id: session.id,
        project_id: session.projectID,
        event_type: "finding.status",
        action: "finding.status.updated",
        agent: "human",
        target: findingId,
      })
      expect(JSON.parse(auditEntries[0].payload)).toMatchObject({
        findingID: findingId,
        fromStatus: "open",
        toStatus: "verified",
        actor: "human",
      })
    }),
  )

  it.live("project webhook test dispatch reaches the configured URL", () =>
    Effect.gen(function* () {
      const dir = yield* tmpdirScoped({ git: true })
      const current = yield* HttpClientRequest.get(InstancePaths.path).pipe(directoryHeader(dir), HttpClient.execute)
      expect(current.status).toBe(200)
      const path = (yield* current.json) as { directory: string }

      const projectRes = yield* HttpClientRequest.get("/project/current").pipe(
        directoryHeader(path.directory),
        HttpClient.execute,
      )
      expect(projectRes.status).toBe(200)
      const project = (yield* projectRes.json) as { id: string }

      let received: unknown
      const { server, port } = yield* Effect.promise(
        () =>
          new Promise<{ server: http.Server; port: number }>((resolve) => {
            const srv = http.createServer((req, res) => {
              const chunks: Buffer[] = []
              req.on("data", (c) => chunks.push(c))
              req.on("end", () => {
                received = JSON.parse(Buffer.concat(chunks).toString("utf-8"))
                res.writeHead(200, { "content-type": "application/json" })
                res.end(JSON.stringify({ ok: true }))
              })
            })
            srv.listen(0, "127.0.0.1", () => {
              const addr = srv.address()
              resolve({ server: srv, port: typeof addr === "object" && addr ? addr.port : 0 })
            })
          }),
      )
      yield* Effect.addFinalizer(() => Effect.sync(() => server.close()))

      const testPath = `/project/${project.id}/webhook/test`
      const response = yield* HttpClientRequest.post(testPath).pipe(
        directoryHeader(dir),
        HttpClientRequest.bodyJson({ url: `http://127.0.0.1:${port}/hook`, format: "generic" }),
        Effect.flatMap(HttpClient.execute),
      )

      expect(response.status).toBe(200)
      const result = (yield* response.json) as { ok: boolean; statusCode: number }
      expect(result.ok).toBe(true)
      expect(result.statusCode).toBe(200)
      expect(received).toMatchObject({ event: "argos.findings.dispatched", count: 1 })
    }),
  )
})
