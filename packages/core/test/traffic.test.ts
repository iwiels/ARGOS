import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import path from "node:path"
import { describe, expect, test } from "bun:test"
import { Effect } from "effect"
import { Database } from "@argos/core/database/database"
import { Project } from "@argos/core/project"
import { ProjectTable } from "@argos/core/project/sql"
import { SessionV2 } from "@argos/core/session"
import { SessionTable } from "@argos/core/session/sql"
import { TrafficExchangeTable } from "@argos/core/security/sql"
import {
  diffTrafficExchangePair,
  listTrafficExchanges,
  reconcileTrafficStore,
  trafficSessionDir,
  getTrafficExchange,
} from "@argos/core/security/traffic"
import { AbsolutePath } from "@argos/core/schema"
import { eq } from "drizzle-orm"
import { testEffect } from "./lib/effect"

/**
 * The traffic store is written by the Go binary (`argos-bin/internal/traffic`)
 * and read by the backend. These tests reproduce the exact on-disk shape so
 * the contract between both sides stays verified.
 */
const SESSION_ID = SessionV2.ID.make("ses_traffic_store")

const database = Database.layerFromPath(":memory:")
const it = testEffect(database)

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
      slug: "traffic-store",
      directory: "/project",
      title: "traffic store test",
      version: "test",
    })
    .onConflictDoNothing()
    .run()
    .pipe(Effect.orDie)
})

/** An exchange exactly as the Go store writes it. */
const storedExchange = (overrides: Record<string, unknown> = {}) => ({
  id: "ex_0000000000000001",
  session_id: SESSION_ID,
  timestamp: "2026-10-21T10:00:00Z",
  method: "GET",
  url: "https://example.com/login",
  host: "example.com",
  request_headers: { Accept: ["*/*"], Authorization: ["Bearer ***"] },
  request_body: { text: "user=admin&password=[REDACTED]", sha256: "abc123", size: 30 },
  status: 200,
  response_headers: { "Content-Type": ["text/html"] },
  response_body: { text: "<html>ok</html>", sha256: "def456", size: 15 },
  duration_ms: 42,
  source_tool: "web.probe",
  target: "https://example.com/login",
  scope_allowed: true,
  ...overrides,
})

/** Writes the traffic store of a session, as the Go binary does. */
const makeStore = (exchanges: Array<Record<string, unknown>>) =>
  Effect.promise(async () => {
    const memoryDir = await mkdtemp(path.join(tmpdir(), "argos-traffic-store-"))
    const dir = trafficSessionDir(memoryDir, SESSION_ID)
    await mkdir(dir, { recursive: true })
    await Promise.all(
      exchanges.map((exchange, index) =>
        writeFile(path.join(dir, `ex_${index}.json`), JSON.stringify(exchange)),
      ),
    )
    return memoryDir
  })

const cleanup = (dir: string) => Effect.promise(() => rm(dir, { recursive: true, force: true }))

const rowsFor = (sessionID: string) =>
  Effect.gen(function* () {
    const { db } = yield* Database.Service
    return yield* db.select().from(TrafficExchangeTable).where(eq(TrafficExchangeTable.session_id, sessionID)).all().pipe(Effect.orDie)
  })

describe("traffic store", () => {
  it.effect("the table is populated from the on-disk store", () =>
    Effect.gen(function* () {
      yield* seed
      const { db } = yield* Database.Service
      const memoryDir = yield* makeStore([storedExchange()])

      const result = yield* reconcileTrafficStore(db, { sessionID: SESSION_ID, memoryDir })
      expect(result).toMatchObject({ scanned: 1, inserted: 1, updated: 0 })

      const rows = yield* rowsFor(SESSION_ID)
      expect(rows).toHaveLength(1)
      expect(rows[0]).toMatchObject({
        id: "ex_0000000000000001",
        method: "GET",
        url: "https://example.com/login",
        host: "example.com",
        status: 200,
        duration_ms: 42,
        source_tool: "web.probe",
        scope_allowed: true,
        response_body: "<html>ok</html>",
        response_body_sha256: "def456",
      })

      // The credentials never reach the database in clear: the store already
      // masked them.
      expect(JSON.stringify(rows[0])).not.toContain("Bearer ey")

      yield* cleanup(memoryDir)
    }),
  )

  it.effect("reconciling twice does not duplicate the exchanges", () =>
    Effect.gen(function* () {
      yield* seed
      const { db } = yield* Database.Service
      const memoryDir = yield* makeStore([storedExchange()])

      yield* reconcileTrafficStore(db, { sessionID: SESSION_ID, memoryDir })
      const second = yield* reconcileTrafficStore(db, { sessionID: SESSION_ID, memoryDir })

      expect(second).toMatchObject({ scanned: 1, inserted: 0, updated: 1 })
      expect(yield* rowsFor(SESSION_ID)).toHaveLength(1)

      yield* cleanup(memoryDir)
    }),
  )

  it.effect("the API lists the exchanges of the session with its filters", () =>
    Effect.gen(function* () {
      yield* seed
      const { db } = yield* Database.Service
      const memoryDir = yield* makeStore([
        storedExchange(),
        storedExchange({
          id: "ex_0000000000000002",
          method: "POST",
          url: "https://example.com/api",
          host: "example.com",
          status: 404,
          source_tool: "web.tls",
          timestamp: "2026-10-21T10:05:00Z",
        }),
        storedExchange({
          id: "ex_0000000000000003",
          url: "https://other.test/",
          host: "other.test",
          status: 500,
          source_tool: "web.fuzz",
          timestamp: "2026-10-21T10:10:00Z",
        }),
      ])
      yield* reconcileTrafficStore(db, { sessionID: SESSION_ID, memoryDir })

      const all = yield* listTrafficExchanges(db, { sessionID: SESSION_ID })
      expect(all.total).toBe(3)
      expect(all.data).toHaveLength(3)

      const byMethod = yield* listTrafficExchanges(db, {
        sessionID: SESSION_ID,
        filter: { method: "POST" },
      })
      expect(byMethod.total).toBe(1)
      expect(byMethod.data[0]?.id).toBe("ex_0000000000000002")

      const byTool = yield* listTrafficExchanges(db, {
        sessionID: SESSION_ID,
        filter: { sourceTool: "web.fuzz" },
      })
      expect(byTool.total).toBe(1)
      expect(byTool.data[0]?.host).toBe("other.test")

      const byStatus = yield* listTrafficExchanges(db, {
        sessionID: SESSION_ID,
        filter: { status: "5xx" },
      })
      expect(byStatus.total).toBe(1)
      expect(byStatus.data[0]?.status).toBe(500)

      const byHost = yield* listTrafficExchanges(db, {
        sessionID: SESSION_ID,
        filter: { host: "example.com" },
      })
      expect(byHost.total).toBe(2)

      yield* cleanup(memoryDir)
    }),
  )

  it.effect("the API reads one exchange of the session", () =>
    Effect.gen(function* () {
      yield* seed
      const { db } = yield* Database.Service
      const memoryDir = yield* makeStore([storedExchange()])
      yield* reconcileTrafficStore(db, { sessionID: SESSION_ID, memoryDir })

      const exchange = yield* getTrafficExchange(db, {
        sessionID: SESSION_ID,
        exchangeID: "ex_0000000000000001",
      })
      expect(exchange?.url).toBe("https://example.com/login")
      expect(exchange?.responseHeaders["Content-Type"]).toEqual(["text/html"])

      const missing = yield* getTrafficExchange(db, {
        sessionID: SESSION_ID,
        exchangeID: "ex_missing",
      })
      expect(missing).toBeUndefined()

      yield* cleanup(memoryDir)
    }),
  )

  it.effect("the diff of two exchanges detects the status, the headers and the body", () =>
    Effect.sync(() => {
    const a = {
      id: "a",
      sessionID: SESSION_ID,
      timestamp: 0,
      method: "GET",
      url: "https://example.com/",
      host: "example.com",
      status: 200,
      durationMs: 0,
      sourceTool: "web.probe",
      target: "",
      scopeAllowed: true,
      requestHeaders: {},
      responseHeaders: { "Content-Type": ["text/html"] },
      requestBody: "",
      responseBody: "line1\nline2",
      requestBodySHA256: "",
      responseBodySHA256: "hash-a",
      requestBodySize: 0,
      responseBodySize: 0,
    }
    const b = {
      ...a,
      id: "b",
      status: 500,
      responseHeaders: { "Content-Type": ["application/json"], "X-New": ["1"] },
      responseBody: "line1\nline changed",
      responseBodySHA256: "hash-b",
    }

    const diff = diffTrafficExchangePair(a, b)
    expect(diff.statusChanged).toBe(true)
    expect(diff.statusA).toBe(200)
    expect(diff.statusB).toBe(500)
    expect(diff.bodyChanged).toBe(true)
    expect(diff.headersAdded.map((h) => h.name)).toEqual(["x-new"])
    expect(diff.headersChanged.map((h) => h.name)).toEqual(["content-type"])
    expect(diff.identical).toBe(false)
    expect(diff.bodyDiff).toContain("-line2")
    expect(diff.bodyDiff).toContain("+line changed")
    expect(diff.bodyLinesAdded).toBe(1)
    expect(diff.bodyLinesRemoved).toBe(1)
    }),
  )

  it.effect("a session without a traffic store reconciles to nothing", () =>
    Effect.gen(function* () {
      yield* seed
      const { db } = yield* Database.Service
      const memoryDir = yield* Effect.promise(() => mkdtemp(path.join(tmpdir(), "argos-traffic-empty-")))

      const result = yield* reconcileTrafficStore(db, { sessionID: SESSION_ID, memoryDir })
      expect(result).toMatchObject({ scanned: 0, inserted: 0, updated: 0 })
      expect(yield* rowsFor(SESSION_ID)).toHaveLength(0)

      yield* cleanup(memoryDir)
    }),
  )
})
