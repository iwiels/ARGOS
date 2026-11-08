import { describe, expect } from "bun:test"
import { eq } from "drizzle-orm"
import { Effect, Layer } from "effect"
import { Database } from "@argos/core/database/database"
import { Project } from "@argos/core/project"
import { ProjectTable } from "@argos/core/project/sql"
import { SessionV2 } from "@argos/core/session"
import { SessionTable } from "@argos/core/session/sql"
import { FindingTable } from "@argos/core/security/sql"
import { retestFinding, type RetestHttpExecutor } from "@argos/core/security/retest"
import * as ScopeService from "@argos/core/security/scope-service"
import { AbsolutePath } from "@argos/core/schema"
import { testEffect } from "./lib/effect"

const SESSION_ID = SessionV2.ID.make("ses_retest_scope_test")

const database = Database.layerFromPath(":memory:")
const scope = ScopeService.layer.pipe(Layer.provide(database))
const it = testEffect(Layer.mergeAll(database, scope))

const fixtureExecutor: RetestHttpExecutor = async (request) => {
  expect(request.sessionId).toBe(SESSION_ID)
  expect(request.url).toBe("https://app.allowed.test/login")
  expect(request.redirect).toBe("manual")
  expect(request.timeoutMs).toBe(6000)
  expect(request.maxResponseBytes).toBe(1 << 20)
  return undefined
}

const seed = (input: { id: string; vector: string; status?: string; domains?: string[] }) =>
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
        id: SESSION_ID,
        project_id: Project.ID.global,
        slug: SESSION_ID,
        directory: "/project",
        title: "retest scope test",
        version: "test",
        scope_domains: input.domains ?? ["*.allowed.test"],
      })
      .onConflictDoNothing()
      .run()
      .pipe(Effect.orDie)
    yield* db
      .insert(FindingTable)
      .values({
        id: input.id,
        session_id: SESSION_ID,
        project_id: Project.ID.global,
        fingerprint: input.id,
        title: "Missing HSTS header",
        severity: "medium",
        status: input.status ?? "open",
        source: "memory",
        vector: input.vector,
        target: input.vector,
        evidence: {},
        tags: [],
        time_created: Date.now(),
        time_updated: Date.now(),
      })
      .onConflictDoNothing()
      .run()
      .pipe(Effect.orDie)
  })

const statusOf = (id: string) =>
  Effect.gen(function* () {
    const { db } = yield* Database.Service
    const row = yield* db
      .select({ status: FindingTable.status })
      .from(FindingTable)
      .where(eq(FindingTable.id, id))
      .get()
      .pipe(Effect.orDie)
    return row?.status
  })

describe("retestFinding — gate de scope sobre el vector del hallazgo", () => {
  it.effect(
    "un vector fuera de scope NO se re-testea: checked=false y el estado no se mueve",
    () =>
      Effect.gen(function* () {
        yield* seed({
          id: "find-out-of-scope",
          vector: "http://attacker.example.net/steal",
          status: "open",
        })

        const { db } = yield* Database.Service
        const result = yield* retestFinding(db, "find-out-of-scope", SESSION_ID, fixtureExecutor)

        expect(result).toBeDefined()
        expect(result?.checked).toBe(false)
        expect(result?.stillVulnerable).toBe(false)
        // El status NO cambia: un target no autorizado no puede empujar el
        // hallazgo a "verified" ni a "open".
        expect(result?.previousStatus).toBe("open")
        expect(result?.newStatus).toBe("open")
        expect(result?.newStatus).toBe(result?.previousStatus)
        expect(result?.message.toLowerCase()).toContain("scope")

        // Y el estado persistido sigue siendo el original.
        expect(yield* statusOf("find-out-of-scope")).toBe("open")
      }),
    { timeout: 15000 },
  )

  it.effect(
    "un target privado (metadata de nube) fuera de scope tampoco se re-testea",
    () =>
      Effect.gen(function* () {
        yield* seed({
          id: "find-metadata",
          vector: "http://169.254.169.254/latest/meta-data/",
          status: "in-progress",
          domains: ["*.allowed.test"],
        })

        const { db } = yield* Database.Service
        const result = yield* retestFinding(db, "find-metadata", SESSION_ID, fixtureExecutor)

        expect(result?.checked).toBe(false)
        expect(result?.newStatus).toBe("in-progress")
        expect(result?.message.toLowerCase()).toContain("scope")
        expect(yield* statusOf("find-metadata")).toBe("in-progress")
      }),
    { timeout: 15000 },
  )

  it.effect(
    "un vector dentro del scope se re-testea con normalidad",
    () =>
      Effect.gen(function* () {
        yield* seed({
          id: "find-in-scope",
          vector: "https://app.allowed.test/login",
          status: "open",
        })

        const { db } = yield* Database.Service
        const result = yield* retestFinding(db, "find-in-scope", SESSION_ID, fixtureExecutor)

        expect(result).toBeDefined()
        expect(result?.checked).toBe(false)
        // El target está autorizado pero no hay evidencia: el hallazgo queda
        // "in-progress" como en cualquier caso sin verificación automática.
        expect(result?.newStatus).toBe("in-progress")
        expect(result?.message.toLowerCase()).not.toContain("fuera del scope")
      }),
    { timeout: 15000 },
  )
})
