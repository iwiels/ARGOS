import { describe, expect, test } from "bun:test"
import { Effect, Layer } from "effect"
import { Audit } from "@argos/core/audit"
import { truncatePayload } from "@argos/core/audit/service"
import { AuditLogTable } from "@argos/core/audit/sql"
import { Database } from "@argos/core/database/database"
import { Project } from "@argos/core/project"
import { ProjectTable } from "@argos/core/project/sql"
import { SessionV2 } from "@argos/core/session"
import { SessionTable } from "@argos/core/session/sql"
import { AbsolutePath } from "@argos/core/schema"
import { eq, sql } from "drizzle-orm"
import { testEffect } from "./lib/effect"

const database = Database.layerFromPath(":memory:")
const audit = Audit.layer.pipe(Layer.provideMerge(database))
const it = testEffect(audit)

describe("Audit", () => {
  it.effect("appends hash-chained entries with monotonic seq", () =>
    Effect.gen(function* () {
      const service = yield* Audit.Service
      const first = yield* service.append({
        sessionID: SessionV2.ID.make("ses_one"),
        eventType: "session.created",
        action: "session.create",
        agent: "analyst",
        summary: "Session created",
        payload: { title: "Audit test" },
      })
      const second = yield* service.append({
        sessionID: SessionV2.ID.make("ses_one"),
        eventType: "tool.executed",
        action: "web.scan",
        agent: "analyst",
        summary: "Tool web.scan completed",
        payload: { status: "completed" },
      })

      expect(first.seq).toBe(1)
      expect(second.seq).toBe(2)
      expect(first.prev_hash).toBe("")
      expect(second.prev_hash).toBe(first.hash)
      expect(second.hash).not.toBe(first.hash)
      expect(second.hash).toMatch(/^[a-f0-9]{64}$/)
    }),
  )

  it.effect("verifies an intact chain", () =>
    Effect.gen(function* () {
      const service = yield* Audit.Service
      yield* service.append({ eventType: "session.created", action: "session.create", summary: "one" })
      yield* service.append({ eventType: "tool.executed", action: "web.scan", summary: "two" })
      yield* service.append({ eventType: "tool.executed", action: "es.search", summary: "three" })

      expect(yield* service.verify()).toEqual({ valid: true, total: 3 })
    }),
  )

  it.effect("detects an out-of-chain row inserted by direct SQL", () =>
    Effect.gen(function* () {
      const service = yield* Audit.Service
      yield* service.append({ eventType: "session.created", action: "session.create", summary: "one" })
      yield* service.append({ eventType: "tool.executed", action: "web.scan", summary: "two" })

      const { db } = yield* Database.Service
      yield* db
        .run(sql`INSERT INTO ${AuditLogTable} (id, seq, event_type, action, summary, payload, prev_hash, hash, time_created)
                VALUES ('aud_tampered', 999, 'tampered', 'tamper', 'x', '{}', 'deadbeef', 'deadbeef', 0)`)
        .pipe(Effect.orDie)

      expect(yield* service.verify()).toEqual({ valid: false, total: 3, firstInvalidSeq: 999 })
    }),
  )

  it.effect("rejects UPDATE and DELETE via immutable triggers", () =>
    Effect.gen(function* () {
      const service = yield* Audit.Service
      yield* service.append({ eventType: "session.created", action: "session.create", summary: "one" })
      const { db } = yield* Database.Service

      const update = yield* db
        .run(sql`UPDATE ${AuditLogTable} SET summary = 'tampered' WHERE seq = 1`)
        .pipe(Effect.exit)
      expect(update._tag).toBe("Failure")

      const remove = yield* db.run(sql`DELETE FROM ${AuditLogTable} WHERE seq = 1`).pipe(Effect.exit)
      expect(remove._tag).toBe("Failure")
    }),
  )

  it.effect("detects in-place mutation once immutability triggers are dropped", () =>
    Effect.gen(function* () {
      const service = yield* Audit.Service
      yield* service.append({ eventType: "session.created", action: "session.create", summary: "one" })
      yield* service.append({ eventType: "tool.executed", action: "web.scan", summary: "two" })
      yield* service.append({ eventType: "tool.executed", action: "es.search", summary: "three" })

      const { db } = yield* Database.Service
      // Modelo de amenaza: un atacante con escritura directa al SQLite puede
      // desactivar los triggers antes de mutar. El recompute de sha256 debe
      // detectar la entrada alterada sin importar cómo se cambió.
      yield* db.run(sql`DROP TRIGGER audit_log_immutable_update`).pipe(Effect.orDie)
      yield* db.run(sql`UPDATE ${AuditLogTable} SET summary = 'looks-legit' WHERE seq = 2`).pipe(Effect.orDie)

      expect(yield* service.verify()).toEqual({ valid: false, total: 3, firstInvalidSeq: 2 })
    }),
  )

  it.effect("getSummary reports a cheap integrity check that fails on sequence gaps", () =>
    Effect.gen(function* () {
      const service = yield* Audit.Service
      yield* service.append({ eventType: "tool.executed", action: "web.scan", agent: "analyst", summary: "one" })
      yield* service.append({ eventType: "tool.error", action: "es.search", agent: "analyst", summary: "two" })

      const { db } = yield* Database.Service
      yield* db
        .run(sql`INSERT INTO ${AuditLogTable} (id, seq, event_type, action, summary, payload, prev_hash, hash, time_created)
                VALUES ('aud_gap', 999, 'tampered', 'tamper', 'x', '{}', 'deadbeef', 'deadbeef', 0)`)
        .pipe(Effect.orDie)

      const summary = yield* service.getSummary()
      expect(summary.integrity.valid).toBe(false)
      expect(summary.integrity.verified).toBe(false)
      expect(summary.integrity.total).toBe(3)

      const analyst = summary.agents.find((agent) => agent.agent === "analyst")
      expect(analyst?.total).toBe(2)
      expect(analyst?.completed).toBe(1)
      expect(analyst?.errors).toBe(1)
      expect(analyst?.topTools.map((tool) => tool.tool).sort()).toEqual(["es.search", "web.scan"])
    }),
  )

  it.effect("lists entries newest-first and filters by session", () =>
    Effect.gen(function* () {
      const service = yield* Audit.Service
      const sessionA = SessionV2.ID.make("ses_a")
      const sessionB = SessionV2.ID.make("ses_b")
      yield* service.append({ sessionID: sessionA, eventType: "session.created", action: "session.create", summary: "a" })
      yield* service.append({ sessionID: sessionB, eventType: "session.created", action: "session.create", summary: "b" })
      yield* service.append({ sessionID: sessionA, eventType: "tool.executed", action: "web.scan", summary: "a2" })

      const all = yield* service.list()
      expect(all.total).toBe(3)
      expect(all.items.map((item) => item.seq)).toEqual([3, 2, 1])

      const filtered = yield* service.list({ sessionID: sessionA })
      expect(filtered.total).toBe(2)
      expect(filtered.items.map((item) => item.seq)).toEqual([3, 1])
    }),
  )

  it.effect("resolves the project id from the session when not provided", () =>
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
          id: SessionV2.ID.make("ses_project"),
          project_id: Project.ID.global,
          slug: "audit",
          directory: "/project",
          title: "audit",
          version: "test",
          agent: "analyst",
        })
        .run()
        .pipe(Effect.orDie)

      const service = yield* Audit.Service
      const entry = yield* service.append({
        sessionID: SessionV2.ID.make("ses_project"),
        eventType: "session.created",
        action: "session.create",
        summary: "resolved",
      })

      expect(entry.project_id).toBe(Project.ID.global)
      const row = yield* db
        .select()
        .from(AuditLogTable)
        .where(eq(AuditLogTable.id, entry.id))
        .get()
        .pipe(Effect.orDie)
      expect(row?.project_id).toBe(Project.ID.global)
    }),
  )
})

describe("truncatePayload", () => {
  test("keeps payloads within the limit untouched", () => {
    const value = JSON.stringify({ evidence: "banner" })
    expect(truncatePayload(value)).toBe(value)
  })

  test("truncates oversized payloads with an explicit marker", () => {
    const value = "x".repeat(9000)
    const truncated = truncatePayload(value)
    expect(truncated.length).toBeLessThan(value.length + 100)
    expect(truncated).toContain("[truncated: omitted 1000 chars]")
  })
})
