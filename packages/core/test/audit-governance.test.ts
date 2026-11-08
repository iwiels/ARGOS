import { describe, expect } from "bun:test"
import { sql } from "drizzle-orm"
import { Effect, Layer } from "effect"
import { Audit } from "@argos/core/audit"
import { AuditLogTable } from "@argos/core/audit/sql"
import { Database } from "@argos/core/database/database"
import { testEffect } from "./lib/effect"

const database = Database.layerFromPath(":memory:")
const audit = Audit.layer.pipe(Layer.provideMerge(database))
const it = testEffect(audit)

describe("Audit.getSummary (governance)", () => {
  it.effect("reports integrity, per-agent metrics and top tools", () =>
    Effect.gen(function* () {
      const service = yield* Audit.Service
      yield* service.append({ eventType: "session.created", action: "session.create", agent: "analyst", summary: "one" })
      yield* service.append({ eventType: "tool.executed", action: "web.scan", agent: "analyst", summary: "scan ok" })
      yield* service.append({ eventType: "tool.executed", action: "web.scan", agent: "analyst", summary: "scan ok" })
      yield* service.append({ eventType: "tool.error", action: "es.search", agent: "hunter", summary: "es failed" })
      yield* service.append({ eventType: "tool.executed", action: "es.search", agent: "hunter", summary: "es ok" })

      const summary = yield* service.getSummary()
      expect(summary.integrity.valid).toBe(true)
      expect(summary.integrity.total).toBe(5)
      expect(summary.integrity.verified).toBe(false)
      expect(summary.activity.total).toBe(5)
      expect(summary.activity.lastEntryAt).toBeGreaterThan(0)

      const analyst = summary.agents.find((agent) => agent.agent === "analyst")
      expect(analyst?.total).toBe(3)
      expect(analyst?.completed).toBe(2)
      expect(analyst?.errors).toBe(0)
      expect(analyst?.topTools[0]).toEqual({ tool: "web.scan", count: 2 })

      const hunter = summary.agents.find((agent) => agent.agent === "hunter")
      expect(hunter?.total).toBe(2)
      expect(hunter?.errors).toBe(1)
      expect(hunter?.topTools[0]).toEqual({ tool: "es.search", count: 2 })

      const toolEvent = summary.events.find((event) => event.eventType === "tool.executed")
      expect(toolEvent?.count).toBe(3)
      const errorEvent = summary.events.find((event) => event.eventType === "tool.error")
      expect(errorEvent?.count).toBe(1)
    }),
  )

  it.effect("sorts agents by volume and buckets unknown agents", () =>
    Effect.gen(function* () {
      const service = yield* Audit.Service
      yield* service.append({ eventType: "tool.executed", action: "a", agent: "triage", summary: "x" })
      yield* service.append({ eventType: "tool.executed", action: "a", agent: "triage", summary: "x" })
      yield* service.append({ eventType: "tool.executed", action: "b", summary: "x" })
      yield* service.append({ eventType: "tool.executed", action: "a", agent: "triage", summary: "x" })
      yield* service.append({ eventType: "tool.executed", action: "b", agent: "triage", summary: "x" })

      const summary = yield* service.getSummary()
      expect(summary.agents[0]?.agent).toBe("triage")
      expect(summary.agents[0]?.total).toBe(4)
      expect(summary.agents[1]?.agent).toBe("unknown")
      expect(summary.agents[1]?.total).toBe(1)
    }),
  )

  it.effect("flags a broken chain with the cheap contiguity check", () =>
    Effect.gen(function* () {
      const service = yield* Audit.Service
      yield* service.append({ eventType: "session.created", action: "session.create", summary: "one" })
      yield* service.append({ eventType: "tool.executed", action: "web.scan", summary: "two" })
      // Forzar corrupción vía SQL directo: insertar una fila fuera de cadena (seq 999, hash fake).
      const { db } = yield* Database.Service
      yield* db
        .run(sql`INSERT INTO ${AuditLogTable} (id, seq, event_type, action, summary, payload, prev_hash, hash, time_created)
                VALUES ('aud_tampered', 999, 'tampered', 'tamper', 'x', '{}', 'deadbeef', 'deadbeef', 0)`)
        .pipe(Effect.orDie)

      // El summary usa el chequeo barato (count === max seq): detecta la anomalía sin recomputar sha256.
      const summary = yield* service.getSummary()
      expect(summary.integrity.valid).toBe(false)
      expect(summary.integrity.total).toBe(3)
      expect(summary.integrity.verified).toBe(false)

      // La verificación criptográfica completa sí reporta el eslabón exacto.
      expect(yield* service.verify()).toEqual({ valid: false, total: 3, firstInvalidSeq: 999 })
    }),
  )
})
