import { afterEach, describe, expect } from "bun:test"
import { eq } from "drizzle-orm"
import { Effect, Layer } from "effect"
import { Audit } from "@argos/core/audit"
import { AuditLogTable } from "@argos/core/audit/sql"
import { Database } from "@argos/core/database/database"
import { FindingTable } from "@argos/core/security/sql"
import { CrossSpawnSpawner } from "@argos/core/cross-spawn-spawner"
import { Agent } from "../../src/agent/agent"
import { BackgroundJob } from "@/background/job"
import { Config } from "@/config/config"
import { EventBridge } from "@/event-bridge"
import { Session } from "@/session/session"
import { SessionRunState } from "@/session/run-state"
import { SessionStatus } from "@/session/status"
import { Truncate } from "@/tool/truncate"
import { ToolRegistry } from "@/tool/registry"
import { RuntimeFlags } from "@/effect/runtime-flags"
import { MessageID, type SessionID } from "../../src/session/schema"
import { FindingStatusTool } from "../../src/tool/finding-status"
import { disposeAllInstances } from "../fixture/fixture"
import { testEffect } from "../lib/effect"

afterEach(async () => {
  await disposeAllInstances()
})

const layer = Layer.mergeAll(
  Agent.defaultLayer,
  BackgroundJob.defaultLayer,
  EventBridge.defaultLayer,
  Config.defaultLayer,
  CrossSpawnSpawner.defaultLayer,
  Session.defaultLayer,
  SessionRunState.defaultLayer,
  SessionStatus.defaultLayer,
  Audit.defaultLayer,
  Truncate.defaultLayer,
  ToolRegistry.defaultLayer,
  Database.defaultLayer,
  RuntimeFlags.layer({}),
)

const it = testEffect(layer)

/** Inserta un hallazgo mínimo en la sesión dada y devuelve su id. */
const seedFinding = Effect.fn("FindingStatusTest.seedFinding")(function* (input: {
  sessionID: string
  projectID: string
  id: string
  status?: string
}) {
  const { db } = yield* Database.Service
  const now = Date.now()
  yield* db
    .insert(FindingTable)
    .values({
      id: input.id,
      session_id: input.sessionID,
      project_id: input.projectID,
      fingerprint: `fp-${input.id}`,
      title: "Credenciales hardcodeadas",
      severity: "high",
      status: input.status ?? "open",
      source: "memory",
      evidence: { note: "conninfo con password en el historial" },
      tags: ["hardcoded-secret"],
      time_created: now,
      time_updated: now,
    })
    .run()
    .pipe(Effect.orDie)
  return input.id
})

const readStatus = Effect.fn("FindingStatusTest.readStatus")(function* (id: string) {
  const { db } = yield* Database.Service
  const row = yield* db
    .select({ status: FindingTable.status })
    .from(FindingTable)
    .where(eq(FindingTable.id, id))
    .get()
    .pipe(Effect.orDie)
  return row?.status
})

function context(sessionID: SessionID) {
  return {
    sessionID,
    messageID: MessageID.ascending(),
    agent: "build",
    abort: new AbortController().signal,
    messages: [],
    metadata: () => Effect.void,
    ask: () => Effect.void,
  }
}

describe("tool.finding_status", () => {
  it.instance("queda registrada en el registry, que es lo que ven los agentes", () =>
    Effect.gen(function* () {
      const registry = yield* ToolRegistry.Service
      expect(yield* registry.ids()).toContain("finding_status")
    }),
  )

  it.instance("registra la procedencia y no confunde el veredicto del agente con una verificación independiente", () =>
    Effect.gen(function* () {
      const sessions = yield* Session.Service
      const chat = yield* sessions.create({ title: "Auditoría" })
      yield* seedFinding({ sessionID: chat.id, projectID: chat.projectID, id: "finding-1" })
      const audit = yield* Audit.Service

      const def = yield* (yield* FindingStatusTool).init()
      const result = yield* def.execute(
        { findingID: "finding-1", status: "verified", rationale: "El secreto fue rotado y ya no aparece en el head." },
        context(chat.id),
      )

      expect(yield* readStatus("finding-1")).toBe("remediated")
      expect(result.metadata.previousStatus).toBe("open")
      expect(result.metadata.newStatus).toBe("remediated")
      expect(result.output).toContain("El secreto fue rotado")
      expect(result.output).toContain("verificación independiente")

      const entries = yield* audit.list({ sessionID: chat.id })
      expect(entries.total).toBe(1)
      expect(entries.items[0]).toMatchObject({
        session_id: chat.id,
        event_type: "finding.validation.agent_report",
        action: "finding.status.agent_reported",
        agent: "build",
        target: "finding-1",
      })
      expect(JSON.parse(entries.items[0].payload)).toMatchObject({
        requestedStatus: "verified",
        persistedStatus: "remediated",
        rationale: "El secreto fue rotado y ya no aparece en el head.",
        source: "agent",
      })
    }),
  )

  it.instance("conserva los falsos positivos propuestos por el agente como recomendaciones pendientes", () =>
    Effect.gen(function* () {
      const sessions = yield* Session.Service
      const chat = yield* sessions.create({ title: "Auditoría" })
      yield* seedFinding({ sessionID: chat.id, projectID: chat.projectID, id: "finding-fp" })

      const def = yield* (yield* FindingStatusTool).init()
      const result = yield* def.execute(
        { findingID: "finding-fp", status: "false-positive", rationale: "La ruta parece no alcanzable." },
        context(chat.id),
      )

      expect(yield* readStatus("finding-fp")).toBe("in-progress")
      expect(result.metadata.newStatus).toBe("in-progress")
      expect(result.output).toContain("recomendación del agente")
      const { db } = yield* Database.Service
      const audit = yield* db.select().from(AuditLogTable).all().pipe(Effect.orDie)
      expect(audit).toHaveLength(1)
      expect(JSON.parse(audit[0].payload)).toMatchObject({
        requestedStatus: "false-positive",
        persistedStatus: "in-progress",
      })
    }),
  )

  it.instance("acepta un hallazgo escrito por un subagente hijo (mismo árbol de sesión)", () =>
    Effect.gen(function* () {
      const sessions = yield* Session.Service
      const parent = yield* sessions.create({ title: "Orquestador" })
      const child = yield* sessions.create({ parentID: parent.id, title: "security-code" })
      yield* seedFinding({ sessionID: child.id, projectID: child.projectID, id: "finding-child" })

      const def = yield* (yield* FindingStatusTool).init()
      // El orquestador (padre) cierra el ciclo de un hallazgo que escribió su hijo.
      yield* def.execute(
        { findingID: "finding-child", status: "in-progress", rationale: "Sin acceso al repo para confirmar." },
        context(parent.id),
      )

      expect(yield* readStatus("finding-child")).toBe("in-progress")
    }),
  )

  it.instance("rechaza un hallazgo de otra sesión de auditoría sin tocar la base", () =>
    Effect.gen(function* () {
      const sessions = yield* Session.Service
      const mine = yield* sessions.create({ title: "Auditoría A" })
      const other = yield* sessions.create({ title: "Auditoría B" })
      yield* seedFinding({ sessionID: other.id, projectID: other.projectID, id: "finding-ajeno" })

      const def = yield* (yield* FindingStatusTool).init()
      const exit = yield* def
        .execute(
          { findingID: "finding-ajeno", status: "verified", rationale: "intento de escritura cruzada" },
          context(mine.id),
        )
        .pipe(Effect.exit)

      expect(exit._tag).toBe("Failure")
      expect(yield* readStatus("finding-ajeno")).toBe("open")
    }),
  )

  it.instance("falla ante un findingID inexistente en vez de crear uno", () =>
    Effect.gen(function* () {
      const sessions = yield* Session.Service
      const chat = yield* sessions.create({ title: "Auditoría" })

      const def = yield* (yield* FindingStatusTool).init()
      const exit = yield* def
        .execute({ findingID: "no-existe", status: "verified", rationale: "id alucinado" }, context(chat.id))
        .pipe(Effect.exit)

      expect(exit._tag).toBe("Failure")
    }),
  )
})
