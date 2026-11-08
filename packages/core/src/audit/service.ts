import { createHash } from "node:crypto"
import { desc, eq, sql } from "drizzle-orm"
import { Context, Effect, Layer } from "effect"
import { Database } from "../database/database"
import { SessionSchema } from "../session/schema"
import { SessionTable } from "../session/sql"
import { Identifier } from "../util/identifier"
import { AuditLogTable } from "./sql"

export type AuditEntry = {
  id: string
  seq: number
  project_id: string | null
  session_id: string | null
  event_type: string
  action: string
  agent: string | null
  target: string | null
  summary: string
  payload: string
  prev_hash: string
  hash: string
  time_created: number
}

export type AppendInput = {
  sessionID?: SessionSchema.ID
  projectID?: string
  eventType: string
  action: string
  agent?: string
  target?: string
  summary: string
  payload?: unknown
}

/** Límite de payload por entrada para evitar que la cadena crezca sin control. */
export const MAX_PAYLOAD_CHARS = 8000

export const truncatePayload = (value: string, max = MAX_PAYLOAD_CHARS) =>
  value.length <= max ? value : `${value.slice(0, max)}\n[truncated: omitted ${value.length - max} chars]`

/**
 * Recomputation target for Audit.verify: all fields must come from stored columns.
 * Se serializa el arreglo completo con JSON para eliminar ambigüedad entre campos
 * (un join con separador sería vulnerable a valores que contienen el separador).
 *
 * Modelo de amenaza: la cadena es keyless (SHA-256 público). Detecta modificación o
 * borrado de entradas (bloqueados también por triggers SQLite) y huecos de secuencia.
 * No protege contra un atacante con escritura directa al SQLite que re-apende y
 * recompute toda la cadena; para ese caso se requeriría HMAC con secreto local.
 */
export function auditHash(input: {
  prevHash: string
  seq: number
  eventType: string
  action: string
  agent: string
  target: string
  summary: string
  timeCreated: number
  payload: string
}) {
  return createHash("sha256")
    .update(
      JSON.stringify([
        input.prevHash,
        input.seq,
        input.eventType,
        input.action,
        input.agent,
        input.target,
        input.summary,
        input.timeCreated,
        input.payload,
      ]),
    )
    .digest("hex")
}

export interface AgentSummary {
  agent: string
  total: number
  completed: number
  errors: number
  /** Herramientas más ejecutadas por el agente (tool.executed / tool.error). */
  topTools: Array<{ tool: string; count: number }>
}

export interface GovernanceSummary {
  generatedAt: number
  /** Integridad de la cadena. `verified` indica si se hizo la verificación
   *  criptográfica completa (Audit.verify); el summary periódico solo hace
   *  un chequeo barato de contigüidad de secuencia. */
  integrity: { valid: boolean; total: number; verified: boolean; firstInvalidSeq?: number }
  agents: AgentSummary[]
  /** Distribución por tipo de evento. */
  events: Array<{ eventType: string; count: number }>
  /** Actividad global (entradas por minuto en la última hora, best-effort). */
  activity: { total: number; lastEntryAt: number | null }
}

export interface Interface {
  /** Append an entry to the immutable chain (monotonic seq, sha256 of the previous entry). */
  readonly append: (input: AppendInput) => Effect.Effect<AuditEntry>
  readonly list: (input?: {
    sessionID?: string
    limit?: number
    offset?: number
  }) => Effect.Effect<{ items: AuditEntry[]; total: number }>
  /** Recomputes the whole chain and reports the first broken link, if any. */
  readonly verify: () => Effect.Effect<{ valid: boolean; total: number; firstInvalidSeq?: number }>
  /** Agrega la cadena para el panel de gobernanza: integridad + métricas por
   *  agente (volumen, errores, tools más usadas) + distribución por evento. */
  readonly getSummary: () => Effect.Effect<GovernanceSummary>
}

export class Service extends Context.Service<Service, Interface>()("@argos/audit/Audit") {}

export const layer = Layer.effect(
  Service,
  Effect.gen(function* () {
    const { db } = yield* Database.Service

    const append = Effect.fn("Audit.append")(function* (input: AppendInput) {
      const projectID =
        input.projectID ??
        (input.sessionID
          ? yield* db
              .select({ projectID: SessionTable.project_id })
              .from(SessionTable)
              .where(eq(SessionTable.id, input.sessionID))
              .get()
              .pipe(
                Effect.orDie,
                Effect.map((row) => row?.projectID ?? undefined),
              )
          : undefined)
      const payload = truncatePayload(JSON.stringify(input.payload ?? {}))
      const timeCreated = Date.now()

      return yield* db
        .transaction(
          () =>
            Effect.gen(function* () {
              const latest = yield* db
                .select({ seq: AuditLogTable.seq, hash: AuditLogTable.hash })
                .from(AuditLogTable)
                .orderBy(desc(AuditLogTable.seq))
                .limit(1)
                .get()
                .pipe(Effect.orDie)
              const seq = (latest?.seq ?? 0) + 1
              const prevHash = latest?.hash ?? ""
              const entry: AuditEntry = {
                id: "aud_" + Identifier.ascending(),
                seq,
                project_id: projectID ?? null,
                session_id: input.sessionID ?? null,
                event_type: input.eventType,
                action: input.action,
                agent: input.agent ?? null,
                target: input.target ?? null,
                summary: input.summary,
                payload,
                prev_hash: prevHash,
                hash: auditHash({
                  prevHash,
                  seq,
                  eventType: input.eventType,
                  action: input.action,
                  agent: input.agent ?? "",
                  target: input.target ?? "",
                  summary: input.summary,
                  timeCreated,
                  payload,
                }),
                time_created: timeCreated,
              }
              yield* db.insert(AuditLogTable).values(entry).run().pipe(Effect.orDie)
              return entry
            }),
          { behavior: "immediate" },
        )
        .pipe(Effect.retry({ times: 2 }), Effect.orDie)
    })

    const list = Effect.fn("Audit.list")(function* (input?: {
      sessionID?: string
      limit?: number
      offset?: number
    }) {
      const where = input?.sessionID ? eq(AuditLogTable.session_id, input.sessionID) : undefined
      const countRows = yield* (where
        ? db.select({ count: sql<number>`count(*)` }).from(AuditLogTable).where(where)
        : db.select({ count: sql<number>`count(*)` }).from(AuditLogTable)
      )
        .get()
        .pipe(Effect.orDie)
      const query = where
        ? db.select().from(AuditLogTable).where(where)
        : db.select().from(AuditLogTable)
      const rows = yield* query
        .orderBy(desc(AuditLogTable.seq))
        .limit(input?.limit ?? 100)
        .offset(input?.offset ?? 0)
        .all()
        .pipe(Effect.orDie)
      return { items: rows, total: Number(countRows?.count ?? 0) }
    })

    const verify = Effect.fn("Audit.verify")(function* () {
      const rows = yield* db
        .select()
        .from(AuditLogTable)
        .orderBy(AuditLogTable.seq)
        .all()
        .pipe(Effect.orDie)
      let expectedPrev = ""
      let expectedSeq = 1
      for (const row of rows) {
        if (row.seq !== expectedSeq || row.prev_hash !== expectedPrev) {
          return { valid: false, total: rows.length, firstInvalidSeq: row.seq }
        }
        const recomputed = auditHash({
          prevHash: row.prev_hash,
          seq: row.seq,
          eventType: row.event_type,
          action: row.action,
          agent: row.agent ?? "",
          target: row.target ?? "",
          summary: row.summary,
          timeCreated: row.time_created,
          payload: row.payload,
        })
        if (recomputed !== row.hash) {
          return { valid: false, total: rows.length, firstInvalidSeq: row.seq }
        }
        expectedPrev = row.hash
        expectedSeq += 1
      }
      return { valid: true, total: rows.length }
    })

    const getSummary = Effect.fn("Audit.getSummary")(function* () {
      // Chequeo barato de integridad: la cadena es contigua cuando count === max(seq).
      // La verificación criptográfica completa (recomputo sha256) se delega a Audit.verify,
      // que el botón del panel de gobernanza invoca bajo demanda.
      const counts = yield* db
        .select({
          total: sql<number>`count(*)`,
          maxSeq: sql<number>`max(${AuditLogTable.seq})`,
          lastEntry: sql<number>`max(${AuditLogTable.time_created})`,
        })
        .from(AuditLogTable)
        .get()
        .pipe(Effect.orDie)
      const total = Number(counts?.total ?? 0)
      const maxSeq = Number(counts?.maxSeq ?? 0)
      const valid = total === maxSeq
      // Métricas por agente: total, errores, completadas y tools más usadas.
      const agentRows = yield* db
        .select({
          agent: AuditLogTable.agent,
          eventType: AuditLogTable.event_type,
          action: AuditLogTable.action,
          count: sql<number>`count(*)`,
        })
        .from(AuditLogTable)
        .groupBy(AuditLogTable.agent, AuditLogTable.event_type, AuditLogTable.action)
        .all()
        .pipe(Effect.orDie)
      const events = yield* db
        .select({ eventType: AuditLogTable.event_type, count: sql<number>`count(*)` })
        .from(AuditLogTable)
        .groupBy(AuditLogTable.event_type)
        .orderBy(sql`count(*) desc`)
        .all()
        .pipe(Effect.orDie)

      const byAgent = new Map<string, AgentSummary>()
      for (const row of agentRows) {
        const name = row.agent ?? "unknown"
        const summary = byAgent.get(name) ?? { agent: name, total: 0, completed: 0, errors: 0, topTools: [] }
        summary.total += Number(row.count ?? 0)
        if (row.eventType === "tool.error") summary.errors += Number(row.count ?? 0)
        if (row.eventType === "tool.executed") summary.completed += Number(row.count ?? 0)
        // Herramientas (tool.executed / tool.error → action = nombre de la tool).
        if (row.eventType === "tool.executed" || row.eventType === "tool.error") {
          const existing = summary.topTools.find((tool) => tool.tool === row.action)
          if (existing) existing.count += Number(row.count ?? 0)
          else summary.topTools.push({ tool: row.action, count: Number(row.count ?? 0) })
        }
        byAgent.set(name, summary)
      }
      const agents = [...byAgent.values()]
        .map((summary) => ({
          ...summary,
          topTools: summary.topTools.sort((a, b) => b.count - a.count).slice(0, 8),
        }))
        .sort((a, b) => b.total - a.total)

      return {
        generatedAt: Date.now(),
        integrity: { valid, total, verified: false },
        agents,
        events: events.map((row) => ({ eventType: row.eventType, count: Number(row.count ?? 0) })),
        activity: { total, lastEntryAt: counts?.lastEntry ?? null },
      } satisfies GovernanceSummary
    })

    return Service.of({ append, list, verify, getSummary })
  }),
)

export const defaultLayer = layer.pipe(Layer.provide(Database.defaultLayer))
