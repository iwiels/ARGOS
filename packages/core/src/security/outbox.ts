import { and, eq, lte, or, sql } from "drizzle-orm"
import { Effect } from "effect"
import { createHash } from "node:crypto"
import type { Database } from "../database/database"
import { ConnectorOutboxTable } from "./sql"

export type TargetSystem = "jira" | "linear" | "slack" | "teams" | "defectdojo" | "github"
export type OutboxEventType = "finding.created" | "finding.remediated" | "report.ready" | "alert.triggered"

export interface EnqueueOutboxInput {
  projectID: string
  sessionID?: string
  targetSystem: TargetSystem
  eventType: OutboxEventType
  idempotencyKey?: string
  payload: Record<string, unknown>
}

export class ConnectorOutboxService {
  /**
   * Encola un mensaje en el outbox con clave de idempotencia garantizada (Etapa 4).
   */
  static enqueue(db: Database.Interface["db"], input: EnqueueOutboxInput) {
    return Effect.gen(function* () {
      const now = Date.now()
      const idempotencyKey =
        input.idempotencyKey ||
        createHash("sha256")
          .update(`${input.projectID}:${input.targetSystem}:${input.eventType}:${JSON.stringify(input.payload)}`)
          .digest("hex")

      // Verificar idempotencia
      const existing = yield* db
        .select()
        .from(ConnectorOutboxTable)
        .where(eq(ConnectorOutboxTable.idempotency_key, idempotencyKey))
        .get()
        .pipe(Effect.orDie)

      if (existing) {
        return { id: existing.id, idempotencyKey, deduplicated: true }
      }

      const id = `out_${createHash("sha256").update(`${idempotencyKey}:${now}`).digest("hex").slice(0, 24)}`

      yield* db
        .insert(ConnectorOutboxTable)
        .values({
          id,
          project_id: input.projectID,
          session_id: input.sessionID,
          target_system: input.targetSystem,
          event_type: input.eventType,
          idempotency_key: idempotencyKey,
          payload: input.payload,
          status: "pending",
          attempts: 0,
          max_attempts: 5,
          next_retry_at: now,
          time_created: now,
        })
        .run()
        .pipe(Effect.orDie)

      return { id, idempotencyKey, deduplicated: false }
    })
  }

  /**
   * Obtiene los mensajes listos para ser despachados.
   */
  static fetchPending(db: Database.Interface["db"], limit = 20) {
    return Effect.gen(function* () {
      const now = Date.now()
      const rows = yield* db
        .select()
        .from(ConnectorOutboxTable)
        .where(
          and(
            eq(ConnectorOutboxTable.status, "pending"),
            or(sql`${ConnectorOutboxTable.next_retry_at} IS NULL`, lte(ConnectorOutboxTable.next_retry_at, now)),
          ),
        )
        .limit(limit)
        .all()
        .pipe(Effect.orDie)

      return rows
    })
  }

  /**
   * Marca un mensaje como entregado exitosamente.
   */
  static markDelivered(db: Database.Interface["db"], id: string) {
    return Effect.gen(function* () {
      const now = Date.now()
      yield* db
        .update(ConnectorOutboxTable)
        .set({
          status: "delivered",
          time_delivered: now,
        })
        .where(eq(ConnectorOutboxTable.id, id))
        .run()
        .pipe(Effect.orDie)
    })
  }

  /**
   * Registra un fallo de entrega y calcula el backoff exponencial.
   */
  static markFailed(db: Database.Interface["db"], id: string, errorMessage: string) {
    return Effect.gen(function* () {
      const existing = yield* db
        .select()
        .from(ConnectorOutboxTable)
        .where(eq(ConnectorOutboxTable.id, id))
        .get()
        .pipe(Effect.orDie)

      if (!existing) return

      const newAttempts = existing.attempts + 1
      const isExhausted = newAttempts >= existing.max_attempts
      const now = Date.now()

      // Backoff exponencial: 2^attempts segundos
      const backoffMs = Math.pow(2, newAttempts) * 1000
      const nextRetryAt = isExhausted ? null : now + backoffMs

      yield* db
        .update(ConnectorOutboxTable)
        .set({
          attempts: newAttempts,
          status: isExhausted ? "failed" : "pending",
          last_error: errorMessage,
          next_retry_at: nextRetryAt,
        })
        .where(eq(ConnectorOutboxTable.id, id))
        .run()
        .pipe(Effect.orDie)
    })
  }

  /**
   * Despacha mensajes pendientes ejecutando el handler provisto.
   */
  static dispatch(
    db: Database.Interface["db"],
    handler: (item: typeof ConnectorOutboxTable.$inferSelect) => Promise<boolean>,
    limit = 10,
  ) {
    return Effect.gen(function* () {
      const items = yield* ConnectorOutboxService.fetchPending(db, limit)
      let deliveredCount = 0
      let failedCount = 0

      for (const item of items) {
        try {
          const success = yield* Effect.tryPromise({
            try: () => handler(item),
            catch: (err) => String(err),
          })

          if (success === true) {
            yield* ConnectorOutboxService.markDelivered(db, item.id)
            deliveredCount++
          } else {
            yield* ConnectorOutboxService.markFailed(db, item.id, typeof success === "string" ? success : "Handler returned false")
            failedCount++
          }
        } catch (err) {
          yield* ConnectorOutboxService.markFailed(db, item.id, String(err))
          failedCount++
        }
      }

      return { total: items.length, deliveredCount, failedCount }
    })
  }
}
