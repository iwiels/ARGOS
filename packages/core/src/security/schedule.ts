import { and, desc, eq, lte } from "drizzle-orm"
import { Effect } from "effect"
import { createHash } from "node:crypto"
import type { Database } from "../database/database"
import { SessionTable } from "../session/sql"
import { AuditScheduleTable, AuditTaskExecutionTable } from "./sql"

export interface CreateScheduleInput {
  projectID: string
  name: string
  target: string
  scanType?: "web_scan" | "api_audit" | "code_audit" | "lan_scan" | "full_audit"
  cronExpression?: string
  timezone?: string
  intervalHours?: number
  firstRunAt?: number
}

export interface DueScheduleCheckResult {
  scheduleID: string
  name: string
  target: string
  scanType: string
  timezone: string
  missed: boolean
  missedOccurrences: number
  offerRunNow: boolean
  scheduledFor: number
}

export class AuditScheduleService {
  /**
   * Registra un nuevo horario recurrente de auditoría con zona horaria (Etapa 4).
   */
  static createSchedule(db: Database.Interface["db"], input: CreateScheduleInput) {
    return Effect.gen(function* () {
      const now = Date.now()
      const timezone = input.timezone || "UTC"
      const intervalMs = (input.intervalHours ?? 24) * 60 * 60 * 1000
      const nextRunAt = input.firstRunAt ?? now + intervalMs

      const scheduleID = `sched_${createHash("sha256")
        .update(`${input.projectID}:${input.name}:${now}`)
        .digest("hex")
        .slice(0, 24)}`

      yield* db
        .insert(AuditScheduleTable)
        .values({
          id: scheduleID,
          project_id: input.projectID,
          name: input.name,
          target: input.target,
          scan_type: input.scanType ?? "web_scan",
          cron_expression: input.cronExpression ?? "0 0 * * *",
          timezone,
          next_run_at: nextRunAt,
          last_status: "pending",
          missed_occurrences: 0,
          enabled: true,
          time_created: now,
          time_updated: now,
        })
        .run()
        .pipe(Effect.orDie)

      return { scheduleID, nextRunAt, timezone }
    })
  }

  /**
   * Al abrir Argos o iniciar el servicio, detecta ocurrencias vencidas en segundo plano.
   * Las ocurrencias no ejecutadas aparecen como "missed" y ofrecen "ejecutar ahora" (Etapa 4).
   */
  static checkDueSchedules(db: Database.Interface["db"], now = Date.now()) {
    return Effect.gen(function* () {
      const dueSchedules = yield* db
        .select()
        .from(AuditScheduleTable)
        .where(and(eq(AuditScheduleTable.enabled, true), lte(AuditScheduleTable.next_run_at, now)))
        .all()
        .pipe(Effect.orDie)

      const results: DueScheduleCheckResult[] = []

      for (const sched of dueSchedules) {
        const isMissed = now > sched.next_run_at + 60 * 1000 // más de 1 minuto de retraso
        const missedCount = isMissed ? sched.missed_occurrences + 1 : sched.missed_occurrences

        // Avanzar el siguiente ciclo (ej. 24h por defecto)
        const nextCycle = now + 24 * 60 * 60 * 1000

        yield* db
          .update(AuditScheduleTable)
          .set({
            last_status: isMissed ? "missed" : "pending",
            missed_occurrences: missedCount,
            next_run_at: nextCycle,
            time_updated: now,
          })
          .where(eq(AuditScheduleTable.id, sched.id))
          .run()
          .pipe(Effect.orDie)

        results.push({
          scheduleID: sched.id,
          name: sched.name,
          target: sched.target,
          scanType: sched.scan_type,
          timezone: sched.timezone,
          missed: isMissed,
          missedOccurrences: missedCount,
          offerRunNow: true,
          scheduledFor: sched.next_run_at,
        })
      }

      return results
    })
  }

  /**
   * Dispara inmediatamente la auditoría para un horario vencido u omitido ("Ejecutar ahora").
   */
  static runNow(
    db: Database.Interface["db"],
    scheduleID: string,
    opts?: { sessionID?: string; now?: number },
  ) {
    return Effect.gen(function* () {
      const now = opts?.now ?? Date.now()
      const sched = yield* db
        .select()
        .from(AuditScheduleTable)
        .where(eq(AuditScheduleTable.id, scheduleID))
        .get()
        .pipe(Effect.orDie)

      if (!sched) {
        return yield* Effect.fail(new Error(`Schedule ${scheduleID} not found`))
      }

      const sessionID = opts?.sessionID ?? `sched-session-${now}`
      const taskID = `task_${createHash("sha256").update(`${scheduleID}:${now}:run_now`).digest("hex").slice(0, 24)}`

      const existingSession = yield* db
        .select({ id: SessionTable.id })
        .from(SessionTable)
        .where(eq(SessionTable.id, sessionID as any))
        .get()
        .pipe(Effect.orDie)

      if (!existingSession) {
        yield* db
          .insert(SessionTable)
          .values({
            id: sessionID as any,
            project_id: sched.project_id as any,
            slug: sessionID,
            directory: "/" as any,
            title: `Scheduled Audit: ${sched.name}`,
            version: "1.0",
            time_created: now,
            time_updated: now,
          })
          .run()
          .pipe(Effect.orDie)
      }

      // 1. Crear tarea de auditoría para ejecución inmediata
      yield* db
        .insert(AuditTaskExecutionTable)
        .values({
          id: taskID,
          session_id: sessionID,
          project_id: sched.project_id,
          type: sched.scan_type,
          target: sched.target,
          status: "queued",
          metadata: { scheduleID: sched.id, triggeredBy: "schedule_run_now" },
          time_created: now,
          time_updated: now,
        })
        .run()
        .pipe(Effect.orDie)

      // 2. Actualizar estado del horario
      yield* db
        .update(AuditScheduleTable)
        .set({
          last_run_at: now,
          last_status: "running",
          missed_occurrences: 0,
          time_updated: now,
        })
        .where(eq(AuditScheduleTable.id, scheduleID))
        .run()
        .pipe(Effect.orDie)

      return {
        scheduleID,
        taskID,
        sessionID,
        status: "queued" as const,
      }
    })
  }

  /**
   * Lista los horarios configurados para el proyecto.
   */
  static listSchedules(db: Database.Interface["db"], projectID: string) {
    return db
      .select()
      .from(AuditScheduleTable)
      .where(eq(AuditScheduleTable.project_id, projectID))
      .orderBy(desc(AuditScheduleTable.time_created))
      .all()
      .pipe(Effect.orDie)
  }
}
