import { and, desc, eq, or } from "drizzle-orm"
import { Effect } from "effect"
import { createHash } from "node:crypto"
import type { Database } from "../database/database"
import { AuditCheckpointTable, AuditTaskExecutionTable } from "./sql"

export type TaskStatus = "queued" | "running" | "paused" | "interrupted" | "cancelled" | "completed"

export interface CreateTaskInput {
  sessionID: string
  projectID: string
  type: "web_scan" | "api_audit" | "code_audit" | "lan_scan" | "full_audit"
  target?: string
  metadata?: Record<string, unknown>
}

export interface SaveCheckpointInput {
  taskID: string
  sessionID: string
  stepName: string
  stepIndex: number
  completedSteps: string[]
  stateSnapshot: Record<string, unknown>
  progress?: number
}

export class ExecutionService {
  /**
   * Crea una nueva tarea de auditoría con estado inicial 'queued' (Etapa 3).
   */
  static createTask(db: Database.Interface["db"], input: CreateTaskInput) {
    return Effect.gen(function* () {
      const now = Date.now()
      const taskID = `task_${createHash("sha256").update(`${input.sessionID}:${input.type}:${now}`).digest("hex").slice(0, 24)}`

      yield* db
        .insert(AuditTaskExecutionTable)
        .values({
          id: taskID,
          session_id: input.sessionID,
          project_id: input.projectID,
          type: input.type,
          status: "queued",
          target: input.target,
          progress: 0,
          current_step: "initialized",
          metadata: input.metadata,
          time_created: now,
          time_updated: now,
        })
        .run()
        .pipe(Effect.orDie)

      return { taskID, status: "queued" as TaskStatus }
    })
  }

  /**
   * Pasa una tarea a estado 'running'.
   */
  static startTask(db: Database.Interface["db"], taskID: string) {
    return Effect.gen(function* () {
      const now = Date.now()
      yield* db
        .update(AuditTaskExecutionTable)
        .set({ status: "running", time_updated: now })
        .where(eq(AuditTaskExecutionTable.id, taskID))
        .run()
        .pipe(Effect.orDie)

      return { taskID, status: "running" as TaskStatus }
    })
  }

  /**
   * Persiste un checkpoint durable con el snapshot del estado intermedio.
   */
  static saveCheckpoint(db: Database.Interface["db"], input: SaveCheckpointInput) {
    return Effect.gen(function* () {
      const now = Date.now()
      const checkpointID = `chk_${createHash("sha256").update(`${input.taskID}:${input.stepIndex}:${now}`).digest("hex").slice(0, 24)}`

      yield* db
        .insert(AuditCheckpointTable)
        .values({
          id: checkpointID,
          task_id: input.taskID,
          session_id: input.sessionID,
          step_name: input.stepName,
          step_index: input.stepIndex,
          completed_steps: input.completedSteps,
          state_snapshot: input.stateSnapshot,
          time_created: now,
        })
        .run()
        .pipe(Effect.orDie)

      yield* db
        .update(AuditTaskExecutionTable)
        .set({
          checkpoint_id: checkpointID,
          current_step: input.stepName,
          progress: input.progress ?? Math.min(100, Math.round((input.stepIndex + 1) * 10)),
          time_updated: now,
        })
        .where(eq(AuditTaskExecutionTable.id, input.taskID))
        .run()
        .pipe(Effect.orDie)

      return { checkpointID, taskID: input.taskID }
    })
  }

  /**
   * Recupera el último checkpoint para reanudar la ejecución sin repetir pasos.
   */
  static getLatestCheckpoint(db: Database.Interface["db"], taskID: string) {
    return Effect.gen(function* () {
      const checkpoints = yield* db
        .select()
        .from(AuditCheckpointTable)
        .where(eq(AuditCheckpointTable.task_id, taskID))
        .orderBy(desc(AuditCheckpointTable.step_index), desc(AuditCheckpointTable.time_created))
        .all()
        .pipe(
          Effect.catch(() => Effect.succeed([])),
        )

      for (const cp of checkpoints) {
        if (cp && typeof cp === "object" && cp.step_name) {
          return cp
        }
      }

      return null
    })
  }

  /**
   * Pausa la ejecución.
   */
  static pauseTask(db: Database.Interface["db"], taskID: string) {
    return Effect.gen(function* () {
      const now = Date.now()
      yield* db
        .update(AuditTaskExecutionTable)
        .set({ status: "paused", time_updated: now })
        .where(eq(AuditTaskExecutionTable.id, taskID))
        .run()
        .pipe(Effect.orDie)

      return { taskID, status: "paused" as TaskStatus }
    })
  }

  /**
   * Interrumpe la tarea por fallo o crash del proceso.
   */
  static interruptTask(db: Database.Interface["db"], taskID: string, reason?: string) {
    return Effect.gen(function* () {
      const now = Date.now()
      yield* db
        .update(AuditTaskExecutionTable)
        .set({ status: "interrupted", error: reason, time_updated: now })
        .where(eq(AuditTaskExecutionTable.id, taskID))
        .run()
        .pipe(Effect.orDie)

      return { taskID, status: "interrupted" as TaskStatus }
    })
  }

  /**
   * Cancela la tarea voluntariamente.
   */
  static cancelTask(db: Database.Interface["db"], taskID: string, reason?: string) {
    return Effect.gen(function* () {
      const now = Date.now()
      yield* db
        .update(AuditTaskExecutionTable)
        .set({ status: "cancelled", error: reason, time_updated: now })
        .where(eq(AuditTaskExecutionTable.id, taskID))
        .run()
        .pipe(Effect.orDie)

      return { taskID, status: "cancelled" as TaskStatus }
    })
  }

  /**
   * Completa la tarea exitosamente al 100%.
   */
  static completeTask(db: Database.Interface["db"], taskID: string) {
    return Effect.gen(function* () {
      const now = Date.now()
      yield* db
        .update(AuditTaskExecutionTable)
        .set({ status: "completed", progress: 100, current_step: "finished", time_updated: now })
        .where(eq(AuditTaskExecutionTable.id, taskID))
        .run()
        .pipe(Effect.orDie)

      return { taskID, status: "completed" as TaskStatus }
    })
  }

  /**
   * Reanuda una tarea pausada o interrumpida desde el último checkpoint.
   */
  static resumeTask(db: Database.Interface["db"], taskID: string) {
    return Effect.gen(function* () {
      const task = yield* db
        .select()
        .from(AuditTaskExecutionTable)
        .where(eq(AuditTaskExecutionTable.id, taskID))
        .get()
        .pipe(Effect.orDie)

      if (!task) {
        return yield* Effect.fail(new Error(`Task ${taskID} not found`))
      }

      if (task.status !== "paused" && task.status !== "interrupted") {
        return yield* Effect.fail(new Error(`Task ${taskID} cannot be resumed from status: ${task.status}`))
      }

      const latestCheckpoint = yield* ExecutionService.getLatestCheckpoint(db, taskID)

      yield* db
        .update(AuditTaskExecutionTable)
        .set({ status: "running", time_updated: Date.now() })
        .where(eq(AuditTaskExecutionTable.id, taskID))
        .run()
        .pipe(Effect.orDie)

      return {
        taskID,
        status: "running" as TaskStatus,
        resumeStep: latestCheckpoint?.step_name ?? "start",
        completedSteps: latestCheckpoint?.completed_steps ?? [],
        stateSnapshot: latestCheckpoint?.state_snapshot ?? {},
      }
    })
  }

  /**
   * Consulta una tarea específica.
   */
  static getTask(db: Database.Interface["db"], taskID: string) {
    return db
      .select()
      .from(AuditTaskExecutionTable)
      .where(eq(AuditTaskExecutionTable.id, taskID))
      .get()
      .pipe(Effect.orDie)
  }

  /**
   * Lista ejecuciones interrumpidas o pausadas para reanudación explícita al abrir Argos (Etapa 3).
   */
  static listResumableTasks(
    db: Database.Interface["db"],
    opts?: { sessionID?: string; projectID?: string },
  ) {
    return Effect.gen(function* () {
      const where = and(
        opts?.sessionID ? eq(AuditTaskExecutionTable.session_id, opts.sessionID) : undefined,
        opts?.projectID ? eq(AuditTaskExecutionTable.project_id, opts.projectID) : undefined,
        or(
          eq(AuditTaskExecutionTable.status, "interrupted"),
          eq(AuditTaskExecutionTable.status, "paused"),
        ),
      )

      return yield* db
        .select()
        .from(AuditTaskExecutionTable)
        .where(where)
        .orderBy(desc(AuditTaskExecutionTable.time_updated))
        .all()
        .pipe(Effect.orDie)
    })
  }
}
