export * as EngagementBudget from "./budget"

import { eq } from "drizzle-orm"
import { Context, Effect, Layer, Option, Schema, Semaphore } from "effect"
import { Database } from "../database/database"
import { ProjectTable } from "../project/sql"
import { SessionSchema } from "./schema"
import { EngagementBudgetTable, SessionTable } from "./sql"

/**
 * Techo de consumo de un engagement (una sesión de auditoría).
 *
 * Los defaults son deliberadamente conservativeos: son el punto de partida de
 * una auditoría y el número que el cliente ve cuando pregunta "¿cuánto me va a
 * costar esto?". El límite real lo fija el proyecto (columna `project.budget`).
 */
export interface EngagementBudget {
  maxToolCalls: number
  maxTokens: number
  maxWallClockMs: number
  maxFindings: number
  maxConcurrentAgents: number
}

export const DEFAULT_BUDGET: EngagementBudget = {
  maxToolCalls: 200,
  maxTokens: 2_000_000,
  // 4 h: una auditoría larga pero finita. Un engagement que se pasa de acá
  // está quemando presupuesto del cliente sin resultado.
  maxWallClockMs: 4 * 60 * 60 * 1000,
  maxFindings: 500,
  // Coincide con el "máximo 3 agentes concurrentes" de argos-config/AGENTS.md,
  // que hasta ahora era solo una regla de prompt y ningún límite de runtime.
  maxConcurrentAgents: 3,
}

export const Dimension = Schema.Literals(["tool-calls", "tokens", "wall-clock", "findings"])
export type Dimension = typeof Dimension.Type

/**
 * El presupuesto se excedió. Es un error tipado (no una string) para que el
 * llamador pueda distinguir "el cliente se quedó sin presupuesto" de "la tool
 * falló" y cortar la ejecución con el motivo correcto.
 */
export class BudgetExceededError extends Schema.TaggedErrorClass<BudgetExceededError>()(
  "EngagementBudget.BudgetExceededError",
  {
    sessionID: Schema.String,
    dimension: Dimension,
    limit: Schema.Int,
    used: Schema.Int,
  },
) {}

export interface BudgetUsage {
  toolCalls: number
  tokens: number
  findings: number
  /** Milisegundos transcurridos desde el arranque de la sesión. */
  elapsedMs: number
  /** Epoch ms del arranque de la sesión. */
  startedAt: number
  budget: EngagementBudget
}

type SessionState = {
  toolCalls: number
  tokens: number
  findings: number
  startedAt: number
  budget: EngagementBudget | undefined
  initialized: boolean
  dbBacked: boolean
  /** Serializa el read-modify-write de los contadores. */
  lock: Semaphore.Semaphore
  /** Permisos de subagentes en vuelo; el límite sale del presupuesto efectivo. */
  agents: Semaphore.Semaphore | undefined
  agentsLimit: number | undefined
}

/**
 * Session usage and its effective budget snapshot are persisted in SQLite.
 * Agent concurrency permits remain process-local.
 */
export interface Interface {
  /** Presupuesto efectivo de la sesión (config del proyecto sobre DEFAULT_BUDGET). */
  readonly forSession: (sessionID: string) => Effect.Effect<EngagementBudget, never, Database.Service>
  /** Consume una llamada de tool. Falla con BudgetExceededError al superar el límite. */
  readonly consumeToolCall: (sessionID: string) => Effect.Effect<void, BudgetExceededError>
  /** Consume tokens de LLM. Falla con BudgetExceededError al superar el límite. */
  readonly consumeTokens: (sessionID: string, tokens: number) => Effect.Effect<void, BudgetExceededError>
  /** Consume un finding. Falla con BudgetExceededError al superar el límite. */
  readonly consumeFinding: (sessionID: string) => Effect.Effect<void, BudgetExceededError>
  /** Consumo actual de la sesión. */
  readonly usage: (sessionID: string) => Effect.Effect<BudgetUsage, never, Database.Service>
  /** Reinicia los contadores de la sesión (arranque de un nuevo engagement). */
  readonly reset: (sessionID: string) => Effect.Effect<void>
  /**
   * Toma un permiso de subagente. El llamador DEBE liberar el permiso con el
   * efecto devuelto: sin ese release el slot queda tomado para siempre.
   */
  readonly acquireAgentSlot: (sessionID: string) => Effect.Effect<Effect.Effect<void>>
}

export class Service extends Context.Service<Service, Interface>()("@argos/EngagementBudget") {}

const positive = (value: number | undefined, fallback: number) =>
  typeof value === "number" && Number.isFinite(value) && value > 0 ? Math.floor(value) : fallback

const merge = (partial: Partial<EngagementBudget> | undefined): EngagementBudget => ({
  maxToolCalls: positive(partial?.maxToolCalls, DEFAULT_BUDGET.maxToolCalls),
  maxTokens: positive(partial?.maxTokens, DEFAULT_BUDGET.maxTokens),
  maxWallClockMs: positive(partial?.maxWallClockMs, DEFAULT_BUDGET.maxWallClockMs),
  maxFindings: positive(partial?.maxFindings, DEFAULT_BUDGET.maxFindings),
  maxConcurrentAgents: positive(partial?.maxConcurrentAgents, DEFAULT_BUDGET.maxConcurrentAgents),
})

const syncState = (state: SessionState, row: typeof EngagementBudgetTable.$inferSelect) => {
  state.toolCalls = row.tool_calls
  state.tokens = row.tokens
  state.findings = row.findings
  state.startedAt = row.started_at
  state.budget = merge(row.budget)
  state.initialized = true
  state.dbBacked = true
}

export const layer = Layer.effect(
  Service,
  Effect.gen(function* () {
    const states = new Map<string, SessionState>()

    const stateFor = (sessionID: string): SessionState => {
      const existing = states.get(sessionID)
      if (existing) return existing
      const created: SessionState = {
        toolCalls: 0,
        tokens: 0,
        findings: 0,
        startedAt: Date.now(),
        budget: undefined,
        initialized: false,
        dbBacked: false,
        lock: Semaphore.makeUnsafe(1),
        agents: undefined,
        agentsLimit: undefined,
      }
      states.set(sessionID, created)
      return created
    }

    /**
     * Presupuesto configurado en el proyecto de la sesión. Sin fila de proyecto
     * (o sin columna `budget`) el default aplica.
     */
    const readProjectBudget = Effect.fn("EngagementBudget.readProjectBudget")(function* (
      db: Database.Interface["db"],
      sessionID: string,
    ) {
      const session = yield* db
        .select({ projectID: SessionTable.project_id })
        .from(SessionTable)
        .where(eq(SessionTable.id, sessionID as SessionSchema.ID))
        .get()
        .pipe(Effect.orDie)
      if (!session?.projectID) return merge(undefined)
      const project = yield* db
        .select({ budget: ProjectTable.budget })
        .from(ProjectTable)
        .where(eq(ProjectTable.id, session.projectID))
        .get()
        .pipe(Effect.orDie)
      return merge(project?.budget ?? undefined)
    })

    const ancestors = Effect.fn("EngagementBudget.ancestors")(function* (
      db: Database.Interface["db"],
      sessionID: string,
    ) {
      const result: string[] = []
      const visited = new Set<string>()
      let current: string | undefined = sessionID
      while (current) {
        if (visited.has(current)) {
          return yield* Effect.die(new Error(`Cycle in session parent chain at ${current}`))
        }
        visited.add(current)
        result.push(current)
        const row: { parentID: SessionSchema.ID | null } | undefined = yield* db
          .select({ parentID: SessionTable.parent_id })
          .from(SessionTable)
          .where(eq(SessionTable.id, current as SessionSchema.ID))
          .get()
          .pipe(Effect.orDie)
        current = row?.parentID ?? undefined
      }
      return result
    })

    const resolve = Effect.fn("EngagementBudget.resolve")(function* (sessionID: string) {
      const state = stateFor(sessionID)
      const database = yield* Effect.serviceOption(Database.Service)
      if (Option.isNone(database)) {
        if (!state.initialized) {
          state.startedAt = Date.now()
          state.budget = merge(undefined)
          state.initialized = true
        }
        return state.budget ?? merge(undefined)
      }
      if (state.dbBacked) return state.budget ?? merge(undefined)

      const db = database.value.db
      const existing = yield* db
        .select()
        .from(EngagementBudgetTable)
        .where(eq(EngagementBudgetTable.session_id, sessionID as SessionSchema.ID))
        .get()
        .pipe(Effect.orDie)
      if (existing) {
        syncState(state, existing)
        return state.budget!
      }

      const budget = state.budget ?? (yield* readProjectBudget(db, sessionID))
      const startedAt = state.initialized ? state.startedAt : Date.now()
      yield* db
        .insert(EngagementBudgetTable)
        .values({
          session_id: sessionID as SessionSchema.ID,
          tool_calls: state.toolCalls,
          tokens: state.tokens,
          findings: state.findings,
          started_at: startedAt,
          budget,
          time_updated: Date.now(),
        })
        .onConflictDoNothing()
        .run()
        .pipe(Effect.orDie)
      const persisted = yield* db
        .select()
        .from(EngagementBudgetTable)
        .where(eq(EngagementBudgetTable.session_id, sessionID as SessionSchema.ID))
        .get()
        .pipe(Effect.orDie)
      if (!persisted) return yield* Effect.die(new Error(`Unable to initialize budget for session ${sessionID}`))
      syncState(state, persisted)
      return state.budget!
    })

    const exceeded = (
      sessionID: string,
      dimension: Dimension,
      limit: number,
      used: number,
    ): Effect.Effect<void, BudgetExceededError> =>
      Effect.fail(
        new BudgetExceededError({
          sessionID,
          dimension,
          limit,
          used,
        }),
      )

    const consume = Effect.fn("EngagementBudget.consume")(function* (
      sessionID: string,
      dimension: "tool-calls" | "tokens" | "findings",
      amount: number,
    ) {
      const database = yield* Effect.serviceOption(Database.Service)
      const lineage = Option.isSome(database) ? yield* ancestors(database.value.db, sessionID) : [sessionID]
      for (const id of lineage) yield* resolve(id)
      const lockOwner = lineage[lineage.length - 1] ?? sessionID
      const state = stateFor(lockOwner)
      return yield* state.lock.withPermit(
        Effect.gen(function* () {
          if (Option.isNone(database)) {
            const budget = state.budget ?? merge(undefined)
            const elapsed = Date.now() - state.startedAt
            if (elapsed > budget.maxWallClockMs) {
              return yield* exceeded(sessionID, "wall-clock", budget.maxWallClockMs, elapsed)
            }
            const nextUsed =
              dimension === "tool-calls"
                ? state.toolCalls + amount
                : dimension === "tokens"
                  ? state.tokens + amount
                  : state.findings + amount
            const limit =
              dimension === "tool-calls"
                ? budget.maxToolCalls
                : dimension === "tokens"
                  ? budget.maxTokens
                  : budget.maxFindings
            if (nextUsed > limit) return yield* exceeded(sessionID, dimension, limit, nextUsed)
            if (dimension === "tool-calls") state.toolCalls = nextUsed
            else if (dimension === "tokens") state.tokens = nextUsed
            else state.findings = nextUsed
            return
          }

          const db = database.value.db
          const updatedRows: Array<{ id: string; row: typeof EngagementBudgetTable.$inferSelect }> = []
          yield* db
            .transaction(() =>
              Effect.gen(function* () {
                const rows = yield* Effect.forEach(lineage, (id) =>
                  db
                    .select()
                    .from(EngagementBudgetTable)
                    .where(eq(EngagementBudgetTable.session_id, id as SessionSchema.ID))
                    .get()
                    .pipe(Effect.orDie),
                )
                for (let index = 0; index < rows.length; index++) {
                  const row = rows[index]
                  const id = lineage[index]!
                  if (!row) return yield* Effect.die(new Error(`Missing persisted budget for session ${id}`))
                  const budget = merge(row.budget)
                  const elapsed = Date.now() - row.started_at
                  if (elapsed > budget.maxWallClockMs) {
                    return yield* exceeded(id, "wall-clock", budget.maxWallClockMs, elapsed)
                  }
                  const nextUsed =
                    dimension === "tool-calls"
                      ? row.tool_calls + amount
                      : dimension === "tokens"
                        ? row.tokens + amount
                        : row.findings + amount
                  const limit =
                    dimension === "tool-calls"
                      ? budget.maxToolCalls
                      : dimension === "tokens"
                        ? budget.maxTokens
                        : budget.maxFindings
                  if (nextUsed > limit) return yield* exceeded(id, dimension, limit, nextUsed)
                }
                const updated: Array<{ id: string; row: typeof EngagementBudgetTable.$inferSelect }> = []
                for (let index = 0; index < rows.length; index++) {
                  const row = rows[index]!
                  const id = lineage[index]!
                  const budget = merge(row.budget)
                  const nextUsed =
                    dimension === "tool-calls"
                      ? row.tool_calls + amount
                      : dimension === "tokens"
                        ? row.tokens + amount
                        : row.findings + amount
                  const next = {
                    tool_calls: dimension === "tool-calls" ? nextUsed : row.tool_calls,
                    tokens: dimension === "tokens" ? nextUsed : row.tokens,
                    findings: dimension === "findings" ? nextUsed : row.findings,
                    started_at: row.started_at,
                    budget,
                    time_updated: Date.now(),
                  }
                  yield* db
                    .update(EngagementBudgetTable)
                    .set(next)
                    .where(eq(EngagementBudgetTable.session_id, id as SessionSchema.ID))
                    .run()
                    .pipe(Effect.orDie)
                  updated.push({ id, row: { ...row, ...next } })
                }
                updatedRows.push(...updated)
              }),
            )
            .pipe(
              Effect.catch((error) => (error instanceof BudgetExceededError ? Effect.fail(error) : Effect.die(error))),
            )
          for (const { id, row } of updatedRows) syncState(stateFor(id), row)
        }),
      )
    })

    const consumeToolCall = (sessionID: string) => consume(sessionID, "tool-calls", 1)

    const consumeTokens = (sessionID: string, tokens: number) => {
      if (!Number.isFinite(tokens) || tokens <= 0) return Effect.void
      return consume(sessionID, "tokens", Math.floor(tokens))
    }

    const consumeFinding = (sessionID: string) => consume(sessionID, "findings", 1)

    const forSession = Effect.fn("EngagementBudget.forSession")(function* (sessionID: string) {
      return yield* resolve(sessionID)
    })

    const usage = Effect.fn("EngagementBudget.usage")(function* (sessionID: string) {
      const budget = yield* resolve(sessionID)
      const state = stateFor(sessionID)
      const database = yield* Effect.serviceOption(Database.Service)
      if (Option.isSome(database)) {
        const row = yield* database.value.db
          .select()
          .from(EngagementBudgetTable)
          .where(eq(EngagementBudgetTable.session_id, sessionID as SessionSchema.ID))
          .get()
          .pipe(Effect.orDie)
        if (row) syncState(state, row)
      }
      return {
        toolCalls: state.toolCalls,
        tokens: state.tokens,
        findings: state.findings,
        elapsedMs: Date.now() - state.startedAt,
        startedAt: state.startedAt,
        budget,
      } satisfies BudgetUsage
    })

    const reset = Effect.fn("EngagementBudget.reset")(function* (sessionID: string) {
      const database = yield* Effect.serviceOption(Database.Service)
      if (Option.isSome(database)) {
        const budget = yield* resolve(sessionID)
        const now = Date.now()
        yield* database.value.db
          .update(EngagementBudgetTable)
          .set({ tool_calls: 0, tokens: 0, findings: 0, started_at: now, budget, time_updated: now })
          .where(eq(EngagementBudgetTable.session_id, sessionID as SessionSchema.ID))
          .run()
          .pipe(Effect.orDie)
      }
      states.delete(sessionID)
    })

    const acquireAgentSlot = Effect.fn("EngagementBudget.acquireAgentSlot")(function* (sessionID: string) {
      const database = yield* Effect.serviceOption(Database.Service)
      const lineage = Option.isSome(database) ? yield* ancestors(database.value.db, sessionID) : [sessionID]
      const rootSessionID = lineage[lineage.length - 1] ?? sessionID
      const budget = yield* resolve(rootSessionID)
      const state = stateFor(rootSessionID)
      // El semáforo se crea con el límite del presupuesto; si la config del
      // proyecto cambia, se redimensiona sin perder los permisos en vuelo.
      if (!state.agents) {
        state.agents = Semaphore.makeUnsafe(budget.maxConcurrentAgents)
        state.agentsLimit = budget.maxConcurrentAgents
      } else if (state.agentsLimit !== budget.maxConcurrentAgents) {
        state.agentsLimit = budget.maxConcurrentAgents
        yield* state.agents.resize(budget.maxConcurrentAgents)
      }
      yield* state.agents.take(1)
      const agents = state.agents
      return Effect.suspend(() => agents.release(1)).pipe(Effect.asVoid)
    })

    return Service.of({
      forSession,
      consumeToolCall,
      consumeTokens,
      consumeFinding,
      usage,
      reset,
      acquireAgentSlot,
    })
  }),
)

export const defaultLayer = layer
