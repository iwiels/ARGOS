import { describe, expect } from "bun:test"
import { Context, Effect, Exit, Fiber, Layer } from "effect"
import { eq } from "drizzle-orm"
import { Audit } from "@argos/core/audit"
import { Database } from "@argos/core/database/database"
import { Project } from "@argos/core/project"
import { ProjectTable } from "@argos/core/project/sql"
import { AbsolutePath } from "@argos/core/schema"
import { SessionV2 } from "@argos/core/session"
import { EngagementBudget } from "@argos/core/session/budget"
import { EngagementBudgetTable, SessionTable } from "@argos/core/session/sql"
import { testEffect } from "./lib/effect"

const database = Database.layerFromPath(":memory:")
const budget = EngagementBudget.defaultLayer
const it = testEffect(Layer.mergeAll(database, budget))

/** Crea un proyecto con presupuesto y una sesión que lo apunta. */
const seed = Effect.fn("BudgetTest.seed")(function* (input: {
  project: string
  session: string
  budget?: Partial<EngagementBudget.EngagementBudget>
}) {
  const { db } = yield* Database.Service
  const projectID = Project.ID.make(input.project)
  yield* db
    .insert(ProjectTable)
    .values({
      id: projectID,
      worktree: AbsolutePath.make("/project"),
      sandboxes: [],
      budget: input.budget,
    })
    .run()
    .pipe(Effect.orDie)
  yield* db
    .insert(SessionTable)
    .values({
      id: SessionV2.ID.make(input.session),
      project_id: projectID,
      slug: "budget",
      directory: "/project",
      title: "budget",
      version: "test",
      agent: "analyst",
    })
    .run()
    .pipe(Effect.orDie)
  return input.session
})

const seedChild = Effect.fn("BudgetTest.seedChild")(function* (input: {
  project: string
  parent: string
  session: string
}) {
  const { db } = yield* Database.Service
  const projectID = Project.ID.make(input.project)
  yield* db
    .insert(SessionTable)
    .values({
      id: SessionV2.ID.make(input.session),
      project_id: projectID,
      parent_id: SessionV2.ID.make(input.parent),
      slug: "budget-child",
      directory: "/project",
      title: "budget child",
      version: "test",
      agent: "analyst",
    })
    .run()
    .pipe(Effect.orDie)
  return input.session
})

describe("EngagementBudget", () => {
  it.effect("falls back to the default budget when the project has none", () =>
    Effect.gen(function* () {
      const service = yield* EngagementBudget.Service
      const session = yield* seed({ project: "proj_budget_default", session: "ses_budget_default" })

      expect(yield* service.forSession(session)).toEqual(EngagementBudget.DEFAULT_BUDGET)
    }),
  )

  it.effect("uses the project budget over the default", () =>
    Effect.gen(function* () {
      const service = yield* EngagementBudget.Service
      const session = yield* seed({
        project: "proj_budget_scoped",
        session: "ses_budget_scoped",
        budget: { maxToolCalls: 3, maxTokens: 10, maxFindings: 2, maxConcurrentAgents: 1 },
      })

      const resolved = yield* service.forSession(session)
      expect(resolved.maxToolCalls).toBe(3)
      expect(resolved.maxTokens).toBe(10)
      expect(resolved.maxFindings).toBe(2)
      expect(resolved.maxConcurrentAgents).toBe(1)
      // Los campos ausentes caen en el default.
      expect(resolved.maxWallClockMs).toBe(EngagementBudget.DEFAULT_BUDGET.maxWallClockMs)
    }),
  )

  it.effect("consumes tool calls up to the limit and fails with the typed error after it", () =>
    Effect.gen(function* () {
      const service = yield* EngagementBudget.Service
      const session = yield* seed({
        project: "proj_budget_calls",
        session: "ses_budget_calls",
        budget: { maxToolCalls: 2 },
      })

      yield* service.consumeToolCall(session)
      yield* service.consumeToolCall(session)

      const failure = yield* service.consumeToolCall(session).pipe(Effect.flip)
      expect(failure).toBeInstanceOf(EngagementBudget.BudgetExceededError)
      expect(failure.dimension).toBe("tool-calls")
      expect(failure.limit).toBe(2)
      expect(failure.used).toBe(3)
      expect(failure.sessionID).toBe(session)

      const usage = yield* service.usage(session)
      expect(usage.toolCalls).toBe(2)
    }),
  )

  it.effect("accumulates tokens and fails once the token ceiling is crossed", () =>
    Effect.gen(function* () {
      const service = yield* EngagementBudget.Service
      const session = yield* seed({
        project: "proj_budget_tokens",
        session: "ses_budget_tokens",
        budget: { maxTokens: 1000 },
      })

      yield* service.consumeTokens(session, 400)
      yield* service.consumeTokens(session, 400)
      expect((yield* service.usage(session)).tokens).toBe(800)

      const failure = yield* service.consumeTokens(session, 400).pipe(Effect.flip)
      expect(failure.dimension).toBe("tokens")
      expect(failure.limit).toBe(1000)
      expect(failure.used).toBe(1200)
      // El consumo rechazado no se descuenta.
      expect((yield* service.usage(session)).tokens).toBe(800)
    }),
  )

  it.effect("charges child-agent consumption to the child and every parent engagement", () =>
    Effect.gen(function* () {
      const service = yield* EngagementBudget.Service
      const parent = yield* seed({
        project: "proj_budget_child_rollup",
        session: "ses_budget_parent_rollup",
        budget: { maxToolCalls: 1, maxTokens: 500, maxFindings: 1 },
      })
      const child = yield* seedChild({
        project: "proj_budget_child_rollup",
        parent,
        session: "ses_budget_child_rollup",
      })
      const grandchild = yield* seedChild({
        project: "proj_budget_child_rollup",
        parent: child,
        session: "ses_budget_grandchild_rollup",
      })

      yield* service.forSession(child)
      yield* service.forSession(grandchild)
      const { db } = yield* Database.Service
      yield* db
        .update(EngagementBudgetTable)
        .set({ budget: { ...EngagementBudget.DEFAULT_BUDGET, maxTokens: 750 } })
        .where(eq(EngagementBudgetTable.session_id, SessionV2.ID.make(child)))
        .run()
        .pipe(Effect.orDie)
      yield* db
        .update(EngagementBudgetTable)
        .set({ budget: { ...EngagementBudget.DEFAULT_BUDGET, maxTokens: 1_000 } })
        .where(eq(EngagementBudgetTable.session_id, SessionV2.ID.make(grandchild)))
        .run()
        .pipe(Effect.orDie)

      yield* service.consumeToolCall(grandchild)
      yield* service.consumeTokens(grandchild, 400)
      yield* service.consumeFinding(grandchild)

      expect(yield* service.usage(grandchild)).toMatchObject({ toolCalls: 1, tokens: 400, findings: 1 })
      expect(yield* service.usage(child)).toMatchObject({ toolCalls: 1, tokens: 400, findings: 1 })
      expect(yield* service.usage(parent)).toMatchObject({ toolCalls: 1, tokens: 400, findings: 1 })

      const callsExceeded = yield* service.consumeToolCall(grandchild).pipe(Effect.flip)
      expect(callsExceeded).toMatchObject({ sessionID: parent, dimension: "tool-calls", limit: 1, used: 2 })
      const tokensExceeded = yield* service.consumeTokens(grandchild, 200).pipe(Effect.flip)
      expect(tokensExceeded).toMatchObject({ sessionID: parent, dimension: "tokens", limit: 500, used: 600 })
      const findingsExceeded = yield* service.consumeFinding(grandchild).pipe(Effect.flip)
      expect(findingsExceeded).toMatchObject({ sessionID: parent, dimension: "findings", limit: 1, used: 2 })

      expect(yield* service.usage(grandchild)).toMatchObject({ toolCalls: 1, tokens: 400, findings: 1 })
      expect(yield* service.usage(child)).toMatchObject({ toolCalls: 1, tokens: 400, findings: 1 })
      expect(yield* service.usage(parent)).toMatchObject({ toolCalls: 1, tokens: 400, findings: 1 })
    }),
  )

  it.effect("serializes consumption from sibling agents against the shared parent limit", () =>
    Effect.gen(function* () {
      const service = yield* EngagementBudget.Service
      const parent = yield* seed({
        project: "proj_budget_sibling_rollup",
        session: "ses_budget_sibling_parent",
        budget: { maxToolCalls: 1 },
      })
      const children = yield* Effect.forEach(["ses_budget_sibling_a", "ses_budget_sibling_b"], (session) =>
        seedChild({ project: "proj_budget_sibling_rollup", parent, session }),
      )

      const results = yield* Effect.forEach(
        children,
        (session) => service.consumeToolCall(session).pipe(Effect.exit),
        { concurrency: "unbounded" },
      )

      expect(results.filter(Exit.isSuccess)).toHaveLength(1)
      expect(yield* service.usage(parent)).toMatchObject({ toolCalls: 1 })
    }),
  )

  it.effect("consumes findings up to the limit", () =>
    Effect.gen(function* () {
      const service = yield* EngagementBudget.Service
      const session = yield* seed({
        project: "proj_budget_findings",
        session: "ses_budget_findings",
        budget: { maxFindings: 1 },
      })

      yield* service.consumeFinding(session)
      const failure = yield* service.consumeFinding(session).pipe(Effect.flip)
      expect(failure.dimension).toBe("findings")
      expect(failure.limit).toBe(1)
      expect(failure.used).toBe(2)
    }),
  )

  it.effect("fails once the persisted wall clock of the session is exhausted", () =>
    Effect.gen(function* () {
      const service = yield* EngagementBudget.Service
      const session = yield* seed({
        project: "proj_budget_clock",
        session: "ses_budget_clock",
        budget: { maxWallClockMs: 1000, maxToolCalls: 100 },
      })

      yield* service.forSession(session)
      const { db } = yield* Database.Service
      yield* db
        .update(EngagementBudgetTable)
        .set({ started_at: Date.now() - 2000 })
        .where(eq(EngagementBudgetTable.session_id, SessionV2.ID.make(session)))
        .run()
        .pipe(Effect.orDie)
      const failure = yield* service.consumeToolCall(session).pipe(Effect.flip)
      expect(failure.dimension).toBe("wall-clock")
      expect(failure.limit).toBe(1000)
      expect(failure.used).toBeGreaterThanOrEqual(2000)
    }),
  )

  it.effect("never overshoots the tool call limit under concurrency", () =>
    Effect.gen(function* () {
      const service = yield* EngagementBudget.Service
      const session = yield* seed({
        project: "proj_budget_race",
        session: "ses_budget_race",
        budget: { maxToolCalls: 3 },
      })

      const attempts = 10
      const results = yield* Effect.all(
        Array.from({ length: attempts }, () =>
          service.consumeToolCall(session).pipe(
            Effect.map(() => "ok" as const),
            Effect.catchTag("EngagementBudget.BudgetExceededError", () => Effect.succeed("exceeded" as const)),
          ),
        ),
        { concurrency: "unbounded" },
      )

      const passed = results.filter((result) => result === "ok").length
      const exceeded = results.filter((result) => result === "exceeded").length
      expect(passed).toBe(3)
      expect(exceeded).toBe(attempts - 3)
      // El límite no se sobrepasó nunca.
      expect((yield* service.usage(session)).toolCalls).toBe(3)
    }),
  )

  it.effect("resets the counters of a session", () =>
    Effect.gen(function* () {
      const service = yield* EngagementBudget.Service
      const session = yield* seed({
        project: "proj_budget_reset",
        session: "ses_budget_reset",
        budget: { maxToolCalls: 1 },
      })

      yield* service.consumeToolCall(session)
      expect(yield* service.consumeToolCall(session).pipe(Effect.flip)).toBeInstanceOf(
        EngagementBudget.BudgetExceededError,
      )

      yield* service.reset(session)
      expect((yield* service.usage(session)).toolCalls).toBe(0)
      yield* service.consumeToolCall(session)
    }),
  )

  it.effect("persists consumption across service reinitialization", () =>
    Effect.gen(function* () {
      const service = yield* EngagementBudget.Service
      const session = yield* seed({
        project: "proj_budget_memory",
        session: "ses_budget_memory",
        budget: { maxToolCalls: 1 },
      })

      yield* service.consumeToolCall(session)
      yield* service.consumeTokens(session, 57)
      yield* service.consumeFinding(session)
      expect(yield* service.consumeToolCall(session).pipe(Effect.flip)).toBeInstanceOf(
        EngagementBudget.BudgetExceededError,
      )
      const { db } = yield* Database.Service
      yield* db
        .update(ProjectTable)
        .set({ budget: { maxToolCalls: 100 } })
        .where(eq(ProjectTable.id, Project.ID.make("proj_budget_memory")))
        .run()
        .pipe(Effect.orDie)

      const restarted = yield* Layer.build(Layer.fresh(EngagementBudget.defaultLayer))
      const parent = yield* Effect.context()
      const restartedContext = Context.merge(parent, restarted)
      const usage = yield* Effect.gen(function* () {
        const fresh = yield* EngagementBudget.Service
        return yield* fresh.usage(session)
      }).pipe(Effect.provideContext(restartedContext))

      expect(usage).toMatchObject({ toolCalls: 1, tokens: 57, findings: 1, budget: { maxToolCalls: 1 } })
      const failure = yield* Effect.gen(function* () {
        const fresh = yield* EngagementBudget.Service
        return yield* fresh.consumeToolCall(session).pipe(Effect.flip)
      }).pipe(Effect.provideContext(restartedContext))
      expect(failure).toBeInstanceOf(EngagementBudget.BudgetExceededError)
    }),
  )

  it.effect("limits the concurrency of subagents to the configured maximum", () =>
    Effect.gen(function* () {
      const service = yield* EngagementBudget.Service
      const parent = yield* seed({
        project: "proj_budget_agents",
        session: "ses_budget_agents",
        budget: { maxConcurrentAgents: 2 },
      })
      const agents = yield* Effect.forEach(["ses_budget_agent_a", "ses_budget_agent_b", "ses_budget_agent_c"], (session) =>
        seedChild({ project: "proj_budget_agents", parent, session }),
      )

      const releaseOne = yield* service.acquireAgentSlot(agents[0]!)
      const releaseTwo = yield* service.acquireAgentSlot(agents[1]!)

      let acquired = false
      const third = yield* service.acquireAgentSlot(agents[2]!).pipe(
        Effect.map((release) => {
          acquired = true
          return release
        }),
        Effect.forkChild,
      )
      yield* Effect.yieldNow
      expect(acquired).toBe(false)

      yield* releaseOne
      const releaseThree = yield* Fiber.join(third)
      expect(acquired).toBe(true)
      yield* releaseTwo
      yield* releaseThree
    }),
  )
})

const auditIt = testEffect(Layer.mergeAll(database, budget, Audit.layer.pipe(Layer.provide(database))))

describe("EngagementBudget audit chain", () => {
  auditIt.effect("keeps the audit chain valid after budget events", () =>
    Effect.gen(function* () {
      const audit = yield* Audit.Service
      const service = yield* EngagementBudget.Service
      const session = yield* seed({
        project: "proj_budget_chain",
        session: "ses_budget_chain",
      })
      yield* service.consumeToolCall(session)
      yield* audit.append({
        sessionID: SessionV2.ID.make(session),
        eventType: "engagement.abort",
        action: "engagement.abort",
        summary: "Engagement aborted: test",
        payload: { reason: "test" },
      })
      expect(yield* audit.verify()).toEqual({ valid: true, total: 1 })
    }),
  )
})
