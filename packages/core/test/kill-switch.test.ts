import { describe, expect } from "bun:test"
import { Effect, Layer, Schema } from "effect"
import { Audit } from "@argos/core/audit"
import { Database } from "@argos/core/database/database"
import { AgentV2 } from "@argos/core/agent"
import { Project } from "@argos/core/project"
import { ProjectTable } from "@argos/core/project/sql"
import { AbsolutePath } from "@argos/core/schema"
import { SessionV2 } from "@argos/core/session"
import { SessionKillSwitch } from "@argos/core/session/kill-switch"
import { SessionMessage } from "@argos/core/session/message"
import { SessionRunCoordinator } from "@argos/core/session/run-coordinator"
import { SessionRunner } from "@argos/core/session/runner"
import { EngagementBudget } from "@argos/core/session/budget"
import { Tool } from "@argos/core/tool/tool"
import { ToolOutputStore } from "@argos/core/tool-output-store"
import { ApplicationTools } from "@argos/core/tool/application-tools"
import { ToolRegistry } from "@argos/core/tool/registry"
import { SessionTable } from "@argos/core/session/sql"
import { testEffect } from "./lib/effect"

const database = Database.layerFromPath(":memory:")
const audit = Audit.layer.pipe(Layer.provide(database))
const killSwitch = SessionKillSwitch.defaultLayer
const budget = EngagementBudget.defaultLayer
const runner = Layer.mock(SessionRunner.Service, { run: () => Effect.void })
const coordinator = SessionRunCoordinator.layer.pipe(
  Layer.provide(runner),
  Layer.provide(killSwitch),
  Layer.provide(audit),
)
const it = testEffect(Layer.mergeAll(database, audit, killSwitch, budget, coordinator))

const registry = ToolRegistry.layer.pipe(
  Layer.provide(ApplicationTools.layer),
  Layer.provide(ToolOutputStore.defaultLayer),
  Layer.provide(budget),
  Layer.provide(killSwitch),
)
const registryIt = testEffect(Layer.mergeAll(database, killSwitch, budget, registry))

const sessionID = SessionV2.ID.make("ses_kill_switch")
const identity = {
  agent: AgentV2.ID.make("build"),
  assistantMessageID: SessionMessage.ID.make("msg_kill_switch"),
}

/** Crea un proyecto con presupuesto y una sesión que lo apunta. */
const seed = Effect.fn("KillSwitchTest.seed")(function* (input: {
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
      slug: "kill-switch",
      directory: "/project",
      title: "kill-switch",
      version: "test",
      agent: "analyst",
    })
    .run()
    .pipe(Effect.orDie)
  return input.session
})

const echo = Tool.make({
  description: "Echo text",
  input: Schema.Struct({ text: Schema.String }),
  output: Schema.Struct({ text: Schema.String }),
  execute: ({ text }) => Effect.succeed({ text }),
  toModelOutput: ({ output }) => [{ type: "text", text: output.text }],
})

describe("kill switch", () => {
  it.effect("marks the session as aborted", () =>
    Effect.gen(function* () {
      const service = yield* SessionKillSwitch.Service
      expect(yield* service.isAborted(sessionID)).toBe(false)

      yield* service.abort(sessionID, "operator stopped the engagement")

      expect(yield* service.isAborted(sessionID)).toBe(true)
      expect(yield* service.reason(sessionID)).toBe("operator stopped the engagement")
    }),
  )

  it.effect("keeps the first abort reason", () =>
    Effect.gen(function* () {
      const service = yield* SessionKillSwitch.Service
      const id = SessionV2.ID.make("ses_kill_switch_first")
      yield* service.abort(id, "first")
      yield* service.abort(id, "second")
      expect(yield* service.reason(id)).toBe("first")
    }),
  )

  it.effect("clears the abort state", () =>
    Effect.gen(function* () {
      const service = yield* SessionKillSwitch.Service
      const id = SessionV2.ID.make("ses_kill_switch_clear")
      yield* service.abort(id, "stop")
      expect(yield* service.isAborted(id)).toBe(true)
      yield* service.clear(id)
      expect(yield* service.isAborted(id)).toBe(false)
    }),
  )

  it.effect("records the abort in the audit chain without breaking it", () =>
    Effect.gen(function* () {
      const service = yield* SessionRunCoordinator.Service
      const chain = yield* Audit.Service

      yield* service.abort(sessionID, "operator stopped the engagement")

      const entries = yield* chain.list({ sessionID })
      expect(entries.total).toBe(1)
      expect(entries.items[0]?.event_type).toBe("engagement.abort")
      expect(entries.items[0]?.action).toBe("engagement.abort")
      expect(entries.items[0]?.session_id).toBe(sessionID)
      // La cadena sigue siendo válida: el evento de aborto no la rompe.
      expect(yield* chain.verify()).toEqual({ valid: true, total: 1 })
    }),
  )

  it.effect("marks the session aborted when the coordinator aborts it", () =>
    Effect.gen(function* () {
      const service = yield* SessionRunCoordinator.Service
      const switchState = yield* SessionKillSwitch.Service

      yield* service.abort(sessionID, "operator stopped the engagement")

      expect(yield* switchState.isAborted(sessionID)).toBe(true)
    }),
  )
})

describe("kill switch and tools", () => {
  registryIt.effect("fails a tool fast after the session was aborted", () =>
    Effect.gen(function* () {
      const registryService = yield* ToolRegistry.Service
      const switchState = yield* SessionKillSwitch.Service
      const session = yield* seed({ project: "proj_kill_switch", session: "ses_kill_switch_tools" })
      yield* registryService.register({ echo })
      const materialized = yield* registryService.materialize()

      const before = yield* materialized.settle({
        sessionID: session,
        ...identity,
        call: { type: "tool-call", id: "call-before", name: "echo", input: { text: "before" } },
      })
      expect(before.result).toEqual({ type: "text", value: "before" })

      yield* switchState.abort(session, "operator stopped the engagement")

      const after = yield* materialized.settle({
        sessionID: session,
        ...identity,
        call: { type: "tool-call", id: "call-after", name: "echo", input: { text: "after" } },
      })
      expect(after.result).toEqual({
        type: "error",
        value: "SESSION ABORTED: operator stopped the engagement",
      })
    }),
  )

  registryIt.effect("fails the tool with the typed budget error when the limit is exceeded", () =>
    Effect.gen(function* () {
      const registryService = yield* ToolRegistry.Service
      const session = yield* seed({
        project: "proj_kill_switch_budget",
        session: "ses_kill_switch_budget",
        budget: { maxToolCalls: 1 },
      })
      yield* registryService.register({ echo })
      const materialized = yield* registryService.materialize()

      yield* materialized.settle({
        sessionID: session,
        ...identity,
        call: { type: "tool-call", id: "call-budget-1", name: "echo", input: { text: "x" } },
      })

      const failure = yield* materialized
        .settle({
          sessionID: session,
          ...identity,
          call: { type: "tool-call", id: "call-budget-2", name: "echo", input: { text: "x" } },
        })
        .pipe(Effect.flip)
      expect(failure).toBeInstanceOf(EngagementBudget.BudgetExceededError)
      expect(failure.dimension).toBe("tool-calls")
      expect(failure.limit).toBe(1)
    }),
  )
})
