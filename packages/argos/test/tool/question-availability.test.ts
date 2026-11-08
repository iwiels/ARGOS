import { afterEach, describe, expect } from "bun:test"
import path from "path"
import { Effect, Layer } from "effect"
import { FetchHttpClient } from "effect/unstable/http"
import { CrossSpawnSpawner } from "@argos/core/cross-spawn-spawner"
import { Database } from "@argos/core/database/database"
import { Audit } from "@argos/core/audit"
import { EngagementBudget } from "@argos/core/session/budget"
import { FSUtil } from "@argos/core/fs-util"
import { Search } from "@argos/core/filesystem/search"
import { Agent } from "@/agent/agent"
import { BackgroundJob } from "@/background/job"
import { EventBridge } from "@/event-bridge"
import { Format } from "@/format"
import { Git } from "@/git"
import { InstanceState } from "@/effect/instance-state"
import { Instruction } from "@/session/instruction"
import { LSP } from "@/lsp/lsp"
import { Plugin } from "@/plugin"
import { Provider } from "@/provider/provider"
import { Question } from "@/question"
import { Reference } from "@/reference/reference"
import { RepositoryCache } from "@/reference/repository-cache"
import { RuntimeFlags } from "@/effect/runtime-flags"
import { Session } from "@/session/session"
import { SessionStatus } from "@/session/status"
import { Skill } from "@/skill"
import { Todo } from "@/session/todo"
import { ToolRegistry } from "@/tool/registry"
import * as Truncate from "@/tool/truncate"
import { TestConfig } from "../fixture/config"
import { disposeAllInstances } from "../fixture/fixture"
import { testEffect } from "../lib/effect"

afterEach(async () => {
  await disposeAllInstances()
})

const configLayer = TestConfig.layer({
  directories: () => InstanceState.directory.pipe(Effect.map((dir) => [path.join(dir, ".opencode")])),
})

/**
 * Se arma sobre `ToolRegistry.layer` y no sobre `defaultLayer`: este último
 * provee su propio `RuntimeFlags.defaultLayer`, así que los flags que se pasen
 * por fuera quedan ignorados y la prueba mediría siempre el entorno por defecto.
 */
const registryLayer = (flags: Partial<RuntimeFlags.Info>) =>
  ToolRegistry.layer
    .pipe(
      Layer.provide(configLayer),
      Layer.provide(Plugin.defaultLayer),
      Layer.provide(Question.defaultLayer),
      Layer.provide(Todo.defaultLayer),
      Layer.provide(Skill.defaultLayer),
      Layer.provide(Agent.defaultLayer),
      Layer.provide(Session.defaultLayer),
      Layer.provide(Layer.mergeAll(SessionStatus.defaultLayer, BackgroundJob.defaultLayer)),
      Layer.provide(Provider.defaultLayer),
      Layer.provide(Layer.mergeAll(Git.defaultLayer, RepositoryCache.defaultLayer)),
      Layer.provide(Reference.defaultLayer),
      Layer.provide(LSP.defaultLayer),
      Layer.provide(Instruction.defaultLayer),
      Layer.provide(FSUtil.defaultLayer),
      Layer.provide(EventBridge.defaultLayer),
      Layer.provide(FetchHttpClient.layer),
      Layer.provide(Format.defaultLayer),
      Layer.provide(Layer.mergeAll(EngagementBudget.defaultLayer, Audit.defaultLayer)),
      Layer.provide(Layer.mergeAll(CrossSpawnSpawner.defaultLayer, Database.defaultLayer)),
      Layer.provide(Layer.mergeAll(Search.defaultLayer, Truncate.defaultLayer)),
    )
    .pipe(Layer.provide(RuntimeFlags.layer(flags)))

const desktop = testEffect(registryLayer({ client: "desktop" }))
const headless = testEffect(registryLayer({ client: "server" }))
const headlessForced = testEffect(registryLayer({ client: "server", enableQuestionTool: true }))

/**
 * Un agente reportó "el entorno no expone la tool `question`" y, en vez de
 * preguntar, rellenó el entregable con marcadores. Estas pruebas fijan que en
 * el cliente de escritorio la tool SÍ se registra: si vuelve a pasar es
 * alucinación del modelo, no una regresión del host.
 */
describe("disponibilidad de la tool question", () => {
  desktop.instance("se registra en el cliente de escritorio, que es el que usa la app", () =>
    Effect.gen(function* () {
      const registry = yield* ToolRegistry.Service
      expect(yield* registry.ids()).toContain("question")
    }),
  )

  headless.instance("queda fuera en un cliente sin interfaz donde nadie podría responder", () =>
    Effect.gen(function* () {
      const registry = yield* ToolRegistry.Service
      expect(yield* registry.ids()).not.toContain("question")
    }),
  )

  headlessForced.instance("se puede forzar en un cliente sin interfaz con el flag explícito", () =>
    Effect.gen(function* () {
      const registry = yield* ToolRegistry.Service
      expect(yield* registry.ids()).toContain("question")
    }),
  )
})
