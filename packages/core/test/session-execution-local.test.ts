import { expect, test } from "bun:test"
import { DateTime, Effect, Layer } from "effect"
import { Audit } from "../src/audit"
import { LocationServiceMap } from "../src/location-layer"
import { ProjectV2 } from "../src/project"
import { SessionExecution } from "../src/session/execution"
import * as SessionExecutionLocal from "../src/session/execution/local"
import { SessionSchema } from "../src/session/schema"
import { SessionStore } from "../src/session/store"
import { SessionRunner } from "../src/session/runner"
import { Location } from "../src/location"
import { AbsolutePath } from "../src/schema"
import { testEffect } from "./lib/effect"

const sessionID = SessionSchema.ID.make("ses_execution_resume")
const session = SessionSchema.Info.make({
  id: sessionID,
  projectID: ProjectV2.ID.make("prj_execution_resume"),
  title: "Execution resume",
  cost: 0,
  tokens: { input: 0, output: 0, reasoning: 0, cache: { read: 0, write: 0 } },
  time: { created: DateTime.makeUnsafe(1), updated: DateTime.makeUnsafe(1) },
  location: Location.Ref.make({ directory: AbsolutePath.make("/project") }),
})

const runnerCalls: Array<{ sessionID: SessionSchema.ID; force?: boolean }> = []
const runner = Layer.mock(SessionRunner.Service, {
  run: (input) =>
    Effect.sync(() => {
      runnerCalls.push(input)
    }),
})
const runtime = SessionExecutionLocal.layer.pipe(
  Layer.provide(
    Layer.mergeAll(
      Layer.mock(SessionStore.Service, {
        get: (id) => Effect.succeed(id === sessionID ? session : undefined),
      }),
      Layer.mock(LocationServiceMap, { get: () => runner }),
      Layer.mock(Audit.Service, {}),
    ),
  ),
)
const it = testEffect(runtime)

it.effect("routes an explicit resume to the session runner", () =>
  Effect.gen(function* () {
    runnerCalls.length = 0
    const execution = yield* SessionExecution.Service

    yield* execution.resume(sessionID)

    expect(runnerCalls).toEqual([{ sessionID, force: true }])
  }),
)
