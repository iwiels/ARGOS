import { Effect, Layer } from "effect"
import { Audit } from "../../audit"
import { LocationServiceMap } from "../../location-layer"
import { SessionRunCoordinator } from "../run-coordinator"
import { SessionRunner } from "../runner"
import { SessionSchema } from "../schema"
import { SessionStore } from "../store"
import { SessionExecution } from "../execution"
import { SessionKillSwitch } from "../kill-switch"
import { logFailure } from "../logging"

/** Current-process routing for implicit-local Locations. Future remote placement belongs here. */
export const layer = Layer.effect(
  SessionExecution.Service,
  Effect.gen(function* () {
    const store = yield* SessionStore.Service
    const locations = yield* LocationServiceMap
    const audit = yield* Audit.Service
    const killSwitch = yield* SessionKillSwitch.Service
    const coordinator = yield* SessionRunCoordinator.make<SessionSchema.ID, void, SessionRunner.RunError>({
      drain: Effect.fnUntraced(function* (sessionID: SessionSchema.ID, mode) {
        const session = yield* store.get(sessionID)
        if (!session) return yield* Effect.die(`Session not found: ${sessionID}`)
        return yield* SessionRunner.Service.use((runner) => runner.run({ sessionID, force: mode === "run" })).pipe(
          Effect.provide(locations.get(session.location)),
        )
      }),
      onFailure: (sessionID, cause) => logFailure("Failed to drain Session", sessionID, cause),
    })

    const abort = Effect.fn("SessionExecution.abort")(function* (
      sessionID: SessionSchema.ID,
      reason: string,
    ) {
      yield* killSwitch.abort(sessionID, reason)
      yield* coordinator.interrupt(sessionID)
      yield* audit.append(SessionRunCoordinator.abortEvent(sessionID, reason))
    })

    return SessionExecution.Service.of({
      interrupt: coordinator.interrupt,
      resume: coordinator.run,
      wake: coordinator.wake,
      abort,
    })
  }),
).pipe(Layer.provide(SessionKillSwitch.defaultLayer))

export const defaultLayer = layer.pipe(
  Layer.provide(SessionStore.defaultLayer),
  Layer.provide(Audit.defaultLayer),
)
