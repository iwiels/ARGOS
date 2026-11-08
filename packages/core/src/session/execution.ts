export * as SessionExecution from "./execution"

import { Context, Effect, Layer } from "effect"
import { SessionRunner } from "./runner/index"
import { SessionSchema } from "./schema"

export interface Interface {
  /** Explicitly drain one Session, making at least one provider attempt. */
  readonly resume: (sessionID: SessionSchema.ID) => Effect.Effect<void, SessionRunner.RunError>
  /** Schedule a drain after durable work is recorded. Repeated wakeups may coalesce. */
  readonly wake: (sessionID: SessionSchema.ID, seq?: number) => Effect.Effect<void, SessionRunner.RunError>
  /** Interrupt active work owned by this process. Idle interruption is a no-op. */
  readonly interrupt: (sessionID: SessionSchema.ID, seq?: number) => Effect.Effect<void>
  /**
   * Emergency stop: mark the Session aborted so later tools fail fast, cut the
   * in-flight execution and record the event in the audit chain.
   */
  readonly abort: (sessionID: SessionSchema.ID, reason: string) => Effect.Effect<void>
}

/** Routes execution from a Session ID to the runner owned by that Session's Location. */
export class Service extends Context.Service<Service, Interface>()("@argos/SessionExecution") {}

/** Low-level compatibility layer for callers that only need durable Session recording. */
export const noopLayer = Layer.succeed(
  Service,
  Service.of({
    resume: () => Effect.void,
    wake: () => Effect.void,
    interrupt: () => Effect.void,
    abort: () => Effect.void,
  }),
)
