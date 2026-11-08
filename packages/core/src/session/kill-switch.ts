export * as SessionKillSwitch from "./kill-switch"

import { Context, Effect, Layer } from "effect"

/**
 * Estado de parada de emergencia de un engagement.
 *
 * Vive aparte del presupuesto a propósito: el kill switch no consulta la base
 * (tiene que responder en microsegundos, incluso con la base trabada) y lo
 * consultan dos mundos que no se deben conocer entre sí: el registro de tools
 * y el coordinador de ejecución.
 */
export interface Interface {
  /** Marca la sesión como abortada. Idempotente: el primer motivo gana. */
  readonly abort: (sessionID: string, reason: string) => Effect.Effect<void>
  /** ¿La sesión está abortada? */
  readonly isAborted: (sessionID: string) => Effect.Effect<boolean>
  /** Motivo del aborto, si hubo. */
  readonly reason: (sessionID: string) => Effect.Effect<string | undefined>
  /** Libera el estado de aborto (arranque de un nuevo engagement). */
  readonly clear: (sessionID: string) => Effect.Effect<void>
}

export class Service extends Context.Service<Service, Interface>()("@argos/SessionKillSwitch") {}

export const layer = Layer.sync(Service, () => {
  const aborted = new Map<string, string>()

  return Service.of({
    abort: (sessionID, reason) =>
      Effect.sync(() => {
        if (!aborted.has(sessionID)) aborted.set(sessionID, reason)
      }),
    isAborted: (sessionID) => Effect.sync(() => aborted.has(sessionID)),
    reason: (sessionID) => Effect.sync(() => aborted.get(sessionID)),
    clear: (sessionID) =>
      Effect.sync(() => {
        aborted.delete(sessionID)
      }),
  })
})

export const defaultLayer = layer
