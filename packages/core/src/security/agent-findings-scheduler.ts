export * as AgentFindingsScheduler from "./agent-findings-scheduler"

import { Effect, Option, Scope } from "effect"
import type { Database } from "../database/database"
import type { EventV2 } from "../event"
import type { Location } from "../location"
import { reconcileAgentFindings } from "./agent-findings-reconcile"

type DatabaseService = Database.Interface["db"]

/**
 * Espera antes de reconciliar. Los peer agents escriben sus hallazgos en el
 * store compartido en rafagas (una llamada por tool), asi que reconciliar en
 * cada parte leeria el directorio decenas de veces por el mismo lote.
 */
const RECONCILE_DELAY = "1200 millis"

/**
 * Una reconciliacion pendiente por sesion.
 *
 * Sin esto, cada tool call de la sesion releeria el store completo. Con
 * esto, una rafaga de llamadas del equipo dispara una sola lectura y el
 * resto espera a la siguiente ventana.
 */
const pending = new Set<string>()

/**
 * Programa la reconciliacion de los hallazgos que el equipo de agentes
 * escribio en el store compartido.
 *
 * Por que hace falta: los peer agents corren fuera del tracking de la
 * Session, asi que sus llamadas no producen un `PartUpdated` en la sesion del
 * orquestador y el camino de ingesta por tool part no las ve. El store es la
 * unica fuente de esos hallazgos, y el unico que permite Reconcile es el
 * Session ID exacto, asi que el backend tiene que ir a buscarlo.
 */
const defaultScope = Scope.makeUnsafe()

export function schedule(
  db: DatabaseService,
  sessionID: string,
  options?: { events?: EventV2.Interface; location?: Location.Ref },
): Effect.Effect<void> {
  if (pending.has(sessionID)) return Effect.void
  pending.add(sessionID)

  return Effect.gen(function* () {
    const scopeOpt = yield* Effect.serviceOption(Scope.Scope)
    const scope = Option.getOrElse(scopeOpt, () => defaultScope)
    yield* Effect.sleep(RECONCILE_DELAY).pipe(
      Effect.andThen(
        reconcileAgentFindings(db, { sessionID: sessionID as never }, options).pipe(
          // Una reconciliacion fallida no puede tumbar la sesion: los
          // hallazgos que no entran ahora entran en la siguiente.
          Effect.catch(() => Effect.void),
        ),
      ),
      // La ventana se libera en cualquier salida, incluida la interrupcion
      // por cierre del scope: si no, la sesion quedaria bloqueada para
      // siempre esperando una reconciliacion que nunca llega.
      Effect.ensuring(Effect.sync(() => pending.delete(sessionID))),
      Effect.forkIn(scope, { startImmediately: true }),
      Effect.asVoid,
    )
  })
}

/**
 * Ejecuta la reconciliacion de inmediato, sin ventana de espera.
 *
 * Se usa en los puntos donde el auditor espera el resultado ahora mismo
 * (por ejemplo, al abrir el panel de hallazgos de una sesion que ya termino).
 */
export function runNow(
  db: DatabaseService,
  sessionID: string,
  options?: { events?: EventV2.Interface; location?: Location.Ref },
): Effect.Effect<void> {
  return reconcileAgentFindings(db, { sessionID: sessionID as never }, options).pipe(
    Effect.catch(() => Effect.void),
  )
}
