import { EventV2 } from "@argos/core/event"
import { Compliance } from "@argos/core/compliance"
import { FindingUpserted } from "@argos/core/security"
import * as Log from "@argos/core/util/log"
import { InstanceState } from "@/effect/instance-state"
import { EventBridge } from "@/event-bridge"
import { Context, Duration, Effect, Exit, Layer, Scope } from "effect"

const log = Log.create({ service: "compliance-hook" })
const disabled =
  process.env.ARGOS_DISABLE_COMPLIANCE === "true" || process.env.ARGOS_DISABLE_COMPLIANCE === "1"

// Monitoreo continuo (CCM): re-deriva todos los proyectos periódicamente para
// detectar drift aunque no lleguen findings nuevos (ej. cierres externos o
// cambios en la evidencia de Elasticsearch). Intervalo en ms por env.
const ccmDisabled = process.env.ARGOS_DISABLE_CCM === "true" || process.env.ARGOS_DISABLE_CCM === "1"
const ccmIntervalMs = Number(process.env.ARGOS_CCM_INTERVAL_MS ?? 300_000)
const sweepEnabled = !ccmDisabled && Number.isFinite(ccmIntervalMs) && ccmIntervalMs > 0

export interface Interface {
  readonly init: () => Effect.Effect<void>
}

export class Service extends Context.Service<Service, Interface>()("@argos/ComplianceHook") {}

export const layer = Layer.effect(
  Service,
  Effect.gen(function* () {
    const events = yield* EventBridge.Service
    const compliance = yield* Compliance.Service

    const state = yield* InstanceState.make(
      Effect.fn("ComplianceHook.state")(function* (_ctx) {
        const scope = yield* Scope.make()
        const unsubscribers: EventV2.Unsubscribe[] = []
        yield* Effect.addFinalizer(() =>
          Effect.forEach(unsubscribers, (unsubscribe) => unsubscribe, { discard: true }).pipe(
            Effect.andThen(Scope.close(scope, Exit.void)),
          ),
        )
        if (disabled) return

        const watch = <D extends EventV2.Definition>(
          def: D,
          fn: (data: EventV2.Data<D>) => Effect.Effect<void, unknown>,
        ) =>
          Effect.gen(function* () {
            const unsubscribe = yield* events.listen((event) => {
              if (event.type !== def.type || event.location?.directory !== _ctx.directory) return Effect.void
              return fn(event.data as EventV2.Data<D>).pipe(
                Effect.catchCause((cause) =>
                  Effect.sync(() => log.error("compliance subscriber failed", { type: def.type, cause })),
                ),
              )
            })
            unsubscribers.push(unsubscribe)
          })

        // Carga el catálogo desde las fuentes públicas la primera vez (best-effort,
        // nunca bloquea el bootstrap de la instancia).
        yield* compliance.ensureCatalog().pipe(
          Effect.forkIn(scope, { startImmediately: true }),
          Effect.asVoid,
        )

        // Cada finding persistido re-deriva el estado de controles de su proyecto.
        yield* watch(FindingUpserted, (data) =>
          compliance.recomputeSession(data.sessionID).pipe(
            Effect.forkIn(scope, { startImmediately: true }),
            Effect.asVoid,
          ),
        )

        // Monitoreo continuo: barrido periódico de todos los proyectos. Detecta
        // drift de controles incluso sin findings nuevos. Nunca bloquea el
        // bootstrap (forkIn en el scope de la instancia).
        if (sweepEnabled) {
          // Barrido inicial inmediato (baseline fresco desde el arranque) y
          // después en loop cada `ccmIntervalMs`. Nunca bloquea el bootstrap.
          const sweep = Effect.gen(function* () {
            yield* compliance.sweepAll().pipe(
              Effect.catchCause((cause) => Effect.sync(() => log.warn("ccm sweep failed", { cause }))),
            )
          })
          yield* Effect.gen(function* () {
            yield* sweep
            const loop = Effect.gen(function* () {
              yield* Effect.sleep(Duration.millis(ccmIntervalMs))
              yield* sweep
            })
            yield* loop.pipe(Effect.forever)
          }).pipe(Effect.forkIn(scope, { startImmediately: true }), Effect.asVoid)
        }
      }),
    )

    const init = Effect.fn("ComplianceHook.init")(function* () {
      if (disabled) return
      yield* InstanceState.get(state)
    })

    return Service.of({ init })
  }),
)

export const defaultLayer = layer.pipe(
  Layer.provide(EventBridge.defaultLayer),
  Layer.provide(Compliance.defaultLayer),
)

export * as ComplianceHook from "./hook"
