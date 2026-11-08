import { EventV2 } from "@argos/core/event"
import { FindingUpserted } from "@argos/core/security"
import { ThreatIntelEnrichment } from "@argos/core/threat-intel"
import * as Log from "@argos/core/util/log"
import { InstanceState } from "@/effect/instance-state"
import { EventBridge } from "@/event-bridge"
import { Context, Effect, Exit, Layer, Scope } from "effect"

const log = Log.create({ service: "threat-intel-hook" })
const disabled =
  process.env.ARGOS_DISABLE_ENRICHMENT === "true" || process.env.ARGOS_DISABLE_ENRICHMENT === "1"

export interface Interface {
  readonly init: () => Effect.Effect<void>
}

export class Service extends Context.Service<Service, Interface>()("@argos/ThreatIntelHook") {}

export const layer = Layer.effect(
  Service,
  Effect.gen(function* () {
    const events = yield* EventBridge.Service
    const enrichment = yield* ThreatIntelEnrichment.Service

    const state = yield* InstanceState.make(
      Effect.fn("ThreatIntelHook.state")(function* (_ctx) {
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
                  Effect.sync(() => log.error("enrichment subscriber failed", { type: def.type, cause })),
                ),
              )
            })
            unsubscribers.push(unsubscribe)
          })

        // Enrich cada finding persistido en segundo plano: el trabajo (incluida
        // la reputación con timeout) corre en un fiber del scope de instancia,
        // sin bloquear el dispatcher de eventos.
        yield* watch(FindingUpserted, (data) =>
          enrichment.enrich(data.findingID).pipe(
            Effect.forkIn(scope, { startImmediately: true }),
            Effect.asVoid,
          ),
        )
      }),
    )

    const init = Effect.fn("ThreatIntelHook.init")(function* () {
      if (disabled) return
      yield* InstanceState.get(state)
    })

    return Service.of({ init })
  }),
)

export const defaultLayer = layer.pipe(
  Layer.provide(EventBridge.defaultLayer),
  Layer.provide(ThreatIntelEnrichment.defaultLayer),
)

export * as ThreatIntelHook from "./hook"
