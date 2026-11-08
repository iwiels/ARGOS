import { eq } from "drizzle-orm"
import { EventV2 } from "@argos/core/event"
import { FindingUpserted } from "@argos/core/security"
import { FindingTable } from "@argos/core/security/sql"
import { dispatchFindingsWebhook } from "@argos/core/security/webhook"
import { Database } from "@argos/core/database/database"
import { ProjectV2 } from "@argos/core/project"
import * as Log from "@argos/core/util/log"
import { InstanceState } from "@/effect/instance-state"
import { EventBridge } from "@/event-bridge"
import { Project } from "@/project/project"
import { Context, Effect, Exit, Layer, Scope } from "effect"

const log = Log.create({ service: "webhook-hook" })
const disabled = process.env.ARGOS_DISABLE_WEBHOOK === "true" || process.env.ARGOS_DISABLE_WEBHOOK === "1"

export interface Interface {
  readonly init: () => Effect.Effect<void>
}

export class Service extends Context.Service<Service, Interface>()("@argos/WebhookHook") {}

export const layer = Layer.effect(
  Service,
  Effect.gen(function* () {
    const events = yield* EventBridge.Service
    const project = yield* Project.Service
    const { db } = yield* Database.Service

    const state = yield* InstanceState.make(
      Effect.fn("WebhookHook.state")(function* (_ctx) {
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
                  Effect.sync(() => log.error("webhook subscriber failed", { type: def.type, cause })),
                ),
              )
            })
            unsubscribers.push(unsubscribe)
          })

        // Cada finding persistido se despacha al webhook configurado del
        // proyecto, si tiene uno habilitado. Corre en background (forkIn) para
        // no bloquear el flujo de ingesta con un fetch de red saliente.
        yield* watch(FindingUpserted, (data) =>
          Effect.gen(function* () {
            const finding = yield* db
              .select()
              .from(FindingTable)
              .where(eq(FindingTable.id, data.findingID))
              .get()
              .pipe(Effect.orDie)
            if (!finding) return

            const info = yield* project.get(ProjectV2.ID.make(finding.project_id))
            const webhook = info?.webhook
            if (!webhook?.enabled) return

            const result = yield* dispatchFindingsWebhook([finding], {
              url: webhook.url,
              secret: webhook.secret,
              format: webhook.format,
            })
            if (!result.ok) log.warn("webhook dispatch failed", { projectID: finding.project_id, statusCode: result.statusCode })
          }).pipe(
            Effect.forkIn(scope, { startImmediately: true }),
            Effect.asVoid,
          ),
        )
      }),
    )

    const init = Effect.fn("WebhookHook.init")(function* () {
      if (disabled) return
      yield* InstanceState.get(state)
    })

    return Service.of({ init })
  }),
)

export const defaultLayer = layer.pipe(
  Layer.provide(EventBridge.defaultLayer),
  Layer.provide(Project.defaultLayer),
  Layer.provide(Database.defaultLayer),
)

export * as WebhookHook from "./webhook-hook"
