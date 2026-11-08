import { Audit } from "@argos/core/audit"
import { EventV2 } from "@argos/core/event"
import * as Log from "@argos/core/util/log"
import { InstanceState } from "@/effect/instance-state"
import { EventBridge } from "@/event-bridge"
import { Message } from "@/session/message"
import { Session } from "@/session/session"
import { Context, Effect, Exit, Layer, Scope } from "effect"

const log = Log.create({ service: "audit-hook" })
const disabled = process.env.ARGOS_DISABLE_AUDIT === "true" || process.env.ARGOS_DISABLE_AUDIT === "1"

const MAX = 2000
const trim = (text: string, max = MAX) =>
  text.length <= max ? text : `${text.slice(0, max)}\n[truncated: omitted ${text.length - max} chars]`

const json = (value: unknown, max = MAX) => {
  try {
    return trim(JSON.stringify(value), max)
  } catch {
    return "{}"
  }
}

// Los audit logs capturan qué ordenó el agente, nunca el output completo de la tool.
const toolTarget = (input: Record<string, unknown> | undefined) => {
  if (!input) return undefined
  for (const key of ["target", "url", "host", "path", "index", "domain", "endpoint"]) {
    const value = input[key]
    if (typeof value === "string" && value) return value
  }
  return undefined
}

export interface Interface {
  readonly init: () => Effect.Effect<void>
}

export class Service extends Context.Service<Service, Interface>()("@argos/AuditHook") {}

export const layer = Layer.effect(
  Service,
  Effect.gen(function* () {
    const events = yield* EventBridge.Service
    const audit = yield* Audit.Service

    const state = yield* InstanceState.make(
      Effect.fn("AuditHook.state")(function* (_ctx) {
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
                  Effect.sync(() => log.error("audit subscriber failed", { type: def.type, cause })),
                ),
              )
            })
            unsubscribers.push(unsubscribe)
          })

        yield* watch(Session.Event.Created, (data) =>
          audit.append({
            sessionID: data.info.id,
            projectID: data.info.projectID,
            eventType: "session.created",
            action: "session.create",
            agent: data.info.agent,
            target: data.info.directory,
            summary: `Session created: ${data.info.title}`,
            payload: { title: data.info.title, parentID: data.info.parentID, workspaceID: data.info.workspaceID },
          }),
        )

        yield* watch(Session.Event.Deleted, (data) =>
          audit.append({
            sessionID: data.sessionID,
            projectID: data.info.projectID,
            eventType: "session.deleted",
            action: "session.delete",
            agent: data.info.agent,
            target: data.info.directory,
            summary: `Session deleted: ${data.info.title}`,
            payload: { title: data.info.title },
          }),
        )

        yield* watch(Message.Event.Updated, (data) => {
          const info = data.info
          if (info.role === "assistant" && !info.finish && !info.error) return Effect.void
          const model =
            info.role === "user"
              ? `${info.model.providerID}/${info.model.modelID}`
              : `${info.providerID}/${info.modelID}`
          return audit.append({
            sessionID: info.sessionID,
            eventType: info.role === "user" ? "prompt.created" : "message.completed",
            action: info.role === "user" ? "prompt" : "assistant",
            agent: info.agent,
            target: model,
            summary: info.role === "user" ? "User prompt" : "Assistant response completed",
            payload: { role: info.role, model },
          })
        })

        yield* watch(Message.Event.PartUpdated, (data) => {
          const part = data.part
          if (part.type !== "tool") return Effect.void
          const status = part.state.status
          if (status !== "completed" && status !== "error") return Effect.void
          const input = part.state.input as Record<string, unknown> | undefined
          return audit.append({
            sessionID: part.sessionID,
            eventType: status === "completed" ? "tool.executed" : "tool.error",
            action: part.tool,
            target: toolTarget(input),
            summary: `Tool ${part.tool} ${status}`,
            payload: { status, input: json(input) },
          })
        })

        yield* watch(Message.Event.PartRemoved, (data) =>
          audit.append({
            sessionID: data.sessionID,
            eventType: "part.removed",
            action: "part.delete",
            summary: `Part removed: ${data.partID}`,
            payload: { messageID: data.messageID, partID: data.partID },
          }),
        )

        yield* watch(Message.Event.Removed, (data) =>
          audit.append({
            sessionID: data.sessionID,
            eventType: "message.removed",
            action: "message.delete",
            summary: `Message removed: ${data.messageID}`,
            payload: { messageID: data.messageID },
          }),
        )

        yield* watch(Session.Event.Diff, (data) =>
          audit.append({
            sessionID: data.sessionID,
            eventType: "file.changed",
            action: "session.diff",
            summary: `${data.diff.length} file change(s)`,
            payload: {
              files: data.diff
                .map((item) => item.file)
                .filter((file): file is string => !!file)
                .slice(0, 100),
            },
          }),
        )
      }),
    )

    const init = Effect.fn("AuditHook.init")(function* () {
      if (disabled) return
      yield* InstanceState.get(state)
    })

    return Service.of({ init })
  }),
)

export const defaultLayer = layer.pipe(
  Layer.provide(EventBridge.defaultLayer),
  Layer.provide(Audit.defaultLayer),
)

export * as AuditHook from "./hook"
