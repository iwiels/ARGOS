import { Compliance } from "@argos/core/compliance"
import { Effect } from "effect"
import { HttpApiBuilder } from "effect/unstable/httpapi"
import { InstanceHttpApi } from "../api"

export const complianceHandlers = HttpApiBuilder.group(InstanceHttpApi, "compliance", (handlers) =>
  Effect.gen(function* () {
    const compliance = yield* Compliance.Service

    const status = Effect.fn("ComplianceHttpApi.status")(function* (ctx: { params: { sessionID: string } }) {
      return yield* compliance.getSessionStatus(ctx.params.sessionID)
    })

    const refresh = Effect.fn("ComplianceHttpApi.refresh")(function* () {
      return yield* compliance.refresh()
    })

    return handlers.handle("status", status).handle("refresh", refresh)
  }),
)
