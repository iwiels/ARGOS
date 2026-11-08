import { Audit } from "@argos/core/audit"
import { Effect } from "effect"
import { HttpApiBuilder } from "effect/unstable/httpapi"
import { InstanceHttpApi } from "../api"
import { AuditQuery } from "../groups/audit"

export const auditHandlers = HttpApiBuilder.group(InstanceHttpApi, "audit", (handlers) =>
  Effect.gen(function* () {
    const audit = yield* Audit.Service

    const list = Effect.fn("AuditHttpApi.list")(function* (ctx: { query: typeof AuditQuery.Type }) {
      return yield* audit.list({
        sessionID: ctx.query.sessionID,
        limit: ctx.query.limit,
        offset: ctx.query.offset,
      })
    })

    const verify = Effect.fn("AuditHttpApi.verify")(function* () {
      return yield* audit.verify()
    })

    const summary = Effect.fn("AuditHttpApi.summary")(function* () {
      return yield* audit.getSummary()
    })

    return handlers.handle("list", list).handle("verify", verify).handle("summary", summary)
  }),
)
