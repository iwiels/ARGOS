import { Database } from "@argos/core/database/database"
import {
  diffTrafficExchanges,
  getTrafficExchange,
  listTrafficExchanges,
  reconcileTrafficStore,
} from "@argos/core/security/traffic"
import { Effect } from "effect"
import { HttpApiBuilder } from "effect/unstable/httpapi"
import type { SessionID } from "@/session/schema"
import { InstanceHttpApi } from "../api"

/**
 * El store de tráfico en disco es la fuente de verdad: lo escribe el binario
 * Go (`argos-bin/internal/traffic`) y las credenciales ya vienen
 * enmascaradas. La tabla `traffic_exchange` es un índice de lectura para la
 * UI, así que cada request la reconcilia antes de leerla — nunca hay dos
 * fuentes de verdad.
 */
export const trafficHandlers = HttpApiBuilder.group(InstanceHttpApi, "traffic", (handlers) =>
  Effect.gen(function* () {
    const list = Effect.fn("TrafficHttpApi.list")(function* (ctx: {
      params: { sessionID: SessionID }
      query: {
        host?: string
        method?: string
        status?: string
        tool?: string
        limit?: number
        offset?: number
      }
    }) {
      const { db } = yield* Database.Service
      yield* reconcileTrafficStore(db, { sessionID: ctx.params.sessionID })
      const result = yield* listTrafficExchanges(db, {
        sessionID: ctx.params.sessionID,
        filter: {
          host: ctx.query.host,
          method: ctx.query.method,
          status: ctx.query.status,
          sourceTool: ctx.query.tool,
          limit: ctx.query.limit,
          offset: ctx.query.offset,
        },
      })
      return { exchanges: result.data, total: result.total }
    })

    const get = Effect.fn("TrafficHttpApi.get")(function* (ctx: {
      params: { sessionID: SessionID; exchangeID: string }
    }) {
      const { db } = yield* Database.Service
      yield* reconcileTrafficStore(db, { sessionID: ctx.params.sessionID })
      const exchange = yield* getTrafficExchange(db, {
        sessionID: ctx.params.sessionID,
        exchangeID: ctx.params.exchangeID,
      })
      // Sin exchange no hay panel: un 404 explícito es mejor que un
      // exchange vacío que el auditor tomaría por "no hay tráfico".
      if (!exchange) return undefined
      return exchange
    })

    const diff = Effect.fn("TrafficHttpApi.diff")(function* (ctx: {
      params: { sessionID: SessionID; aID: string; bID: string }
    }) {
      const { db } = yield* Database.Service
      yield* reconcileTrafficStore(db, { sessionID: ctx.params.sessionID })
      return yield* diffTrafficExchanges(db, {
        sessionID: ctx.params.sessionID,
        aID: ctx.params.aID,
        bID: ctx.params.bID,
      })
    })

    return handlers.handle("list", list).handle("get", get).handle("diff", diff)
  }),
)
