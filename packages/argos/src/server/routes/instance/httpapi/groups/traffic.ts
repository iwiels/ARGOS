import { Schema } from "effect"
import { HttpApi, HttpApiEndpoint, HttpApiGroup, OpenApi } from "effect/unstable/httpapi"
import { NonNegativeInt } from "@argos/core/schema"
import { SessionID } from "@/session/schema"
import { Authorization } from "../middleware/authorization"
import { InstanceContextMiddleware } from "../middleware/instance-context"
import { WorkspaceRoutingMiddleware, WorkspaceRoutingQuery, WorkspaceRoutingQueryFields } from "../middleware/workspace-routing"
import { described } from "./metadata"

/**
 * Un exchange de tráfico tal como lo consume el panel: los cuerpos vienen
 * del store (que ya enmascaró las credenciales) y las cabeceras son un
 * mapa de nombre a valores.
 */
export const TrafficExchangeSchema = Schema.Struct({
  id: Schema.String,
  sessionID: Schema.String,
  timestamp: NonNegativeInt,
  method: Schema.String,
  url: Schema.String,
  host: Schema.String,
  status: NonNegativeInt,
  durationMs: NonNegativeInt,
  sourceTool: Schema.String,
  target: Schema.String,
  scopeAllowed: Schema.Boolean,
  requestHeaders: Schema.Record(Schema.String, Schema.Array(Schema.String)),
  responseHeaders: Schema.Record(Schema.String, Schema.Array(Schema.String)),
  requestBody: Schema.String,
  responseBody: Schema.String,
  requestBodySHA256: Schema.String,
  responseBodySHA256: Schema.String,
  requestBodySize: NonNegativeInt,
  responseBodySize: NonNegativeInt,
})

export const TrafficHeaderChangeSchema = Schema.Struct({
  name: Schema.String,
  a: Schema.String,
  b: Schema.String,
})

export const TrafficDiffSchema = Schema.Struct({
  aId: Schema.String,
  bId: Schema.String,
  identical: Schema.Boolean,
  statusChanged: Schema.Boolean,
  statusA: NonNegativeInt,
  statusB: NonNegativeInt,
  headersAdded: Schema.Array(TrafficHeaderChangeSchema),
  headersRemoved: Schema.Array(TrafficHeaderChangeSchema),
  headersChanged: Schema.Array(TrafficHeaderChangeSchema),
  bodyChanged: Schema.Boolean,
  bodySHA256A: Schema.String,
  bodySHA256B: Schema.String,
  bodyDiff: Schema.String,
  bodyLinesAdded: NonNegativeInt,
  bodyLinesRemoved: NonNegativeInt,
})

import { QueryNonNegativeInt } from "./query"

export const TrafficHistoryQuery = Schema.Struct({
  ...WorkspaceRoutingQueryFields,
  host: Schema.optional(Schema.String),
  method: Schema.optional(Schema.String),
  status: Schema.optional(Schema.String),
  tool: Schema.optional(Schema.String),
  limit: Schema.optional(QueryNonNegativeInt),
  offset: Schema.optional(QueryNonNegativeInt),
})

export const TrafficHistoryResponse = Schema.Struct({
  exchanges: Schema.Array(TrafficExchangeSchema),
  total: NonNegativeInt,
})

export const TrafficPaths = {
  list: "/session/:sessionID/traffic",
  get: "/session/:sessionID/traffic/:exchangeID",
  diff: "/session/:sessionID/traffic/diff/:aID/:bID",
} as const

export const TrafficApi = HttpApi.make("traffic")
  .add(
    HttpApiGroup.make("traffic")
      .add(
        HttpApiEndpoint.get("list", TrafficPaths.list, {
          params: { sessionID: SessionID },
          query: TrafficHistoryQuery,
          success: described(
            TrafficHistoryResponse,
            "Tráfico HTTP capturado en la sesión. El store en disco es la fuente de verdad; la tabla es el índice que la UI lee.",
          ),
        }).annotateMerge(
          OpenApi.annotations({
            identifier: "traffic.list",
            summary: "List the captured HTTP traffic",
            description:
              "Reconciles the traffic store written by the web scanner (argos-bin/internal/traffic) and returns the exchanges of a session.",
          }),
        ),
        HttpApiEndpoint.get("get", TrafficPaths.get, {
          params: { sessionID: SessionID, exchangeID: Schema.String },
          query: WorkspaceRoutingQuery,
          success: described(
            Schema.UndefinedOr(TrafficExchangeSchema),
            "Un exchange de tráfico. `undefined` cuando el exchange no existe.",
          ),
        }).annotateMerge(
          OpenApi.annotations({
            identifier: "traffic.get",
            summary: "Get one captured HTTP exchange",
            description: "Retrieve one captured HTTP exchange by ID.",
          }),
        ),
        HttpApiEndpoint.get("diff", TrafficPaths.diff, {
          params: { sessionID: SessionID, aID: Schema.String, bID: Schema.String },
          query: WorkspaceRoutingQuery,
          success: described(
            Schema.UndefinedOr(TrafficDiffSchema),
            "Diferencia estructural entre dos exchanges. `undefined` cuando alguno no existe.",
          ),
        }).annotateMerge(
          OpenApi.annotations({
            identifier: "traffic.diff",
            summary: "Compare two captured HTTP exchanges",
            description:
              "Structural difference between two exchanges: status, headers added/removed/changed and a unified diff of the response bodies.",
          }),
        ),
      )
      .annotateMerge(
        OpenApi.annotations({
          title: "traffic",
          description: "Captured HTTP traffic: history, detail and comparison.",
        }),
      )
      .middleware(InstanceContextMiddleware)
      .middleware(WorkspaceRoutingMiddleware)
      .middleware(Authorization),
  )
  .annotateMerge(
    OpenApi.annotations({
      title: "opencode experimental HttpApi",
      version: "0.0.1",
      description: "Experimental HttpApi surface for selected instance routes.",
    }),
  )
