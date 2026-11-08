import { Schema } from "effect"
import { HttpApi, HttpApiEndpoint, HttpApiGroup, OpenApi } from "effect/unstable/httpapi"
import { NonNegativeInt } from "@argos/core/schema"
import { SessionID } from "@/session/schema"
import { Authorization } from "../middleware/authorization"
import { InstanceContextMiddleware } from "../middleware/instance-context"
import {
  WorkspaceRoutingMiddleware,
  WorkspaceRoutingQuery,
  WorkspaceRoutingQueryFields,
} from "../middleware/workspace-routing"
import { described } from "./metadata"
import { QueryNonNegativeInt } from "./query"

export const AuditQuery = Schema.Struct({
  // El middleware de workspace routing exige estos campos en todo endpoint del grupo.
  ...WorkspaceRoutingQueryFields,
  sessionID: Schema.optional(SessionID),
  limit: Schema.optional(QueryNonNegativeInt),
  offset: Schema.optional(QueryNonNegativeInt),
})

export const AuditEntrySchema = Schema.Struct({
  id: Schema.String,
  seq: NonNegativeInt,
  project_id: Schema.optional(Schema.NullOr(Schema.String)),
  session_id: Schema.optional(Schema.NullOr(Schema.String)),
  event_type: Schema.String,
  action: Schema.String,
  agent: Schema.optional(Schema.NullOr(Schema.String)),
  target: Schema.optional(Schema.NullOr(Schema.String)),
  summary: Schema.String,
  payload: Schema.String,
  prev_hash: Schema.String,
  hash: Schema.String,
  time_created: NonNegativeInt,
})

export const AuditListResponse = Schema.Struct({
  items: Schema.Array(AuditEntrySchema),
  total: NonNegativeInt,
})

export const AuditVerifyResponse = Schema.Struct({
  valid: Schema.Boolean,
  total: NonNegativeInt,
  firstInvalidSeq: Schema.optional(NonNegativeInt),
})

export const AuditSummaryIntegrity = Schema.Struct({
  valid: Schema.Boolean,
  total: NonNegativeInt,
  /** false cuando el summary usó el chequeo barato (count === max seq) sin recomputo sha256. */
  verified: Schema.Boolean,
  firstInvalidSeq: Schema.optional(NonNegativeInt),
})

export const AgentToolSummarySchema = Schema.Struct({
  tool: Schema.String,
  count: NonNegativeInt,
})

export const AgentSummarySchema = Schema.Struct({
  agent: Schema.String,
  total: NonNegativeInt,
  completed: NonNegativeInt,
  errors: NonNegativeInt,
  topTools: Schema.Array(AgentToolSummarySchema),
})

export const AuditSummaryResponse = Schema.Struct({
  generatedAt: NonNegativeInt,
  integrity: AuditSummaryIntegrity,
  agents: Schema.Array(AgentSummarySchema),
  events: Schema.Array(
    Schema.Struct({ eventType: Schema.String, count: NonNegativeInt }),
  ),
  activity: Schema.Struct({
    total: NonNegativeInt,
    lastEntryAt: Schema.optional(Schema.NullOr(NonNegativeInt)),
  }),
})

export const AuditPaths = {
  list: "/audit",
  verify: "/audit/verify",
  summary: "/audit/summary",
} as const

export const AuditApi = HttpApi.make("audit")
  .add(
    HttpApiGroup.make("audit")
      .add(
        HttpApiEndpoint.get("list", AuditPaths.list, {
          query: AuditQuery,
          success: described(AuditListResponse, "Audit trail entries"),
        }).annotateMerge(
          OpenApi.annotations({
            identifier: "audit.list",
            summary: "List audit trail entries",
            description: "Read the immutable agent audit trail (append-only, hash-chained).",
          }),
        ),
        HttpApiEndpoint.get("verify", AuditPaths.verify, {
          query: WorkspaceRoutingQuery,
          success: described(AuditVerifyResponse, "Audit chain integrity"),
        }).annotateMerge(
          OpenApi.annotations({
            identifier: "audit.verify",
            summary: "Verify audit chain integrity",
            description: "Recomputes the sha256 chain and reports the first broken link, if any.",
          }),
        ),
        HttpApiEndpoint.get("summary", AuditPaths.summary, {
          query: WorkspaceRoutingQuery,
          success: described(AuditSummaryResponse, "Agent governance summary"),
        }).annotateMerge(
          OpenApi.annotations({
            identifier: "audit.summary",
            summary: "Agent governance summary",
            description: "Aggregated agent governance: audit chain integrity, per-agent metrics and event distribution.",
          }),
        ),
      )
      .annotateMerge(
        OpenApi.annotations({
          title: "audit",
          description: "Immutable agent audit trail.",
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
