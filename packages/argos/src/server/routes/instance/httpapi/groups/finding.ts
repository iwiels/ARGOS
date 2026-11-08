import { Schema } from "effect"
import { HttpApi, HttpApiEndpoint, HttpApiGroup, OpenApi } from "effect/unstable/httpapi"
import { NonNegativeInt } from "@argos/core/schema"
import { SessionID } from "@/session/schema"
import { Authorization } from "../middleware/authorization"
import { InstanceContextMiddleware } from "../middleware/instance-context"
import { WorkspaceRoutingMiddleware, WorkspaceRoutingQuery, WorkspaceRoutingQueryFields } from "../middleware/workspace-routing"
import { QueryNonNegativeInt } from "./query"
import { described } from "./metadata"

export const FindingListQuery = Schema.Struct({
  // El middleware de workspace routing exige estos campos en todo endpoint del grupo.
  ...WorkspaceRoutingQueryFields,
  limit: Schema.optional(QueryNonNegativeInt),
  offset: Schema.optional(QueryNonNegativeInt),
})

/**
 * Forma de un hallazgo persistido tal como lo consume `mapFinding` en la app
 * (`security-findings-api.ts`). Campos dinámicos (evidence/tags/attack/iocs)
 * van como Unknown — la app los parsea defensivamente. Se exponen tanto los
 * nombres de columna crudos como los alias camelCase que el mapper lee.
 */
export const FindingItemSchema = Schema.Record(Schema.String, Schema.Unknown)

export const FindingListResponse = Schema.Struct({
  findings: Schema.Array(FindingItemSchema),
  total: NonNegativeInt,
})

export const FindingLifecycleStatusSchema = Schema.Literals([
  "open",
  "in-progress",
  "remediated",
  "verified",
  "false-positive",
  "accepted-risk",
])

export const RetestResponse = Schema.Struct({
  findingId: Schema.String,
  previousStatus: Schema.String,
  newStatus: Schema.String,
  stillVulnerable: Schema.Boolean,
  checked: Schema.Boolean,
  message: Schema.String,
  verifiedAt: NonNegativeInt,
})

export const UpdateStatusPayload = Schema.Struct({
  status: FindingLifecycleStatusSchema,
})

export const UpdateStatusResponse = Schema.Struct({
  ok: Schema.Boolean,
})

export const FindingFeedbackInput = Schema.Struct({
  verdict: Schema.Literals(["false-positive", "true-positive", "accepted-risk"]),
  reason: Schema.optional(Schema.String),
})

export const FindingFeedbackResponse = Schema.Struct({
  data: Schema.Struct({
    findingID: Schema.String,
    verdict: Schema.Literals(["false-positive", "true-positive", "accepted-risk"]),
    reason: Schema.optional(Schema.String),
    actor: Schema.Literals(["human", "agent"]),
    createdAt: NonNegativeInt,
    updatedAt: NonNegativeInt,
  }),
})

export class FindingFeedbackNotFoundError extends Schema.ErrorClass<FindingFeedbackNotFoundError>("FindingFeedbackNotFoundError")(
  {
    name: Schema.Literal("FindingFeedbackNotFoundError"),
    data: Schema.Struct({ message: Schema.String }),
  },
  { httpApiStatus: 404 },
) {}

export const FindingPaths = {
  list: "/session/:sessionID/findings",
  retest: "/session/:sessionID/finding/:findingID/retest",
  status: "/session/:sessionID/finding/:findingID/status",
  feedback: "/session/:sessionID/findings/:findingID/feedback",
} as const

export const FindingApi = HttpApi.make("finding")
  .add(
    HttpApiGroup.make("finding")
      .add(
        HttpApiEndpoint.get("list", FindingPaths.list, {
          params: { sessionID: SessionID },
          query: FindingListQuery,
          success: described(
            FindingListResponse,
            "Hallazgos persistidos de la sesión. El panel pide esto por cada sesión del árbol (orquestador + subagentes) y los fusiona — por eso los hallazgos de subagentes aparecen sin copiar datos.",
          ),
        }).annotateMerge(
          OpenApi.annotations({
            identifier: "finding.list",
            summary: "List persisted findings for a session",
            description:
              "Returns the security_finding rows for one session. The app aggregates this across a session's whole family (parent + subagent children) via parent_id, so a subagent's findings surface in the orchestrator's panel from a single source of truth.",
          }),
        ),
        HttpApiEndpoint.post("retest", FindingPaths.retest, {
          params: { sessionID: SessionID, findingID: Schema.String },
          query: WorkspaceRoutingQuery,
          success: described(
            Schema.UndefinedOr(RetestResponse),
            "Resultado de la re-verificación pasiva. `checked:false` significa que no hubo una comprobación real — el estado se mueve a 'in-progress', nunca se afirma 'verified' sin evidencia.",
          ),
        }).annotateMerge(
          OpenApi.annotations({
            identifier: "finding.retest",
            summary: "Re-test a finding",
            description:
              "Runs a passive, finding-type-aware HTTP re-check. Only sets status to 'verified' when a real check ran (checked:true) — otherwise moves to 'in-progress' pending manual confirmation.",
          }),
        ),
        HttpApiEndpoint.post("status", FindingPaths.status, {
          params: { sessionID: SessionID, findingID: Schema.String },
          query: WorkspaceRoutingQuery,
          payload: UpdateStatusPayload,
          success: described(UpdateStatusResponse, "Whether the status transition was persisted"),
        }).annotateMerge(
          OpenApi.annotations({
            identifier: "finding.status",
            summary: "Manually set a finding's lifecycle status",
            description: "For operator-driven transitions (e.g. false-positive, accepted-risk) that don't need a retest.",
          }),
        ),
        HttpApiEndpoint.post("feedback", FindingPaths.feedback, {
          params: { sessionID: SessionID, findingID: Schema.String },
          query: WorkspaceRoutingQuery,
          payload: FindingFeedbackInput,
          success: described(FindingFeedbackResponse, "Persisted per-session finding feedback"),
          error: [FindingFeedbackNotFoundError],
        }).annotateMerge(
          OpenApi.annotations({
            identifier: "finding.feedback",
            summary: "Record per-session finding feedback",
            description: "Persists a human triage verdict for the finding and appends it to the audit log.",
          }),
        ),
      )
      .annotateMerge(
        OpenApi.annotations({
          title: "finding",
          description: "Finding lifecycle: manual status transitions and passive re-testing.",
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
