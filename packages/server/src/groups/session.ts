import { SessionMessage } from "@argos/core/session/message"
import { SessionInput } from "@argos/core/session/input"
import { Prompt } from "@argos/core/session/prompt"
import { SessionV2 } from "@argos/core/session"
import { SessionCoverage } from "@argos/core/session/coverage"
import { ProjectV2 } from "@argos/core/project"
import { AbsolutePath, PositiveInt, RelativePath, withStatics } from "@argos/core/schema"
import { WorkspaceV2 } from "@argos/core/workspace"
import { Schema, Struct } from "effect"
import { HttpApiEndpoint, HttpApiGroup, HttpApiSchema, OpenApi } from "effect/unstable/httpapi"
import {
  ConflictError,
  InvalidCursorError,
  InvalidRequestError,
  ServiceUnavailableError,
  SessionNotFoundError,
  SessionRunNotFoundError,
  UnknownError,
} from "../errors"
import { SessionLocationMiddleware } from "../middleware/session-location"

const SessionsQueryFields = {
  workspace: WorkspaceV2.ID.pipe(Schema.optional),
  limit: Schema.NumberFromString.pipe(Schema.decodeTo(PositiveInt), Schema.optional).annotate({
    description: "Maximum number of sessions to return. Defaults to the newest 50 sessions.",
  }),
  order: Schema.optional(Schema.Union([Schema.Literal("asc"), Schema.Literal("desc")])).annotate({
    description: "Session order for the first page. Use desc for newest first or asc for oldest first.",
  }),
  search: Schema.optional(Schema.String),
}

const SessionsDirectoryQuery = Schema.Struct({
  ...SessionsQueryFields,
  directory: AbsolutePath,
})

const SessionsProjectQuery = Schema.Struct({
  ...SessionsQueryFields,
  project: ProjectV2.ID,
  subpath: RelativePath.pipe(Schema.optional),
})

const SessionsAllQuery = Schema.Struct(SessionsQueryFields)

const withCursor = <Fields extends Schema.Struct.Fields>(schema: Schema.Struct<Fields>) =>
  schema.mapFields((fields) => ({
    ...Struct.omit(fields, ["limit"]),
    anchor: SessionV2.ListAnchor,
  }))

const SessionsCursorInput = Schema.Union([
  withCursor(SessionsDirectoryQuery),
  withCursor(SessionsProjectQuery),
  withCursor(SessionsAllQuery),
])
const SessionsCursorJson = Schema.fromJsonString(SessionsCursorInput)
const encodeSessionsCursor = Schema.encodeSync(SessionsCursorJson)
const decodeSessionsCursor = Schema.decodeUnknownEffect(SessionsCursorJson)

export const SessionsCursor = Schema.String.pipe(
  Schema.brand("SessionsCursor"),
  withStatics((schema) => {
    const make = schema.make.bind(schema)
    return {
      make: (input: typeof SessionsCursorInput.Type) =>
        make(Buffer.from(encodeSessionsCursor(input)).toString("base64url")),
      parse: (input: string) => decodeSessionsCursor(Buffer.from(input, "base64url").toString("utf8")),
    }
  }),
)
export type SessionsCursor = typeof SessionsCursor.Type

const SessionsCursorQuery = Schema.Struct({
  cursor: SessionsCursor.annotate({
    description: "Opaque pagination cursor returned as cursor.previous or cursor.next in the previous response.",
  }),
  limit: SessionsQueryFields.limit,
})

export const SessionsQuery = Schema.Struct({
  ...SessionsQueryFields,
  directory: AbsolutePath.pipe(Schema.optional),
  project: ProjectV2.ID.pipe(Schema.optional),
  subpath: RelativePath.pipe(Schema.optional),
  cursor: SessionsCursorQuery.fields.cursor.pipe(Schema.optional),
}).annotate({ identifier: "SessionsQuery" })

export const SessionGroup = HttpApiGroup.make("server.session")
  .add(
    HttpApiEndpoint.get("session.list", "/api/session", {
      query: SessionsQuery,
      success: Schema.Struct({
        data: Schema.Array(SessionV2.Info),
        cursor: Schema.Struct({
          previous: SessionsCursor.pipe(Schema.optional),
          next: SessionsCursor.pipe(Schema.optional),
        }),
      }).annotate({ identifier: "SessionsResponse" }),
      error: [InvalidCursorError, InvalidRequestError],
    }).annotateMerge(
      OpenApi.annotations({
        identifier: "session.list",
        summary: "List sessions",
        description:
          "Retrieve sessions in the requested order. Items keep that order across pages; use cursor.next or cursor.previous to move through the ordered list.",
      }),
    ),
  )
  .add(
    HttpApiEndpoint.post("session.prompt", "/api/session/:sessionID/prompt", {
      params: { sessionID: SessionV2.ID },
      payload: Schema.Struct({
        id: SessionMessage.ID.pipe(Schema.optional),
        prompt: Prompt,
        delivery: SessionInput.Delivery.pipe(Schema.optional),
        resume: Schema.Boolean.pipe(Schema.optional),
      }),
      success: Schema.Struct({ data: SessionInput.Admitted }),
      error: [ConflictError, SessionNotFoundError],
    })
      .middleware(SessionLocationMiddleware)
      .annotateMerge(
        OpenApi.annotations({
          identifier: "session.prompt",
          summary: "Send message",
          description: "Durably admit one session input and schedule agent-loop execution unless resume is false.",
        }),
      ),
  )
  .add(
    HttpApiEndpoint.get("session.runs", "/api/session/:sessionID/runs", {
      params: { sessionID: SessionV2.ID },
      success: Schema.Struct({ data: Schema.Array(SessionV2.RunInfo) }),
      error: [SessionNotFoundError],
    })
      .middleware(SessionLocationMiddleware)
      .annotateMerge(
        OpenApi.annotations({
          identifier: "session.runs",
          summary: "List session executions",
          description: "Retrieve durable execution states, including interrupted runs that require an explicit resume.",
        }),
      ),
  )
  .add(
    HttpApiEndpoint.get("session.coverage", "/api/session/:sessionID/runs/:runID/coverage", {
      params: { sessionID: SessionV2.ID, runID: Schema.String },
      success: Schema.Struct({ data: Schema.Array(SessionCoverage.Info) }),
      error: [SessionNotFoundError, SessionRunNotFoundError],
    })
      .middleware(SessionLocationMiddleware)
      .annotateMerge(
        OpenApi.annotations({
          identifier: "session.coverage.list",
          summary: "List run coverage observations",
          description:
            "List append-only coverage records for a specific session execution, including their evidence references and attestation level.",
        }),
      ),
  )
  .add(
    HttpApiEndpoint.get("session.coverage-plan", "/api/session/:sessionID/runs/:runID/coverage-plan", {
      params: { sessionID: SessionV2.ID, runID: Schema.String },
      success: Schema.Struct({ data: Schema.NullOr(SessionCoverage.PlanInfo) }),
      error: [SessionNotFoundError, SessionRunNotFoundError],
    })
      .middleware(SessionLocationMiddleware)
      .annotateMerge(
        OpenApi.annotations({
          identifier: "session.coverage-plan.get",
          summary: "Get the controller-required run coverage plan",
          description:
            "Return the immutable controller-generated coverage plan for this exact run, or null while no plan has been generated.",
        }),
      ),
  )
  .add(
    HttpApiEndpoint.post("session.coverage.report", "/api/session/:sessionID/runs/:runID/coverage", {
      params: { sessionID: SessionV2.ID, runID: Schema.String },
      payload: SessionCoverage.ReportInput,
      success: Schema.Struct({ data: SessionCoverage.Info }),
      error: [SessionNotFoundError, SessionRunNotFoundError, ConflictError, InvalidRequestError],
    })
      .middleware(SessionLocationMiddleware)
      .annotateMerge(
        OpenApi.annotations({
          identifier: "session.coverage.report",
          summary: "Record a coverage observation",
          description:
            "Append a coverage observation to a run. API-submitted observations are explicitly marked as reported and are not runtime-attested evidence.",
        }),
      ),
  )
  .add(
    HttpApiEndpoint.post("session.resume", "/api/session/:sessionID/resume", {
      params: { sessionID: SessionV2.ID },
      payload: Schema.Struct({ runID: Schema.String }),
      success: HttpApiSchema.NoContent,
      error: [ConflictError, SessionNotFoundError, UnknownError],
    })
      .middleware(SessionLocationMiddleware)
      .annotateMerge(
        OpenApi.annotations({
          identifier: "session.resume",
          summary: "Resume session execution",
          description: "Explicitly resume the latest interrupted execution after reviewing its saved history.",
        }),
      ),
  )
  .add(
    HttpApiEndpoint.post("session.compact", "/api/session/:sessionID/compact", {
      params: { sessionID: SessionV2.ID },
      success: HttpApiSchema.NoContent,
      error: [SessionNotFoundError, ServiceUnavailableError],
    })
      .middleware(SessionLocationMiddleware)
      .annotateMerge(
        OpenApi.annotations({
          identifier: "session.compact",
          summary: "Compact session",
          description: "Compact a session conversation.",
        }),
      ),
  )
  .add(
    HttpApiEndpoint.post("session.wait", "/api/session/:sessionID/wait", {
      params: { sessionID: SessionV2.ID },
      success: HttpApiSchema.NoContent,
      error: [SessionNotFoundError, ServiceUnavailableError],
    })
      .middleware(SessionLocationMiddleware)
      .annotateMerge(
        OpenApi.annotations({
          identifier: "session.wait",
          summary: "Wait for session",
          description: "Wait for a session agent loop to become idle.",
        }),
      ),
  )
  .add(
    HttpApiEndpoint.get("session.context", "/api/session/:sessionID/context", {
      params: { sessionID: SessionV2.ID },
      success: Schema.Struct({ data: Schema.Array(SessionMessage.Message) }),
      error: [SessionNotFoundError, UnknownError],
    })
      .middleware(SessionLocationMiddleware)
      .annotateMerge(
        OpenApi.annotations({
          identifier: "session.context",
          summary: "Get session context",
          description: "Retrieve the active context messages for a session (all messages after the last compaction).",
        }),
      ),
  )
  .annotateMerge(
    OpenApi.annotations({
      title: "sessions",
      description: "Experimental session routes.",
    }),
  )
