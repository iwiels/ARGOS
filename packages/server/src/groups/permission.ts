import { PermissionV2 } from "@argos/core/permission"
import { Location } from "@argos/core/location"
import { PermissionSaved } from "@argos/core/permission/saved"
import { ProjectV2 } from "@argos/core/project"
import { SessionV2 } from "@argos/core/session"
import { Schema } from "effect"
import { HttpApiEndpoint, HttpApiGroup, HttpApiSchema, OpenApi } from "effect/unstable/httpapi"
import { PermissionNotFoundError, SessionNotFoundError } from "../errors"
import { SessionLocationMiddleware } from "../middleware/session-location"
import { LocationQuery, locationQueryOpenApi, LocationMiddleware } from "./location"

export const PermissionGroup = HttpApiGroup.make("server.permission")
  .add(
    HttpApiEndpoint.get("permission.request.list", "/api/permission/request", {
      query: LocationQuery,
      success: Location.response(Schema.Array(PermissionV2.Request)),
    })
      .annotateMerge(locationQueryOpenApi)
      .annotateMerge(
        OpenApi.annotations({
          identifier: "permission.request.list",
          summary: "List pending permission requests",
          description: "Retrieve pending permission requests for a location.",
        }),
      ),
  )
  .add(
    HttpApiEndpoint.get("permission.saved.list", "/api/permission/saved", {
      query: Schema.Struct({ projectID: ProjectV2.ID.pipe(Schema.optional) }),
      success: Schema.Struct({ data: Schema.Array(PermissionSaved.Info) }),
    }).annotateMerge(
      OpenApi.annotations({
        identifier: "permission.saved.list",
        summary: "List saved permissions",
        description: "Retrieve saved permissions, optionally filtered by project.",
      }),
    ),
  )
  .add(
    HttpApiEndpoint.delete("permission.saved.remove", "/api/permission/saved/:id", {
      params: { id: PermissionSaved.ID },
      success: HttpApiSchema.NoContent,
    }).annotateMerge(
      OpenApi.annotations({
        identifier: "permission.saved.remove",
        summary: "Remove saved permission",
        description: "Remove a saved permission by ID.",
      }),
    ),
  )
  .middleware(LocationMiddleware)
  .add(
    HttpApiEndpoint.get("session.permission.list", "/api/session/:sessionID/permission", {
      params: { sessionID: SessionV2.ID },
      success: Schema.Struct({ data: Schema.Array(PermissionV2.Request) }),
      error: SessionNotFoundError,
    })
      .middleware(SessionLocationMiddleware)
      .annotateMerge(
        OpenApi.annotations({
          identifier: "session.permission.list",
          summary: "List session permission requests",
          description: "Retrieve pending permission requests owned by a session.",
        }),
      ),
  )
  .add(
    HttpApiEndpoint.post("session.permission.reply", "/api/session/:sessionID/permission/:requestID/reply", {
      params: { sessionID: SessionV2.ID, requestID: PermissionV2.ID },
      payload: Schema.Struct({
        reply: PermissionV2.Reply,
        message: Schema.String.pipe(Schema.optional),
      }),
      success: HttpApiSchema.NoContent,
      error: [SessionNotFoundError, PermissionNotFoundError],
    })
      .middleware(SessionLocationMiddleware)
      .annotateMerge(
        OpenApi.annotations({
          identifier: "session.permission.reply",
          summary: "Reply to pending permission request",
          description: "Respond to a pending permission request owned by a session.",
        }),
      ),
  )
  .annotateMerge(OpenApi.annotations({ title: "permissions", description: "Experimental permission routes." }))
