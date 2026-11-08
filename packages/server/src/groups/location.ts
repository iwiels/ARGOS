import { Location } from "@argos/core/location"
import { LocationServiceMap } from "@argos/core/location-layer"
import { AbsolutePath } from "@argos/core/schema"
import { WorkspaceV2 } from "@argos/core/workspace"
import { Effect, Layer, Schema } from "effect"
import { HttpServerRequest } from "effect/unstable/http"
import { HttpApiMiddleware, OpenApi } from "effect/unstable/httpapi"

export const LocationQuery = Schema.Struct({
  location: Schema.optional(
    Schema.Struct({
      directory: Schema.optional(Schema.String),
      workspace: Schema.optional(Schema.String),
    }),
  ),
}).annotate({ identifier: "LocationQuery" })

export const locationQueryOpenApi = OpenApi.annotations({
  transform: (operation) => {
    const parameters = operation.parameters
    if (!Array.isArray(parameters)) return operation
    return {
      ...operation,
      parameters: parameters.map((parameter) =>
        parameter?.name === "location" && parameter?.in === "query"
          ? { ...parameter, style: "deepObject", explode: true }
          : parameter,
      ),
    }
  },
})

export function response<A, E, R>(data: Effect.Effect<A, E, R>) {
  return Effect.gen(function* () {
    const location = yield* Location.Service
    return {
      location: new Location.Info({
        directory: location.directory,
        workspaceID: location.workspaceID,
        project: location.project,
      }),
      data: yield* data,
    }
  })
}

export type LocationServices = Layer.Success<ReturnType<typeof LocationServiceMap.get>>

export class LocationMiddleware extends HttpApiMiddleware.Service<
  LocationMiddleware,
  {
    provides: LocationServices
  }
>()("@argos/HttpApiLocation") {}

function decode(input: string): string {
  try {
    return decodeURIComponent(input)
  } catch {
    return input
  }
}

function ref(request: HttpServerRequest.HttpServerRequest): Location.Ref {
  const query = new URL(request.url, "http://localhost").searchParams
  const workspaceID = query.get("location[workspace]") || request.headers["x-opencode-workspace"]
  const directory =
    query.get("location[directory]") ??
    (request.headers["x-opencode-directory"]
      ? decode(request.headers["x-opencode-directory"])
      : undefined) ??
    process.cwd()
  return {
    directory: AbsolutePath.make(directory),
    workspaceID: workspaceID ? WorkspaceV2.ID.make(workspaceID) : undefined,
  }
}

export const layer = Layer.effect(
  LocationMiddleware,
  Effect.gen(function* () {
    const locations = yield* LocationServiceMap
    return LocationMiddleware.of((effect) =>
      Effect.gen(function* () {
        const request = yield* HttpServerRequest.HttpServerRequest
        return yield* effect.pipe(Effect.provide(locations.get(ref(request))))
      }),
    )
  }),
)
