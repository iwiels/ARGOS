import { AgentV2 } from "@argos/core/agent"
import { Location } from "@argos/core/location"
import { Schema } from "effect"
import { HttpApiEndpoint, HttpApiGroup, OpenApi } from "effect/unstable/httpapi"
import { LocationQuery, locationQueryOpenApi, LocationMiddleware } from "./location"

export const AgentGroup = HttpApiGroup.make("server.agent")
  .add(
    HttpApiEndpoint.get("agent.list", "/api/agent", {
      query: LocationQuery,
      success: Location.response(Schema.Array(AgentV2.Info)),
    })
      .annotateMerge(locationQueryOpenApi)
      .annotateMerge(
        OpenApi.annotations({
          identifier: "agent.list",
          summary: "List agents",
          description: "Retrieve currently registered agents.",
        }),
      ),
  )
  .middleware(LocationMiddleware)
