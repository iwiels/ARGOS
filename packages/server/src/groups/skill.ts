import { SkillV2 } from "@argos/core/skill"
import { Location } from "@argos/core/location"
import { Schema } from "effect"
import { HttpApiEndpoint, HttpApiGroup, OpenApi } from "effect/unstable/httpapi"
import { LocationQuery, locationQueryOpenApi, LocationMiddleware } from "./location"

export const SkillGroup = HttpApiGroup.make("server.skill")
  .add(
    HttpApiEndpoint.get("skill.list", "/api/skill", {
      query: LocationQuery,
      success: Location.response(Schema.Array(SkillV2.Info)),
    })
      .annotateMerge(locationQueryOpenApi)
      .annotateMerge(
        OpenApi.annotations({
          identifier: "skill.list",
          summary: "List skills",
          description: "Retrieve currently registered skills.",
        }),
      ),
  )
  .annotateMerge(
    OpenApi.annotations({
      title: "skills",
      description: "Experimental skill routes.",
    }),
  )
  .middleware(LocationMiddleware)
