import { EventV2 } from "../event"
import { SessionSchema } from "../session/schema"
import { Schema } from "effect"

export const FindingUpserted = EventV2.define({
  type: "security.finding.upserted",
  schema: {
    sessionID: SessionSchema.ID,
    findingID: Schema.String,
    fingerprint: Schema.String,
  },
})

export type FindingUpserted = typeof FindingUpserted.Type
