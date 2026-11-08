export * as ConfigCommandV1 from "./command"

import { Schema } from "effect"
import { SessionAuditProfile } from "../../session/audit-profile"

export const Info = Schema.Struct({
  template: Schema.String,
  description: Schema.optional(Schema.String),
  agent: Schema.optional(Schema.String),
  model: Schema.optional(Schema.String),
  variant: Schema.optional(Schema.String),
  subtask: Schema.optional(Schema.Boolean),
  auditProfile: Schema.optional(SessionAuditProfile.ID),
})
export type Info = Schema.Schema.Type<typeof Info>
