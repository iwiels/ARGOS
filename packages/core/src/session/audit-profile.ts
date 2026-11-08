export * as SessionAuditProfile from "./audit-profile"

import { Schema } from "effect"

export const ID = Schema.Literal("web")
export type ID = typeof ID.Type
