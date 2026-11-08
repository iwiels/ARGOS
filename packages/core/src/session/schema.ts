export * as SessionSchema from "./schema"

import { Schema } from "effect"
import { Location } from "../location"
import { ModelV2 } from "../model"
import { ProjectV2 } from "../project"
import { externalID, type ExternalID, RelativePath, optionalOmitUndefined, withStatics } from "../schema"
import { Identifier } from "../util/identifier"
import { CoreSchema } from "../core-schema"
import { AgentV2 } from "../agent"

export const ID = Schema.String.check(Schema.isStartsWith("ses")).pipe(
  Schema.brand("SessionID"),
  withStatics((schema) => {
    const create = () => schema.make("ses_" + Identifier.descending())
    return {
      create,
      descending: (id?: string) => (id === undefined ? create() : schema.make(id)),
      fromExternal: (input: ExternalID) => schema.make(externalID("ses", input)),
    }
  }),
)
export type ID = typeof ID.Type

export const RunStatus = Schema.Literals(["running", "completed", "interrupted", "failed"])
export type RunStatus = typeof RunStatus.Type

export const RunInfo = Schema.Struct({
  id: Schema.String,
  status: RunStatus,
  startedAt: Schema.Int,
  updatedAt: Schema.Int,
  endedAt: Schema.Int.pipe(Schema.optional),
  lastEventSeq: Schema.Int.pipe(Schema.optional),
  resumeCount: Schema.Int,
  error: Schema.String.pipe(Schema.optional),
})
export type RunInfo = typeof RunInfo.Type

export class Info extends Schema.Class<Info>("SessionV2.Info")({
  id: ID,
  parentID: ID.pipe(optionalOmitUndefined),
  projectID: ProjectV2.ID,
  agent: AgentV2.ID.pipe(Schema.optional),
  model: ModelV2.Ref.pipe(Schema.optional),
  cost: Schema.Finite,
  tokens: Schema.Struct({
    input: Schema.Finite,
    output: Schema.Finite,
    reasoning: Schema.Finite,
    cache: Schema.Struct({
      read: Schema.Finite,
      write: Schema.Finite,
    }),
  }),
  time: Schema.Struct({
    created: CoreSchema.DateTimeUtcFromMillis,
    updated: CoreSchema.DateTimeUtcFromMillis,
    archived: CoreSchema.DateTimeUtcFromMillis.pipe(Schema.optional),
  }),
  title: Schema.String,
  location: Location.Ref,
  subpath: RelativePath.pipe(Schema.optional),
  scope: Schema.Struct({
    cidrs: Schema.Array(Schema.String).pipe(Schema.optional),
    domains: Schema.Array(Schema.String).pipe(Schema.optional),
    excluded: Schema.Array(Schema.String).pipe(Schema.optional),
    maxRPS: Schema.Number.pipe(Schema.optional),
    safeMode: Schema.Boolean.pipe(Schema.optional),
  }).pipe(Schema.optional),
}) {}
