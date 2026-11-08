import { createHash } from "node:crypto"
import { and, count, desc, eq } from "drizzle-orm"
import { Effect } from "effect"
import type { Database } from "../database/database"
import { FindingObservationTable } from "./sql"

export interface FindingObservationListInput {
  sessionID: string
  findingID?: string
  limit?: number
  offset?: number
}

export interface FindingObservationInput {
  projectID: string
  sessionID: string
  findingID: string
  sourceEventID: string
  fingerprint: string
  source: string
  sourceTool?: string | null
  ruleID?: string | null
  observedAt: number
  snapshot: string
}

export const findingObservationID = (
  sessionID: string,
  sourceEventID: string,
  sourceTool: string | null | undefined,
  fingerprint: string,
) =>
  `fob_${createHash("sha256").update(JSON.stringify([sessionID, sourceEventID, sourceTool ?? "", fingerprint])).digest("hex")}`

export function recordFindingObservation(db: Database.Interface["db"], input: FindingObservationInput) {
  const sourceEventID = input.sourceEventID.trim().slice(0, 256) || `legacy:${input.fingerprint}`
  return db
    .insert(FindingObservationTable)
    .values({
      id: findingObservationID(input.sessionID, sourceEventID, input.sourceTool, input.fingerprint),
      project_id: input.projectID,
      session_id: input.sessionID,
      finding_id: input.findingID,
      source_event_id: sourceEventID,
      fingerprint: input.fingerprint,
      source: input.source,
      source_tool: input.sourceTool ?? null,
      rule_id: input.ruleID ?? null,
      observed_at: input.observedAt,
      snapshot: input.snapshot,
    })
    .onConflictDoNothing({ target: FindingObservationTable.id })
    .run()
}

export function listFindingObservations(db: Database.Interface["db"], input: FindingObservationListInput) {
  const limit = Math.max(0, Math.min(500, Math.trunc(input.limit ?? 100)))
  const offset = Math.max(0, Math.trunc(input.offset ?? 0))
  const where = and(
    eq(FindingObservationTable.session_id, input.sessionID),
    input.findingID ? eq(FindingObservationTable.finding_id, input.findingID) : undefined,
  )

  return Effect.gen(function* () {
    const [records, total] = yield* Effect.all([
      db
        .select()
        .from(FindingObservationTable)
        .where(where)
        .orderBy(desc(FindingObservationTable.observed_at), desc(FindingObservationTable.id))
        .limit(limit)
        .offset(offset)
        .all(),
      db.select({ total: count() }).from(FindingObservationTable).where(where).get(),
    ]).pipe(Effect.orDie)
    return { records, total: total?.total ?? 0 }
  })
}
