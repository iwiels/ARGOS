import { and, count, desc, eq, notInArray } from "drizzle-orm"
import { Effect } from "effect"
import type { Database } from "../database/database"
import { feedbackByFindingID, feedbackForSession, type FeedbackRow } from "./finding-feedback"
import { FindingFeedbackTable, FindingTable } from "./sql"
import { trustedFindingSourceCondition } from "./finding-provenance"

export interface FindingRecord {
  row: typeof FindingTable.$inferSelect
  feedback: FeedbackRow | undefined
}

export interface FindingListInput {
  sessionID: string
  limit: number
  offset: number
  status?: string
  severity?: string
  includeSuppressed?: boolean
}

export function listFindingRecords(db: Database.Interface["db"], input: FindingListInput) {
  return Effect.gen(function* () {
    const feedback = yield* feedbackForSession(db, input.sessionID)
    const byFinding = feedbackByFindingID(feedback)
    const suppressedIDs = input.includeSuppressed
      ? []
      : feedback.filter((row) => row.verdict === "false-positive").map((row) => row.finding_id)
    const where = and(
      eq(FindingTable.session_id, input.sessionID),
      trustedFindingSourceCondition(),
      input.status ? eq(FindingTable.status, input.status) : undefined,
      input.severity ? eq(FindingTable.severity, input.severity) : undefined,
      suppressedIDs.length > 0 ? notInArray(FindingTable.id, suppressedIDs) : undefined,
    )
    const [rows, total] = yield* Effect.all([
      db.select().from(FindingTable).where(where).orderBy(desc(FindingTable.time_updated)).limit(input.limit).offset(input.offset).all(),
      db.select({ total: count() }).from(FindingTable).where(where).get(),
    ]).pipe(Effect.orDie)
    return {
      records: rows.map((row): FindingRecord => ({ row, feedback: byFinding.get(row.id) })),
      total: total?.total ?? 0,
    }
  })
}

export function getFindingRecord(db: Database.Interface["db"], sessionID: string, findingID: string) {
  return Effect.gen(function* () {
    const row = yield* db.select().from(FindingTable)
      .where(and(eq(FindingTable.id, findingID), eq(FindingTable.session_id, sessionID), trustedFindingSourceCondition()))
      .get().pipe(Effect.orDie)
    if (!row) return undefined
    const feedback = yield* db.select().from(FindingFeedbackTable)
      .where(eq(FindingFeedbackTable.finding_id, row.id)).get().pipe(Effect.orDie)
    return { row, feedback } satisfies FindingRecord
  })
}
