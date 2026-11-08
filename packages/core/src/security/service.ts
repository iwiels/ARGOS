import { and, count, desc, eq, notInArray, sql } from "drizzle-orm"
import { Effect } from "effect"
import type { Database } from "../database/database"
import { SessionV2 } from "../session"
import { SessionTable } from "../session/sql"
import { FindingFeedbackTable, FindingTable } from "./sql"
import { feedbackForSession, normalizeVerdict, recordFeedback, type FeedbackRow } from "./finding-feedback"
import { findingFingerprint } from "./ingest"
import { trustedFindingSourceCondition } from "./finding-provenance"

export interface FindingQueryOptions {
  sessionID: string
  status?: string
  severity?: string
  includeSuppressed?: boolean
  limit?: number
  offset?: number
}

export interface UnifiedFindingDTO {
  id: string
  sessionID: string
  session_id: string
  projectID: string
  project_id: string
  fingerprint: string
  title: string
  severity: string
  status: string
  source: string
  sourceTool: string | null
  source_tool: string | null
  agent: string | null
  target: string | null
  cwe: string | null
  vector: string | null
  evidence: Record<string, unknown>
  remediation: string | null
  tags: string[]
  raw?: string | null
  attackTechniques?: unknown
  iocs?: unknown
  enrichment?: unknown
  enrichedAt?: number | null
  feedback?: {
    verdict: "false-positive" | "true-positive" | "accepted-risk"
    reason?: string | null
    actor: "human" | "agent"
  }
  timeCreated: number
  timeUpdated: number
  createdAt: number
  updatedAt: number
}

export function toUnifiedFindingDTO(
  row: typeof FindingTable.$inferSelect,
  feedback?: typeof FindingFeedbackTable.$inferSelect,
): UnifiedFindingDTO {
  const normFeedback = feedback
    ? {
        verdict: normalizeVerdict(feedback.verdict) ?? "accepted-risk",
        reason: feedback.reason,
        actor: feedback.actor === "agent" ? ("agent" as const) : ("human" as const),
      }
    : undefined

  const dto: UnifiedFindingDTO = {
    id: row.id,
    sessionID: row.session_id,
    session_id: row.session_id,
    projectID: row.project_id,
    project_id: row.project_id,
    fingerprint: row.fingerprint,
    title: row.title,
    severity: row.severity,
    status: row.status,
    source: row.source,
    sourceTool: row.source_tool,
    source_tool: row.source_tool,
    agent: row.agent,
    target: row.target,
    cwe: row.cwe,
    vector: row.vector,
    evidence: row.evidence ?? {},
    remediation: row.remediation,
    tags: row.tags ?? [],
    raw: row.raw,
    ...(row.attack_techniques ? { attackTechniques: row.attack_techniques } : {}),
    ...(row.iocs ? { iocs: row.iocs } : {}),
    ...(row.enrichment ? { enrichment: row.enrichment } : {}),
    enrichedAt: row.enriched_at ?? null,
    ...(normFeedback ? { feedback: normFeedback } : {}),
    timeCreated: row.time_created,
    timeUpdated: row.time_updated,
    createdAt: row.time_created,
    updatedAt: row.time_updated,
  }

  for (const key of Object.keys(dto) as (keyof UnifiedFindingDTO)[]) {
    if (dto[key] === undefined) {
      delete dto[key]
    }
  }

  return dto
}

export class FindingService {
  static list(db: Database.Interface["db"], opts: FindingQueryOptions) {
    return Effect.gen(function* () {
      const limit = Math.min(Math.max(opts.limit ?? 50, 1), 500)
      const offset = Math.max(opts.offset ?? 0, 0)

      const sessionFeedback = yield* feedbackForSession(db, opts.sessionID)
      const byFinding = new Map(sessionFeedback.map((row) => [row.finding_id, row]))

      const suppressedIDs = opts.includeSuppressed
        ? []
        : sessionFeedback.filter((row) => row.verdict === "false-positive").map((row) => row.finding_id)

      const where = and(
        eq(FindingTable.session_id, opts.sessionID),
        trustedFindingSourceCondition(),
        opts.status ? eq(FindingTable.status, opts.status) : undefined,
        opts.severity ? eq(FindingTable.severity, opts.severity) : undefined,
        suppressedIDs.length > 0 ? notInArray(FindingTable.id, suppressedIDs) : undefined,
      )

      const [rows, totalResult] = yield* Effect.all([
        db
          .select()
          .from(FindingTable)
          .where(where)
          .orderBy(desc(FindingTable.time_updated))
          .limit(limit)
          .offset(offset)
          .all(),
        db.select({ total: count() }).from(FindingTable).where(where).get(),
      ]).pipe(Effect.orDie)

      const findings = rows.map((row) => toUnifiedFindingDTO(row, byFinding.get(row.id)))

      return {
        findings,
        data: findings,
        total: totalResult?.total ?? rows.length,
        limit,
        offset,
      }
    })
  }

  static get(db: Database.Interface["db"], sessionID: string, findingID: string) {
    return Effect.gen(function* () {
      const row = yield* db
        .select()
        .from(FindingTable)
        .where(and(eq(FindingTable.id, findingID), eq(FindingTable.session_id, sessionID), trustedFindingSourceCondition()))
        .get()
        .pipe(Effect.orDie)

      if (!row) return null

      const feedback = yield* db
        .select()
        .from(FindingFeedbackTable)
        .where(eq(FindingFeedbackTable.finding_id, row.id))
        .get()
        .pipe(Effect.orDie)

      return toUnifiedFindingDTO(row, feedback ?? undefined)
    })
  }

  static recordTriage(
    db: Database.Interface["db"],
    opts: {
      sessionID: string
      findingID: string
      verdict: "false-positive" | "true-positive" | "accepted-risk"
      reason?: string
      actor?: "human" | "agent"
    },
  ) {
    return recordFeedback(db, opts)
  }
}
