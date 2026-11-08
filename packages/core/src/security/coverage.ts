import { and, eq, sql } from "drizzle-orm"
import { Effect } from "effect"
import { createHash } from "node:crypto"
import type { Database } from "../database/database"
import { SurfaceCoverageTable } from "./sql"

export type CoverageStatus = "executed" | "no_findings" | "blocked" | "omitted" | "inconclusive"

export interface RecordCoverageInput {
  sessionID: string
  projectID: string
  targetUrl: string
  method: string
  role?: string
  status: CoverageStatus
  toolsExecuted?: string[]
  findingsCount?: number
  reason?: string
}

export class SurfaceCoverageService {
  /**
   * Registra o actualiza el estado de cobertura de un endpoint bajo un rol específico (Etapa 3).
   */
  static recordCoverage(db: Database.Interface["db"], input: RecordCoverageInput) {
    return Effect.gen(function* () {
      const role = input.role || "anonymous"
      const now = Date.now()

      const existing = yield* db
        .select()
        .from(SurfaceCoverageTable)
        .where(
          and(
            eq(SurfaceCoverageTable.session_id, input.sessionID),
            eq(SurfaceCoverageTable.target_url, input.targetUrl),
            eq(SurfaceCoverageTable.method, input.method.toUpperCase()),
            eq(SurfaceCoverageTable.role, role),
          ),
        )
        .get()
        .pipe(Effect.orDie)

      if (existing) {
        yield* db
          .update(SurfaceCoverageTable)
          .set({
            status: input.status,
            tools_executed: input.toolsExecuted ?? existing.tools_executed,
            findings_count: input.findingsCount !== undefined ? input.findingsCount : existing.findings_count,
            reason: input.reason ?? existing.reason,
            time_updated: now,
          })
          .where(eq(SurfaceCoverageTable.id, existing.id))
          .run()
          .pipe(Effect.orDie)

        return { id: existing.id, updated: true }
      }

      const id = `cov_${createHash("sha256").update(`${input.sessionID}:${input.method}:${input.targetUrl}:${role}`).digest("hex").slice(0, 24)}`

      yield* db
        .insert(SurfaceCoverageTable)
        .values({
          id,
          session_id: input.sessionID,
          project_id: input.projectID,
          target_url: input.targetUrl,
          method: input.method.toUpperCase(),
          role,
          status: input.status,
          tools_executed: input.toolsExecuted ?? [],
          findings_count: input.findingsCount ?? 0,
          reason: input.reason,
          time_updated: now,
        })
        .run()
        .pipe(Effect.orDie)

      return { id, updated: false }
    })
  }

  /**
   * Obtiene la matriz agregada de cobertura por sesión.
   */
  static getCoverageSummary(db: Database.Interface["db"], sessionID: string) {
    return Effect.gen(function* () {
      const rows = yield* db
        .select()
        .from(SurfaceCoverageTable)
        .where(eq(SurfaceCoverageTable.session_id, sessionID))
        .all()
        .pipe(Effect.orDie)

      const total = rows.length
      const counts: Record<CoverageStatus, number> = {
        executed: 0,
        no_findings: 0,
        blocked: 0,
        omitted: 0,
        inconclusive: 0,
      }

      let totalFindings = 0
      for (const row of rows) {
        const s = row.status as CoverageStatus
        if (counts[s] !== undefined) {
          counts[s]++
        }
        totalFindings += row.findings_count
      }

      const executedCount = counts.executed + counts.no_findings
      const coverageRate = total > 0 ? (executedCount / total) * 100 : 0

      return {
        totalEndpoints: total,
        executedCount,
        coverageRate: Math.round(coverageRate * 10) / 10,
        counts,
        totalFindings,
        entries: rows,
      }
    })
  }
}
