import { and, eq } from "drizzle-orm"
import { Database } from "@argos/core/database/database"
import { Audit } from "@argos/core/audit"
import { FindingFeedbackTable, FindingTable } from "@argos/core/security/sql"
import { SessionV2 } from "@argos/core/session"
import {
  feedbackAuditEntry,
  listFindingRecords,
  recordFeedback,
  toSecurityFeedbackDTO,
  toSecurityFindingDTO,
} from "@argos/core/security"
import { retestFinding, updateFindingStatus, type FindingLifecycleStatus } from "@argos/core/security/retest"
import * as ScopeService from "@argos/core/security/scope-service"
import { Effect } from "effect"
import { HttpApiBuilder } from "effect/unstable/httpapi"
import { InstanceHttpApi } from "../api"
import { FindingFeedbackNotFoundError } from "../groups/finding"

const DEFAULT_LIMIT = 200
const MAX_LIMIT = 500

/** Fila cruda de BD → forma que consume `mapFinding` en la app (expone alias camelCase de los campos de enrichment). */
function toResponseItem(
  row: typeof FindingTable.$inferSelect,
  feedback?: typeof FindingFeedbackTable.$inferSelect,
): Record<string, unknown> {
  const dto = toSecurityFindingDTO(row, feedback)
  return Object.fromEntries(
    Object.entries({
      ...dto,
      session_id: row.session_id,
      project_id: row.project_id,
      source_tool: row.source_tool,
      raw: row.raw,
      attack_techniques: row.attack_techniques,
      enrichment: row.enrichment,
      timeCreated: row.time_created,
      timeUpdated: row.time_updated,
      time_created: row.time_created,
      time_updated: row.time_updated,
    }).filter(([, value]) => value !== undefined),
  )
}

export const findingHandlers = HttpApiBuilder.group(InstanceHttpApi, "finding", (handlers) =>
  Effect.gen(function* () {
    const scopeService = yield* ScopeService.Service
    const { db } = yield* Database.Service
    const audit = yield* Audit.Service

    const list = Effect.fn("FindingHttpApi.list")(function* (ctx: {
      params: { sessionID: string }
      query: { limit?: number; offset?: number }
    }) {
      const limit = Math.min(ctx.query.limit ?? DEFAULT_LIMIT, MAX_LIMIT)
      const offset = ctx.query.offset ?? 0

      const result = yield* listFindingRecords(db, {
        sessionID: ctx.params.sessionID,
        limit,
        offset,
        includeSuppressed: true,
      })

      return {
        findings: result.records.map(({ row, feedback }) => toResponseItem(row, feedback)),
        total: result.total,
      }
    })

    const retest = Effect.fn("FindingHttpApi.retest")(function* (ctx: {
      params: { sessionID: string; findingID: string }
    }) {
      return yield* retestFinding(db, ctx.params.findingID, ctx.params.sessionID).pipe(
        Effect.provideService(ScopeService.Service, scopeService),
      )
    })

    const status = Effect.fn("FindingHttpApi.status")(function* (ctx: {
      params: { sessionID: string; findingID: string }
      payload: { status: FindingLifecycleStatus }
    }) {
      const finding = yield* db
        .select({
          id: FindingTable.id,
          projectID: FindingTable.project_id,
          status: FindingTable.status,
          title: FindingTable.title,
        })
        .from(FindingTable)
        .where(and(eq(FindingTable.id, ctx.params.findingID), eq(FindingTable.session_id, ctx.params.sessionID)))
        .get()
        .pipe(Effect.orDie)
      if (!finding) return { ok: false }

      const ok = yield* updateFindingStatus(db, ctx.params.findingID, ctx.payload.status, ctx.params.sessionID)
      if (ok && finding.status !== ctx.payload.status) {
        yield* audit.append({
          sessionID: SessionV2.ID.make(ctx.params.sessionID),
          projectID: finding.projectID,
          eventType: "finding.status",
          action: "finding.status.updated",
          agent: "human",
          target: finding.id,
          summary: `El operador cambió ${finding.title ?? "el hallazgo"} de ${finding.status} a ${ctx.payload.status}`,
          payload: {
            findingID: finding.id,
            fromStatus: finding.status,
            toStatus: ctx.payload.status,
            actor: "human",
            source: "operator",
          },
        })
      }
      return { ok }
    })

    const feedback = Effect.fn("FindingHttpApi.feedback")(function* (ctx: {
      params: { sessionID: string; findingID: string }
      payload: { verdict: "false-positive" | "true-positive" | "accepted-risk"; reason?: string }
    }) {
      const row = yield* recordFeedback(db, {
        sessionID: ctx.params.sessionID,
        findingID: ctx.params.findingID,
        verdict: ctx.payload.verdict,
        reason: ctx.payload.reason,
        actor: "human",
      }).pipe(
        Effect.catch((error) =>
          Effect.fail(
            new FindingFeedbackNotFoundError({
              name: "FindingFeedbackNotFoundError",
              data: { message: error.message },
            }),
          ),
        ),
      )
      yield* audit.append(feedbackAuditEntry(row))
      const dto = toSecurityFeedbackDTO(row)
      return {
        data: {
          findingID: dto.findingID,
          verdict: dto.verdict,
          ...(dto.reason ? { reason: dto.reason } : {}),
          actor: dto.actor,
          createdAt: dto.createdAt,
          updatedAt: dto.updatedAt,
        },
      }
    })

    return handlers.handle("list", list).handle("retest", retest).handle("status", status).handle("feedback", feedback)
    // El ScopeService se resuelve una vez, al construir el grupo: el re-test
    // valida el vector del hallazgo contra el scope antes de emitir la
    // petición de re-verificación.
  }).pipe(Effect.provide(ScopeService.defaultLayer), Effect.provide(Database.defaultLayer)),
)
