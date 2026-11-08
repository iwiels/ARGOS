import { Audit } from "@argos/core/audit"
import { Database } from "@argos/core/database/database"
import {
  FindingFeedbackTable,
  FindingTable,
  type FindingCaseStatus,
  type FindingCaseOperationRecord,
  FindingCaseError,
  countFindingCasesForSession,
  getFindingCaseForSession,
  listFindingCasesForSession,
  listFindingCaseTransitions,
  listFindingCaseOperations,
  mergeFindingCases,
  splitFindingCase,
  reverseFindingCaseOperation,
  setFindingCaseStatus,
  FindingImportError,
  feedbackAuditEntry,
  feedbackForProject,
  getFindingRecord,
  importFindingDocument,
  listFindingRecords,
  parseFindingImport,
  recordFeedback,
  ruleFeedbackStats,
  toSecurityFeedbackDTO,
  toSecurityFindingDTO,
} from "@argos/core/security"
import { SessionV2 } from "@argos/core/session"
import { SessionTable } from "@argos/core/session/sql"
import { eq } from "drizzle-orm"
import { Effect } from "effect"
import { HttpApiBuilder } from "effect/unstable/httpapi"
import { Api } from "../api"
import {
  SecurityFindingCaseError as SecurityFindingCaseRequestError,
  SecurityFindingCaseConflictError,
  SecurityFindingCaseNotFoundError,
  SecurityFindingImportError,
  SecurityFindingNotFoundError,
  SessionNotFoundError,
} from "../errors"

type FeedbackRow = typeof FindingFeedbackTable.$inferSelect

const toDTO = (row: typeof FindingTable.$inferSelect, feedback?: FeedbackRow) => ({
  ...toSecurityFindingDTO(row, feedback),
  sessionID: SessionV2.ID.make(row.session_id),
})

const toCaseDTO = (row: {
  id: string
  status: string
  status_reason: string | null
  owner: string | null
  due_at: number | null
  accepted_risk_until: number | null
  time_created: number
  time_updated: number
  finding_count: number
  session_count: number
}) => ({
  id: row.id,
  status: row.status as FindingCaseStatus,
  statusReason: row.status_reason,
  owner: row.owner,
  dueAt: row.due_at,
  acceptedRiskUntil: row.accepted_risk_until,
  findingCount: row.finding_count,
  sessionCount: row.session_count,
  createdAt: row.time_created,
  updatedAt: row.time_updated,
})

const toCaseTransitionDTO = (row: {
  id: string
  from_status: string | null
  to_status: string
  reason: string | null
  actor: string
  session_id: string | null
  time_created: number
}) => ({
  id: row.id,
  fromStatus: row.from_status as FindingCaseStatus | null,
  toStatus: row.to_status as FindingCaseStatus,
  reason: row.reason,
  actor: row.actor as "human" | "system",
  sessionID: row.session_id ? SessionV2.ID.make(row.session_id) : null,
  createdAt: row.time_created,
})

const toCaseOperationDTO = (row: FindingCaseOperationRecord) => {
  const findingIDs = typeof row.finding_ids === "string" ? JSON.parse(row.finding_ids) : row.finding_ids
  if (!Array.isArray(findingIDs) || !findingIDs.every((findingID) => typeof findingID === "string")) {
    throw new Error(`Invalid finding ID snapshot for case operation ${row.id}`)
  }
  return {
    id: row.id,
    kind: row.kind as "merge" | "split",
    sourceCaseID: row.source_case_id,
    targetCaseID: row.target_case_id,
    reason: row.reason,
    actor: row.actor as "human" | "system",
    sessionID: row.session_id ? SessionV2.ID.make(row.session_id) : null,
    findingIDs,
    createdAt: row.time_created,
    reversedAt: row.reversed_at ?? null,
    reversedReason: row.reversed_reason ?? null,
    reversedBy: row.reversed_by as "human" | "system" | null,
  }
}

export const SecurityHandler = HttpApiBuilder.group(Api, "server.security", (handlers) =>
  Effect.gen(function* () {
    const { db } = yield* Database.Service
    const audit = yield* Audit.Service

    const ensureSession = (sessionID: string) =>
      db
        .select({ id: SessionTable.id, projectID: SessionTable.project_id })
        .from(SessionTable)
        .where(eq(SessionTable.id, SessionV2.ID.make(sessionID)))
        .get()
        .pipe(
          Effect.orDie,
          Effect.flatMap((row) =>
            row
              ? Effect.succeed(row)
              : Effect.fail(new SessionNotFoundError({ sessionID, message: `Session not found: ${sessionID}` })),
          ),
        )

    const toImportError = (error: unknown) =>
      error instanceof FindingImportError
        ? new SecurityFindingImportError({ code: error.code, line: error.line, message: error.message })
        : new SecurityFindingImportError({
            code: "invalid_document",
            message: error instanceof Error ? error.message : "Unable to process scanner import",
          })

    const toCaseOperationError = (
      error: unknown,
      caseID: string,
    ): Effect.Effect<
      never,
      SecurityFindingCaseRequestError | SecurityFindingCaseConflictError | SecurityFindingCaseNotFoundError
    > => {
      if (!(error instanceof FindingCaseError)) return Effect.die(error)
      if (error.code === "not_found") {
        return Effect.fail(new SecurityFindingCaseNotFoundError({ caseID, message: error.message }))
      }
      if (
        error.code === "case_not_active" ||
        error.code === "operation_not_reversible" ||
        error.code === "dependent_operation"
      ) {
        return Effect.fail(new SecurityFindingCaseConflictError({ code: error.code, message: error.message }))
      }
      return Effect.fail(new SecurityFindingCaseRequestError({ code: error.code, message: error.message }))
    }

    return handlers
      .handle(
        "security.findings.import.preview",
        Effect.fn(function* (ctx) {
          yield* ensureSession(ctx.params.sessionID)
          const preview = yield* Effect.try({
            try: () => parseFindingImport(ctx.payload.format, ctx.payload.content),
            catch: toImportError,
          })
          return { data: preview }
        }),
      )
      .handle(
        "security.findings.import",
        Effect.fn(function* (ctx) {
          yield* ensureSession(ctx.params.sessionID)
          const imported = yield* importFindingDocument(db, {
            sessionID: ctx.params.sessionID,
            format: ctx.payload.format,
            content: ctx.payload.content,
            importID: ctx.payload.importID,
          }).pipe(
            Effect.catch((error) =>
              error instanceof FindingImportError ? Effect.fail(toImportError(error)) : Effect.die(error),
            ),
          )
          return { data: imported }
        }),
      )
      .handle(
        "security.findings.list",
        Effect.fn(function* (ctx) {
          yield* ensureSession(ctx.params.sessionID)
          const limit = ctx.query.limit ?? 50
          const offset = ctx.query.offset ?? 0

          const result = yield* listFindingRecords(db, {
            sessionID: ctx.params.sessionID,
            limit,
            offset,
            status: ctx.query.status,
            severity: ctx.query.severity,
            includeSuppressed: ctx.query.includeSuppressed ?? false,
          })
          return {
            data: result.records.map(({ row, feedback }) => toDTO(row, feedback)),
            total: result.total,
            limit,
            offset,
          }
        }),
      )
      .handle(
        "security.finding-cases.list",
        Effect.fn(function* (ctx) {
          const session = yield* ensureSession(ctx.params.sessionID)
          const limit = ctx.query.limit ?? 50
          const offset = ctx.query.offset ?? 0
          const input = { projectID: session.projectID, sessionID: ctx.params.sessionID }
          const data = yield* listFindingCasesForSession(db, { ...input, limit, offset })
          const total = yield* countFindingCasesForSession(db, input)
          return { data: data.map(toCaseDTO), total, limit, offset }
        }),
      )
      .handle(
        "security.finding-cases.history",
        Effect.fn(function* (ctx) {
          const session = yield* ensureSession(ctx.params.sessionID)
          const current = yield* getFindingCaseForSession(db, {
            sessionID: ctx.params.sessionID,
            caseID: ctx.params.caseID,
          })
          if (!current || current.project_id !== session.projectID) {
            return yield* new SecurityFindingCaseNotFoundError({
              caseID: ctx.params.caseID,
              message: `Finding case not found in session ${ctx.params.sessionID}`,
            })
          }
          const transitions = yield* listFindingCaseTransitions(db, {
            sessionID: ctx.params.sessionID,
            caseID: ctx.params.caseID,
            limit: ctx.query.limit,
          })
          return { data: transitions.map(toCaseTransitionDTO) }
        }),
      )
      .handle(
        "security.finding-cases.operations",
        Effect.fn(function* (ctx) {
          const session = yield* ensureSession(ctx.params.sessionID)
          const current = yield* getFindingCaseForSession(db, {
            sessionID: ctx.params.sessionID,
            caseID: ctx.params.caseID,
          })
          if (!current || current.project_id !== session.projectID) {
            return yield* new SecurityFindingCaseNotFoundError({
              caseID: ctx.params.caseID,
              message: `Finding case not found in session ${ctx.params.sessionID}`,
            })
          }
          const operations = yield* listFindingCaseOperations(db, {
            sessionID: ctx.params.sessionID,
            caseID: ctx.params.caseID,
            limit: ctx.query.limit,
          })
          return { data: operations.map(toCaseOperationDTO) }
        }),
      )
      .handle(
        "security.finding-cases.merge",
        Effect.fn(function* (ctx) {
          const session = yield* ensureSession(ctx.params.sessionID)
          const [source, target] = yield* Effect.all([
            getFindingCaseForSession(db, { sessionID: ctx.params.sessionID, caseID: ctx.params.caseID }),
            getFindingCaseForSession(db, { sessionID: ctx.params.sessionID, caseID: ctx.payload.targetCaseID }),
          ])
          if (
            !source ||
            !target ||
            source.project_id !== session.projectID ||
            target.project_id !== session.projectID
          ) {
            return yield* new SecurityFindingCaseNotFoundError({
              caseID: !source ? ctx.params.caseID : ctx.payload.targetCaseID,
              message: `Both finding cases must be visible in session ${ctx.params.sessionID}`,
            })
          }
          const operation = yield* mergeFindingCases(db, {
            projectID: session.projectID,
            sessionID: ctx.params.sessionID,
            sourceCaseID: ctx.params.caseID,
            targetCaseID: ctx.payload.targetCaseID,
            reason: ctx.payload.reason,
            actor: "human",
          }).pipe(Effect.catch((error) => toCaseOperationError(error, ctx.params.caseID)))
          yield* audit.append({
            sessionID: SessionV2.ID.make(ctx.params.sessionID),
            projectID: session.projectID,
            eventType: "finding.case.merge",
            action: "finding.case.merge",
            target: operation.id,
            summary: `Caso ${operation.source_case_id} fusionado en ${operation.target_case_id}`,
            payload: {
              operationID: operation.id,
              sourceCaseID: operation.source_case_id,
              targetCaseID: operation.target_case_id,
              findingIDs: operation.finding_ids,
              reason: operation.reason,
              actor: "human",
            },
          })
          return { data: toCaseOperationDTO(operation) }
        }),
      )
      .handle(
        "security.finding-cases.split",
        Effect.fn(function* (ctx) {
          const session = yield* ensureSession(ctx.params.sessionID)
          const source = yield* getFindingCaseForSession(db, {
            sessionID: ctx.params.sessionID,
            caseID: ctx.params.caseID,
          })
          if (!source || source.project_id !== session.projectID) {
            return yield* new SecurityFindingCaseNotFoundError({
              caseID: ctx.params.caseID,
              message: `Finding case not found in session ${ctx.params.sessionID}`,
            })
          }
          const result = yield* splitFindingCase(db, {
            projectID: session.projectID,
            sessionID: ctx.params.sessionID,
            sourceCaseID: ctx.params.caseID,
            findingIDs: ctx.payload.findingIDs,
            reason: ctx.payload.reason,
            actor: "human",
          }).pipe(Effect.catch((error) => toCaseOperationError(error, ctx.params.caseID)))
          yield* audit.append({
            sessionID: SessionV2.ID.make(ctx.params.sessionID),
            projectID: session.projectID,
            eventType: "finding.case.split",
            action: "finding.case.split",
            target: result.operation.id,
            summary: `Se separaron hallazgos del caso ${result.operation.source_case_id}`,
            payload: {
              operationID: result.operation.id,
              sourceCaseID: result.operation.source_case_id,
              targetCaseID: result.operation.target_case_id,
              findingIDs: result.operation.finding_ids,
              reason: result.operation.reason,
              actor: "human",
            },
          })
          return { caseID: result.caseID, operation: toCaseOperationDTO(result.operation) }
        }),
      )
      .handle(
        "security.finding-cases.reverse",
        Effect.fn(function* (ctx) {
          const session = yield* ensureSession(ctx.params.sessionID)
          const current = yield* getFindingCaseForSession(db, {
            sessionID: ctx.params.sessionID,
            caseID: ctx.params.caseID,
          })
          if (!current || current.project_id !== session.projectID) {
            return yield* new SecurityFindingCaseNotFoundError({
              caseID: ctx.params.caseID,
              message: `Finding case not found in session ${ctx.params.sessionID}`,
            })
          }
          const operation = yield* reverseFindingCaseOperation(db, {
            projectID: session.projectID,
            sessionID: ctx.params.sessionID,
            caseID: ctx.params.caseID,
            operationID: ctx.params.operationID,
            reason: ctx.payload.reason,
            actor: "human",
          }).pipe(Effect.catch((error) => toCaseOperationError(error, ctx.params.caseID)))
          yield* audit.append({
            sessionID: SessionV2.ID.make(ctx.params.sessionID),
            projectID: session.projectID,
            eventType: "finding.case.operation.reverse",
            action: "finding.case.operation.reverse",
            target: operation.id,
            summary: `Se revirtió la operación ${operation.kind} del caso`,
            payload: {
              operationID: operation.id,
              sourceCaseID: operation.source_case_id,
              targetCaseID: operation.target_case_id,
              findingIDs: operation.finding_ids,
              reason: operation.reversed_reason,
              actor: "human",
            },
          })
          return { data: toCaseOperationDTO(operation) }
        }),
      )
      .handle(
        "security.finding-cases.status",
        Effect.fn(function* (ctx) {
          const session = yield* ensureSession(ctx.params.sessionID)
          const current = yield* getFindingCaseForSession(db, {
            sessionID: ctx.params.sessionID,
            caseID: ctx.params.caseID,
          })
          if (!current || current.project_id !== session.projectID) {
            return yield* new SecurityFindingCaseNotFoundError({
              caseID: ctx.params.caseID,
              message: `Finding case not found in session ${ctx.params.sessionID}`,
            })
          }

          const updated = yield* setFindingCaseStatus(db, {
            projectID: session.projectID,
            caseID: ctx.params.caseID,
            status: ctx.payload.status,
            actor: "human",
            reason: ctx.payload.reason,
            acceptedRiskUntil: ctx.payload.acceptedRiskUntil,
            sessionID: ctx.params.sessionID,
          }).pipe(Effect.catch((error) => toCaseOperationError(error, ctx.params.caseID)))

          if (
            current.status !== updated.status ||
            current.status_reason !== updated.status_reason ||
            current.accepted_risk_until !== updated.accepted_risk_until
          ) {
            yield* audit.append({
              sessionID: SessionV2.ID.make(ctx.params.sessionID),
              projectID: session.projectID,
              eventType: "finding.case.status",
              action: `finding.case.${updated.status}`,
              target: updated.id,
              summary: `Caso ${updated.id} cambió de ${current.status} a ${updated.status}`,
              payload: {
                caseID: updated.id,
                fromStatus: current.status,
                toStatus: updated.status,
                reason: updated.status_reason,
                acceptedRiskUntil: updated.accepted_risk_until,
                actor: "human",
              },
            })
          }
          return {
            data: toCaseDTO({
              ...updated,
              finding_count: current.finding_count,
              session_count: current.session_count,
            }),
          }
        }),
      )
      .handle(
        "security.findings.get",
        Effect.fn(function* (ctx) {
          yield* ensureSession(ctx.params.sessionID)
          const record = yield* getFindingRecord(db, ctx.params.sessionID, ctx.params.findingID)
          if (!record)
            return yield* new SecurityFindingNotFoundError({
              findingID: ctx.params.findingID,
              message: `Security finding not found: ${ctx.params.findingID}`,
            })
          return { data: toDTO(record.row, record.feedback) }
        }),
      )
      .handle(
        "security.findings.feedback",
        Effect.fn(function* (ctx) {
          yield* ensureSession(ctx.params.sessionID)
          const feedback = yield* recordFeedback(db, {
            sessionID: ctx.params.sessionID,
            findingID: ctx.params.findingID,
            verdict: ctx.payload.verdict,
            reason: ctx.payload.reason,
          }).pipe(
            Effect.catch((error) =>
              Effect.fail(
                new SecurityFindingNotFoundError({
                  findingID: ctx.params.findingID,
                  message: error.message,
                }),
              ),
            ),
          )
          // La decisión de triage queda en la cadena de auditoría: es lo que
          // permite explicar después por qué un hallazgo dejó de mostrarse.
          yield* audit.append(feedbackAuditEntry(feedback))
          return { data: toSecurityFeedbackDTO(feedback) }
        }),
      )
      .handle(
        "security.feedback.rules",
        Effect.fn(function* (ctx) {
          yield* ensureSession(ctx.params.sessionID)
          const session = yield* db
            .select({ projectID: SessionTable.project_id })
            .from(SessionTable)
            .where(eq(SessionTable.id, SessionV2.ID.make(ctx.params.sessionID)))
            .get()
            .pipe(Effect.orDie)
          const rows = yield* feedbackForProject(db, session?.projectID ?? "")
          return { data: ruleFeedbackStats(rows) }
        }),
      )
  }),
)
