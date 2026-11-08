import { and, eq, sql } from "drizzle-orm"
import { Effect } from "effect"
import { createHash } from "node:crypto"
import type { Database } from "../database/database"
import {
  CaseTransitionHistoryTable,
  CaseObservationTable,
  FindingTable,
  SecurityCaseTable,
} from "./sql"
import { findingFingerprint } from "./ingest"

export type ContextType = "endpoint_param" | "code_location" | "component_dep" | "asset_infra"

export interface RecordObservationInput {
  sessionID: string
  projectID: string
  findingID?: string
  runID?: string
  source?: string // scanner | agent | import | manual
  sourceTool?: string
  ruleID?: string
  title: string
  severity: string
  cwe?: string
  target?: string
  vector?: string
  evidence: Record<string, unknown>
  raw?: string
  confidence?: string
  contextType?: ContextType
  observedAt?: number
}

export const SLA_DAYS_BY_SEVERITY: Record<string, number> = {
  critical: 7,
  high: 15,
  medium: 30,
  low: 90,
  info: 180,
}

export function calculateSlaDueAt(firstSeenAt: number, severity: string): number {
  const days = SLA_DAYS_BY_SEVERITY[severity.toLowerCase()] ?? 30
  return firstSeenAt + days * 24 * 60 * 60 * 1000
}

export function determineSlaStatus(
  caseItem: {
    status: string
    first_seen_at: number
    severity: string
    sla_due_at?: number | null
    accepted_risk_expires_at?: number | null
  },
  now = Date.now(),
): "within_sla" | "warning" | "breached" | "risk_expired" | "met" {
  if (["remediated", "verified", "closed", "false_positive"].includes(caseItem.status)) {
    return "met"
  }
  if (caseItem.status === "accepted_risk") {
    if (caseItem.accepted_risk_expires_at && now > caseItem.accepted_risk_expires_at) {
      return "risk_expired"
    }
    return "within_sla"
  }
  const dueAt = caseItem.sla_due_at ?? calculateSlaDueAt(caseItem.first_seen_at, caseItem.severity)
  if (now > dueAt) {
    return "breached"
  }
  const totalDuration = dueAt - caseItem.first_seen_at
  if (now > dueAt - totalDuration * 0.2) {
    return "warning"
  }
  return "within_sla"
}

export class CaseService {
  /**
   * Registra una observación en un caso de vulnerabilidad del proyecto (Etapa 2).
   * Si el caso no existe, se crea; si ya existía, se vincula la nueva observación
   * y se actualiza `last_seen_at`. Nunca destruye evidencia histórica previa.
   */
  static recordObservation(db: Database.Interface["db"], input: RecordObservationInput) {
    return Effect.gen(function* () {
      const now = input.observedAt ?? Date.now()
      const fingerprint = findingFingerprint({
        title: input.title,
        cwe: input.cwe,
        target: input.target,
        vector: input.vector,
      })

      // 1. Buscar si ya existe el caso en el proyecto
      let securityCase = yield* db
        .select()
        .from(SecurityCaseTable)
        .where(
          and(
            eq(SecurityCaseTable.project_id, input.projectID),
            eq(SecurityCaseTable.fingerprint, fingerprint),
          ),
        )
        .get()
        .pipe(Effect.orDie)

      const caseID = securityCase?.id ?? `case_${createHash("sha256").update(`${input.projectID}:${fingerprint}`).digest("hex").slice(0, 32)}`

      const slaDueAt = calculateSlaDueAt(now, input.severity)
      const slaStatus = determineSlaStatus({
        status: "open",
        first_seen_at: now,
        severity: input.severity,
        sla_due_at: slaDueAt,
      }, now)

      if (!securityCase) {
        // Crear caso nuevo
        yield* db
          .insert(SecurityCaseTable)
          .values({
            id: caseID,
            project_id: input.projectID,
            fingerprint,
            context_type: input.contextType ?? "endpoint_param",
            title: input.title,
            severity: input.severity,
            status: "open",
            cwe: input.cwe,
            target: input.target,
            vector: input.vector,
            first_seen_at: now,
            last_seen_at: now,
            sla_due_at: slaDueAt,
            sla_status: slaStatus,
            time_created: now,
            time_updated: now,
          })
          .run()
          .pipe(Effect.orDie)

        yield* db
          .insert(CaseTransitionHistoryTable)
          .values({
            id: `hist_${createHash("sha256").update(`${caseID}:${now}:created`).digest("hex").slice(0, 32)}`,
            case_id: caseID,
            project_id: input.projectID,
            previous_status: null,
            new_status: "open",
            action: "status_change",
            reason: `Vulnerabilidad detectada por primera vez vía ${input.sourceTool || input.source}`,
            actor: "system",
            time_created: now,
          })
          .run()
          .pipe(Effect.orDie)
      } else {
        // Actualizar last_seen_at
        yield* db
          .update(SecurityCaseTable)
          .set({
            last_seen_at: now,
            time_updated: now,
            // Reabrir si estaba resuelto y volvió a observarse
            status: securityCase.status === "remediated" || securityCase.status === "closed" ? "open" : securityCase.status,
          })
          .where(eq(SecurityCaseTable.id, caseID))
          .run()
          .pipe(Effect.orDie)

        if (securityCase.status === "remediated" || securityCase.status === "closed") {
          yield* db
            .insert(CaseTransitionHistoryTable)
            .values({
              id: `hist_${createHash("sha256").update(`${caseID}:${now}:reopened`).digest("hex").slice(0, 32)}`,
              case_id: caseID,
              project_id: input.projectID,
              previous_status: securityCase.status,
              new_status: "open",
              action: "status_change",
              reason: "Reabierto: re-observado en nueva auditoría",
              actor: "system",
              time_created: now,
            })
            .run()
            .pipe(Effect.orDie)
        }
      }

      // 2. Registrar la observación inmutable
      const observationID = `obs_${createHash("sha256").update(`${caseID}:${input.sessionID}:${now}:${Math.random()}`).digest("hex").slice(0, 32)}`
      yield* db
        .insert(CaseObservationTable)
        .values({
          id: observationID,
          case_id: caseID,
          finding_id: input.findingID,
          session_id: input.sessionID,
          project_id: input.projectID,
          run_id: input.runID,
          source: input.source || "scanner",
          source_tool: input.sourceTool,
          rule_id: input.ruleID,
          observed_at: now,
          evidence: input.evidence,
          raw: input.raw,
          confidence: input.confidence ?? "possible",
        })
        .run()
        .pipe(Effect.orDie)

      return { caseID, observationID, isNewCase: !securityCase }
    })
  }

  /**
   * Fusión reversible de dos casos (Etapa 2 - DefectDojo deduplication).
   */
  static mergeCases(
    db: Database.Interface["db"],
    opts: {
      sourceCaseID: string
      targetCaseID: string
      projectID: string
      reason: string
      actor?: string
    },
  ) {
    return Effect.gen(function* () {
      const now = Date.now()
      yield* db
        .update(SecurityCaseTable)
        .set({
          merged_into_id: opts.targetCaseID,
          merge_reason: opts.reason,
          time_updated: now,
        })
        .where(eq(SecurityCaseTable.id, opts.sourceCaseID))
        .run()
        .pipe(Effect.orDie)

      yield* db
        .insert(CaseTransitionHistoryTable)
        .values({
          id: `hist_merge_${now}_${opts.sourceCaseID.slice(0, 8)}`,
          case_id: opts.sourceCaseID,
          project_id: opts.projectID,
          previous_status: "open",
          new_status: "merged",
          action: "merge",
          reason: `Fusionado en ${opts.targetCaseID}: ${opts.reason}`,
          actor: opts.actor ?? "human",
          time_created: now,
        })
        .run()
        .pipe(Effect.orDie)

      return { ok: true }
    })
  }

  /**
   * Separación reversible de un caso previamente fusionado.
   */
  static splitCase(
    db: Database.Interface["db"],
    opts: {
      caseID: string
      projectID: string
      reason: string
      actor?: string
    },
  ) {
    return Effect.gen(function* () {
      const now = Date.now()
      yield* db
        .update(SecurityCaseTable)
        .set({
          merged_into_id: null,
          merge_reason: null,
          time_updated: now,
        })
        .where(eq(SecurityCaseTable.id, opts.caseID))
        .run()
        .pipe(Effect.orDie)

      yield* db
        .insert(CaseTransitionHistoryTable)
        .values({
          id: `hist_split_${now}_${opts.caseID.slice(0, 8)}`,
          case_id: opts.caseID,
          project_id: opts.projectID,
          previous_status: "merged",
          new_status: "open",
          action: "split",
          reason: `Separado: ${opts.reason}`,
          actor: opts.actor ?? "human",
          time_created: now,
        })
        .run()
        .pipe(Effect.orDie)

      return { ok: true }
    })
  }

  /**
   * Al eliminar una sesión, purga sus observaciones y recalcula casos compartidos.
   * Si un caso no tiene observaciones de otras sesiones, se elimina (Etapa 2).
   */
  static purgeSession(db: Database.Interface["db"], sessionID: string) {
    return Effect.gen(function* () {
      // 1. Obtener los case IDs afectados por esta sesión
      const observations = yield* db
        .select({ case_id: CaseObservationTable.case_id })
        .from(CaseObservationTable)
        .where(eq(CaseObservationTable.session_id, sessionID))
        .all()
        .pipe(Effect.orDie)

      const caseIDs = [...new Set(observations.map((o) => o.case_id))]

      // 2. Eliminar las observaciones de la sesión
      yield* db
        .delete(CaseObservationTable)
        .where(eq(CaseObservationTable.session_id, sessionID))
        .run()
        .pipe(Effect.orDie)

      // 3. Revisar cada caso: si ya no le quedan observaciones, eliminarlo
      for (const id of caseIDs) {
        const remaining = yield* db
          .select({ count: sql<number>`count(*)` })
          .from(CaseObservationTable)
          .where(eq(CaseObservationTable.case_id, id))
          .get()
          .pipe(Effect.orDie)

        if ((remaining?.count ?? 0) === 0) {
          yield* db.delete(SecurityCaseTable).where(eq(SecurityCaseTable.id, id)).run().pipe(Effect.orDie)
        }
      }

      return { purgedCases: caseIDs.length }
    })
  }

  /**
   * Marca un caso como riesgo aceptado con fecha de expiración y motivo justificado (Etapa 4).
   */
  static acceptRisk(
    db: Database.Interface["db"],
    input: {
      caseID: string
      reason: string
      actor?: string
      expiresInDays?: number
    },
  ) {
    return Effect.gen(function* () {
      const now = Date.now()
      const expiresInDays = input.expiresInDays ?? 90
      const expiresAt = now + expiresInDays * 24 * 60 * 60 * 1000

      const currentCase = yield* db
        .select()
        .from(SecurityCaseTable)
        .where(eq(SecurityCaseTable.id, input.caseID))
        .get()
        .pipe(Effect.orDie)

      if (!currentCase) {
        return yield* Effect.fail(new Error(`Case ${input.caseID} not found`))
      }

      yield* db
        .update(SecurityCaseTable)
        .set({
          status: "accepted_risk",
          accepted_risk_expires_at: expiresAt,
          accepted_risk_reason: input.reason,
          sla_status: "within_sla",
          time_updated: now,
        })
        .where(eq(SecurityCaseTable.id, input.caseID))
        .run()
        .pipe(Effect.orDie)

      yield* db
        .insert(CaseTransitionHistoryTable)
        .values({
          id: `hist_${createHash("sha256").update(`${input.caseID}:${now}:accept_risk`).digest("hex").slice(0, 32)}`,
          case_id: input.caseID,
          project_id: currentCase.project_id,
          previous_status: currentCase.status,
          new_status: "accepted_risk",
          action: "status_change",
          reason: `Riesgo aceptado (${expiresInDays} días): ${input.reason}`,
          actor: input.actor ?? "human",
          time_created: now,
        })
        .run()
        .pipe(Effect.orDie)

      return { caseID: input.caseID, expiresAt }
    })
  }

  /**
   * Recalcula y actualiza el estado de SLA de un caso según el tiempo actual (Etapa 4).
   */
  static refreshSla(db: Database.Interface["db"], caseID: string) {
    return Effect.gen(function* () {
      const currentCase = yield* db
        .select()
        .from(SecurityCaseTable)
        .where(eq(SecurityCaseTable.id, caseID))
        .get()
        .pipe(Effect.orDie)

      if (!currentCase) return null

      const slaStatus = determineSlaStatus(currentCase)
      if (slaStatus !== currentCase.sla_status) {
        yield* db
          .update(SecurityCaseTable)
          .set({ sla_status: slaStatus, time_updated: Date.now() })
          .where(eq(SecurityCaseTable.id, caseID))
          .run()
          .pipe(Effect.orDie)
      }

      return { ...currentCase, sla_status: slaStatus }
    })
  }
}
