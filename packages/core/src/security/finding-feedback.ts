/**
 * Triage de falsos positivos con aprendizaje (ARG-064).
 *
 * El principio que gobierna este módulo: **el feedback es por engagement**.
 * Un auditor que marca un hallazgo como falso positivo está diciendo "en este
 * target, con este alcance, esta regla se equivocó". No está diciendo "esta
 * regla siempre se equivoca". Por eso:
 *
 *  - Dentro del engagement, el veredicto se aplica: el hallazgo sale del
 *    listado por defecto y se puede recuperar pidiendo los suprimidos.
 *  - Fuera del engagement, el veredicto solo alimenta la precisión histórica
 *    de la regla, que se muestra como contexto. Nunca suprime.
 *
 * La supresión automática no existe: suprimir es una decisión registrada, con
 * actor y motivo, y queda en la cadena de auditoría (`feedbackAuditEntry`).
 */

import { and, eq, inArray } from "drizzle-orm"
import { Effect } from "effect"
import type { Audit } from "../audit"
import type { Database } from "../database/database"
import type { FindingRow } from "./validation"
import { FindingFeedbackTable, FindingTable } from "./sql"
import { trustedFindingSourceCondition } from "./finding-provenance"

export const FEEDBACK_VERDICTS = ["false-positive", "true-positive", "accepted-risk"] as const
export type FeedbackVerdict = (typeof FEEDBACK_VERDICTS)[number]

export const FEEDBACK_ACTORS = ["human", "agent"] as const
export type FeedbackActor = (typeof FEEDBACK_ACTORS)[number]

export const MAX_FEEDBACK_REASON_CHARS = 2000

export type FeedbackRow = typeof FindingFeedbackTable.$inferSelect

export interface FeedbackInput {
  sessionID: string
  findingID: string
  verdict: FeedbackVerdict
  reason?: string
  actor?: FeedbackActor
}

export interface RuleFeedbackStats {
  ruleId: string
  truePositives: number
  falsePositives: number
  acceptedRisk: number
  /** tp / (tp + fp). Cuando no hay veredictos de TP/FP se reporta 1: no hay
   *  evidencia de que la regla falle, pero `verdicts` deja ver que tampoco de
   *  que acierte. */
  precision: number
  verdicts: number
}

const isVerdict = (value: unknown): value is FeedbackVerdict =>
  typeof value === "string" && (FEEDBACK_VERDICTS as readonly string[]).includes(value)

/** Normaliza el veredicto: es un vocabulario cerrado, no texto libre. */
export function normalizeVerdict(value: unknown): FeedbackVerdict | undefined {
  return isVerdict(value) ? value : undefined
}

/** Normaliza el actor: cualquier cosa que no sea "agent" es humana. */
export function normalizeActor(value: unknown): FeedbackActor {
  return value === "agent" ? "agent" : "human"
}

/** Recorta y limpia el motivo. Un motivo vacío es `undefined`, no "". */
export function normalizeReason(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined
  const trimmed = value.trim()
  return trimmed ? trimmed.slice(0, MAX_FEEDBACK_REASON_CHARS) : undefined
}

/**
 * Registra (o corrige) el veredicto de un hallazgo.
 *
 * La identidad del hallazgo —fingerprint, regla, tool, CWE, proyecto— se lee
 * de la fila persistida, nunca del cliente: un request no puede declarar que
 * un hallazgo ajeno es suyo ni cambiar la regla que lo produjo.
 */
export function recordFeedback(
  db: Database.Interface["db"],
  input: FeedbackInput,
): Effect.Effect<FeedbackRow, Error> {
  return Effect.gen(function* () {
    const verdict = normalizeVerdict(input.verdict)
    if (!verdict) {
      return yield* Effect.fail(new Error(`Unknown feedback verdict: ${String(input.verdict)}`))
    }

    const finding: FindingRow | undefined = yield* db
      .select()
      .from(FindingTable)
      .where(and(eq(FindingTable.id, input.findingID), eq(FindingTable.session_id, input.sessionID), trustedFindingSourceCondition()))
      .get()
      .pipe(Effect.orDie)

    if (!finding) {
      return yield* Effect.fail(
        new Error(`Finding ${input.findingID} does not belong to session ${input.sessionID}`),
      )
    }

    const now = Date.now()
    const reason = normalizeReason(input.reason)
    const actor = normalizeActor(input.actor)

    yield* db
      .insert(FindingFeedbackTable)
      .values({
        id: `fbf_${finding.id}`,
        project_id: finding.project_id,
        session_id: finding.session_id,
        finding_id: finding.id,
        fingerprint: finding.fingerprint,
        rule_id: finding.rule_id,
        source_tool: finding.source_tool,
        cwe: finding.cwe,
        verdict,
        reason,
        actor,
        time_created: now,
        time_updated: now,
      })
      .onConflictDoUpdate({
        target: FindingFeedbackTable.finding_id,
        set: { verdict, reason, actor, time_updated: now },
      })
      .run()
      .pipe(Effect.orDie)

    const stored = yield* db
      .select()
      .from(FindingFeedbackTable)
      .where(eq(FindingFeedbackTable.finding_id, finding.id))
      .get()
      .pipe(Effect.orDie)

    if (!stored) {
      return yield* Effect.fail(new Error(`Feedback for finding ${finding.id} was not persisted`))
    }
    return stored
  })
}

/** Veredictos registrados en un engagement. */
export function feedbackForSession(
  db: Database.Interface["db"],
  sessionID: string,
): Effect.Effect<FeedbackRow[]> {
  return db
    .select()
    .from(FindingFeedbackTable)
    .where(eq(FindingFeedbackTable.session_id, sessionID))
    .all()
    .pipe(Effect.orDie)
}

/** Veredictos de un conjunto de hallazgos, por id de hallazgo. */
export function feedbackByFindingID(rows: readonly FeedbackRow[]): Map<string, FeedbackRow> {
  return new Map(rows.map((row) => [row.finding_id, row]))
}

/**
 * Precisión histórica por regla dentro de un proyecto.
 *
 * Cruza engagements a propósito: es el "learning" que el auditor ve al
 * revisar una regla. No suprime nada por sí mismo — el consumidor decide qué
 * hacer con el número, y la UI lo muestra como contexto.
 */
export function ruleFeedbackStats(rows: readonly FeedbackRow[]): RuleFeedbackStats[] {
  const byRule = new Map<string, { tp: number; fp: number; ar: number }>()
  for (const row of rows) {
    const key = row.rule_id ?? row.source_tool ?? "unknown"
    const entry = byRule.get(key) ?? { tp: 0, fp: 0, ar: 0 }
    if (row.verdict === "true-positive") entry.tp += 1
    else if (row.verdict === "false-positive") entry.fp += 1
    else entry.ar += 1
    byRule.set(key, entry)
  }
  return [...byRule.entries()]
    .map(([ruleId, counts]) => {
      const judged = counts.tp + counts.fp
      return {
        ruleId,
        truePositives: counts.tp,
        falsePositives: counts.fp,
        acceptedRisk: counts.ar,
        precision: judged === 0 ? 1 : counts.tp / judged,
        verdicts: counts.tp + counts.fp + counts.ar,
      } satisfies RuleFeedbackStats
    })
    .sort((a, b) => a.precision - b.precision || b.verdicts - a.verdicts)
}

/**
 * Umbral por debajo del cual una regla se marca como sospechosa de ruido.
 *
 * No dispara ninguna acción: es el número que la UI usa para pintar la regla
 * en ámbar y para ordenar el triage. La decisión de dejar de usar una regla
 * sigue siendo humana.
 */
export const RULE_NOISE_THRESHOLD = 0.5

export function noisyRules(stats: readonly RuleFeedbackStats[], minimumVerdicts = 5): RuleFeedbackStats[] {
  return stats.filter((entry) => entry.verdicts >= minimumVerdicts && entry.precision < RULE_NOISE_THRESHOLD)
}

export interface FeedbackPartition<T> {
  /** Hallazgos que se muestran. */
  visible: T[]
  /** Hallazgos suprimidos en este engagement, con su veredicto. */
  suppressed: Array<{ finding: T; feedback: FeedbackRow }>
}

/**
 * Aplica el feedback **del engagement** a una lista de hallazgos.
 *
 * Solo los veredictos `false-positive` de la misma sesión suprimen, y solo si
 * el llamador no pidió verlos. `accepted-risk` y `true-positive` se conservan
 * visibles: un riesgo aceptado sigue siendo un hallazgo, y un TP confirmado es
 * el hallazgo más importante.
 */
export function partitionByFeedback<T extends { id: string; fingerprint: string }>(
  findings: readonly T[],
  sessionFeedback: readonly FeedbackRow[],
  options: { includeSuppressed?: boolean } = {},
): FeedbackPartition<T> {
  const byID = feedbackByFindingID(sessionFeedback)
  const byFingerprint = new Map(sessionFeedback.map((row) => [row.fingerprint, row]))
  const visible: T[] = []
  const suppressed: Array<{ finding: T; feedback: FeedbackRow }> = []

  for (const finding of findings) {
    const feedback = byID.get(finding.id) ?? byFingerprint.get(finding.fingerprint)
    if (feedback?.verdict === "false-positive" && !options.includeSuppressed) {
      suppressed.push({ finding, feedback })
      continue
    }
    visible.push(finding)
  }
  return { visible, suppressed }
}

/**
 * Evento de auditoría del veredicto.
 *
 * Se emite al registrar el triage, que es la decisión; la supresión en el
 * listado es su consecuencia y no vuelve a escribir la cadena. `actor` y
 * `reason` viajan en el payload para que el revisor sepa quién decidió y por
 * qué, sin abrir la tabla.
 */
export function feedbackAuditEntry(row: FeedbackRow): Audit.AppendInput {
  return {
    sessionID: row.session_id as never,
    projectID: row.project_id,
    eventType: "finding.feedback",
    action: `finding.${row.verdict}`,
    agent: row.actor === "agent" ? "agent" : undefined,
    target: row.finding_id,
    summary:
      row.verdict === "false-positive"
        ? `Hallazgo ${row.finding_id} marcado como falso positivo`
        : row.verdict === "true-positive"
          ? `Hallazgo ${row.finding_id} confirmado como verdadero positivo`
          : `Hallazgo ${row.finding_id} marcado como riesgo aceptado`,
    payload: {
      findingID: row.finding_id,
      fingerprint: row.fingerprint,
      ruleID: row.rule_id,
      sourceTool: row.source_tool,
      cwe: row.cwe,
      verdict: row.verdict,
      actor: row.actor,
      reason: row.reason,
    },
  }
}

/** Lee el feedback de un proyecto entero (para la vista de precisión por regla). */
export function feedbackForProject(
  db: Database.Interface["db"],
  projectID: string,
): Effect.Effect<FeedbackRow[]> {
  return db
    .select()
    .from(FindingFeedbackTable)
    .where(eq(FindingFeedbackTable.project_id, projectID))
    .all()
    .pipe(Effect.orDie)
}

/** Lee el feedback de un conjunto acotado de sesiones (misma sesión + proyecto). */
export function feedbackForSessions(
  db: Database.Interface["db"],
  sessionIDs: readonly string[],
): Effect.Effect<FeedbackRow[]> {
  if (sessionIDs.length === 0) return Effect.succeed([])
  return db
    .select()
    .from(FindingFeedbackTable)
    .where(inArray(FindingFeedbackTable.session_id, [...sessionIDs]))
    .all()
    .pipe(Effect.orDie)
}
