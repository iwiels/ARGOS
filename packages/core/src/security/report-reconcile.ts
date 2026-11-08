import { and, eq, or } from "drizzle-orm"
import { Effect } from "effect"
import type { Database } from "../database/database"
import type { EventV2 } from "../event"
import type { Location } from "../location"
import { SessionTable } from "../session/sql"
import { SessionSchema } from "../session/schema"
import { FindingUpserted } from "./events"
import { findingFingerprint, findingId, findingTaxonomy, findFindingByTaxonomy, legacyFindingFingerprint, normalizeFindingSeverity, normalizeFindingStatus } from "./ingest"
import { FindingTable } from "./sql"
import { resolveFindingCase } from "./finding-case"

type DatabaseService = Database.Interface["db"]

const REPORT_RECONCILE_SOURCE_TOOL = "report-reconcile"

export interface ParsedReportFinding {
  readonly reportId: string
  readonly severity: string
  readonly title: string
  readonly cwe?: string
  readonly cve?: string
  readonly status: string
  readonly vector?: string
  readonly target?: string
}

export interface ReconcileResult {
  readonly total: number
  readonly inserted: number
  readonly skipped: number
}

const DASH_VALUES = new Set(["—", "-", "–", ""])
const cell = (value: string | undefined) => (value && !DASH_VALUES.has(value) ? value : undefined)

/**
 * Parsea la tabla "Hallazgos consolidados" (| ID | Severidad | Titulo | CWE |
 * CVE | Estado | Vector |) que security-report/orquestador escriben en
 * reports/*.md. Es el mismo catálogo que a veces no llega completo a
 * memory_save (ver "Modo degradado" en argos-config/AGENTS.md) — este
 * parser permite reconciliar lo que el reporte documentó contra lo que
 * realmente quedó persistido en security_finding.
 *
 * Solo reconoce filas de tabla con exactamente 7 columnas cuya primera celda
 * matchea `F-<número>` — esto excluye automáticamente separadores de tabla
 * markdown (`|---|---|`) y otras tablas del mismo reporte con distinto número
 * de columnas (p.ej. la de "Análisis de riesgo del top").
 */
export function parseReportTarget(markdown: string): string | undefined {
  const match = markdown.match(/\*\*Target:\*\*\s*([^\r\n]+)/i) ?? markdown.match(/^Target:\s*([^\r\n]+)/im)
  return match ? match[1].trim() : undefined
}

export function parseReportFindingsTable(markdown: string): ParsedReportFinding[] {
  const docTarget = parseReportTarget(markdown)
  const out: ParsedReportFinding[] = []
  for (const line of markdown.split(/\r?\n/)) {
    const trimmed = line.trim()
    if (!trimmed.startsWith("|")) continue
    const body = trimmed.startsWith("|") && trimmed.endsWith("|") ? trimmed.slice(1, -1) : trimmed.slice(1)
    const cells = body.split("|").map((part) => part.trim())
    if (cells.length !== 7) continue
    const [id, severity, title, cwe, cve, status, vector] = cells
    if (!/^F-\d+$/i.test(id)) continue
    if (!title) continue
    const vec = cell(vector)
    const isUrlTarget = vec ? /^https?:\/\//i.test(vec) : false
    out.push({
      reportId: id.toUpperCase(),
      severity,
      title,
      cwe: cell(cwe),
      cve: cell(cve),
      status,
      vector: vec,
      target: docTarget ?? (isUrlTarget ? vec : undefined),
    })
  }
  return out
}

/**
 * Inserta como Finding cada fila del reporte que todavía no exista en
 * security_finding para esta Session (por taxonomía —CWE, target y vector—
 * igual que ingest.ts). No pisa hallazgos ya persistidos — un reporte es una
 * foto estática y no debe sobrescribir datos que pudieron actualizarse
 * después vía memory_save. Nota conocida: si el CWE del reporte difiere del
 * CWE original pasado a memory_save para el mismo hallazgo real, no coincide
 * y el hallazgo se inserta de nuevo (duplicado suave, no falla ni corrompe
 * nada — preferible a perder el hallazgo por completo).
 */
export const reconcileReportFindings = Effect.fn("Security.reconcileReportFindings")(function* (
  db: DatabaseService,
  input: {
    sessionID: SessionSchema.ID
    reportMarkdown: string
    agent?: string
    target?: string
  },
  options?: { events?: EventV2.Interface; location?: Location.Ref },
) {
  const docTarget = input.target ?? parseReportTarget(input.reportMarkdown)
  const parsed = parseReportFindingsTable(input.reportMarkdown)
  const session = yield* db
    .select({ projectID: SessionTable.project_id })
    .from(SessionTable)
    .where(eq(SessionTable.id, input.sessionID))
    .get()
    .pipe(Effect.orDie)
  if (!session) return { total: parsed.length, inserted: 0, skipped: parsed.length } satisfies ReconcileResult

  let inserted = 0
  for (const finding of parsed) {
    const effectiveTarget = finding.target ?? docTarget
    // El fingerprint es taxonómico (CWE + target + vector): el reporte y el
    // panel tienen que hablar el mismo idioma para que la fila del reporte
    // no duplique un hallazgo que ya está contado.
    const fingerprint = findingFingerprint({
      title: finding.title,
      vector: finding.vector,
      target: effectiveTarget,
      cwe: finding.cwe,
    })
    // El reporte puede declarar un CWE que el memory_save original no
    // declaraba: en ese caso la fila del panel se indexó con la identidad
    // histórica (título + vector) y el fingerprint taxonómico no coincide.
    // Se buscan las dos identidades.
    const legacy = legacyFindingFingerprint({
      title: finding.title,
      vector: finding.vector,
      target: effectiveTarget,
    })
    const existing = yield* db
      .select({ id: FindingTable.id })
      .from(FindingTable)
      .where(
        and(
          eq(FindingTable.session_id, input.sessionID),
          or(eq(FindingTable.fingerprint, fingerprint), eq(FindingTable.fingerprint, legacy)),
        ),
      )
      .get()
      .pipe(Effect.orDie)
    if (existing) continue

    // La tabla "Hallazgos consolidados" no tiene columna de target: cuando el
    // documento tampoco lo declara, la única señal de ubicación es el
    // vector. Sin esta búsqueda el reporte insertaría un duplicado suave de
    // un bug que el panel ya está contando.
    const taxonomy = findingTaxonomy({
      title: finding.title,
      vector: finding.vector,
      target: effectiveTarget,
      cwe: finding.cwe,
    })
    if (taxonomy) {
      const match = yield* findFindingByTaxonomy(db, input.sessionID, taxonomy)
      if (match) continue
    }

    const now = Date.now()
    const id = findingId(input.sessionID, fingerprint)
    const caseID = yield* resolveFindingCase(db, {
      projectID: session.projectID,
      identityKey: fingerprint,
      now,
    }).pipe(Effect.orDie)
    yield* db
      .insert(FindingTable)
      .values({
        id,
        session_id: input.sessionID,
        project_id: session.projectID,
        case_id: caseID,
        fingerprint,
        title: finding.title,
        severity: normalizeFindingSeverity(finding.severity),
        status: normalizeFindingStatus(finding.status),
        source: "memory",
        source_tool: REPORT_RECONCILE_SOURCE_TOOL,
        agent: input.agent,
        target: effectiveTarget,
        cwe: finding.cwe,
        vector: finding.vector,
        evidence: {},
        tags: [finding.reportId],
        raw: JSON.stringify(finding),
        time_created: now,
        time_updated: now,
      })
      .onConflictDoNothing()
      .run()
      .pipe(Effect.orDie)
    inserted++

    if (options?.events) {
      yield* options.events.publish(
        FindingUpserted,
        { sessionID: input.sessionID, findingID: id, fingerprint },
        { location: options.location },
      )
    }
  }

  return { total: parsed.length, inserted, skipped: parsed.length - inserted } satisfies ReconcileResult
})
