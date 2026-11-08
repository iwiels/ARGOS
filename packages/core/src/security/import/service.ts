import { and, eq } from "drizzle-orm"
import { Effect } from "effect"
import { createHash } from "node:crypto"
import type { Database } from "../../database/database"
import { CaseService } from "../case-service"
import { contractToDbRow, normalizeContract } from "../contract"
import { findingFingerprint, findingId } from "../ingest"
import { FindingTable } from "../sql"
import { PARSER_REGISTRY } from "./parsers"
import type { ImportFormat, ParsedImportResult } from "./types"

export interface ImportOptions {
  sessionID: string
  projectID: string
  format: ImportFormat
  content: string
  target?: string
  isCompleteScan?: boolean
  runID?: string
}

export class ImportService {
  /**
   * Vista previa y validación del archivo sin tocar la base de datos (Etapa 2).
   */
  static preview(format: ImportFormat, content: string, opts?: { target?: string; isCompleteScan?: boolean }): ParsedImportResult {
    const parser = PARSER_REGISTRY[format]
    if (!parser) {
      throw new Error(`Unsupported import format: ${format}`)
    }
    return parser.parse(content, opts)
  }

  /**
   * Ingesta idempotente de hallazgos desde escáneres o reportes externos (Etapa 2).
   * Registra cada hallazgo en `FindingTable`, su observación en `FindingObservationTable`
   * y su caso de proyecto en `SecurityCaseTable`.
   */
  static importFindings(db: Database.Interface["db"], options: ImportOptions) {
    return Effect.gen(function* () {
      const parsed = ImportService.preview(options.format, options.content, {
        target: options.target,
        isCompleteScan: options.isCompleteScan,
      })

      const now = Date.now()
      let inserted = 0
      let updated = 0
      const findingIDs: string[] = []

      for (const rawFinding of parsed.findings) {
        const normalized = normalizeContract(rawFinding)
        const fp = findingFingerprint({
          title: normalized.title,
          cwe: normalized.cwe,
          target: normalized.target,
          vector: normalized.vector,
        })
        const id = findingId(options.sessionID, fp)
        findingIDs.push(id)

        // 1. Proyección compatible en FindingTable (upsert idempotente)
        const existing = yield* db
          .select({ id: FindingTable.id, status: FindingTable.status })
          .from(FindingTable)
          .where(and(eq(FindingTable.session_id, options.sessionID), eq(FindingTable.fingerprint, fp)))
          .get()
          .pipe(Effect.orDie)

        const row = contractToDbRow(normalized)
        const rowValues = {
          id,
          session_id: options.sessionID,
          project_id: options.projectID,
          fingerprint: fp,
          ...row,
          time_created: now,
          time_updated: now,
        }

        if (!existing) {
          yield* db.insert(FindingTable).values(rowValues).run().pipe(Effect.orDie)
          inserted++
        } else {
          yield* db
            .update(FindingTable)
            .set({
              ...rowValues,
              status: existing.status, // preserve previous triage/status
              time_created: undefined,
              time_updated: now,
            })
            .where(eq(FindingTable.id, id))
            .run()
            .pipe(Effect.orDie)
          updated++
        }

        // 2. Registro de observación longitudinal y caso en SecurityCaseTable (Etapa 2)
        yield* CaseService.recordObservation(db, {
          sessionID: options.sessionID,
          projectID: options.projectID,
          findingID: id,
          runID: options.runID,
          source: "import",
          sourceTool: normalized.sourceTool ?? parsed.scanner,
          ruleID: normalized.ruleId,
          title: normalized.title,
          severity: normalized.severity,
          cwe: normalized.cwe,
          target: normalized.target,
          vector: normalized.vector,
          evidence: normalized.evidence,
          raw: options.format,
          confidence: normalized.confidence,
          observedAt: now,
        })
      }

      return {
        format: options.format,
        scanner: parsed.scanner,
        total: parsed.findings.length,
        inserted,
        updated,
        findingIDs,
        summary: parsed.summary,
      }
    })
  }
}
