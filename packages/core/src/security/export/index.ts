/**
 * Punto de entrada único de los exportadores de auditoría.
 *
 * Un solo `exportAll(sessionID, format, opts)` para todos los formatos: el
 * que consume la UI, el que consume el CLI y el que usan los tests. Cada
 * formato vive en su propio módulo (`sarif.ts`, `defectdojo.ts`, `junit.ts`,
 * `html.ts`, `sbom.ts`, `har.ts`, `csv.ts`, `markdown.ts`) y el PDF vive en
 * `packages/core/src/security/pdf.ts` porque necesita su propio writer.
 */

import { and, eq, inArray } from "drizzle-orm"
import { Effect } from "effect"
import { createHash } from "node:crypto"
import { Database } from "../../database/database"
import { renderReportPdf, type PdfRenderer } from "../pdf"
import { SessionSchema } from "../../session/schema"
import { feedbackByFindingID, feedbackForSessions } from "../finding-feedback"
import { FindingTable } from "../sql"
import { trustedFindingSourceCondition } from "../finding-provenance"
import { listTrafficExchanges } from "../traffic"
import { exportCsv } from "./csv"
import { exportDefectDojo } from "./defectdojo"
import { exportHar, harExchangesFromTraffic, type HarExchange } from "./har"
import { exportHtml } from "./html"
import { exportJunit } from "./junit"
import { buildReport, reportContentHash, reportFindingFromRow, type ReportDocument, type ReportMeta } from "./model"
import { exportMarkdown } from "./markdown"
import { exportSarif } from "./sarif"
import { exportSbom } from "./sbom"
import { DocxExporter } from "./docx"
import { AuditSnapshotService } from "./snapshot"
export { redactSecrets, redactReportDocument } from "./redact"

export const EXPORT_FORMATS = ["pdf", "sarif", "defectdojo", "junit", "html", "sbom", "har", "csv", "markdown", "docx", "snapshot"] as const

export type ExportFormat = (typeof EXPORT_FORMATS)[number]

export interface ExportFormatSpec {
  format: ExportFormat
  extension: string
  mimeType: string
  label: string
}

export const EXPORT_FORMAT_SPECS: Record<ExportFormat, ExportFormatSpec> = {
  pdf: { format: "pdf", extension: "pdf", mimeType: "application/pdf", label: "PDF" },
  sarif: { format: "sarif", extension: "sarif", mimeType: "application/sarif+json", label: "SARIF 2.1.0" },
  defectdojo: { format: "defectdojo", extension: "json", mimeType: "application/json", label: "DefectDojo" },
  junit: { format: "junit", extension: "xml", mimeType: "application/xml", label: "JUnit XML" },
  html: { format: "html", extension: "html", mimeType: "text/html;charset=utf-8", label: "HTML" },
  sbom: { format: "sbom", extension: "cdx.json", mimeType: "application/json", label: "CycloneDX SBOM" },
  har: { format: "har", extension: "har", mimeType: "application/json", label: "HAR" },
  csv: { format: "csv", extension: "csv", mimeType: "text/csv;charset=utf-8", label: "CSV" },
  markdown: { format: "markdown", extension: "md", mimeType: "text/markdown;charset=utf-8", label: "Markdown" },
  docx: {
    format: "docx",
    extension: "docx",
    mimeType: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    label: "Word (DOCX)",
  },
  snapshot: {
    format: "snapshot",
    extension: "json",
    mimeType: "application/json",
    label: "Canonical JSON Snapshot",
  },
}

export function isExportFormat(value: unknown): value is ExportFormat {
  return typeof value === "string" && (EXPORT_FORMATS as readonly string[]).includes(value)
}

/** Metadatos por defecto del entregable. La app los pisa con los valores que
 * el usuario guardó por workspace —esta capa sólo cubre el caso CLI. */
export const DEFAULT_REPORT_META: Omit<ReportMeta, "generatedAt"> = {
  title: "Informe Ejecutivo de Auditoría de Seguridad",
  clientName: "Argos Security Operations",
  scope: "Superficie de Ataque Evaluada",
  classification: "CONFIDENCIAL — TLP:AMBER",
  leadAuditor: "Argos AI Cybersecurity Engine",
  methodology: "OWASP Testing Guide v4.2 / PTES / NIST SP 800-115 / OSSTMM 3",
  sessionID: "",
  engine: "argos-security-operations",
  engineVersion: "1.0.0",
}

export interface ExportOptions {
  /** Metadata del cliente y del engagement (la resuelve la capa que la posee). */
  meta?: Partial<ReportMeta>
  /** Momento de emisión — inyectado para que el artefacto sea determinista. */
  now?: Date
  /** Renderer del PDF (inyectable para testear el resto del pipeline). */
  renderer?: PdfRenderer
  /** Exchanges de red para el HAR; si no se pasan, se derivan de la evidencia. */
  exchanges?: HarExchange[]
}

export interface ExportArtifact {
  format: ExportFormat
  filename: string
  mimeType: string
  /** Contenido textual del export (formatos de texto). */
  text?: string
  /** Contenido binario del export (PDF). */
  bytes?: Uint8Array
  /** sha256 del artefacto generado. */
  sha256: string
  /** sha256 del contenido del informe (independiente del formato). */
  contentHash: string
}

export function reportFilename(document: ReportDocument, format: ExportFormat, now: Date): string {
  const spec = EXPORT_FORMAT_SPECS[format]
  const stamp = now.toISOString().slice(0, 10)
  const session = document.meta.sessionID ? `-${document.meta.sessionID}` : ""
  return `argos-report${session}-${stamp}.${spec.extension}`
}

export function resolveReportMeta(meta: Partial<ReportMeta> | undefined, now: Date, sessionID: string): ReportMeta {
  return {
    ...DEFAULT_REPORT_META,
    ...meta,
    sessionID: meta?.sessionID ?? sessionID,
    generatedAt: meta?.generatedAt ?? now,
  }
}

/** Exporta un informe ya construido. Es la vía pura: no toca la base de datos. */
export async function exportDocument(
  document: ReportDocument,
  format: ExportFormat,
  opts?: ExportOptions,
): Promise<ExportArtifact> {
  const spec = EXPORT_FORMAT_SPECS[format]
  const contentHash = reportContentHash(document)
  const now = document.meta.generatedAt
  const filename = reportFilename(document, format, now)

  if (format === "pdf") {
    const artifact = await renderReportPdf(document, { renderer: opts?.renderer })
    return {
      format,
      filename,
      mimeType: spec.mimeType,
      bytes: artifact.bytes,
      sha256: artifact.sha256,
      contentHash: artifact.contentHash,
    }
  }

  const text =
    format === "sarif"
      ? exportSarif(document)
      : format === "defectdojo"
        ? exportDefectDojo(document)
        : format === "junit"
          ? exportJunit(document)
          : format === "html"
            ? exportHtml(document)
            : format === "sbom"
              ? exportSbom(document)
              : format === "har"
                ? exportHar(document, opts?.exchanges)
                : format === "csv"
                  ? exportCsv(document)
                  : format === "docx"
                    ? DocxExporter.exportDocxXml(document)
                    : format === "snapshot"
                      ? JSON.stringify(AuditSnapshotService.createSnapshot(document), null, 2)
                      : exportMarkdown(document)

  return {
    format,
    filename,
    mimeType: spec.mimeType,
    text,
    sha256: sha256OfText(text),
    contentHash,
  }
}

function sha256OfText(text: string): string {
  return createHash("sha256").update(text).digest("hex")
}

/**
 * Carga los hallazgos persistidos de una sesión (o de un conjunto de sesiones
 * del mismo workspace) y arma el informe.
 * Es la mitad "de datos" de `exportAll`, separada para que el PDF pueda
 * reutilizarla sin pasar por el registro de formatos.
 */
export const loadReportDocument = Effect.fn("Security.loadReportDocument")(function* (
  sessionIDs: string | string[],
  opts?: ExportOptions,
) {
  const { db } = yield* Database.Service
  const ids = (typeof sessionIDs === "string" ? [sessionIDs] : sessionIDs).filter(Boolean)
  const rows = yield* db
    .select()
    .from(FindingTable)
    .where(and(ids.length > 1 ? inArray(FindingTable.session_id, ids) : eq(FindingTable.session_id, ids[0] ?? ""), trustedFindingSourceCondition()))
    .all()
    .pipe(Effect.orDie)
  const feedback = feedbackByFindingID(yield* feedbackForSessions(db, ids))

  const now = opts?.now ?? new Date()
  const findings = rows.map((row) => reportFindingFromRow(row, feedback.get(row.id)))
  const target = opts?.meta?.target ?? findings.find((finding) => finding.target)?.target
  const meta = resolveReportMeta(
    { ...opts?.meta, target },
    now,
    typeof sessionIDs === "string" ? sessionIDs : (ids[0] ?? ""),
  )
  return buildReport({ meta, findings })
})

/**
 * Exporta la auditoría de una sesión. Lee los hallazgos persistidos y produce
 * el artefacto del formato pedido.
 */
export const exportAll = Effect.fn("Security.exportAll")(function* (
  sessionID: string,
  format: ExportFormat,
  opts?: ExportOptions,
) {
  const { db } = yield* Database.Service
  const document = yield* loadReportDocument(sessionID, opts)
  // El HAR sale del store de traffic (la captura real del binario); si la
  // sesión no tiene exchanges se cae a la evidencia HTTP de los hallazgos.
  const exchanges =
    opts?.exchanges ??
    (format === "har"
      ? harExchangesFromTraffic(
          (yield* listTrafficExchanges(db, { sessionID: SessionSchema.ID.make(sessionID), filter: { limit: 500 } }))
            .data,
        )
      : undefined)
  return yield* Effect.promise(() =>
    exportDocument(document, format, { ...opts, now: opts?.now ?? document.meta.generatedAt, exchanges }),
  )
})

/**
 * Exporta la auditoría de varias sesiones del mismo workspace (el informe
 * consolidado que ve el usuario en la página de reportes).
 */
export const exportSessions = Effect.fn("Security.exportSessions")(function* (
  sessionIDs: string[],
  format: ExportFormat,
  opts?: ExportOptions,
) {
  const { db } = yield* Database.Service
  const document = yield* loadReportDocument(sessionIDs, opts)
  const exchanges =
    opts?.exchanges ??
    (format === "har"
      ? harExchangesFromTraffic(
          (yield* Effect.forEach(sessionIDs, (sessionID) =>
            listTrafficExchanges(db, { sessionID: SessionSchema.ID.make(sessionID), filter: { limit: 500 } }),
          )).flatMap((result) => result.data),
        )
      : undefined)
  return yield* Effect.promise(() =>
    exportDocument(document, format, { ...opts, now: opts?.now ?? document.meta.generatedAt, exchanges }),
  )
})

export * from "./model"
export * from "./csv"
export * from "./defectdojo"
export * from "./har"
export * from "./html"
export * from "./junit"
export * from "./markdown"
export * from "./sarif"
export * from "./sbom"
export * from "./docx"
export * from "./snapshot"
