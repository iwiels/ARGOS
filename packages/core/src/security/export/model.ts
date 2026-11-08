/**
 * Modelo canónico del informe de auditoría.
 *
 * Es la única fuente de verdad que consumen todos los exportadores (SARIF,
 * DefectDojo, JUnit, HTML, SBOM, HAR, CSV, Markdown) y el generador de PDF.
 * Vive en el core —y no en la app— porque el render de los entregables es
 * server-side: el PDF y los formatos de ingestión tienen que salir de los
 * hallazgos persistidos, no de lo que el navegador tiene en memoria.
 *
 * La metadata del cliente (razón social, logo, auditor, clasificación) no se
 * redefine acá: se recibe ya resuelta desde la capa que la posee (la app la
 * persiste por workspace) y se propaga tal cual.
 */

import { createHash } from "node:crypto"
import { SEVERITIES, type Severity } from "../contract"
import { generateCurlCommand } from "../poc"
import { fromFindingRow, type SarifDataflowStep, type SarifSuppression } from "../sarif"
import {
  normalizeActor,
  normalizeReason,
  normalizeVerdict,
  type FeedbackActor,
  type FeedbackRow,
  type FeedbackVerdict,
} from "../finding-feedback"
import type { FindingTable } from "../sql"

export type ReportSeverity = Severity

export const REPORT_SEVERITIES = SEVERITIES

export interface ReportFinding {
  id: string
  title: string
  severity: ReportSeverity
  status: string
  cwe?: string
  owasp?: string[]
  target?: string
  vector?: string
  evidence?: string
  remediation?: string
  httpRequest?: string
  httpResponse?: string
  curlCommand?: string
  tags?: string[]
  references?: string[]
  attackTechniqueIds?: string[]
  sourceTool?: string
  fingerprint?: string
  cvssScore?: number
  cvssVector?: string
  epssScore?: number
  cisaKev?: boolean
  detectedAt?: number
  dataflow?: SarifDataflowStep[]
  partialFingerprints?: Record<string, string>
  suppressions?: SarifSuppression[]
  feedback?: {
    verdict: FeedbackVerdict
    reason?: string
    actor: FeedbackActor
    updatedAt: number
  }
}

export interface ReportMeta {
  /** Título del entregable. */
  title: string
  /** Nombre corto del cliente / objetivo. */
  clientName: string
  /** Razón social del cliente (dato de portada). */
  clientLegalName?: string
  /** Logo del cliente como data URL (`data:image/png;base64,…`). */
  clientLogoDataUrl?: string
  /** Alcance autorizado de la auditoría. */
  scope: string
  /** Clasificación de confidencialidad (TLP). */
  classification: string
  /** Auditor responsable del informe. */
  leadAuditor: string
  /** Metodología declarada. */
  methodology: string
  /** Sesión de la que salen los hallazgos. */
  sessionID: string
  /** Identificador del engagement (aparece en las keywords del PDF). */
  engagement?: string
  /** Objetivo técnico principal de la auditoría. */
  target?: string
  /** Momento de emisión — inyectado para que el render sea determinista. */
  generatedAt: Date
  engine?: string
  engineVersion?: string
}

export interface ReportTargetSummary {
  url: string
  total: number
  counts: Record<ReportSeverity, number>
}

export interface ReportSummary {
  totalFindings: number
  counts: Record<ReportSeverity, number>
  averageCvss: number
  highestCvss: number
  globalRisk: ReportSeverity | "none"
  targets: ReportTargetSummary[]
  topVulnerabilities: Array<{ title: string; count: number; severity: ReportSeverity; cwe?: string; cvssScore: number }>
}

export interface ReportDocument {
  meta: ReportMeta
  findings: ReportFinding[]
  summary: ReportSummary
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  !!value && typeof value === "object" && !Array.isArray(value)

export function normalizeReportSeverity(value: unknown): ReportSeverity {
  const normalized = typeof value === "string" ? value.trim().toLowerCase() : ""
  if ((REPORT_SEVERITIES as readonly string[]).includes(normalized)) return normalized as ReportSeverity
  if (normalized === "critico" || normalized === "crítico") return "critical"
  if (normalized === "alto") return "high"
  if (normalized === "medio") return "medium"
  if (normalized === "bajo") return "low"
  if (normalized === "informativo" || normalized === "informational") return "info"
  return "medium"
}

/** Lee un string del evidence, aceptando las claves que usa cada productor. */
function pickString(evidence: Record<string, unknown>, keys: string[]): string | undefined {
  for (const key of keys) {
    const value = evidence[key]
    if (typeof value === "string" && value.trim()) return value.trim()
  }
  for (const key of keys) {
    const nested = evidence[key]
    if (!isRecord(nested)) continue
    for (const inner of ["text", "value", "raw", "body", "content"]) {
      const value = nested[inner]
      if (typeof value === "string" && value.trim()) return value.trim()
    }
  }
  return undefined
}

/**
 * El evidence persistido es un record libre: cada tool escribe sus propias
 * claves. Para el informe interesa el texto legible de la evidencia, no el
 * volcado crudo — por eso se prioriza el texto explícito y, si no existe, se
 * serializa el record sin los campos voluminosos (petición/respuesta HTTP ya
 * tienen su propia sección en el informe).
 */
function evidenceText(evidence: Record<string, unknown>): string | undefined {
  const explicit = pickString(evidence, ["text", "description", "summary", "detail", "message", "evidence"])
  if (explicit) return explicit
  const rest: Record<string, unknown> = {}
  for (const [key, value] of Object.entries(evidence)) {
    if (key === "httpRequest" || key === "httpResponse" || key === "curlCommand" || key === "curl") continue
    if (typeof value === "string") rest[key] = value
    else if (typeof value === "number" || typeof value === "boolean") rest[key] = value
    else if (Array.isArray(value) && value.every((item) => typeof item === "string")) rest[key] = value
  }
  if (Object.keys(rest).length === 0) return undefined
  return JSON.stringify(rest, null, 2)
}

/**
 * El curl reproducible del proof of concept.
 *
 * El PoC del hallazgo (la petición que lo reproduce y el matcher con el que
 * se re-verifica) viaja dentro de la evidencia: el informe lo entrega como
 * comando cURL, que es lo que el lector necesita para repetir la prueba.
 */
function pocCurlCommand(value: unknown): string | undefined {
  if (!isRecord(value)) return undefined
  const url = typeof value.url === "string" ? value.url.trim() : ""
  if (!url) return undefined
  const headers = isRecord(value.headers)
    ? Object.fromEntries(
        Object.entries(value.headers).filter((entry): entry is [string, string] => typeof entry[1] === "string"),
      )
    : undefined
  const payload =
    typeof value.payload === "string" && value.payload
      ? value.payload
      : typeof value.body === "string" && value.body
        ? value.body
        : undefined
  return generateCurlCommand({
    target: url,
    method: typeof value.method === "string" ? value.method : undefined,
    payload,
    headers,
  })
}

/** Convierte una fila persistida en el modelo de hallazgo del informe. */
export function reportFindingFromRow(
  row: typeof FindingTable.$inferSelect,
  feedback?: FeedbackRow,
): ReportFinding {
  const sarif = fromFindingRow(row)
  const evidence = isRecord(row.evidence) ? row.evidence : {}
  const verdict = feedback ? normalizeVerdict(feedback.verdict) : undefined
  return {
    id: sarif.id,
    title: sarif.title,
    severity: normalizeReportSeverity(sarif.severity),
    status: sarif.status,
    cwe: sarif.cwe,
    owasp: sarif.owasp,
    target: sarif.target,
    vector: sarif.vector,
    evidence: evidenceText(evidence),
    remediation: sarif.remediation,
    httpRequest: pickString(evidence, ["httpRequest", "request", "raw_request"]),
    httpResponse: pickString(evidence, ["httpResponse", "response", "raw_response"]),
    curlCommand: pickString(evidence, ["curlCommand", "curl", "repro", "reproduction"]) ?? pocCurlCommand(evidence.poc),
    tags: sarif.tags,
    references: sarif.references,
    attackTechniqueIds: sarif.attackTechniqueIds,
    sourceTool: sarif.sourceTool,
    fingerprint: sarif.fingerprint,
    cvssScore: sarif.cvssScore,
    cvssVector: sarif.cvssVector,
    epssScore: sarif.epssScore,
    cisaKev: sarif.cisaKev,
    detectedAt: row.time_created,
    dataflow: sarif.dataflow,
    partialFingerprints: sarif.partialFingerprints,
    suppressions: sarif.suppressions,
    feedback: feedback && verdict
      ? {
          verdict,
          reason: normalizeReason(feedback.reason),
          actor: normalizeActor(feedback.actor),
          updatedAt: feedback.time_updated,
        }
      : undefined,
  }
}

function emptyCounts(): Record<ReportSeverity, number> {
  return { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
}

function summarize(findings: ReportFinding[]): ReportSummary {
  const activeFindings = findings.filter((finding) => finding.status !== "false-positive" && finding.feedback?.verdict !== "false-positive")
  const counts = emptyCounts()
  for (const finding of activeFindings) counts[finding.severity]++

  let weighted = 0
  let scored = 0
  let highest = 0
  for (const finding of activeFindings) {
    if (typeof finding.cvssScore === "number") {
      weighted += finding.cvssScore
      scored++
      if (finding.cvssScore > highest) highest = finding.cvssScore
    }
  }

  const targetMap = new Map<string, ReportTargetSummary>()
  const vulnMap = new Map<
    string,
    { title: string; count: number; severity: ReportSeverity; cwe?: string; cvssScore: number }
  >()
  for (const finding of activeFindings) {
    const url = (finding.target ?? finding.vector ?? "objetivo local").trim() || "objetivo local"
    const entry = targetMap.get(url) ?? { url, total: 0, counts: emptyCounts() }
    entry.total++
    entry.counts[finding.severity]++
    targetMap.set(url, entry)

    const vuln = vulnMap.get(finding.title) ?? {
      title: finding.title,
      count: 0,
      severity: finding.severity,
      cwe: finding.cwe,
      cvssScore: finding.cvssScore ?? 0,
    }
    vuln.count++
    if (severityWeight(finding.severity) < severityWeight(vuln.severity)) vuln.severity = finding.severity
    vuln.cvssScore = Math.max(vuln.cvssScore, finding.cvssScore ?? 0)
    vulnMap.set(finding.title, vuln)
  }

  const globalRisk: ReportSummary["globalRisk"] =
    counts.critical > 0
      ? "critical"
      : counts.high > 0
        ? "high"
        : counts.medium > 0
          ? "medium"
          : counts.low > 0
            ? "low"
            : counts.info > 0
              ? "info"
              : "none"

  return {
    totalFindings: activeFindings.length,
    counts,
    averageCvss: scored > 0 ? Math.round((weighted / scored) * 10) / 10 : 0,
    highestCvss: Math.round(highest * 10) / 10,
    globalRisk,
    targets: [...targetMap.values()].sort((a, b) => b.total - a.total),
    topVulnerabilities: [...vulnMap.values()]
      .sort((a, b) => severityWeight(a.severity) - severityWeight(b.severity) || b.cvssScore - a.cvssScore)
      .slice(0, 10),
  }
}

const SEVERITY_WEIGHT: Record<ReportSeverity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }

export function severityWeight(severity: ReportSeverity): number {
  return SEVERITY_WEIGHT[severity] ?? 5
}

export function buildReport(input: { meta: ReportMeta; findings: ReportFinding[] }): ReportDocument {
  const findings = [...input.findings].sort(
    (a, b) => severityWeight(a.severity) - severityWeight(b.severity) || a.title.localeCompare(b.title),
  )
  return { meta: input.meta, findings, summary: summarize(findings) }
}

/**
 * Serialización canónica del contenido del informe. Es la entrada del hash
 * que se imprime en la portada y en el pie: dos informes con el mismo
 * contenido producen el mismo hash, sin importar el momento de emisión.
 * El timestamp queda fuera a propósito — se declara como metadata del PDF.
 */
export function canonicalReportContent(document: ReportDocument): string {
  return JSON.stringify({
    meta: {
      title: document.meta.title,
      clientName: document.meta.clientName,
      clientLegalName: document.meta.clientLegalName ?? null,
      scope: document.meta.scope,
      classification: document.meta.classification,
      leadAuditor: document.meta.leadAuditor,
      methodology: document.meta.methodology,
      sessionID: document.meta.sessionID,
      engagement: document.meta.engagement ?? null,
      target: document.meta.target ?? null,
    },
    findings: document.findings.map((finding) => ({
      id: finding.id,
      title: finding.title,
      severity: finding.severity,
      status: finding.status,
      cwe: finding.cwe ?? null,
      owasp: finding.owasp ?? null,
      target: finding.target ?? null,
      vector: finding.vector ?? null,
      evidence: finding.evidence ?? null,
      remediation: finding.remediation ?? null,
      httpRequest: finding.httpRequest ?? null,
      httpResponse: finding.httpResponse ?? null,
      curlCommand: finding.curlCommand ?? null,
      tags: finding.tags ?? null,
      references: finding.references ?? null,
      attackTechniqueIds: finding.attackTechniqueIds ?? null,
      sourceTool: finding.sourceTool ?? null,
      fingerprint: finding.fingerprint ?? null,
      cvssScore: finding.cvssScore ?? null,
      cvssVector: finding.cvssVector ?? null,
      epssScore: finding.epssScore ?? null,
      cisaKev: finding.cisaKev ?? null,
      feedback: finding.feedback ?? null,
    })),
  })
}

export function sha256Hex(input: string | Uint8Array): string {
  return createHash("sha256").update(input).digest("hex")
}

/** `YYYY-MM-DD` en UTC — formato que espera DefectDojo para `date`. */
export function toIsoDate(value: Date): string {
  return value.toISOString().slice(0, 10)
}

/** `YYYY-MM-DDTHH:MM:SSZ` en UTC — timestamp ISO 8601 (CycloneDX / HAR). */
export function toIsoDateTime(value: Date): string {
  return value.toISOString().replace(/\.\d{3}Z$/, "Z")
}

/** `D:YYYYMMDDHHmmSSZ` — fecha de creación del PDF. */
export function toPdfDate(value: Date): string {
  const iso = value.toISOString()
  return `D:${iso.slice(0, 4)}${iso.slice(5, 7)}${iso.slice(8, 10)}${iso.slice(11, 13)}${iso.slice(14, 16)}${iso.slice(17, 19)}Z`
}

/** Hash del contenido del informe (independiente del timestamp de emisión). */
export function reportContentHash(document: ReportDocument): string {
  return sha256Hex(canonicalReportContent(document))
}
