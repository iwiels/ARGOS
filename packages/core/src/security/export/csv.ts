/**
 * Export CSV — una fila por hallazgo, con las columnas que un ticketing
 * necesita para dar de alta los tickets sin volver a tocar el informe.
 *
 * RFC 4180: campos entre comillas cuando contienen coma, comilla doble o
 * salto de línea; la comilla doble interna se escapa duplicándola; las
 * líneas terminan en CRLF.
 */

import type { ReportDocument, ReportFinding } from "./model"

export const CSV_COLUMNS = [
  "id",
  "title",
  "severity",
  "status",
  "feedback_verdict",
  "feedback_reason",
  "feedback_actor",
  "feedback_updated_at",
  "cvss_score",
  "cvss_vector",
  "cwe",
  "owasp",
  "target",
  "source_tool",
  "detected_at",
  "fingerprint",
  "tags",
  "references",
  "session",
  "evidence",
  "remediation",
] as const

function csvField(value: string | number | undefined): string {
  if (value === undefined) return ""
  const text = String(value)
  if (!/[",\r\n]/.test(text)) return text
  return `"${text.replace(/"/g, '""')}"`
}

function row(finding: ReportFinding, sessionID: string): string {
  return [
    finding.id,
    finding.title,
    finding.severity,
    finding.status,
    finding.feedback?.verdict,
    finding.feedback?.reason,
    finding.feedback?.actor,
    finding.feedback?.updatedAt ? new Date(finding.feedback.updatedAt).toISOString() : "",
    finding.cvssScore,
    finding.cvssVector,
    finding.cwe,
    (finding.owasp ?? []).join(" "),
    finding.target,
    finding.sourceTool,
    finding.detectedAt ? new Date(finding.detectedAt).toISOString() : "",
    finding.fingerprint,
    (finding.tags ?? []).join(" "),
    (finding.references ?? []).join(" "),
    sessionID,
    finding.evidence,
    finding.remediation,
  ]
    .map((value) => csvField(value))
    .join(",")
}

export function exportCsv(document: ReportDocument): string {
  const lines = [CSV_COLUMNS.join(","), ...document.findings.map((finding) => row(finding, document.meta.sessionID))]
  return lines.join("\r\n") + "\r\n"
}
