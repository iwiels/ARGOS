/**
 * Export DefectDojo (formato de importación de hallazgos).
 *
 * DefectDojo es el estándar open source de gestión de vulnerabilidades que
 * consume la mayoría de los pipelines de gestión (y es lo que espera el
 * importador `Findings` de una instancia DefectDojo self-hosted).
 *
 * El importador lee los campos con `.get()` y defaults, así que el documento
 * puede llevar campos extra (`hash`, `unique_id_from_tool`) sin romper la
 * importación: son los que permiten reconciliar el hallazgo con el informe
 * firmado que lo originó.
 */

import { reportContentHash, toIsoDate, type ReportDocument, type ReportFinding, type ReportSeverity } from "./model"

export interface DefectDojoFinding {
  title: string
  description: string
  severity: string
  cwe: number
  cve: string
  date: string
  active: boolean
  verified: boolean
  references: string
  tags: string
  endpoints: string[]
  mitigation: string
  impact: string
  hash: string
  unique_id_from_tool: string
  severity_justification: string
}

const SEVERITY_LABEL: Record<ReportSeverity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
}

/** DefectDojo guarda el CWE como entero. `CWE-79` → 79; sin CWE → 0. */
export function cweToInt(cwe: string | undefined): number {
  if (!cwe) return 0
  const match = cwe.match(/(\d{1,6})/)
  if (!match) return 0
  const value = Number.parseInt(match[1], 10)
  return Number.isFinite(value) ? value : 0
}

function escapeMarkdown(value: string): string {
  return value.replace(/([*_`|<>])/g, "\\$1")
}

function describe(finding: ReportFinding, contentHash: string): string {
  const lines: string[] = []
  lines.push(`### ${escapeMarkdown(finding.title)}`)
  lines.push("")
  if (finding.evidence) {
    lines.push("**Evidencia**")
    lines.push("")
    lines.push("```")
    lines.push(finding.evidence)
    lines.push("```")
    lines.push("")
  }
  if (finding.curlCommand) {
    lines.push("**Reproducción (cURL)**")
    lines.push("")
    lines.push("```bash")
    lines.push(finding.curlCommand)
    lines.push("```")
    lines.push("")
  }
  if (finding.httpRequest) {
    lines.push("**Petición HTTP**")
    lines.push("")
    lines.push("```http")
    lines.push(finding.httpRequest)
    lines.push("```")
    lines.push("")
  }
  if (finding.httpResponse) {
    lines.push("**Respuesta HTTP**")
    lines.push("")
    lines.push("```http")
    lines.push(finding.httpResponse)
    lines.push("```")
    lines.push("")
  }
  if (finding.cvssVector) {
    lines.push(`**Vector CVSS v3.1**: \`${finding.cvssVector}\``)
    lines.push("")
  }
  if (finding.attackTechniqueIds?.length) {
    lines.push(`**MITRE ATT&CK**: ${finding.attackTechniqueIds.join(", ")}`)
    lines.push("")
  }
  if (finding.feedback) {
    lines.push(`**Triage Argos**: ${finding.feedback.verdict} (${finding.feedback.actor})`)
    if (finding.feedback.reason) lines.push(`**Motivo del triage**: ${finding.feedback.reason}`)
    lines.push("")
  }
  lines.push(`**Hash del reporte**: \`${contentHash}\``)
  lines.push("")
  return lines.join("\n")
}

export function exportDefectDojo(document: ReportDocument): string {
  const contentHash = reportContentHash(document)
  const findings: DefectDojoFinding[] = document.findings.map((finding) => ({
    title: finding.title,
    description: describe(finding, contentHash),
    severity: SEVERITY_LABEL[finding.severity] ?? "Medium",
    cwe: cweToInt(finding.cwe),
    cve: "",
    date: toIsoDate(finding.detectedAt ? new Date(finding.detectedAt) : document.meta.generatedAt),
    active:
      finding.status !== "remediated" &&
      finding.status !== "false-positive" &&
      finding.feedback?.verdict !== "false-positive",
    verified: finding.status === "verified" || finding.status === "remediated",
    references: (finding.references ?? []).join(" "),
    tags: [...(finding.tags ?? []), finding.cwe, finding.sourceTool].filter(Boolean).join(","),
    endpoints: finding.target ? [finding.target] : [],
    mitigation: finding.remediation ?? "",
    impact: "",
    hash: contentHash,
    unique_id_from_tool: finding.id,
    severity_justification: `CVSS ${finding.cvssScore ?? "n/a"} — severidad declarada: ${finding.severity}`,
  }))

  return JSON.stringify(findings, null, 2)
}
