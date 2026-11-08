/**
 * Export Markdown — el informe en texto plano, para el cliente que lo quiere
 * en un wiki, un ticket o un repositorio.
 *
 * El front-matter lleva los metadatos de emisión (clasificación, cliente,
 * fecha) y el hash del contenido, que es lo que permite verificar que el
 * texto entregado es el mismo que firmó el auditor.
 */

import { reportContentHash, toIsoDateTime, type ReportDocument, type ReportFinding } from "./model"

function escapeCell(value: string): string {
  return value.replace(/\|/g, "\\|").replace(/\r?\n/g, " ")
}

function findingSection(finding: ReportFinding, index: number): string[] {
  const lines: string[] = []
  lines.push(`### ${index}. ${finding.title}`)
  lines.push("")
  lines.push(`- **ID:** \`${finding.id}\``)
  lines.push(`- **Severidad:** \`${finding.severity.toUpperCase()}\``)
  if (finding.cvssScore !== undefined) {
    lines.push(`- **CVSS v3.1:** ${finding.cvssScore}${finding.cvssVector ? ` — \`${finding.cvssVector}\`` : ""}`)
  }
  if (finding.cwe) lines.push(`- **CWE:** \`${finding.cwe}\``)
  if (finding.owasp?.length) lines.push(`- **OWASP:** ${finding.owasp.join(", ")}`)
  if (finding.target) lines.push(`- **Objetivo:** \`${finding.target}\``)
  lines.push(`- **Estado:** \`${finding.status}\``)
  if (finding.feedback) {
    lines.push(`- **Triage:** \`${finding.feedback.verdict}\` (${finding.feedback.actor})`)
    if (finding.feedback.reason) lines.push(`- **Motivo del triage:** ${escapeCell(finding.feedback.reason)}`)
  }
  if (finding.sourceTool) lines.push(`- **Origen:** \`${finding.sourceTool}\``)
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
  if (finding.remediation) {
    lines.push("**Remediación**")
    lines.push("")
    lines.push(finding.remediation)
    lines.push("")
  }
  return lines
}

export function exportMarkdown(document: ReportDocument): string {
  const { meta, summary, findings } = document
  const contentHash = reportContentHash(document)
  const lines: string[] = []

  lines.push("---")
  lines.push(`classification: "${meta.classification}"`)
  if (meta.clientLegalName) lines.push(`razon_social: "${meta.clientLegalName}"`)
  lines.push(`session: "${meta.sessionID}"`)
  lines.push(`generated_at: "${toIsoDateTime(meta.generatedAt)}"`)
  lines.push(`content_sha256: "${contentHash}"`)
  lines.push("---")
  lines.push("")
  lines.push(`# ${meta.title}`)
  lines.push("")
  lines.push(`> **CLASIFICACIÓN:** \`${meta.classification}\``)
  lines.push(`> **CLIENTE:** ${meta.clientName}${meta.clientLegalName ? ` (${meta.clientLegalName})` : ""}`)
  lines.push(`> **ALCANCE AUTORIZADO:** ${meta.scope}`)
  lines.push(`> **AUDITOR RESPONSABLE:** ${meta.leadAuditor}`)
  lines.push(`> **METODOLOGÍA:** ${meta.methodology}`)
  lines.push(`> **FECHA DE EMISIÓN:** ${toIsoDateTime(meta.generatedAt)}`)
  lines.push(`> **HASH DEL CONTENIDO:** \`${contentHash}\``)
  lines.push("")
  lines.push("---")
  lines.push("")

  lines.push("## 1. Resumen ejecutivo")
  lines.push("")
  lines.push(`- **Hallazgos totales:** ${summary.totalFindings}`)
  lines.push(
    `- **Críticos / Altos / Medios / Bajos / Info:** ${summary.counts.critical} / ${summary.counts.high} / ${summary.counts.medium} / ${summary.counts.low} / ${summary.counts.info}`,
  )
  lines.push(`- **Riesgo global:** ${summary.globalRisk.toUpperCase()}`)
  lines.push(`- **CVSS v3.1 promedio:** ${summary.averageCvss}`)
  lines.push(`- **CVSS v3.1 máximo:** ${summary.highestCvss}`)
  lines.push("")

  lines.push("## 2. Objetivos evaluados")
  lines.push("")
  lines.push("| Objetivo | Total | Críticos | Altos | Medios | Bajos | Info |")
  lines.push("| :--- | ---: | ---: | ---: | ---: | ---: | ---: |")
  for (const target of summary.targets) {
    lines.push(
      `| \`${escapeCell(target.url)}\` | ${target.total} | ${target.counts.critical} | ${target.counts.high} | ${target.counts.medium} | ${target.counts.low} | ${target.counts.info} |`,
    )
  }
  lines.push("")

  lines.push("## 3. Matriz consolidada de hallazgos")
  lines.push("")
  lines.push("| ID | Severidad | CVSS | CWE | Título | Objetivo | Estado |")
  lines.push("| :--- | :---: | ---: | :--- | :--- | :--- | :--- |")
  for (const finding of findings) {
    lines.push(
      `| \`${finding.id}\` | **${finding.severity.toUpperCase()}** | ${finding.cvssScore ?? "-"} | ${finding.cwe ?? "-"} | ${escapeCell(finding.title)} | \`${escapeCell(finding.target ?? "-")}\` | \`${finding.status}\` |`,
    )
  }
  lines.push("")

  lines.push("## 4. Detalle técnico de vulnerabilidades")
  lines.push("")
  if (findings.length === 0) {
    lines.push("_No se identificaron hallazgos en esta auditoría._")
    lines.push("")
  }
  findings.forEach((finding, index) => {
    lines.push(...findingSection(finding, index + 1))
    lines.push("---")
    lines.push("")
  })

  lines.push("## 5. Control de emisión y aprobaciones")
  lines.push("")
  lines.push("| Rol | Nombre / Entidad | Fecha | Firma / Sello |")
  lines.push("| :--- | :--- | :--- | :--- |")
  lines.push(
    `| **Auditor responsable** | ${meta.leadAuditor} | ${toIsoDateTime(meta.generatedAt)} | \`[VERIFICADO - AI CORE]\` |`,
  )
  lines.push(`| **Receptor de seguridad** | ${meta.clientName} | | |`)
  if (meta.clientLegalName) lines.push(`| **Razón social del receptor** | ${meta.clientLegalName} | | |`)
  lines.push("")

  return lines.join("\n")
}
