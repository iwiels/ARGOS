import type { ReportDocument, ReportFinding } from "./model"
import { redactReportDocument } from "./redact"

function escapeXml(unsafe: string | undefined | null): string {
  if (!unsafe) return ""
  return unsafe
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;")
}

export class DocxExporter {
  /**
   * Genera un informe WordprocessingML compatible con Microsoft Word y LibreOffice (Etapa 4).
   */
  static exportDocxXml(rawDoc: ReportDocument): string {
    const doc = redactReportDocument(rawDoc)
    const meta = doc.meta
    const summary = doc.summary
    const findings = doc.findings

    const paragraphs: string[] = []

    // Helper para párrafo de texto
    const p = (text: string, bold = false, size = 22, color = "000000") => {
      const bTag = bold ? "<w:b/>" : ""
      const colorTag = `<w:color w:val="${color}"/>`
      const szTag = `<w:sz w:val="${size}"/>`
      return `<w:p><w:r><w:rPr>${bTag}${colorTag}${szTag}</w:rPr><w:t xml:space="preserve">${escapeXml(text)}</w:t></w:r></w:p>`
    }

    // Título y Portada
    paragraphs.push(p(meta.title, true, 36, "0F172A"))
    paragraphs.push(p(`Cliente: ${meta.clientName}`, true, 24, "334155"))
    if (meta.target) {
      paragraphs.push(p(`Objetivo: ${meta.target}`, false, 22, "475569"))
    }
    paragraphs.push(p(`Auditor Líder: ${meta.leadAuditor} | Clasificación: ${meta.classification}`, false, 20, "64748B"))
    paragraphs.push(p(`Fecha de Emisión: ${meta.generatedAt.toISOString().slice(0, 10)}`, false, 20, "64748B"))
    paragraphs.push(p("", false, 20))

    // Resumen Ejecutivo
    paragraphs.push(p("1. RESUMEN EJECUTIVO", true, 28, "0284C7"))
    paragraphs.push(
      p(
        `Durante la evaluación de seguridad se identificaron un total de ${summary.totalFindings} vulnerabilidades. ` +
          `Nivel de riesgo global: ${summary.globalRisk.toUpperCase()}.`,
        false,
        22,
      ),
    )
    paragraphs.push(
      p(
        `Desglose por severidad: ` +
          `Crítico: ${summary.counts.critical} | ` +
          `Alto: ${summary.counts.high} | ` +
          `Medio: ${summary.counts.medium} | ` +
          `Bajo: ${summary.counts.low} | ` +
          `Informativo: ${summary.counts.info}`,
        true,
        22,
        "1E293B",
      ),
    )
    paragraphs.push(p("", false, 20))

    // Detalle de Vulnerabilidades
    paragraphs.push(p("2. DETALLE DE HALLAZGOS", true, 28, "0284C7"))

    if (findings.length === 0) {
      paragraphs.push(p("No se detectaron vulnerabilidades activas durante la auditoría.", false, 22, "16A34A"))
    } else {
      for (const [idx, finding] of findings.entries()) {
        const severityColor =
          finding.severity === "critical"
            ? "DC2626"
            : finding.severity === "high"
              ? "EA580C"
              : finding.severity === "medium"
                ? "D97706"
                : "2563EB"

        paragraphs.push(p(`${idx + 1}. [${finding.severity.toUpperCase()}] ${finding.title}`, true, 24, severityColor))
        paragraphs.push(p(`Objetivo: ${finding.target || "N/A"} | Vector: ${finding.vector || "N/A"}`, false, 20, "475569"))
        paragraphs.push(p(`Estado: ${finding.status}`, false, 20, "475569"))
        if (finding.feedback) {
          paragraphs.push(p(`Triage: ${finding.feedback.verdict} (${finding.feedback.actor})`, false, 20, "475569"))
          if (finding.feedback.reason) paragraphs.push(p(`Motivo del triage: ${finding.feedback.reason}`, false, 20, "475569"))
        }
        if (finding.cwe) {
          paragraphs.push(p(`Taxonomía: ${finding.cwe}`, false, 20, "475569"))
        }
        if (finding.evidence) {
          paragraphs.push(p("Evidencia Técnica:", true, 20, "334155"))
          paragraphs.push(p(finding.evidence, false, 18, "64748B"))
        }
        if (finding.remediation) {
          paragraphs.push(p("Remediación Recomendada:", true, 20, "15803D"))
          paragraphs.push(p(finding.remediation, false, 20, "334155"))
        }
        paragraphs.push(p("", false, 16))
      }
    }

    return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>
    ${paragraphs.join("\n    ")}
  </w:body>
</w:document>`
  }
}
