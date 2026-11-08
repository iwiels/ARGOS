type Translate = (key: string, params?: Record<string, string | number>) => string

export type ReportRequestInput = {
  /** Datos del entregable que el generador no puede deducir y el agente debe preguntar. */
  missing: string[]
  findingsCount: number
  criticalCount: number
  highCount: number
  target?: string
}

/**
 * Arma el mensaje que el botón "Generar reporte" inserta en el chat.
 *
 * Las métricas y tablas ya las produce `report-generator` de forma determinista,
 * así que el pedido al agente se centra en lo que un cálculo no puede resolver:
 * preguntarle al auditor los datos del entregable que faltan (con la tool
 * `question`, no inventándolos) y redactar el informe extenso correlacionando
 * hallazgos con cumplimiento.
 */
export function buildReportPrompt(input: ReportRequestInput, t: Translate): string {
  const lines: string[] = [
    t("report.prompt.intro"),
    "",
    t("report.prompt.context", {
      findings: input.findingsCount,
      critical: input.criticalCount,
      high: input.highCount,
    }),
  ]

  if (input.target) lines.push(t("report.prompt.target", { value: input.target }))

  lines.push("", t("report.prompt.steps"))

  if (input.missing.length > 0) {
    lines.push("", t("report.prompt.missing", { fields: input.missing.join(", ") }))
  } else {
    lines.push("", t("report.prompt.metaComplete"))
  }

  lines.push("", t("report.prompt.honesty"))

  return lines.join("\n")
}
