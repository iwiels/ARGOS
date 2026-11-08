import { describe, expect, test } from "bun:test"
import { buildReportPrompt } from "./report-request"

/**
 * Traductor de prueba: devuelve la clave y adjunta los parámetros, para poder
 * afirmar sobre los valores interpolados sin acoplar el test al catálogo real.
 */
const t = (key: string, params?: Record<string, string | number>) =>
  params ? `${key} ${JSON.stringify(params)}` : key

const base = { missing: [], findingsCount: 12, criticalCount: 2, highCount: 3 }

describe("buildReportPrompt", () => {
  test("incluye las métricas medidas para que el agente no las invente", () => {
    const prompt = buildReportPrompt(base, t)
    expect(prompt).toContain("12")
    expect(prompt).toContain("2")
    expect(prompt).toContain("3")
    expect(prompt).toContain("report.prompt.steps")
  })

  test("pide preguntar por los datos faltantes en vez de asumirlos", () => {
    const prompt = buildReportPrompt({ ...base, missing: ["Auditor líder", "Razón social"] }, t)
    expect(prompt).toContain("Auditor líder, Razón social")
    expect(prompt).toContain("report.prompt.missing")
    expect(prompt).not.toContain("report.prompt.metaComplete")
  })

  test("cambia el mensaje cuando ya no falta nada", () => {
    const prompt = buildReportPrompt(base, t)
    expect(prompt).toContain("report.prompt.metaComplete")
    expect(prompt).not.toContain("report.prompt.missing")
  })

  test("incluye el objetivo solo cuando se conoce", () => {
    expect(buildReportPrompt(base, t)).not.toContain("report.prompt.target")
    expect(buildReportPrompt({ ...base, target: "example.com" }, t)).toContain("example.com")
  })

  test("siempre incluye la regla de honestidad sobre lo no verificado", () => {
    expect(buildReportPrompt(base, t)).toContain("report.prompt.honesty")
    expect(buildReportPrompt({ ...base, missing: ["Auditor líder"] }, t)).toContain("report.prompt.honesty")
  })
})
