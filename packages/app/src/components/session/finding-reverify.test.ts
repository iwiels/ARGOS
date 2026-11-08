import { describe, expect, test } from "bun:test"
import { buildReverifyPrompt } from "./finding-reverify"
import type { Finding } from "./findings-data"

/** Traductor de prueba: interpola igual que el real, sin depender del catálogo. */
const t = (key: string, params?: Record<string, string | number>) => {
  const rendered = params
    ? Object.entries(params).reduce((acc, [name, value]) => acc.replaceAll(`{{${name}}}`, String(value)), key)
    : key
  return params ? `${rendered} ${JSON.stringify(params)}` : rendered
}

const base: Finding = {
  id: "finding-abc",
  session: "ses_1",
  title: "Credenciales PostgreSQL hardcodeadas",
  severity: "high",
  source: "db",
}

describe("buildReverifyPrompt", () => {
  test("incluye el id del hallazgo para que el agente pueda cerrar el ciclo", () => {
    const prompt = buildReverifyPrompt(base, t)
    expect(prompt).toContain("finding-abc")
    expect(prompt).toContain("findings.reverify.task")
    expect(prompt).toContain("findings.reverify.honesty")
  })

  test("omite las líneas de los campos ausentes en vez de renderizarlas vacías", () => {
    const prompt = buildReverifyPrompt(base, t)
    expect(prompt).not.toContain("findings.copy.vector")
    expect(prompt).not.toContain("findings.copy.cwe")
    expect(prompt).not.toContain("findings.reverify.target")
    expect(prompt).not.toContain("findings.reverify.evidenceLabel")
  })

  test("incluye los campos de contexto cuando están presentes", () => {
    const prompt = buildReverifyPrompt(
      {
        ...base,
        vector: "txts/JSON with DB.txt",
        cwe: "CWE-798",
        target: "github.com/ejemplo/repo",
        agent: "security-code",
        status: "in-progress",
        evidence: "const char* conninfo = ...",
      },
      t,
    )
    expect(prompt).toContain("txts/JSON with DB.txt")
    expect(prompt).toContain("CWE-798")
    expect(prompt).toContain("github.com/ejemplo/repo")
    expect(prompt).toContain("security-code")
    expect(prompt).toContain("in-progress")
    expect(prompt).toContain("const char* conninfo")
  })

  test("trunca evidencias enormes para no inundar el prompt", () => {
    const prompt = buildReverifyPrompt({ ...base, evidence: "A".repeat(5000) }, t)
    expect(prompt).toContain("…")
    expect(prompt.length).toBeLessThan(3000)
  })

  test("usa la severidad cruda cuando el hallazgo la trae", () => {
    const prompt = buildReverifyPrompt({ ...base, severityRaw: "ALTO" }, t)
    expect(prompt).toContain("ALTO")
  })
})
