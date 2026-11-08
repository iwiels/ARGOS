import { describe, expect, test } from "bun:test"
import {
  CONFIDENCES,
  CONTRACT_WIRE_FIELDS,
  MAX_AGENT_CHARS,
  MAX_CWE_CHARS,
  MAX_EVIDENCE_CHARS,
  MAX_ID_CHARS,
  MAX_OWASP_ITEMS,
  MAX_RAW_CHARS,
  MAX_REFERENCE_CHARS,
  MAX_REFERENCES,
  MAX_REMEDIATION_CHARS,
  MAX_RULE_ID_CHARS,
  MAX_SOURCE_TOOL_CHARS,
  MAX_TAG_CHARS,
  MAX_TAGS,
  MAX_TARGET_CHARS,
  MAX_TITLE_CHARS,
  MAX_VECTOR_CHARS,
  SEVERITIES,
  contractToDbRow,
  normalizeContract,
  normalizeContractConfidence,
  normalizeContractCwe,
  normalizeContractSeverity,
  type Severity,
} from "@argos/core/security/contract"

describe("canonical vocabularies", () => {
  test("severities are the closed set the backend stores", () => {
    expect(SEVERITIES).toEqual(["critical", "high", "medium", "low", "info"])
  })
  test("confidences are the closed set the backend stores", () => {
    expect(CONFIDENCES).toEqual(["confirmed", "probable", "possible"])
  })
})

describe("normalizeContractSeverity", () => {
  const cases: Array<[unknown, Severity]> = [
    ["critical", "critical"],
    ["CRÍTICO", "critical"],
    ["critico", "critical"],
    ["alto", "high"],
    ["ALTA", "high"],
    ["medio", "medium"],
    ["media", "medium"],
    ["moderate", "medium"],
    ["bajo", "low"],
    ["informativo", "info"],
    ["unknown-value", "info"],
    [undefined, "info"],
    [42, "info"],
  ]
  for (const [input, expected] of cases) {
    test(`${JSON.stringify(input)} -> ${expected}`, () => expect(normalizeContractSeverity(input)).toBe(expected))
  }
})

describe("normalizeContractConfidence", () => {
  test("keeps a known confidence", () => expect(normalizeContractConfidence("confirmed")).toBe("confirmed"))
  test("is case-insensitive", () => expect(normalizeContractConfidence(" PROBABLE ")).toBe("probable"))
  test("falls back to possible for anything outside the vocabulary", () => {
    expect(normalizeContractConfidence("maybe")).toBe("possible")
    expect(normalizeContractConfidence(undefined)).toBe("possible")
    expect(normalizeContractConfidence(7)).toBe("possible")
  })
})

describe("normalizeContractCwe", () => {
  test("normalizes the accepted spellings", () => {
    expect(normalizeContractCwe("CWE-89")).toBe("CWE-89")
    expect(normalizeContractCwe("cwe-89")).toBe("CWE-89")
    expect(normalizeContractCwe("CWE 89")).toBe("CWE-89")
    expect(normalizeContractCwe("89")).toBe("CWE-89")
  })
  test("drops values that do not parse", () => {
    expect(normalizeContractCwe("not a cwe")).toBeUndefined()
    expect(normalizeContractCwe("")).toBeUndefined()
    expect(normalizeContractCwe(undefined)).toBeUndefined()
  })
})

describe("normalizeContract", () => {
  test("normalizes a full tool payload", () => {
    const normalized = normalizeContract({
      id: "finding_1",
      source: "web.scan",
      source_tool: "web.sqli",
      rule_id: "nuclei:exposed-env-file",
      title: "  Exposed environment file  ",
      severity: "CRÍTICO",
      confidence: "CONFIRMED",
      cwe: "89",
      owasp: ["A05:2021"],
      target: "https://example.com/.env",
      vector: "id",
      evidence: { template: "exposed-env-file" },
      remediation: "Remove the file",
      cvss: { AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "H", I: "H", A: "H" },
      tags: ["SQLi", " secret-exposure "],
      references: ["https://example.com/advisory"],
    })

    expect(normalized).toEqual({
      id: "finding_1",
      source: "web.scan",
      sourceTool: "web.sqli",
      ruleId: "nuclei:exposed-env-file",
      title: "Exposed environment file",
      severity: "critical",
      confidence: "confirmed",
      cwe: "CWE-89",
      owasp: ["A05:2021"],
      target: "https://example.com/.env",
      vector: "id",
      evidence: { template: "exposed-env-file" },
      remediation: "Remove the file",
      cvss: { AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "H", I: "H", A: "H" },
      tags: ["sqli", "secret-exposure"],
      references: ["https://example.com/advisory"],
    })
  })

  test("defaults a missing severity to info and a missing confidence to possible", () => {
    const normalized = normalizeContract({ title: "Something" })
    expect(normalized.severity).toBe("info")
    expect(normalized.confidence).toBe("possible")
    expect(normalized.evidence).toEqual({})
    expect(normalized.tags).toEqual([])
    expect(normalized.owasp).toEqual([])
    expect(normalized.references).toEqual([])
    expect(normalized.cvss).toBeUndefined()
  })

  test("turns a string evidence into a text object", () => {
    expect(normalizeContract({ evidence: "server said no" }).evidence).toEqual({ text: "server said no" })
  })

  test("drops an evidence value that is not an object", () => {
    expect(normalizeContract({ evidence: 42 }).evidence).toEqual({})
    expect(normalizeContract({ evidence: ["a"] }).evidence).toEqual({})
  })

  test("truncates an oversized string evidence", () => {
    const normalized = normalizeContract({ evidence: "E".repeat(33_000) })
    expect((normalized.evidence.text as string).length).toBe(MAX_EVIDENCE_CHARS)
  })

  test("drops the junk out of the tag list", () => {
    const normalized = normalizeContract({ tags: ["tls", "", 42, null, " TLS ", "tls"] })
    expect(normalized.tags).toEqual(["tls"])
  })

  test("caps the number of tags", () => {
    const normalized = normalizeContract({ tags: Array.from({ length: 40 }, (_, i) => `tag-${i}`) })
    expect(normalized.tags).toHaveLength(MAX_TAGS)
  })

  test("caps every free-text field", () => {
    const normalized = normalizeContract({
      title: "T".repeat(MAX_TITLE_CHARS + 100),
      target: "T".repeat(MAX_TARGET_CHARS + 100),
      vector: "V".repeat(MAX_VECTOR_CHARS + 100),
      remediation: "R".repeat(MAX_REMEDIATION_CHARS + 100),
      source_tool: "S".repeat(MAX_SOURCE_TOOL_CHARS + 100),
      cwe: "9".repeat(MAX_CWE_CHARS + 100),
      tags: ["t".repeat(MAX_TAG_CHARS + 100)],
    })
    expect(normalized.title).toHaveLength(MAX_TITLE_CHARS)
    expect(normalized.target).toHaveLength(MAX_TARGET_CHARS)
    expect(normalized.vector).toHaveLength(MAX_VECTOR_CHARS)
    expect(normalized.remediation).toHaveLength(MAX_REMEDIATION_CHARS)
    expect(normalized.sourceTool).toHaveLength(MAX_SOURCE_TOOL_CHARS)
    expect(normalized.cwe).toBeUndefined()
    expect(normalized.tags[0]).toHaveLength(MAX_TAG_CHARS)
  })

  test("rejects an invalid cvss vector but keeps a valid one", () => {
    expect(normalizeContract({ cvss: { AV: "Z", AC: "L", PR: "N", UI: "N", S: "U", C: "H", I: "H", A: "H" } }).cvss).toBeUndefined()
    expect(normalizeContract({ cvss: { AV: "N" } }).cvss).toBeUndefined()
    expect(
      normalizeContract({ cvss: { AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "H", I: "H", A: "H" } }).cvss,
    ).toEqual({ AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "H", I: "H", A: "H" })
  })

  test("survives a payload that is not an object", () => {
    expect(normalizeContract(undefined).title).toBe("")
    expect(normalizeContract("nope").severity).toBe("info")
    expect(normalizeContract([]).confidence).toBe("possible")
  })
})

describe("contractToDbRow", () => {
  test("maps the normalized finding onto the security_finding columns", () => {
    const row = contractToDbRow(
      normalizeContract({
        source: "web.sqli",
        source_tool: "web.sqli",
        rule_id: "sqlmap",
        title: "SQL Injection Confirmada (sqlmap)",
        severity: "critical",
        confidence: "confirmed",
        cwe: "CWE-89",
        owasp: ["A03:2021"],
        target: "https://example.com/item?id=1",
        vector: "id",
        evidence: { parameter: "id" },
        remediation: "Use prepared statements",
        cvss: { AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "H", I: "H", A: "H" },
        tags: ["sqli"],
        references: ["https://example.com/advisory"],
      }),
    )

    expect(row).toMatchObject({
      title: "SQL Injection Confirmada (sqlmap)",
      severity: "critical",
      source: "web.sqli",
      source_tool: "web.sqli",
      rule_id: "sqlmap",
      cwe: "CWE-89",
      owasp: ["A03:2021"],
      target: "https://example.com/item?id=1",
      vector: "id",
      evidence: { parameter: "id" },
      remediation: "Use prepared statements",
      tags: ["sqli"],
      confidence: "confirmed",
      references: ["https://example.com/advisory"],
    })
  })

  test("stores the CVSS vector in the long form the scorer reads", () => {
    const row = contractToDbRow(
      normalizeContract({
        title: "x",
        cvss: { AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "H", I: "H", A: "H" },
      }),
    )
    expect(row.cvss_input).toEqual({
      attackVector: "N",
      attackComplexity: "L",
      privilegesRequired: "N",
      userInteraction: "N",
      scope: "U",
      confidentiality: "H",
      integrity: "H",
      availability: "H",
    })
  })

  test("leaves the cvss column empty when no vector was declared", () => {
    expect(contractToDbRow(normalizeContract({ title: "x" })).cvss_input).toBeUndefined()
  })
})

describe("canonical limits", () => {
  test("are declared once and keep the documented values", () => {
    expect(MAX_TITLE_CHARS).toBe(512)
    expect(MAX_EVIDENCE_CHARS).toBe(32_000)
    expect(MAX_RAW_CHARS).toBe(48_000)
    expect(MAX_TAGS).toBe(32)
    expect(MAX_TAG_CHARS).toBe(64)
    expect(MAX_CWE_CHARS).toBe(64)
    expect(MAX_VECTOR_CHARS).toBe(2048)
    expect(MAX_TARGET_CHARS).toBe(2048)
    expect(MAX_REMEDIATION_CHARS).toBe(8000)
    expect(MAX_SOURCE_TOOL_CHARS).toBe(128)
  })
})

// ── ARG-053: contrato compartido Go ↔ TS ────────────────────────────────────
//
// El golden file es el mismo que consume `argos-bin/internal/contract/
// contract_test.go`. Si un campo se agrega de un solo lado, uno de los dos
// tests falla: no hay forma de que Go y TS se desincronicen en silencio.

const GOLDEN_PATH = `${import.meta.dir}/fixtures/finding-contract.json`

interface GoldenFile {
  version: number
  severities: string[]
  confidences: string[]
  fields: Array<{ json: string; ts: string; go: string | null; required: boolean }>
  limits: Record<string, number>
  sample: Record<string, unknown>
  normalized: Record<string, unknown>
}

async function golden(): Promise<GoldenFile> {
  return (await Bun.file(GOLDEN_PATH).json()) as GoldenFile
}

describe("ARG-053 contrato compartido Go ↔ TS", () => {
  test("los campos del wire son exactamente los del golden", async () => {
    const file = await golden()
    expect(file.version).toBe(1)
    expect([...CONTRACT_WIRE_FIELDS]).toEqual(file.fields.map((field) => field.json))
  })

  test("el mapeo json → ts no tiene huecos ni duplicados", async () => {
    const file = await golden()
    expect(new Set(file.fields.map((field) => field.ts)).size).toBe(file.fields.length)
    for (const field of file.fields) expect(field.ts.length).toBeGreaterThan(0)
  })

  test("severidades y confianzas son las del golden", async () => {
    const file = await golden()
    expect([...SEVERITIES]).toEqual(file.severities)
    expect([...CONFIDENCES]).toEqual(file.confidences)
  })

  test("los límites numéricos son los del golden", async () => {
    const file = await golden()
    const declared: Record<string, number> = {
      MAX_TITLE_CHARS,
      MAX_AGENT_CHARS,
      MAX_TARGET_CHARS,
      MAX_VECTOR_CHARS,
      MAX_CWE_CHARS,
      MAX_EVIDENCE_CHARS,
      MAX_REMEDIATION_CHARS,
      MAX_TAGS,
      MAX_TAG_CHARS,
      MAX_RAW_CHARS,
      MAX_SOURCE_TOOL_CHARS,
      MAX_RULE_ID_CHARS,
      MAX_OWASP_ITEMS,
      MAX_REFERENCES,
      MAX_REFERENCE_CHARS,
      MAX_ID_CHARS,
    }
    expect(declared).toEqual(file.limits)
  })

  test("normalizar el sample produce exactamente el resultado del golden", async () => {
    const file = await golden()
    const normalized = normalizeContract(file.sample)
    expect(normalized).toEqual(file.normalized)
  })
})
