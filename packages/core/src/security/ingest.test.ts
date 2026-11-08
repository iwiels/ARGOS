import { describe, expect, test } from "bun:test"
import {
  findingFingerprint,
  findingId,
  isFindingInput,
  normalizeFindingSeverity,
  normalizeFindingStatus,
  resolveSourceTool,
} from "./ingest"

describe("security finding normalization", () => {
  test("normalizes supported severity aliases and defaults unknown values to info", () => {
    expect(normalizeFindingSeverity("CRITICAL")).toBe("critical")
    expect(normalizeFindingSeverity("alto")).toBe("high")
    expect(normalizeFindingSeverity("media")).toBe("medium")
    expect(normalizeFindingSeverity("BAJO")).toBe("low")
    expect(normalizeFindingSeverity("unrecognised")).toBe("info")
  })

  test("creates a stable fingerprint for the same finding identity", () => {
    const input = { severity: "high", title: "Exposed endpoint", vector: "/admin" }
    expect(findingFingerprint(input)).toBe(findingFingerprint({ ...input }))
    expect(findingFingerprint(input)).toBe(findingFingerprint({ ...input, severity: "ALTO" }))
    expect(findingFingerprint(input)).toBe(findingFingerprint({ ...input, severity: "critical" }))
    expect(findingFingerprint(input)).toBe(findingFingerprint({ ...input, title: "  exposed   endpoint  " }))
  })

  test("normalizes finding status to the supported lifecycle", () => {
    expect(normalizeFindingStatus("VALIDATED")).toBe("validated")
    expect(normalizeFindingStatus("resolved")).toBe("resolved")
    expect(normalizeFindingStatus("unrecognised")).toBe("open")
  })

  test("keeps the same finding isolated between sessions", () => {
    const fingerprint = findingFingerprint({ severity: "high", title: "Exposed endpoint", vector: "/admin" })
    expect(findingId("session-a", fingerprint)).not.toBe(findingId("session-b", fingerprint))
    expect(findingId("session-a", fingerprint)).toBe(findingId("session-a", fingerprint))
  })
})

describe("isFindingInput (decisión revisada por el agente)", () => {
  const reviewed = {
    kind: "finding",
    title: "Acceso a datos de otra cuenta",
    target: "https://x.test/api/account",
    severity: "high",
    evidence: "La respuesta contiene el identificador y correo de otra cuenta.",
    agent_assessment: "Repetí la petición con dos cuentas y confirmé que cambiar el identificador expone el registro ajeno.",
    impact: "Un usuario autenticado puede leer información personal de otras cuentas.",
  }

  test("acepta únicamente una decisión explícita con evidencia, evaluación e impacto", () => {
    expect(isFindingInput(reviewed)).toBe(true)
    expect(isFindingInput({ ...reviewed, kind: "Finding" })).toBe(true)
  })

  test("rechaza campos de revisión ausentes, triviales o placeholders", () => {
    expect(isFindingInput({ ...reviewed, agent_assessment: undefined })).toBe(false)
    expect(isFindingInput({ ...reviewed, agent_assessment: "Confirmed" })).toBe(false)
    expect(isFindingInput({ ...reviewed, impact: "N/A" })).toBe(false)
    expect(isFindingInput({ ...reviewed, evidence: "" })).toBe(false)
  })

  test("rechaza registros sin kind, target, severidad conocida o hallazgo explícito", () => {
    expect(isFindingInput({ ...reviewed, kind: undefined })).toBe(false)
    expect(isFindingInput({ ...reviewed, target: "" })).toBe(false)
    expect(isFindingInput({ ...reviewed, severity: "maybe" })).toBe(false)
    expect(isFindingInput({ ...reviewed, kind: "note" })).toBe(false)
    expect(isFindingInput({ kind: "phase-complete", summary: "ok" })).toBe(false)
  })
})

describe("resolveSourceTool", () => {
  test("usa el source_tool provisto por el agente", () => {
    expect(resolveSourceTool({ source_tool: "web.probe" })).toBe("web.probe")
    expect(resolveSourceTool({ source_tool: "lan.port_scan" })).toBe("lan.port_scan")
  })

  test("recorta espacios en blanco", () => {
    expect(resolveSourceTool({ source_tool: "  web.scan  " })).toBe("web.scan")
  })

  test("cae al literal canónico argos_memory_save cuando el campo está ausente o vacío", () => {
    expect(resolveSourceTool({})).toBe("argos_memory_save")
    expect(resolveSourceTool({ source_tool: "" })).toBe("argos_memory_save")
    expect(resolveSourceTool({ source_tool: "   " })).toBe("argos_memory_save")
    expect(resolveSourceTool({ source_tool: 123 })).toBe("argos_memory_save")
  })
})
