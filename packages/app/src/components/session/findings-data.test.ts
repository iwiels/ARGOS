import { describe, expect, test } from "bun:test"
import {
  bindFindingsToSession,
  extractFindings,
  extractWebSurface,
  normalizeToolPart,
  normalizeToolParts,
  mergeFindings,
  mergeFindingBuckets,
  normalizeSeverity,
  severityCounts,
  type Finding,
  type FindingToolPart,
} from "./findings-data"

const memorySave = (input: Record<string, unknown>): FindingToolPart => ({
  tool: "argos_memory_save",
  status: "completed",
  input: {
    kind: "finding",
    title: "Agent-reviewed finding",
    severity: "high",
    target: "https://demo.test",
    evidence: "The agent verified a security impact from the observed response.",
    agent_assessment: "I compared the observed response with the expected access control and confirmed the discrepancy.",
    impact: "An unauthorized user can access protected data.",
    ...input,
  },
})

test("mergeFindingBuckets keeps anonymous findings without shared identity separate", () => {
  const live = { title: "Exposed admin endpoint", severity: "high", source: "web-mcp" } as Finding
  const persisted = { ...live, source: "db" } as Finding

  const merged = mergeFindingBuckets([[live], [persisted]])

  expect(merged).toHaveLength(2)
})

// Salida real de web-core.ts: varias líneas de status + el reporte final pretty-printed.
const WEB_CORE_OUTPUT = [
  JSON.stringify({ status: "info", message: "Wordlist cargado" }),
  JSON.stringify({ status: "progress", message: "Analizando cabeceras..." }),
  JSON.stringify(
    {
      status: "done",
      report: {
        target: "http://demo.test",
        timestamp: "2026-06-08T00:00:00Z",
        findings: [
          { severity: "low", title: "Cabeceras de Seguridad Faltantes", evidence: "Faltan: CSP, HSTS", remediation: "Configurar cabeceras OWASP." },
          { severity: "high", title: "Ruta Sensible Expuesta", evidence: "HTTP 200 a http://demo.test/.env", remediation: "Restringir acceso." },
        ],
        crawled_urls: ["/login", "/api/v1/users"],
        fuzzing_hits: [{ url: "http://demo.test/.env", status: 200 }],
      },
    },
    null,
    2,
  ),
].join("\n")

const webCorePart: FindingToolPart = {
  tool: "bash",
  status: "completed",
  input: { command: "bun run .../web-core.ts http://demo.test" },
  output: WEB_CORE_OUTPUT,
}

// Resultado real normalizado de las tools argos-web_web.* (motor MCP Go)
const webMcp = (tool: string, result: Record<string, unknown>): FindingToolPart => ({
  tool: `argos-web_${tool}`,
  status: "completed",
  output: JSON.stringify(result),
})

describe("normalizeSeverity", () => {
  test("maps Spanish and English variants", () => {
    expect(normalizeSeverity("CRÍTICO")).toBe("critical")
    expect(normalizeSeverity("Alto")).toBe("high")
    expect(normalizeSeverity("medium")).toBe("medium")
    expect(normalizeSeverity("BAJO")).toBe("low")
    expect(normalizeSeverity("info")).toBe("info")
    expect(normalizeSeverity("???")).toBe("info")
  })
})

describe("normalizeToolPart", () => {
  test("reads the real SDK ToolPart state contract", () => {
    expect(
      normalizeToolPart({
        type: "tool",
        tool: "argos_memory_save",
        state: {
          status: "completed",
          input: { kind: "finding", title: "Exposed endpoint" },
          output: "saved",
        },
      }),
    ).toEqual({
      tool: "argos_memory_save",
      status: "completed",
      input: { kind: "finding", title: "Exposed endpoint" },
      output: "saved",
    })
  })

  test("ignores non-tool parts and preserves only valid tool parts", () => {
    expect(normalizeToolParts([{ type: "text", text: "hello" }, { type: "tool", tool: "scan", state: { status: "running" } }])).toEqual([
      { tool: "scan", status: "running", input: undefined, output: undefined },
    ])
  })
})

describe("mergeFindings", () => {
  test("uses persisted backend identity instead of matching title and severity", () => {
    const first: Finding = {
      id: "finding-a",
      fingerprint: "fingerprint-a",
      title: "Exposed configuration",
      severity: "high",
      target: "https://target.test/.env",
      source: "db",
    }
    const second: Finding = {
      id: "finding-b",
      fingerprint: "fingerprint-b",
      title: "Exposed configuration",
      severity: "high",
      target: "https://target.test/.env",
      source: "db",
    }

    expect(mergeFindings([first, second])).toHaveLength(2)
  })

  test("combines duplicate rows only when they share backend identity", () => {
    const first: Finding = {
      id: "finding-a",
      fingerprint: "fingerprint-a",
      title: "Exposed configuration",
      severity: "high",
      evidence: "response header",
      source: "db",
    }
    const duplicate = { ...first, evidence: "response body" }

    expect(mergeFindings([first], [duplicate])).toEqual([
      expect.objectContaining({ id: "finding-a", evidence: "response header" }),
    ])
  })

  test("keeps different database IDs separate when one session is missing", () => {
    const first: Finding = { id: "one", session: "session-1", title: "Finding", severity: "high", target: "https://example.test", source: "db" }
    const second: Finding = { ...first, id: "two", session: undefined }
    expect(mergeFindings([first], [second])).toHaveLength(2)
  })

  test("merges copies with the same persisted ID even when fingerprints differ", () => {
    const first: Finding = { id: "same-id", session: "session-1", fingerprint: "old", title: "Finding", severity: "high", source: "db" }
    const copy = { ...first, fingerprint: "new" }
    expect(mergeFindings([first], [copy])).toHaveLength(1)
  })

  test("merges the agent save with its persisted row using the session identity", () => {
    const agent = bindFindingsToSession([{
      kind: "finding",
      title: "SQL injection",
      severity: "high",
      cwe: "CWE-89",
      target: "https://demo.test/item",
      vector: "https://demo.test/item?id=1",
      evidence: "Agent-verified database error",
      source: "memory",
    } as Finding], "session-1")[0]
    const persisted = bindFindingsToSession([{
      id: "finding-1",
      fingerprint: "fp-1",
      title: "SQL injection confirmed",
      severity: "high",
      cwe: "CWE-89",
      target: "https://demo.test/item",
      vector: "https://demo.test/item?id=1",
      evidence: "Agent-verified database error",
      source: "db",
    }], "session-1")[0]

    const [merged] = mergeFindings([agent], [persisted])
    expect(mergeFindings([agent], [persisted])).toHaveLength(1)
    expect(merged).toMatchObject({ id: "finding-1", fingerprint: "fp-1", session: "session-1" })
  })

  test("keeps anonymous observations separate when only title and severity match", () => {
    const first: Finding = {
      title: "Exposed configuration",
      severity: "high",
      target: "https://target.test/.env",
      evidence: "scanner A",
      source: "web-mcp",
    }
    const second: Finding = { ...first, evidence: "scanner B", source: "memory" }

    expect(mergeFindings([first], [second])).toHaveLength(2)
  })

  test("keeps persisted findings and supplements them with live findings", () => {
    const persisted = extractFindings([memorySave({ kind: "finding", title: "Persisted", severity: "high" })])
    const live = extractFindings([memorySave({ kind: "finding", title: "Live", severity: "low" })])
    expect(mergeFindings(persisted, live).map((finding) => finding.title)).toEqual(["Persisted", "Live"])
  })

  test("folds an unassociated local cache copy into its persisted session finding", () => {
    const persisted: Finding = {
      id: "finding-db-1",
      session: "session-1",
      title: "Despliegue inexistente en Vercel - DEPLOYMENT_NOT_FOUND (404) en apex y www",
      severity: "high",
      cwe: "CWE-16",
      target: "https://www.application.example.com/",
      source: "db",
    }
    const cachedCopy: Finding = {
      id: "finding-cache-1",
      title: "Despliegue inexistente en Vercel - DEPLOYMENT_NOT_FOUND (404) en apex y www",
      severity: "high",
      target: "`https://www.application.example.com/`",
      vector: "`https://www.application.example.com/`",
      source: "memory",
    }

    const merged = mergeFindings([persisted], [cachedCopy])

    expect(merged).toHaveLength(1)
    expect(merged[0]).toMatchObject({ id: "finding-db-1", session: "session-1", source: "db", cwe: "CWE-16" })
  })

  test("folds an unpersisted child-session copy into the persisted finding", () => {
    const persisted: Finding = {
      id: "finding-db-1",
      session: "root-session",
      title: "Deployment not found",
      severity: "high",
      target: "https://demo.test/",
      source: "db",
    }
    const childCopy: Finding = {
      session: "agent-session",
      title: "Deployment not found",
      severity: "high",
      target: "`https://demo.test/`",
      source: "memory",
    }

    const merged = mergeFindings([persisted], [childCopy])

    expect(merged).toHaveLength(1)
    expect(merged[0]).toMatchObject({ id: "finding-db-1", session: "root-session", source: "db" })
  })

  test("deduplicates findings collected from separate session buckets", () => {
    const persisted: Finding = {
      id: "finding-db-1",
      session: "root-session",
      title: "Deployment not found",
      severity: "high",
      target: "https://demo.test/",
      source: "db",
    }
    const childCopy: Finding = {
      session: "agent-session",
      title: "Deployment not found",
      severity: "high",
      target: "`https://demo.test/`",
      source: "memory",
    }

    const merged = mergeFindings([persisted], [childCopy], [childCopy])

    expect(merged).toHaveLength(1)
    expect(merged[0]).toMatchObject({ id: "finding-db-1", session: "root-session", source: "db" })
  })

  test("deduplicates a persisted finding whose vector lists multiple target URLs", () => {
    const persisted: Finding = {
      id: "finding-db-1",
      session: "child-session",
      title: "Despliegue inexistente en Vercel - DEPLOYMENT_NOT_FOUND (404) en apex y www",
      severity: "high",
      target: "https://www.application.example.com/",
      vector: "https://www.application.example.com/ y https://application.example.com/",
      cwe: "CWE-16",
      source: "memory",
    }
    const cachedCopy: Finding = {
      title: "Despliegue inexistente en Vercel - DEPLOYMENT_NOT_FOUND (404) en apex y www",
      severity: "high",
      vector: "`https://www.application.example.com/`",
      source: "memory",
    }

    const merged = mergeFindings([persisted], [cachedCopy])

    expect(merged).toHaveLength(1)
    expect(merged[0]).toMatchObject({ id: "finding-db-1", session: "child-session", cwe: "CWE-16" })
  })

  test("keeps separate session findings even when their descriptions match", () => {
    const first: Finding = {
      id: "finding-1",
      session: "session-1",
      title: "Exposed configuration",
      severity: "high",
      target: "https://target.test/.env",
      source: "db",
    }
    const second: Finding = { ...first, id: "finding-2", session: "session-2" }

    expect(mergeFindings([first, second])).toHaveLength(2)
  })

  test("preserves findings with same title and path on different hosts", () => {
    const finding1: Finding = {
      title: "Exposed .env",
      severity: "high",
      target: "organization.example.org",
      vector: "http://organization.example.org/.env",
      source: "web-mcp",
    }
    const finding2: Finding = {
      title: "Exposed .env",
      severity: "high",
      target: "admin.organization.example.org",
      vector: "http://admin.organization.example.org/.env",
      source: "web-mcp",
    }
    const merged = mergeFindings([finding1], [finding2])
    expect(merged).toHaveLength(2)
  })

  test("keeps distinct persisted findings even when taxonomy and endpoint match", () => {
    const merged = mergeFindings([
      {
        id: "finding-child-1",
        session: "child-1",
        title: "SQL injection",
        severity: "high",
        cwe: "CWE-89",
        target: "https://demo.test:443/search?source=nuclei",
        vector: "https://demo.test/search?id=1",
        evidence: "Boolean response differs",
        source: "db",
      },
      {
        id: "finding-child-2",
        session: "child-2",
        title: "SQLi verified",
        severity: "high",
        cwe: "cwe 89",
        target: "http://demo.test/search",
        vector: "https://demo.test/search?id=2",
        evidence: "Independent confirmation",
        source: "db",
      },
    ])

    expect(merged).toHaveLength(2)
  })

  test("preserves distinct query parameters and requires a vector for taxonomy dedupe", () => {
    const merged = mergeFindings([
      {
        title: "SQL injection in id",
        severity: "high",
        cwe: "CWE-89",
        target: "https://demo.test/item",
        vector: "https://demo.test/item?id=1",
        source: "db",
      },
      {
        title: "SQLi in id verified",
        severity: "high",
        cwe: "CWE-89",
        target: "https://demo.test/item",
        vector: "https://demo.test/item?id=2",
        source: "db",
      },
      {
        title: "SQL injection in search",
        severity: "high",
        cwe: "CWE-89",
        target: "https://demo.test/item",
        vector: "https://demo.test/item?search=test",
        source: "db",
      },
      {
        title: "SQL injection in path id",
        severity: "high",
        cwe: "CWE-89",
        target: "https://demo.test/item",
        source: "db",
      },
      {
        title: "SQL injection in path search",
        severity: "high",
        cwe: "CWE-89",
        target: "https://demo.test/item",
        source: "db",
      },
    ])

    expect(merged).toHaveLength(4)
  })

  test("does not merge observations from different sources without shared backend identity", () => {
    const finding1: Finding = {
      title: "Exposed .env",
      severity: "high",
      target: "organization.example.org",
      vector: "/.env",
      source: "memory",
    }
    const finding2: Finding = {
      title: "Exposed .env",
      severity: "high",
      target: "organization.example.org",
      vector: "http://organization.example.org/.env",
      source: "web-mcp",
    }
    const merged = mergeFindings([finding1], [finding2])
    expect(merged).toHaveLength(2)
    expect(merged.map((finding) => finding.source).sort()).toEqual(["memory", "web-mcp"])
  })
})

describe("bindFindingsToSession", () => {
  test("uses the controller session instead of a session claimed by an observation", () => {
    const [finding] = bindFindingsToSession(
      [{ id: "model-id", title: "Finding", severity: "high", source: "memory", session: "other-session" }],
      "controller-session",
    )
    expect(finding?.session).toBe("controller-session")
  })
})

describe("extractFindings", () => {
  test("requires an explicit finding kind before accepting memory_save", () => {
    const findings = extractFindings([
      {
        tool: "argos_memory_save",
        status: "completed",
        input: {
          agent: "security-web",
          session: "s1",
          target: "demo.test",
          title: "Cabeceras incompletas",
          severity: "MEDIO",
          cwe: "CWE-693",
          evidence: "Falta CSP",
          vector: "/",
        },
      },
    ])
    expect(findings).toEqual([])
  })

  test("requires target, known severity and concrete evidence for an agent finding", () => {
    const findings = extractFindings([
      memorySave({ target: "", evidence: "" }),
      memorySave({ severity: "maybe" }),
    ])
    expect(findings).toEqual([])
  })

  test("requires an assessment separate from its evidence and impact", () => {
    const findings = extractFindings([
      memorySave({
        evidence: "The response returns another user's private account record.",
        agent_assessment: "The response returns another user's private account record.",
      }),
    ])
    expect(findings).toEqual([])
  })

  test("ignora memory_save con kind reservado de no-hallazgo", () => {
    const findings = extractFindings([
      memorySave({ kind: "note", title: "Autorización", severity: "INFO", body: "..." }),
      memorySave({ kind: "phase-complete", agent: "security-scout", session: "s1", summary: "3 hallazgos" }),
    ])
    expect(findings).toEqual([])
  })

  test("reads structured findings from memory_save inputs", () => {
    const findings = extractFindings([
      memorySave({
        kind: "finding",
        agent: "security-web",
        session: "s1",
        target: "demo.test",
        title: "JWT alg:none aceptado",
        severity: "CRÍTICO",
        status: "validated",
        cwe: "CWE-347",
        evidence: "El backend acepta tokens con alg none",
        vector: "/api/login",
      }),
      memorySave({ kind: "phase-complete", agent: "security-web", session: "s1" }), // no es finding
    ])
    expect(findings).toHaveLength(1)
    expect(findings[0].severity).toBe("critical")
    expect(findings[0].cwe).toBe("CWE-347")
    expect(findings[0].agent).toBe("security-web")
    expect(findings[0].source).toBe("memory")
  })

  test("sorts by severity (critical first)", () => {
    const findings = extractFindings([
      memorySave({ kind: "finding", title: "B", severity: "BAJO" }),
      memorySave({ kind: "finding", title: "C", severity: "CRÍTICO" }),
      memorySave({ kind: "finding", title: "M", severity: "MEDIO" }),
    ])
    expect(findings.map((f) => f.severity)).toEqual(["critical", "medium", "low"])
  })

  test("does not promote web-core scanner output to findings", () => {
    const findings = extractFindings([webCorePart])
    expect(findings).toEqual([])
  })

  test("does not promote a memory save without explicit agent assessment and impact", () => {
    const findings = extractFindings([memorySave({ agent_assessment: "", impact: "" })])
    expect(findings).toEqual([])
  })

  test("rejects placeholder agent review fields", () => {
    const findings = extractFindings([memorySave({ agent_assessment: "Confirmed", impact: "N/A" })])
    expect(findings).toEqual([])
  })

  test("parses the new argos MCP tool names (argos_memory_save / argos-web_web.*)", () => {
    const memory = extractFindings([
      {
        tool: "argos_memory_save",
        status: "completed",
        input: { kind: "finding", title: "Hallazgo con el nombre nuevo", severity: "high", target: "https://demo.test", evidence: "La respuesta devuelve datos de otra cuenta.", agent_assessment: "Verifiqué que los datos pertenecen a otro usuario.", impact: "Permite leer datos privados de otra cuenta." },
      },
    ])
    expect(memory.map((f) => f.title)).toEqual(["Hallazgo con el nombre nuevo"])

    const web = extractFindings([
      {
        tool: "argos-web_web.xss",
        status: "completed",
        output: JSON.stringify({ tool: "web.xss", target: "http://demo.test", findings: [{ severity: "high", title: "XSS nuevo", target: "http://demo.test/a" }] }),
      },
    ])
    expect(web).toEqual([])
  })

  test("unwraps MCP content wrapping ({ content: [{ type:'text', text }] })", () => {
    const inner = {
      tool: "web.xss",
      target: "http://demo.test",
      findings: [{ severity: "high", title: "XSS reflejado", target: "http://demo.test/profile?user=1", detail: "param=user -> <svg onload=alert(1)>" }],
    }
    const findings = extractFindings([
      { tool: "argos-web_web.xss", status: "completed", output: JSON.stringify({ content: [{ type: "text", text: JSON.stringify(inner) }] }) },
    ])
    expect(findings).toEqual([])
  })

  test("MCP output remains a candidate while memory is empty", () => {
    const findings = extractFindings([
      webMcp("web.fuzz", {
        tool: "web.fuzz",
        target: "http://demo.test",
        findings: [{ severity: "medium", title: "Admin Panel", target: "http://demo.test/admin/", detail: "HTTP 200 (159 bytes)" }],
      }),
    ])
    expect(findings).toEqual([])
  })

  test("only shows the finding explicitly accepted by the agent", () => {
    const findings = extractFindings([
      webMcp("web.fuzz", {
        tool: "web.fuzz",
        target: "http://demo.test",
        findings: [
          { severity: "high", title: "Ruta Sensible Expuesta", target: "http://demo.test/.env", detail: "HTTP 200" },
          { severity: "medium", title: "Admin Panel", target: "http://demo.test/admin/", detail: "HTTP 200" },
        ],
      }),
      memorySave({
        kind: "finding",
        title: "Ruta Sensible Expuesta",
        severity: "high",
        target: "https://demo.test",
        evidence: "The response disclosed a credential verified by the agent.",
        vector: "http://demo.test/.env",
        agent: "security-web",
        cwe: "CWE-552",
      }),
    ])
    expect(findings).toHaveLength(1)
    expect(findings[0]).toMatchObject({ title: "Ruta Sensible Expuesta", source: "memory", cwe: "CWE-552" })
  })

  test("does not promote MCP candidates even when they resemble an accepted finding", () => {
    const findings = extractFindings([
      webMcp("web.fuzz", {
        tool: "web.fuzz",
        target: "http://demo.test",
        findings: [{ severity: "high", title: "Ruta Sensible Expuesta", target: "http://demo.test/.env", detail: "HTTP 200" }],
      }),
      memorySave({ kind: "finding", title: "Ruta Sensible Expuesta", severity: "high", vector: "/.env", agent: "security-web" }),
    ])
    expect(findings).toHaveLength(1)
    expect(findings[0].source).toBe("memory")
  })

  test("filters rows with no trusted provenance even when local findings resemble them", () => {
    const persisted = extractFindings([], [
      {
        id: "db-deployment",
        title: "Despliegue inexistente en Vercel - DEPLOYMENT_NOT_FOUND (404) en apex y www",
        severity: "high",
        target: "https://www.application.example.com/",
        cwe_id: "CWE-16",
      },
      {
        id: "db-takeover",
        title: "Riesgo de takeover latente por NS delegado a Vercel sin despliegue activo",
        severity: "medium",
        target: "application.example.com",
        cwe_id: "CWE-829",
      },
      {
        id: "db-email",
        title: "Ausencia total de autenticación de email - sin SPF, DKIM ni DMARC",
        severity: "medium",
        target: "application.example.com",
        cwe_id: "CWE-290",
      },
      {
        id: "db-dnssec",
        title: "DNSSEC deshabilitado y sin registros CAA - control de emisión de certificados ausente",
        severity: "low",
        target: "DNS CAA/DNSSEC (application.example.com)",
        cwe_id: "CWE-345",
      },
      {
        id: "db-surface",
        title: "Superficie web mínima - sin contenido indexable, sin headers de seguridad y sin WAF detectable",
        severity: "low",
        target: "https://www.application.example.com/",
        cwe_id: "CWE-693",
      },
      {
        id: "db-domain-age",
        title: "Dominio recién creado (13 días) - 2026-08-20 sin historial ni reputación",
        severity: "info",
        target: "application.example.com",
        cwe_id: "CWE-1270",
      },
    ])
    const local = extractFindings([
      memorySave({ kind: "finding", title: "Despliegue inexistente en Vercel - DEPLOYMENT_NOT_FOUND (404) en apex y www", severity: "high", vector: "`https://www.application.example.com/`" }),
      memorySave({ kind: "finding", title: "Riesgo de takeover latente por NS delegado a Vercel sin despliegue activo", severity: "medium", vector: "`NS Vercel + sin proyecto`" }),
      memorySave({ kind: "finding", title: "Ausencia total de autenticación de email - sin SPF, DKIM ni DMARC", severity: "medium", vector: "`DNS TXT/MX/_dmarc`" }),
      memorySave({ kind: "finding", title: "DNSSEC deshabilitado y sin registros CAA", severity: "low", vector: "`DNS CAA/DNSSEC`" }),
      memorySave({ kind: "finding", title: "Superficie web mínima - sin headers de seguridad y sin WAF", severity: "low", vector: "`HTTP headers`" }),
      memorySave({ kind: "finding", title: "Dominio recién creado (13 días) sin historial ni reputación", severity: "info", vector: "`WHOIS`" }),
    ])

    const merged = mergeFindings(persisted, local)

    expect(merged).toHaveLength(6)
    expect(merged.every((finding) => finding.source === "memory" && !finding.id)).toBe(true)
  })

  test("keeps distinct persisted records even when their titles and host match", () => {
    const findings = mergeFindings([
      { id: "db-endpoint-one", title: "Exposed endpoint", severity: "high", target: "demo.test", vector: "/one", source: "db" },
      { id: "db-endpoint-two", title: "Exposed endpoint", severity: "high", target: "demo.test", vector: "/two", source: "db" },
    ])

    expect(findings).toHaveLength(2)
  })

  test("ignores non-completed web-mcp parts", () => {
    const findings = extractFindings([
      { tool: "argos-web_web.scan", status: "error", output: JSON.stringify({ tool: "web.scan", findings: [{ severity: "high", title: "x", target: "y" }] }) },
    ])
    expect(findings).toEqual([])
  })

  test("memory is canonical: web-core ignored when memory has findings", () => {
    const findings = extractFindings([
      webCorePart, // 2 hallazgos web-core
      memorySave({
        kind: "finding",
        title: "Ruta Sensible Expuesta",
        severity: "high",
        vector: "http://demo.test/.env",
        agent: "security-web",
        cwe: "CWE-552",
      }),
    ])
    // El texto del scanner no es una segunda vía de ingestión.
    expect(findings).toHaveLength(1)
    expect(findings[0].source).toBe("memory")
    expect(findings[0].cwe).toBe("CWE-552")
  })

  test("returns empty when no findings", () => {
    expect(extractFindings([{ tool: "read", status: "completed", output: "x" }])).toEqual([])
  })

  test("filters out legacy scanner rows from persisted findings", () => {
    expect(extractFindings([], [{
      id: "scanner-row",
      source: "tool",
      title: "Admin Panel",
      severity: "high",
      target: "https://demo.test/admin",
      evidence: { text: "HTTP 200" },
    }])).toEqual([])
  })

  test("filters legacy memory and direct scanner rows from persisted findings", () => {
    for (const source of ["memory", "web.scan", "tool"]) {
      expect(extractFindings([], [{
        id: `legacy-${source}`,
        source,
        title: "Candidate from an old scan",
        severity: "high",
        target: "https://demo.test/admin",
        evidence: { text: "HTTP 200" },
      }])).toEqual([])
    }
  })
})

describe("extractFindings: CVSS", () => {
  test("computa el score localmente desde el vector corto que declaró el agente", () => {
    const findings = extractFindings([
      memorySave({
        kind: "finding",
        title: "SQL injection en /login",
        severity: "critical",
        cvss: { av: "N", ac: "L", pr: "N", ui: "N", s: "U", c: "H", i: "H", a: "H" },
      }),
    ])
    expect(findings[0].cvss?.score).toBe(9.8)
    expect(findings[0].cvss?.severity).toBe("critical")
    expect(findings[0].cvss?.vectorString).toBe("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
  })

  test("prefiere el score ya calculado por el backend en enrichment sobre recalcularlo", () => {
    const findings = extractFindings([
      memorySave({
        kind: "finding",
        title: "XSS reflejado",
        severity: "medium",
        enrichment: { cvss: { score: 6.1, severity: "medium", vectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" } },
      }),
    ])
    expect(findings[0].cvss?.score).toBe(6.1)
  })

  test("sin vector CVSS declarado, no inventa ningún score", () => {
    const findings = extractFindings([memorySave({ kind: "finding", title: "Puerto expuesto", severity: "high" })])
    expect(findings[0].cvss).toBeUndefined()
  })

  test("un vector mal formado se descarta, no rompe el parseo del hallazgo", () => {
    const findings = extractFindings([
      memorySave({
        kind: "finding",
        title: "Hallazgo con vector inválido",
        severity: "low",
        cvss: { av: "NETWORK", ac: "L", pr: "N", ui: "N", s: "U", c: "L", i: "N", a: "N" },
      }),
    ])
    expect(findings[0].cvss).toBeUndefined()
    expect(findings[0].title).toBe("Hallazgo con vector inválido")
  })
})

describe("extractWebSurface", () => {
  test("derives surface from web.crawl + web.fuzz tool output", () => {
    const surface = extractWebSurface([
      webMcp("web.crawl", {
        tool: "web.crawl",
        target: "http://demo.test",
        endpoints: [
          { url: "http://demo.test/login", status_code: 200 },
          { url: "http://demo.test/api/health", status_code: 200 },
        ],
      }),
      webMcp("web.fuzz", {
        tool: "web.fuzz",
        target: "http://demo.test",
        hits: [{ input: { FUZZ: "admin" }, status: 200, url: "http://demo.test/admin/" }],
        findings: [{ severity: "high", title: "Admin Panel", target: "http://demo.test/admin/", detail: "HTTP 200" }],
      }),
    ])
    expect(surface).toBeDefined()
    expect(surface!.target).toBe("http://demo.test")
    expect(surface!.crawledUrls).toContain("http://demo.test/login")
    expect(surface!.fuzzingHits[0].url).toBe("http://demo.test/admin/")
    expect(surface!.findingsCount).toBe(1)
  })

  test("web.scan findings alone do not shadow a web-core surface", () => {
    const surface = extractWebSurface([
      webMcp("web.scan", {
        tool: "web.scan",
        target: "http://demo.test",
        findings: [{ severity: "high", title: "Ruta Sensible Expuesta", target: "http://demo.test/.env", detail: "HTTP 200" }],
      }),
      webCorePart,
    ])
    expect(surface).toBeDefined()
    expect(surface!.crawledUrls).toContain("/login")
  })

  test("summarizes the latest web-core report", () => {
    const surface = extractWebSurface([webCorePart])
    expect(surface).toBeDefined()
    expect(surface!.target).toBe("http://demo.test")
    expect(surface!.crawledUrls).toHaveLength(2)
    expect(surface!.fuzzingHits[0].url).toBe("http://demo.test/.env")
    expect(surface!.findingsCount).toBe(2)
  })

  test("undefined when no web-core output present", () => {
    expect(extractWebSurface([memorySave({ kind: "finding", title: "x", severity: "ALTO" })])).toBeUndefined()
  })
})

describe("severityCounts", () => {
  test("counts per severity", () => {
    const counts = severityCounts(extractFindings([
      memorySave({ kind: "finding", title: "a", severity: "CRÍTICO" }),
      memorySave({ kind: "finding", title: "b", severity: "CRÍTICO" }),
      memorySave({ kind: "finding", title: "c", severity: "MEDIO" }),
    ]))
    expect(counts.critical).toBe(2)
    expect(counts.medium).toBe(1)
    expect(counts.low).toBe(0)
  })
})

describe("extractFindings: dbFindings evidence unwrapping", () => {
  test("unwraps plain text evidence from a DB row", () => {
    const findings = extractFindings([], [
      { title: "Ruta expuesta", severity: "medium", source: "agent-reviewed", evidence: { text: "gau/wayback: /AlumnoPassword.asp" } },
    ])
    expect(findings[0].evidence).toBe("gau/wayback: /AlumnoPassword.asp")
  })

  test("unwraps evidence that was double-JSON-encoded by the agent", () => {
    // Reproduce: el agente pasó evidence ya serializada como '{"text":"..."}',
    // e ingest.ts la volvió a envolver en { text: ... } — quedó doblemente anidada.
    const findings = extractFindings([], [
      {
        title: "Aplicaciones ASP legacy expuestas en wayback",
        severity: "medium",
        source: "agent-reviewed",
        evidence: { text: '{"text":"gau/wayback: http://www.sistemasuni.edu.pe/AlumnoPassword.asp"}' },
      },
    ])
    expect(findings[0].evidence).toBe("gau/wayback: http://www.sistemasuni.edu.pe/AlumnoPassword.asp")
  })

  test("stops unwrapping past the depth guard instead of recursing forever", () => {
    // Cada nivel envuelve al anterior una vez — nesting lineal, no exponencial.
    let nested = "core"
    for (let i = 0; i < 8; i++) nested = JSON.stringify({ text: nested })
    const findings = extractFindings([], [{ title: "Nested", severity: "low", source: "agent-reviewed", evidence: { text: nested } }])
    expect(typeof findings[0].evidence).toBe("string")
  })
})

describe("extractFindings", () => {
  test("does not parse assistant prose or Markdown tables as findings", () => {
    const findings = extractFindings([
      {
        tool: "assistant_text",
        status: "completed",
        output: "| Hallazgo | Severidad |\\n|---|---|\\n| Exposición | CRÍTICO |",
      },
    ])
    expect(findings).toEqual([])
  })
})
