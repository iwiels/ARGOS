import { describe, expect, test } from "bun:test"
import { generateReport, cvssLabel, cvssColor } from "./report-generator"
import { exportReportToMarkdown, exportReportToHtml } from "./report-exporters"
import type { Finding } from "@/components/session/findings-data"

describe("report-generator", () => {
  const sampleFindings: Finding[] = [
    {
      id: "VULN-001",
      title: "SQL Injection in /api/v1/users",
      severity: "critical",
      cwe: "CWE-89",
      target: "https://api.empresa.com/v1/users",
      evidence: "Payload: ' OR 1=1-- returned all database rows.",
      remediation: "Usar consultas parametrizadas (Prepared Statements) con PDO o Prisma.",
      cvss: { score: 9.8, severity: "CRITICAL", vectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" },
      httpRequest: "POST /v1/users HTTP/1.1\r\nHost: api.empresa.com\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nuser=admin' OR 1=1--",
      httpResponse: "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n[{\"id\":1,\"user\":\"admin\",\"hash\":\"$2b$...\"}]",
      curlCommand: "curl -X POST https://api.empresa.com/v1/users -d 'user=admin%27+OR+1%3D1--'",
      attack: [{ id: "T1190", name: "Exploit Public-Facing Application", tactics: ["Initial Access"] }],
      iocs: [{ type: "ip", value: "192.168.1.10", reputation: [{ source: "abuseipdb", verdict: "malicious", score: 95, detail: "Reported for SQLi scans", checkedAt: 12345 }] }],
      source: "web-mcp",
    },
    {
      id: "VULN-002",
      title: "Reflected Cross-Site Scripting in search query",
      severity: "medium",
      cwe: "CWE-79",
      target: "https://app.empresa.com/search",
      evidence: "Payload <script>alert(1)</script> was reflected unescaped.",
      remediation: "Implementar codificación contextual de salida y política Content-Security-Policy (CSP).",
      cvss: { score: 6.1, severity: "MEDIUM", vectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" },
      source: "web-core",
    },
    {
      id: "VULN-003",
      title: "Cleartext HTTP Transmission Enabled",
      severity: "low",
      cwe: "CWE-319",
      target: "http://admin.empresa.com",
      evidence: "El puerto 80 no redirige a HTTPS y transmite credenciales en texto plano.",
      remediation: "Configurar redirección HSTS 301 obligatoria hacia HTTPS con certificado TLS válido.",
      cvss: { score: 3.1, severity: "LOW", vectorString: "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N" },
      source: "memory",
    },
  ]

  test("generates rich executive report with real CVSS and roadmap", () => {
    const report = generateReport({
      findings: sampleFindings,
      sessionCount: 2,
      clientName: "Banco Nacional Corp",
      scope: "*.empresa.com",
      classification: "CONFIDENCIAL — TLP:AMBER",
    })

    expect(report.title).toContain("Informe Ejecutivo")
    expect(report.clientName).toBe("Banco Nacional Corp")
    expect(report.scope).toBe("*.empresa.com")
    expect(report.classification).toBe("CONFIDENCIAL — TLP:AMBER")
    expect(report.sessionCount).toBe(2)

    // Summary checks
    expect(report.summary.totalFindings).toBe(3)
    expect(report.summary.criticalCount).toBe(1)
    expect(report.summary.mediumCount).toBe(1)
    expect(report.summary.lowCount).toBe(1)
    expect(report.summary.globalRiskLevel).toBe("CRITICAL")

    // CVSS checks: Real FIRST.org calculations
    expect(report.summary.highestCvss!.baseScore).toBe(9.8)
    expect(report.summary.highestCvss!.severity).toBe("CRITICAL")
    // Avg of 9.8, 6.1, 3.1 is 6.33 -> 6.3
    expect(report.summary.averageCvss!.baseScore).toBe(6.3)
    expect(report.summary.averageCvss!.severity).toBe("MEDIUM")

    // Executive narrative
    expect(report.summary.executiveNarrative).toContain("crítico")
    expect(report.summary.executiveNarrative).toContain("SQL Injection")
    expect(report.summary.executiveNarrative).toContain("1 crítico")
    expect(report.summary.executiveNarrative).not.toContain("riesgo inminente")
    expect(report.summary.executiveNarrative).not.toContain("exfiltración masiva")
    expect(report.summary.remediationRoadmap[0].basis).toContain("CVSS")
    expect(report.summary.remediationRoadmap[0].description).not.toContain("directamente explotables")

    // Target aggregation
    expect(report.summary.targets).toHaveLength(3)
    expect(report.summary.targets[0].url).toContain("https://api.empresa.com/v1/users")
    expect(report.summary.targets[0].critical).toBe(1)

    // Top vulnerabilities
    expect(report.summary.topVulnerabilities).toHaveLength(3)
    expect(report.summary.topVulnerabilities[0].title).toContain("SQL Injection")
    expect(report.summary.topVulnerabilities[0].cwe).toBe("CWE-89")
    expect(report.summary.topVulnerabilities[0].cvssScore).toBe(9.8)

    // Remediation Roadmap checks
    const roadmap = report.summary.remediationRoadmap
    expect(roadmap).toHaveLength(3)
    // Priority 1 contains the critical finding.
    expect(roadmap[0].findings).toHaveLength(1)
    expect(roadmap[0].findings[0].id).toBe("VULN-001")
    // Priority 2 contains the medium finding.
    expect(roadmap[1].findings).toHaveLength(1)
    expect(roadmap[1].findings[0].id).toBe("VULN-002")
    // Priority 3 contains the low finding.
    expect(roadmap[2].findings).toHaveLength(1)
    expect(roadmap[2].findings[0].id).toBe("VULN-003")

    // Enriched findings preserve PoC and remediation
    const f1 = report.findings.find((f) => f.id === "VULN-001")
    expect(f1).toBeDefined()
    expect(f1!.status).toBeUndefined()
    expect(f1!.remediation).toContain("Prepared Statements")
    expect(f1!.evidence).toContain("OR 1=1")
    expect(f1!.curlCommand).toContain("curl -X POST")
    expect(f1!.attack?.[0].id).toBe("T1190")
  })

  test("handles empty findings gracefully", () => {
    const report = generateReport({ findings: [], sessionCount: 0 })
    expect(report.summary.totalFindings).toBe(0)
    expect(report.summary.globalRiskLevel).toBe("NONE")
    expect(report.summary.averageCvss).toBeUndefined()
    expect(report.summary.highestCvss).toBeUndefined()
    expect(report.summary.executiveNarrative).toContain("El expediente no contiene hallazgos")
    expect(report.summary.executiveNarrative).toContain("ni qué cobertura alcanzó")
    expect(report.summary.executiveNarrative).not.toContain("La auditoría de seguridad se completó")
    expect(report.summary.targets).toHaveLength(0)
  })

  test("does not infer impacts from severity or fill in missing target metadata", () => {
    const mediumOnly = generateReport({ findings: [sampleFindings[1]], sessionCount: 1 })
    expect(mediumOnly.summary.executiveNarrative).toContain("1 medio")
    expect(mediumOnly.summary.executiveNarrative).not.toContain("controles de sesión")

    const targetless = generateReport({
      findings: [{ id: "FIND-004", title: "Finding without target", severity: "low", source: "web-core" }],
      sessionCount: 1,
    })
    expect(targetless.summary.targets[0].url).toBe("Objetivo no indicado")
  })

  test("keeps unscored findings unscored and excludes them from CVSS aggregates", () => {
    const [scored] = sampleFindings
    const unscored: Finding = {
      id: "VULN-004",
      title: "SQL Injection with no explicit vector",
      severity: "critical",
      cwe: "CWE-89",
      source: "web-mcp",
    }
    const report = generateReport({ findings: [scored, unscored], sessionCount: 1 })

    expect(report.findings[0].cvss?.baseScore).toBe(9.8)
    expect(report.findings[1].cvss).toBeUndefined()
    expect(report.summary.averageCvss?.baseScore).toBe(9.8)
    expect(report.summary.highestCvss?.baseScore).toBe(9.8)
    expect(report.summary.topVulnerabilities.find((finding) => finding.title === unscored.title)?.cvssScore).toBeUndefined()
    const markdown = exportReportToMarkdown(report)
    expect(markdown).toContain("CVSS v3.1 Promedio** | **9.8**")
    expect(markdown).toContain("| `VULN-004` | **CRITICAL** | **N/A** |")
    expect(markdown).toContain("**CVSS v3.1:** *No disponible: falta un vector explícito válido.*")
    expect(markdown).toContain("No indicado")
    expect(markdown).not.toContain("VULN-004` | **CRITICAL** | **9.8**")
    const html = exportReportToHtml(report)
    expect(html).toContain("CRITICAL · CVSS N/A")
  })

  test("propagates client metadata and keeps defaults when omitted", () => {
    const bare = generateReport({ findings: [], sessionCount: 0 })
    expect(bare.clientLegalName).toBeUndefined()
    expect(bare.clientLogoDataUrl).toBeUndefined()
    expect(bare.clientName).toBe("No indicado")
    expect(bare.scope).toBe("No indicado")
    expect(bare.classification).toBe("No indicada")
    expect(bare.leadAuditor).toBe("No indicado")
    expect(bare.methodology).toBe("No indicada")

    const full = generateReport({
      findings: [],
      sessionCount: 0,
      clientLegalName: "Banco Ejemplo S.A.",
      clientLogoDataUrl: "data:image/png;base64,AAA",
      classification: "USO INTERNO",
      leadAuditor: "Security Lead",
    })
    expect(full.clientLegalName).toBe("Banco Ejemplo S.A.")
    expect(full.clientLogoDataUrl).toBe("data:image/png;base64,AAA")
    expect(full.classification).toBe("USO INTERNO")
    expect(full.leadAuditor).toBe("Security Lead")
  })

  test("exporters include legal name and logo when present", async () => {
    const report = generateReport({
      findings: sampleFindings,
      sessionCount: 1,
      clientLegalName: "Banco Ejemplo S.A.",
      clientLogoDataUrl: "data:image/png;base64,AAA",
    })
    const md = exportReportToMarkdown(report)
    expect(md).toContain('razon_social: "Banco Ejemplo S.A."')
    expect(md).toContain("> **RAZÓN SOCIAL:** Banco Ejemplo S.A.")
    const html = exportReportToHtml(report)
    expect(html).toContain("Razón Social")
    expect(html).toContain('src="data:image/png;base64,AAA"')
    const noLogo = exportReportToHtml(generateReport({ findings: sampleFindings, sessionCount: 1 }))
    expect(noLogo).not.toContain("<img src=\"data:")
  })

  test("translates cvssLabel with optional translation function", () => {
    const mockTranslate = (key: string) => (key === "severity.critical" ? "Crítico" : undefined)
    expect(cvssLabel("CRITICAL", mockTranslate)).toBe("Crítico")
    expect(cvssLabel("HIGH")).toBe("Alto")
    expect(cvssLabel("LOW")).toBe("Bajo")
  })

  test("returns correct cvssColor thresholds", () => {
    expect(cvssColor(9.8)).toBe("var(--severity-fg-critical)")
    expect(cvssColor(7.5)).toBe("var(--severity-fg-high)")
    expect(cvssColor(5.0)).toBe("var(--severity-fg-medium)")
    expect(cvssColor(2.0)).toBe("var(--severity-fg-low)")
    expect(cvssColor(0.0)).toBe("var(--severity-fg-info)")
  })

  describe("report-exporters", () => {
    test("exportReportToMarkdown produces formatted client deliverable with all sections", () => {
      const report = generateReport({ findings: sampleFindings, sessionCount: 1 })
      const md = exportReportToMarkdown(report)

      expect(md).toContain("# Informe Ejecutivo de Auditoría de Seguridad")
      expect(md).toContain("CLASIFICACIÓN:")
      expect(md).toContain("## 1. Resumen Ejecutivo de Seguridad")
      expect(md).toContain("## 2. Plan de Remediación Priorizado (Roadmap)")
      expect(md).toContain("Prioridad 1 — Validación temprana (`Crítico y alto con CVSS ≥ 8.0`)")
      expect(md).toContain("## 3. Matriz Consolidada de Hallazgos")
      expect(md).toContain("## 4. Detalle Técnico de Vulnerabilidades")
      expect(md).toContain("SQL Injection")
      expect(md).toContain("curl -X POST")
      expect(md).toContain("POST /v1/users HTTP/1.1")
      expect(md).toContain("HTTP/1.1 200 OK")
      expect(md).toContain("IP:192.168.1.10")
      expect(md).toContain("Prepared Statements")
      expect(md).toContain("## 5. Control de Aprobaciones y Emisión")
    })

    test("exportReportToHtml produces standalone HTML document", () => {
      const report = generateReport({ findings: sampleFindings, sessionCount: 1 })
      const html = exportReportToHtml(report)

      expect(html).toContain("<!DOCTYPE html>")
      expect(html).toContain("<title>")
      expect(html).toContain("SQL Injection in /api/v1/users")
      expect(html).toContain("Plan de Remediación Priorizado")
      expect(html).toContain("curl -X POST")
      expect(html).toContain("HTTP/1.1 200 OK")
      expect(html).toContain("192.168.1.10")
      expect(html).toContain("@media print")
    })
  })
})
