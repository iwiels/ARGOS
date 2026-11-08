import { describe, expect, it } from "bun:test"
import { fromFindingRow, generateSarifLog } from "../src/security/sarif"
import type { FindingTable } from "../src/security/sql"

type FindingRow = typeof FindingTable.$inferSelect

describe("security: sarif & retest", () => {
  it("generates valid OASIS SARIF v2.1.0 output from findings", () => {
    const mockFindings: FindingRow[] = [
      {
        id: "find-1",
        session_id: "ses-1",
        project_id: "proj-1",
        case_id: null,
        fingerprint: "fp12345678",
        title: "Certificado TLS expirado",
        severity: "high",
        status: "open",
        source: "memory",
        source_tool: "web-tls-ssl-audit",
        agent: "scout",
        target: "https://example.com",
        cwe: "CWE-295",
        vector: "https://example.com:443",
        poc: null,
        evidence: { text: "SSL certificate expired on 2026-08-01" },
        remediation: "Renovar el certificado TLS",
        tags: ["tls", "crypto"],
        raw: null,
        attack_techniques: [{ id: "T1566.002", name: "Spearphishing", tactics: ["Initial Access"], reason: "SSL" }],
        iocs: null,
        enrichment: {
          attack: [],
          iocs: [],
          reputationSources: [],
          epssKev: {
            cves: ["CVE-2023-38606"],
            primaryCve: "CVE-2023-38606",
            epss: { cve: "CVE-2023-38606", epssScore: 0.95, epssPercentile: 0.99 },
            cisaKev: { isKev: true, cve: "CVE-2023-38606" },
            allEpss: [],
            allKev: [],
            checkedAt: Date.now(),
          },
        },
        enriched_at: Date.now(),
        cvss_input: null,
        confidence: "confirmed",
        rule_id: "tlsx:expired-certificate",
        owasp: [],
        references: [],
        validation_status: "detected",
        validation_evidence: null,
        validated_at: null,
        time_created: Date.now(),
        time_updated: Date.now(),
      },
    ]

    const sarif = generateSarifLog(mockFindings.map(fromFindingRow), { target: "https://example.com" })
    expect(sarif.version).toBe("2.1.0")
    expect(sarif.$schema).toContain("sarif-schema-2.1.0.json")
    expect(sarif.runs.length).toBe(1)
    expect(sarif.runs[0].tool.driver.name).toBe("Argos Security Operations Engine")
    expect(sarif.runs[0].results.length).toBe(1)

    const res = sarif.runs[0].results[0]
    expect(res.level).toBe("error")
    expect(res.properties?.findingId).toBe("find-1")
    expect(res.properties?.cisaKev).toBe(true)
    expect(res.properties?.epssScore).toBe(0.95)
    expect(res.locations?.[0].physicalLocation.artifactLocation.uri).toBe("https://example.com:443")
  })

  it("handles empty findings array returning valid empty SARIF skeleton", () => {
    const sarif = generateSarifLog([])
    expect(sarif.version).toBe("2.1.0")
    expect(sarif.runs[0].results.length).toBe(0)
    expect(sarif.runs[0].tool.driver.rules.length).toBe(0)
  })
})
