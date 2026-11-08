import { describe, expect, test } from "bun:test"
import {
  BurpParser,
  DefectDojoParser,
  GitleaksParser,
  ImportService,
  NucleiParser,
  SarifParser,
  SemgrepParser,
  TrivyParser,
  ZapParser,
} from "../src/security/import"

describe("Universal Multi-Format Importers (Etapa 2)", () => {
  test("SARIF 2.1 parser extracts rules, locations, and CWE tags", () => {
    const sarifJson = JSON.stringify({
      version: "2.1.0",
      runs: [
        {
          tool: { driver: { name: "CodeQL", rules: [{ id: "js/sql-injection", shortDescription: { text: "SQL Injection" }, properties: { tags: ["CWE-89"] } }] } },
          results: [
            {
              ruleId: "js/sql-injection",
              level: "error",
              message: { text: "Database query built from user-controlled source" },
              locations: [{ physicalLocation: { artifactLocation: { uri: "src/db.js" }, region: { startLine: 42 } } }],
            },
          ],
        },
      ],
    })

    const res = ImportService.preview("sarif", sarifJson)
    expect(res.format).toBe("sarif")
    expect(res.scanner).toBe("CodeQL")
    expect(res.findings).toHaveLength(1)
    expect(res.findings[0].title).toBe("Database query built from user-controlled source")
    expect(res.findings[0].severity).toBe("high")
    expect(res.findings[0].cwe).toBe("CWE-89")
    expect(res.findings[0].vector).toBe("src/db.js:42")
    expect(res.summary.high).toBe(1)
  })

  test("Nuclei JSONL parser extracts templates, severity, and curl command", () => {
    const nucleiJsonl = [
      JSON.stringify({
        "template-id": "exposed-env-file",
        info: { name: "Environment File Exposed", severity: "high", classification: { "cwe-id": ["552"] }, tags: ["exposure", "config"] },
        host: "http://example.com",
        "matched-at": "http://example.com/.env",
        "curl-command": "curl -i http://example.com/.env",
        "extracted-results": ["DB_PASSWORD=secret"],
      }),
      JSON.stringify({
        "template-id": "missing-hsts",
        info: { name: "Missing HSTS Header", severity: "low", tags: ["headers"] },
        host: "http://example.com",
        "matched-at": "http://example.com/",
      }),
    ].join("\n")

    const res = ImportService.preview("nuclei", nucleiJsonl)
    expect(res.findings).toHaveLength(2)
    expect(res.findings[0].title).toBe("Environment File Exposed")
    expect(res.findings[0].cwe).toBe("CWE-552")
    expect(res.findings[0].severity).toBe("high")
    expect(res.summary.high).toBe(1)
    expect(res.summary.low).toBe(1)
  })

  test("Semgrep JSON parser extracts path, line numbers, and CWE", () => {
    const semgrepJson = JSON.stringify({
      results: [
        {
          check_id: "rules.security.eval-injection",
          path: "app/server.js",
          start: { line: 15 },
          extra: {
            message: "User input directly passed to eval()",
            severity: "ERROR",
            metadata: { cwe: ["CWE-95: Eval Injection"] },
          },
        },
      ],
    })

    const res = ImportService.preview("semgrep", semgrepJson)
    expect(res.findings).toHaveLength(1)
    expect(res.findings[0].severity).toBe("high")
    expect(res.findings[0].cwe).toContain("CWE-95")
    expect(res.findings[0].vector).toBe("app/server.js:15")
  })

  test("Trivy JSON parser extracts dependency CVEs and secrets", () => {
    const trivyJson = JSON.stringify({
      Results: [
        {
          Target: "package-lock.json",
          Vulnerabilities: [
            {
              VulnerabilityID: "CVE-2023-1234",
              PkgName: "express",
              InstalledVersion: "4.17.1",
              FixedVersion: "4.18.2",
              Severity: "CRITICAL",
              CweIDs: ["CWE-400"],
            },
          ],
          Secrets: [
            {
              RuleID: "aws-access-key-id",
              Title: "AWS Access Key ID",
              Severity: "HIGH",
              StartLine: 10,
              Lines: "AKIAIOSFODNN7EXAMPLE",
            },
          ],
        },
      ],
    })

    const res = ImportService.preview("trivy", trivyJson)
    expect(res.findings).toHaveLength(2)
    expect(res.findings[0].title).toContain("CVE-2023-1234 in express")
    expect(res.findings[0].severity).toBe("critical")
    expect(res.findings[1].title).toBe("AWS Access Key ID")
    expect(res.findings[1].cwe).toBe("CWE-798")
    expect(res.summary.critical).toBe(1)
    expect(res.summary.high).toBe(1)
  })

  test("Gitleaks JSON parser extracts secrets with commit and line info", () => {
    const gitleaksJson = JSON.stringify([
      {
        Description: "GitHub Personal Access Token",
        File: "config/auth.ts",
        StartLine: 24,
        EndLine: 24,
        Commit: "abc1234",
        Author: "dev@example.com",
        Date: "2026-10-01",
        RuleID: "github-pat",
      },
    ])

    const res = ImportService.preview("gitleaks", gitleaksJson)
    expect(res.findings).toHaveLength(1)
    expect(res.findings[0].cwe).toBe("CWE-798")
    expect(res.findings[0].severity).toBe("high")
    expect(res.findings[0].vector).toBe("config/auth.ts:24")
  })

  test("OWASP ZAP JSON parser extracts alerts, instances, and CWE", () => {
    const zapJson = JSON.stringify({
      site: [
        {
          "@name": "https://example.com",
          alerts: [
            {
              pluginId: "40012",
              alert: "Cross Site Scripting (Reflected)",
              riskcode: "3",
              riskdesc: "High (Medium)",
              cweid: "79",
              instances: [{ uri: "https://example.com/search", method: "GET", param: "q" }],
              desc: "XSS vulnerability in search param",
              solution: "Escape user input",
            },
          ],
        },
      ],
    })

    const res = ImportService.preview("zap", zapJson)
    expect(res.findings).toHaveLength(1)
    expect(res.findings[0].severity).toBe("high")
    expect(res.findings[0].cwe).toBe("CWE-79")
    expect(res.findings[0].vector).toBe("https://example.com/search [q]")
  })

  test("Burp Suite XML parser extracts issues and strictly blocks XXE entities", () => {
    const burpXml = `<?xml version="1.0"?>
    <issues burpVersion="2026.1">
      <issue>
        <serialNumber>1001</serialNumber>
        <type>1048832</type>
        <name>SQL injection</name>
        <host ip="192.168.1.5">https://target.local</host>
        <path>/login</path>
        <severity>High</severity>
        <issueDetail><![CDATA[The parameter username is vulnerable to SQL injection.]]></issueDetail>
        <remediationBackground>Use parameterized queries.</remediationBackground>
      </issue>
    </issues>`

    const res = ImportService.preview("burp", burpXml)
    expect(res.findings).toHaveLength(1)
    expect(res.findings[0].title).toBe("SQL injection")
    expect(res.findings[0].severity).toBe("high")
    expect(res.findings[0].vector).toBe("https://target.local/login")

    // Verify Critical severity mapping
    const burpCriticalXml = `<issues><issue><name>RCE</name><severity>Critical</severity><path>/exec</path></issue></issues>`
    const critRes = ImportService.preview("burp", burpCriticalXml)
    expect(critRes.findings[0].severity).toBe("critical")

    // XXE Attack payload must be rejected immediately
    const xxeXml = `<?xml version="1.0"?>
    <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
    <issues>&xxe;</issues>`

    expect(() => ImportService.preview("burp", xxeXml)).toThrow(/XXE Security Violation/)
  })

  test("DefectDojo Generic JSON parser extracts findings, mitigations, and CWE", () => {
    const dojoJson = JSON.stringify({
      findings: [
        {
          title: "Insecure Direct Object Reference",
          severity: "Medium",
          cwe: 639,
          endpoint: "/api/documents/102",
          description: "Users can view arbitrary documents by tampering ID parameter",
          mitigation: "Check session ownership before returning document",
        },
      ],
    })

    const res = ImportService.preview("defectdojo", dojoJson)
    expect(res.findings).toHaveLength(1)
    expect(res.findings[0].title).toBe("Insecure Direct Object Reference")
    expect(res.findings[0].severity).toBe("medium")
    expect(res.findings[0].cwe).toBe("CWE-639")
    expect(res.findings[0].vector).toBe("/api/documents/102")
  })
})
