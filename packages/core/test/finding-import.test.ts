import { describe, expect, test } from "bun:test"
import { FindingImportError, MAX_FINDING_IMPORT_BYTES, parseFindingImport } from "../src/security/finding-import"

const captureError = (run: () => unknown) => {
  try {
    run()
  } catch (error) {
    return error
  }
  throw new Error("Expected import parsing to fail")
}

describe("finding import parsers", () => {
  test("parses SARIF 2.1 with source-code locations and keeps a stable identity", () => {
    const document = {
      version: "2.1.0",
      runs: [
        {
          tool: {
            driver: {
              name: "CodeQL",
              version: "2.18.0",
              informationUri: "https://codeql.github.com",
              rules: [
                {
                  id: "js/sql-injection",
                  name: "SQL injection",
                  shortDescription: { text: "SQL injection" },
                  defaultConfiguration: { level: "error" },
                  properties: { cwe: ["CWE-89"] },
                },
              ],
            },
          },
          results: [
            {
              ruleId: "js/sql-injection",
              ruleIndex: 0,
              message: { text: "Untrusted input reaches a query" },
              level: "error",
              properties: { findingId: "foreign-id", status: "verified" },
              locations: [
                {
                  physicalLocation: {
                    artifactLocation: { uri: "src/server.ts" },
                    region: { startLine: 42, endLine: 42, snippet: { text: "db.query(input)" } },
                  },
                },
              ],
              partialFingerprints: { "primaryLocationLineHash/v1": "source-hash" },
            },
          ],
        },
      ],
    }

    const first = parseFindingImport("sarif-2.1", JSON.stringify(document))
    const second = parseFindingImport("sarif-2.1", JSON.stringify(document))
    expect(first.parserVersion).toBe(1)
    expect(first.findings).toHaveLength(1)
    expect(first.contentSha256).toBe(second.contentSha256)
    expect(first.findings[0]).toMatchObject({
      source: "import",
      source_tool: "CodeQL",
      rule_id: "js/sql-injection",
      title: "js/sql-injection",
      severity: "high",
      cwe: "CWE-89",
      target: "src/server.ts",
      vector: "src/server.ts:L42",
      status: "observed",
    })
    expect(first.findings[0].id).not.toBe("foreign-id")
    expect(first.findings[0].evidence).toMatchObject({
      message: "Untrusted input reaches a query",
      location: { uri: "src/server.ts", startLine: 42, endLine: 42 },
      partialFingerprints: { "primaryLocationLineHash/v1": expect.stringMatching(/^[a-f0-9]{64}$/) },
    })
    expect(JSON.stringify(first.findings[0].evidence)).not.toContain("db.query(input)")
    expect(JSON.stringify(first.findings[0].evidence)).not.toContain("source-hash")
    expect(first.findings[0].id).toBe(second.findings[0].id)
  })

  test("rejects unsupported SARIF versions with a stable error code", () => {
    expect(
      captureError(() => parseFindingImport("sarif-2.1", JSON.stringify({ version: "2.0.0", runs: [] }))),
    ).toMatchObject({
      code: "invalid_document",
    })
  })

  test("does not persist secrets embedded in Gitleaks SARIF messages, snippets or fingerprints", () => {
    const secret = "sample-secret-value-987"
    const preview = parseFindingImport(
      "sarif-2.1",
      JSON.stringify({
        version: "2.1.0",
        runs: [
          {
            tool: { driver: { name: "Gitleaks", rules: [{ id: "generic-api-key" }] } },
            results: [
              {
                ruleId: "generic-api-key",
                ruleIndex: 0,
                message: { text: `Detected ${secret}` },
                level: "warning",
                locations: [
                  {
                    physicalLocation: {
                      artifactLocation: { uri: "config/app.env" },
                      region: { startLine: 8, snippet: { text: secret } },
                    },
                  },
                ],
                partialFingerprints: { secretHash: secret },
                suppressions: [{ kind: "external", status: "accepted", justification: secret }],
              },
            ],
          },
        ],
      }),
    )
    expect(preview.findings).toHaveLength(1)
    expect(JSON.stringify(preview.findings[0])).not.toContain(secret)
    expect(preview.findings[0].status).toBe("observed")
  })

  test("parses Nuclei JSONL without retaining raw request or response secrets", () => {
    const record = {
      "template-id": "exposed-env-file",
      "matched-at": "https://user:password@target.example/.env?token=private-token",
      "matcher-name": "env-file",
      info: {
        name: "Exposed environment file",
        severity: "high",
        tags: "exposure,config",
        reference: ["https://example.test/advisory"],
        classification: { "cwe-id": ["CWE-798"] },
      },
      request: "Authorization: Bearer hidden-token",
      response: "SECRET_KEY=hidden-secret",
    }
    const preview = parseFindingImport("nuclei-jsonl", `${JSON.stringify(record)}\n`)
    expect(preview.findings).toHaveLength(1)
    expect(preview.findings[0]).toMatchObject({
      source: "import",
      source_tool: "nuclei",
      rule_id: "nuclei:exposed-env-file",
      title: "Exposed environment file",
      severity: "high",
      cwe: "CWE-798",
      target: "https://target.example/.env",
      vector: "https://target.example/.env",
      tags: ["exposure", "config"],
      references: ["https://example.test/advisory"],
      confidence: "possible",
    })
    expect(JSON.stringify(preview.findings[0].evidence)).not.toContain("hidden-token")
    expect(JSON.stringify(preview.findings[0].evidence)).not.toContain("hidden-secret")
    expect(JSON.stringify(preview.findings[0])).not.toContain("private-token")
    expect(JSON.stringify(preview.findings[0])).not.toContain("password")
  })

  test("rejects a malformed Nuclei line instead of silently importing partial data", () => {
    const valid = JSON.stringify({ "template-id": "example", info: { name: "Example", severity: "low" } })
    expect(captureError(() => parseFindingImport("nuclei-jsonl", `${valid}\nnot-json\n`))).toMatchObject({
      code: "invalid_document",
      line: 2,
    })
  })

  test("rejects unsupported import formats", () => {
    expect(() => parseFindingImport("burp-xml" as never, "<issues />")).toThrow(FindingImportError)
  })

  test("enforces input byte and JSON depth limits", () => {
    expect(captureError(() => parseFindingImport("sarif-2.1", "x".repeat(MAX_FINDING_IMPORT_BYTES + 1)))).toMatchObject(
      {
        code: "size_limit",
      },
    )
    const nested = `${"[".repeat(70)}0${"]".repeat(70)}`
    expect(captureError(() => parseFindingImport("nuclei-jsonl", nested))).toMatchObject({ code: "size_limit" })
  })

  test("parses Semgrep JSON metadata without retaining matched source code", () => {
    const document = {
      results: [
        {
          check_id: "javascript.lang.security.audit.sql-injection",
          path: "src/api.ts",
          start: { line: 24, col: 3 },
          end: { line: 24, col: 30 },
          extra: {
            message: "Untrusted input reaches a database query",
            severity: "ERROR",
            fingerprint: "stable-semgrep-fingerprint",
            lines: "db.query(userInput)",
            metadata: {
              cwe: ["CWE-89"],
              owasp: ["A03:2021"],
              references: ["https://example.test/sql-injection"],
              tags: ["security", "injection"],
              remediation: "Use parameterized queries",
            },
          },
        },
      ],
    }
    const preview = parseFindingImport("semgrep-json" as never, JSON.stringify(document))
    expect(preview.findings).toHaveLength(1)
    expect(preview.findings[0]).toMatchObject({
      source_tool: "semgrep",
      rule_id: "semgrep:javascript.lang.security.audit.sql-injection",
      severity: "high",
      cwe: "CWE-89",
      owasp: ["A03:2021"],
      target: "src/api.ts",
      vector: "src/api.ts:L24",
      remediation: "Use parameterized queries",
    })
    expect(JSON.stringify(preview.findings[0].evidence)).not.toContain("db.query(userInput)")
  })

  test("imports Gitleaks findings without storing captured credential material", () => {
    const preview = parseFindingImport(
      "gitleaks-json" as never,
      JSON.stringify([
        {
          RuleID: "generic-api-key",
          Description: "Generic API Key",
          File: "config/app.env",
          StartLine: 8,
          EndLine: 8,
          Fingerprint: "config/app.env:generic-api-key:8",
          Secret: "hidden-credential",
          Match: "API_KEY=hidden-credential",
          Line: "API_KEY=hidden-credential",
          Commit: "a1b2c3d4",
        },
      ]),
    )
    expect(preview.findings).toHaveLength(1)
    expect(preview.findings[0]).toMatchObject({
      source_tool: "gitleaks",
      rule_id: "gitleaks:generic-api-key",
      severity: "info",
      target: "config/app.env",
      vector: "config/app.env:L8",
      evidence: { severity_reported: false, file: "config/app.env", startLine: 8 },
    })
    expect(JSON.stringify(preview.findings[0])).not.toContain("hidden-credential")
    expect(preview.warnings.join(" ")).toContain("does not declare a severity")
  })

  test("imports Trivy vulnerabilities and secret metadata without retaining secret matches", () => {
    const preview = parseFindingImport(
      "trivy-json" as never,
      JSON.stringify({
        SchemaVersion: 2,
        ArtifactName: "app-image",
        Results: [
          {
            Target: "package-lock.json",
            Type: "npm",
            Vulnerabilities: [
              {
                VulnerabilityID: "CVE-2025-1234",
                PkgName: "example",
                InstalledVersion: "1.0.0",
                FixedVersion: "1.0.1",
                Severity: "HIGH",
                Title: "Example dependency issue",
                PrimaryURL: "https://example.test/CVE-2025-1234",
                CweIDs: ["CWE-79"],
              },
            ],
            Secrets: [
              {
                RuleID: "aws-access-key-id",
                Category: "AWS",
                Severity: "CRITICAL",
                Title: "AWS Access Key",
                Match: "AKIA-secret-value",
                StartLine: 17,
              },
            ],
          },
        ],
      }),
    )
    expect(preview.findings).toHaveLength(2)
    expect(preview.findings[0]).toMatchObject({
      source_tool: "trivy",
      rule_id: "trivy:CVE-2025-1234",
      severity: "high",
      cwe: "CWE-79",
      target: "package-lock.json",
      remediation: expect.stringContaining("1.0.1"),
    })
    expect(JSON.stringify(preview.findings)).not.toContain("AKIA-secret-value")
    expect(preview.findings[1].evidence).toMatchObject({ severity_reported: true, startLine: 17 })
  })

  test("imports ZAP alerts without request evidence or query secrets", () => {
    const preview = parseFindingImport(
      "zap-json" as never,
      JSON.stringify({
        site: [
          {
            "@name": "https://target.example",
            alerts: [
              {
                pluginid: "40012",
                alert: "Cross Site Scripting",
                riskcode: "3",
                confidence: "2",
                desc: "Input is reflected without encoding",
                solution: "Encode output",
                reference: "https://example.test/xss",
                cweid: "79",
                instances: [
                  {
                    uri: "https://target.example/search?q=secret",
                    method: "GET",
                    param: "q",
                    evidence: "secret",
                    requestHeader: "Authorization: Bearer private-token",
                  },
                ],
              },
            ],
          },
        ],
      }),
    )
    expect(preview.findings).toHaveLength(1)
    expect(preview.findings[0]).toMatchObject({
      source_tool: "zap",
      rule_id: "zap:40012",
      severity: "high",
      target: "https://target.example/search",
      vector: "https://target.example/search",
      cwe: "CWE-79",
      remediation: "Encode output",
    })
    expect(JSON.stringify(preview.findings)).not.toContain("private-token")
    expect(JSON.stringify(preview.findings)).not.toContain("secret")
  })

  test("imports Burp XML with its structural DTD without resolving entities or request bodies", () => {
    const document = `<?xml version="1.0"?><!DOCTYPE issues [<!ELEMENT issues (issue*)><!ELEMENT issue (serialNumber?, type?, name, host, path, location?, severity, confidence, issueDetail?, remediationDetail?, requestresponse?)><!ELEMENT requestresponse (request?, response?)><!ELEMENT request (#PCDATA)><!ELEMENT response (#PCDATA)><!ATTLIST request base64 (true|false) "false">]><issues><issue><serialNumber>42</serialNumber><type>539</type><name>Reflected XSS</name><host>https://target.example</host><path>/search?q=secret</path><severity>High</severity><confidence>Certain</confidence><issueDetail>Found reflected input</issueDetail><remediationDetail>Encode output</remediationDetail><requestresponse><request base64="true">private-token</request></requestresponse></issue></issues>`
    const preview = parseFindingImport("burp-xml" as never, document)
    expect(preview.findings).toHaveLength(1)
    expect(preview.findings[0]).toMatchObject({
      source_tool: "burp",
      severity: "high",
      target: "https://target.example/search",
      remediation: "Encode output",
    })
    expect(JSON.stringify(preview.findings)).not.toContain("private-token")
    expect(
      captureError(() =>
        parseFindingImport("burp-xml" as never, '<!DOCTYPE issues [<!ELEMENT issues EMPTY><!ENTITY x "y">]><issues/>'),
      ),
    ).toMatchObject({
      code: "invalid_document",
    })
  })

  test("keeps Burp entry points distinct while removing query values from location evidence", () => {
    const document = `<issues><issue><serialNumber>101</serialNumber><name>Reflected XSS</name><host>https://target.example</host><path>/search</path><location>https://target.example/search?token=secret (parameter: query)</location><severity>High</severity><confidence>Certain</confidence></issue><issue><serialNumber>102</serialNumber><name>Reflected XSS</name><host>https://target.example</host><path>/search</path><location>https://target.example/search?token=secret (parameter: ref)</location><severity>High</severity><confidence>Certain</confidence></issue></issues>`
    const preview = parseFindingImport("burp-xml" as never, document)
    expect(preview.findings).toHaveLength(2)
    expect(preview.findings[0].id).not.toBe(preview.findings[1].id)
    expect(preview.findings[0].vector).not.toBe(preview.findings[1].vector)
    expect(preview.findings[0].evidence).toMatchObject({ burp_serial_number: "101" })
    expect(JSON.stringify(preview.findings)).toContain("parameter: query")
    expect(JSON.stringify(preview.findings)).not.toContain("secret")
  })

  test("imports DefectDojo generic findings without inferring validation state", () => {
    const preview = parseFindingImport(
      "defectdojo-generic-json" as never,
      JSON.stringify([
        {
          title: "SQL injection",
          description: "Potential SQL injection",
          severity: "Critical",
          cwe: 89,
          references: "https://example.test/advisory",
          tags: "injection,api",
          endpoints: ["https://target.example/items"],
          mitigation: "Use parameters",
          active: false,
          verified: true,
          unique_id_from_tool: "dd-finding-42",
        },
      ]),
    )
    expect(preview.findings).toHaveLength(1)
    expect(preview.findings[0]).toMatchObject({
      source_tool: "defectdojo",
      severity: "critical",
      cwe: "CWE-89",
      target: "https://target.example/items",
      status: "observed",
      remediation: "Use parameters",
    })
    expect(preview.findings[0].id).not.toBe("dd-finding-42")
    expect(preview.findings[0].evidence.external_id).toBe("dd-finding-42")
  })
})
