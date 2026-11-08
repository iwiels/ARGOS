import { describe, expect, test } from "bun:test"
import { findingBelongsToSession, loadComplianceStatus, refreshComplianceCatalog } from "./compliance-api"

const STATUS_PAYLOAD = {
  frameworks: [
    {
      framework: "nist_csf_v2",
      title: "NIST CSF 2.0",
      version: "1.2.0",
      tree: {
        id: "PR.PS-06",
        title: "Software is free from known vulnerabilities",
        level: "subcategory",
        status: "deficient",
        findingCount: 1,
        evidence: [
          {
            findingID: "f-1",
            title: "SQL injection in /login",
            severity: "high",
            status: "open",
            tool: "web.scan",
            fromElasticsearch: false,
            timeUpdated: 1,
            cwe: "CWE-89",
            derivedFrom: "cwe:web-vuln",
            confidence: "high",
          },
        ],
        derivation: [
          {
            derivedFrom: "cwe:web-vuln",
            findings: [
              {
                id: "f-1",
                title: "SQL injection in /login",
                severity: "high",
                cwe: "CWE-89",
                sourceTool: "web.scan",
                confidence: "confirmed",
              },
            ],
            confidence: "high",
          },
        ],
        confidence: "high",
        children: [],
      },
    },
  ],
  catalogCount: 1,
  mappingCount: 0,
}

describe("compliance API client", () => {
  test("associates compliance evidence only by exact finding ID", () => {
    const sessionFindingIDs = new Set(["finding-login-1"])
    expect(findingBelongsToSession("finding-login-1", sessionFindingIDs)).toBe(true)
    expect(findingBelongsToSession("finding-login-10", sessionFindingIDs)).toBe(false)
    expect(findingBelongsToSession("", sessionFindingIDs)).toBe(false)
  })

  test("returns undefined only when the status endpoint is unavailable", async () => {
    const request = async () => new Response(null, { status: 404 })
    await expect(loadComplianceStatus(request, "session-1")).resolves.toBeUndefined()
  })

  test("surfaces a status request failure", async () => {
    const request = async () => new Response("unavailable", { status: 503 })
    await expect(loadComplianceStatus(request, "session-1")).rejects.toThrow("HTTP 503")
  })

  test("surfaces a refresh request failure", async () => {
    const request = async () => new Response("unavailable", { status: 502 })
    await expect(refreshComplianceCatalog(request)).rejects.toThrow("HTTP 502")
  })

  test("the panel receives the evidence, the rule and the confidence as-is", async () => {
    const request = async () => new Response(JSON.stringify(STATUS_PAYLOAD), { status: 200 })
    const status = await loadComplianceStatus(request, "session-1")
    const node = status?.frameworks[0]?.tree
    expect(node?.evidence[0]?.derivedFrom).toBe("cwe:web-vuln")
    expect(node?.evidence[0]?.cwe).toBe("CWE-89")
    expect(node?.evidence[0]?.confidence).toBe("high")
    expect(node?.derivation[0]?.derivedFrom).toBe("cwe:web-vuln")
    expect(node?.derivation[0]?.confidence).toBe("high")
    expect(node?.derivation[0]?.findings[0]?.id).toBe("f-1")
    expect(node?.derivation[0]?.findings[0]?.confidence).toBe("confirmed")
    expect(node?.confidence).toBe("high")
  })
})
