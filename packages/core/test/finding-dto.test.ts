import { describe, expect, test } from "bun:test"
import { FindingFeedbackTable, FindingTable } from "../src/security/sql"
import { toSecurityFindingDTO, toSecurityFeedbackDTO } from "../src/security/finding-dto"

describe("security finding DTO", () => {
  test("maps the persisted finding and feedback into the canonical client shape", () => {
    const finding = {
      id: "finding-1",
      session_id: "session-1",
      project_id: "project-1",
      case_id: "case-1",
      fingerprint: "fingerprint-1",
      title: "Exposed endpoint",
      severity: "high",
      status: "open",
      source: "web-mcp",
      source_tool: "nuclei",
      agent: "security-web",
      target: "https://target.test/admin",
      cwe: "CWE-200",
      vector: "https://target.test/admin",
      evidence: { status: 200 },
      remediation: "Restrict access",
      tags: ["web"],
      attack_techniques: [
        {
          id: "T1190",
          name: "Exploit Public-Facing Application",
          tactics: ["initial-access"],
          reason: "The finding exposes an external endpoint.",
        },
      ],
      iocs: [],
      enriched_at: 10,
      time_created: 1,
      time_updated: 2,
    } as unknown as typeof FindingTable.$inferSelect
    const feedback = {
      finding_id: "finding-1",
      verdict: "false-positive",
      reason: "Reviewed",
      actor: "human",
      rule_id: "nuclei:example",
      source_tool: "nuclei",
      cwe: "CWE-200",
      time_created: 3,
      time_updated: 4,
    } as unknown as typeof FindingFeedbackTable.$inferSelect

    expect(toSecurityFindingDTO(finding, feedback)).toEqual({
      id: "finding-1",
      sessionID: "session-1",
      projectID: "project-1",
      caseID: "case-1",
      fingerprint: "fingerprint-1",
      title: "Exposed endpoint",
      severity: "high",
      status: "open",
      source: "web-mcp",
      sourceTool: "nuclei",
      agent: "security-web",
      target: "https://target.test/admin",
      cwe: "CWE-200",
      vector: "https://target.test/admin",
      evidence: { status: 200 },
      remediation: "Restrict access",
      tags: ["web"],
      attackTechniques: [
        {
          id: "T1190",
          name: "Exploit Public-Facing Application",
          tactics: ["initial-access"],
          reason: "The finding exposes an external endpoint.",
        },
      ],
      iocs: [],
      enrichedAt: 10,
      feedback: { verdict: "false-positive", reason: "Reviewed", actor: "human" },
      createdAt: 1,
      updatedAt: 2,
    })
    expect(toSecurityFeedbackDTO(feedback)).toEqual({
      findingID: "finding-1",
      verdict: "false-positive",
      reason: "Reviewed",
      actor: "human",
      ruleID: "nuclei:example",
      sourceTool: "nuclei",
      cwe: "CWE-200",
      createdAt: 3,
      updatedAt: 4,
    })
  })
})
