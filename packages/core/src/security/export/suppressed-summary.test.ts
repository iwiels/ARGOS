import { expect, test } from "bun:test"
import { buildReport, type ReportFinding, type ReportMeta } from "./model"
import { exportSarif } from "./sarif"
import { exportJunit } from "./junit"
import { DocxExporter } from "./docx"

const meta: ReportMeta = {
  title: "Audit", clientName: "Client", scope: "Scope", classification: "Internal", leadAuditor: "Auditor",
  methodology: "Test", sessionID: "session", generatedAt: new Date("2024-05-17T00:00:00Z"),
  engine: "argos", engineVersion: "1",
}

test("suppressed findings remain auditable without affecting current finding metrics", () => {
  const findings: ReportFinding[] = [
    { id: "current", title: "Current", severity: "medium", status: "open", target: "example", cvssScore: 5 },
    { id: "triaged", title: "Triaged", severity: "critical", status: "open", target: "example", cvssScore: 10,
      feedback: { verdict: "false-positive", reason: "Not exploitable", actor: "human", updatedAt: 1 } },
    { id: "status", title: "Dismissed", severity: "high", status: "false-positive", target: "example", cvssScore: 9 },
  ]
  const document = buildReport({ meta, findings })
  expect(document.findings).toHaveLength(3)
  expect(document.summary.totalFindings).toBe(1)
  expect(document.summary.counts).toEqual({ critical: 0, high: 0, medium: 1, low: 0, info: 0 })
  expect(document.summary.globalRisk).toBe("medium")
  expect(document.summary.averageCvss).toBe(5)
  expect(document.summary.highestCvss).toBe(5)
  expect(document.summary.targets[0].total).toBe(1)
  expect(document.summary.topVulnerabilities.map((item) => item.title)).toEqual(["Current"])
  const sarif = JSON.parse(exportSarif(document))
  const triaged = sarif.runs[0].results.find((result: { properties: { findingId: string } }) => result.properties.findingId === "triaged")
  expect(triaged.suppressions[0].justification).toContain("Not exploitable")
  expect(exportJunit(document)).toContain('<skipped message="false-positive"/>')
  const docx = DocxExporter.exportDocxXml(document)
  expect(docx).toContain("false-positive")
  expect(docx).toContain("Not exploitable")
})
