import { describe, expect, test } from "bun:test"
import type { Finding } from "../components/session/findings-data"
import { generateReport } from "../utils/report-generator"
import { selectSessionFindings } from "./audit-findings-selection"

const saved: Finding = {
  id: "finding-saved",
  title: "Exposed endpoint",
  severity: "low",
  source: "db",
  evidence: "Persisted evidence",
}

const pending: Finding = {
  title: "Pending tool result",
  severity: "critical",
  source: "memory",
}

describe("persisted report findings", () => {
  test("excludes pending tool results from preview counts and evidence", () => {
    const findings = selectSessionFindings(
      "session-1",
      [saved],
      [pending, { ...saved, source: "memory", evidence: "Live evidence" }],
      true,
    )
    const report = generateReport({ findings, sessionCount: 1, clientName: "Client", scope: "Scope" })

    expect(report.summary.totalFindings).toBe(1)
    expect(report.summary.criticalCount).toBe(0)
    expect(report.findings[0]?.evidence).toBe("Persisted evidence")
  })

  test("keeps distinct persisted records with matching descriptions", () => {
    const findings = selectSessionFindings("session-1", [saved, { ...saved, id: "finding-second" }], [], true)

    expect(findings.map((finding) => finding.id)).toEqual(["finding-saved", "finding-second"])
    expect(findings.map((finding) => finding.session)).toEqual(["session-1", "session-1"])
  })

  test("has no report findings when persistence has not returned any rows", () => {
    expect(selectSessionFindings("session-1", [], [pending], true)).toEqual([])
  })

  test("hides legacy scanner rows until an agent accepts them", () => {
    const candidate: Finding = { ...saved, id: "scanner-candidate", source: "tool" }
    expect(selectSessionFindings("session-1", [candidate], [], true)).toEqual([])
  })

  test("continues showing live results for the default audit panel", () => {
    const findings = selectSessionFindings("session-1", [saved], [pending])

    expect(findings.map((finding) => finding.title)).toEqual(["Pending tool result", "Exposed endpoint"])
    expect(findings.every((finding) => finding.session === "session-1")).toBe(true)
  })

  test("does not mix persisted findings from another session into the active session", () => {
    const otherSession = { ...saved, id: "finding-other", session: "session-2", title: "Unrelated target" }
    const findings = selectSessionFindings("session-1", [saved, otherSession], [])

    expect(findings.map((finding) => finding.id)).toEqual(["finding-saved"])
  })
})
