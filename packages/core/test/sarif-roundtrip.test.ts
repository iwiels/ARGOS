import { describe, expect, test } from "bun:test"
import { mkdirSync, readFileSync, writeFileSync } from "node:fs"
import { join } from "node:path"
import { fromFindingRow, fromSarifLog, generateSarifLog, type SarifFinding } from "../src/security/sarif"
import type { FindingTable } from "../src/security/sql"

type FindingRow = typeof FindingTable.$inferSelect

const FIXTURE_PATH = join(import.meta.dir, "fixtures", "sarif-roundtrip.sarif.json")

/**
 * The finding the round trip is about: a tainted flow with a CWE, a CVSS
 * vector and the stable fingerprints the scanners publish.
 */
const taintedSqlInjection: SarifFinding = {
  id: "finding-roundtrip",
  fingerprint: "cwe-89|app/handler.py:42",
  title: "SQL injection through the request parameter",
  severity: "critical",
  status: "open",
  cwe: "CWE-89",
  owasp: ["A03:2021"],
  references: ["https://owasp.org/Top10/A03_2021/"],
  vector: "app/handler.py:42",
  target: "app/handler.py",
  remediation: "Use parameterized queries",
  tags: ["sqli"],
  sourceTool: "code.sast",
  cvssScore: 9.8,
  cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
  dataflow: [
    {
      file: "app/handler.py",
      line: 42,
      endLine: 42,
      message: "Source: request.args",
      snippet: "value = request.args['id']",
    },
    {
      file: "app/handler.py",
      line: 45,
      endLine: 45,
      message: "Sink: cursor.execute(query)",
      snippet: "cursor.execute(query)",
    },
  ],
  partialFingerprints: { "matchBasedId/v1": "9f2b1c8d4e7a6b5c" },
}

describe("sarif round trip", () => {
  test("the export carries the taxonomies, the dataflow and the fingerprints", () => {
    const sarif = generateSarifLog([taintedSqlInjection], { target: "app" })
    const result = sarif.runs[0].results[0]

    expect(result.ruleId).toBe("ARGOS-CWE-89")
    expect(result.ruleIndex).toBe(0)
    expect(result.properties?.cwe).toEqual(["CWE-89"])
    expect(result.properties?.owasp).toEqual(["A03:2021"])
    expect(result.properties?.cvssVector).toBe("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    expect(result.properties?.["security-severity"]).toBe("9.8")

    expect(result.taxonomies?.map((taxonomy) => taxonomy.id)).toEqual(["CWE-89", "A03:2021"])
    expect(result.taxonomies?.[0].toolComponent.name).toBe("CWE")
    expect(result.taxonomies?.[1].toolComponent.name).toBe("OWASP")

    expect(result.partialFingerprints?.["matchBasedId/v1"]).toBe("9f2b1c8d4e7a6b5c")
    expect(result.partialFingerprints?.["argos/v1"]).toBe("cwe-89|app/handler.py:42")

    expect(result.codeFlows).toHaveLength(1)
    const steps = result.codeFlows?.[0].threadFlows[0].locations
    expect(steps).toHaveLength(2)
    expect(steps?.[0].location.message?.text).toBe("Source: request.args")
    expect(steps?.[0].location.physicalLocation.region?.startLine).toBe(42)
    expect(steps?.[1].location.message?.text).toBe("Sink: cursor.execute(query)")
    expect(steps?.[1].location.physicalLocation.region?.startLine).toBe(45)
  })

  test("the export is read back without losing the signal", () => {
    const sarif = generateSarifLog([taintedSqlInjection], { target: "app" })
    const [parsed] = fromSarifLog(sarif)

    expect(parsed.cwe).toBe("CWE-89")
    expect(parsed.owasp).toEqual(["A03:2021"])
    expect(parsed.cvssVector).toBe("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    expect(parsed.cvssScore).toBe(9.8)
    expect(parsed.partialFingerprints?.["matchBasedId/v1"]).toBe("9f2b1c8d4e7a6b5c")
    expect(parsed.partialFingerprints?.["argos/v1"]).toBe("cwe-89|app/handler.py:42")
    expect(parsed.dataflow).toHaveLength(2)
    expect(parsed.dataflow?.[0].message).toBe("Source: request.args")
    expect(parsed.dataflow?.[0].line).toBe(42)
    expect(parsed.dataflow?.[1].message).toBe("Sink: cursor.execute(query)")
  })

  test("a false positive travels suppressed", () => {
    const sarif = generateSarifLog([{ ...taintedSqlInjection, status: "false-positive" }])
    expect(sarif.runs[0].results[0].suppressions).toEqual([{ kind: "external", status: "accepted" }])
  })

  test("triage feedback suppresses open findings and preserves its decision", () => {
    const falsePositive = generateSarifLog([
      {
        ...taintedSqlInjection,
        status: "open",
        feedback: { verdict: "false-positive", reason: "Reviewed", actor: "human" },
      },
    ]).runs[0].results[0]
    expect(falsePositive.suppressions).toEqual([
      { kind: "external", status: "accepted", justification: "false-positive: Reviewed" },
    ])
    expect(falsePositive.properties?.argosFeedback).toMatchObject({ verdict: "false-positive", reason: "Reviewed" })

    const acceptedRisk = generateSarifLog([
      {
        ...taintedSqlInjection,
        status: "open",
        feedback: { verdict: "accepted-risk", reason: "Approved until the next review", actor: "human" },
      },
    ]).runs[0].results[0]
    expect(acceptedRisk.suppressions).toEqual([
      { kind: "external", status: "accepted", justification: "accepted-risk: Approved until the next review" },
    ])
  })

  test("the fixture the Go parser reads is the document the core generates", () => {
    const sarif = generateSarifLog([taintedSqlInjection], { target: "app" })
    const document = `${JSON.stringify(sarif, null, 2)}\n`

    mkdirSync(join(import.meta.dir, "fixtures"), { recursive: true })
    writeFileSync(FIXTURE_PATH, document, "utf8")

    expect(readFileSync(FIXTURE_PATH, "utf8")).toBe(document)
  })

  test("a persisted finding lifts its dataflow and its fingerprints from the evidence", () => {
    const row: FindingRow = {
      id: "finding-roundtrip",
      session_id: "ses-1",
      project_id: "proj-1",
      case_id: null,
      fingerprint: "cwe-89|app/handler.py:42",
      title: "SQL injection through the request parameter",
      severity: "critical",
      status: "open",
      source: "code.sast",
      source_tool: "code.sast",
      agent: null,
      target: "app/handler.py",
      cwe: "CWE-89",
      vector: "app/handler.py:42",
      poc: null,
      evidence: {
        dataflow: taintedSqlInjection.dataflow,
        partialFingerprints: taintedSqlInjection.partialFingerprints,
      },
      remediation: "Use parameterized queries",
      tags: ["sqli"],
      raw: null,
      attack_techniques: null,
      iocs: null,
      enrichment: {
        attack: [],
        iocs: [],
        reputationSources: [],
        cvss: {
          score: 9.8,
          severity: "critical",
          vectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        },
      },
      enriched_at: Date.now(),
      cvss_input: null,
      confidence: "confirmed",
      rule_id: "semgrep:python.sql",
      owasp: ["A03:2021"],
      references: ["https://owasp.org/Top10/A03_2021/"],
      validation_status: "detected",
      validation_evidence: null,
      validated_at: null,
      time_created: Date.now(),
      time_updated: Date.now(),
    }

    const finding = fromFindingRow(row)
    expect(finding.dataflow).toHaveLength(2)
    expect(finding.partialFingerprints?.["matchBasedId/v1"]).toBe("9f2b1c8d4e7a6b5c")
    expect(finding.owasp).toEqual(["A03:2021"])
    expect(finding.cvssVector).toBe("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")

    const sarif = generateSarifLog([finding], { target: "app" })
    expect(sarif.runs[0].results[0].codeFlows?.[0].threadFlows[0].locations).toHaveLength(2)
    expect(sarif.runs[0].results[0].partialFingerprints?.["matchBasedId/v1"]).toBe("9f2b1c8d4e7a6b5c")
  })
})
