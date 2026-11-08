import { describe, expect, test } from "bun:test"
import {
  NIST_DOMAINS,
  ISO_DOMAINS,
  mapToCockpitFinding,
  aggregateAttackTechniques,
  deriveComplianceDomains,
  reportableCockpitFindings,
  cockpitFindingMetrics,
} from "./cockpit-data"
import { LEDGER_LIFECYCLE, nextLedgerStatus, type Finding } from "../../findings-data"
import type { CockpitFinding, NistDomain } from "./cockpit-types"

describe("Cockpit findings metrics", () => {
  test("excludes false-positive status and feedback while retaining both in the ledger", () => {
    const raw: Finding[] = [
      { id: "active", session: "s", title: "Active", severity: "medium", source: "db", target: "https://active.test", cvss: { score: 4.2, vectorString: "", severity: "MEDIUM" } },
      { id: "status", session: "s", title: "Status FP", severity: "critical", source: "db", target: "https://status.test", status: "false-positive", cvss: { score: 9.8, vectorString: "", severity: "CRITICAL" } },
      { id: "verdict", session: "s", title: "Verdict FP", severity: "high", source: "db", target: "https://feedback.test", feedback: { verdict: "false-positive", actor: "human" }, cvss: { score: 8.0, vectorString: "", severity: "HIGH" } },
    ]
    const ledger = raw.map(mapToCockpitFinding)
    const reportable = reportableCockpitFindings(ledger)
    expect(ledger).toHaveLength(3)
    expect(reportable.map((finding) => finding.id)).toEqual(["active"])
    expect(cockpitFindingMetrics(ledger)).toEqual({
      severityCounts: { all: 1, critical: 0, high: 0, medium: 1, low: 0, info: 0 },
      maxCvss: 4.2,
      targetCount: 1,
    })
  })
})

describe("Cockpit Findings Dataset & Adapter", () => {
  test("mapToCockpitFinding maps raw finding with defaults", () => {
    const raw: Finding = {
      title: "SQL Injection in /api/users",
      severity: "critical",
      source: "memory",
      target: "https://example.com/api/users",
      cwe: "CWE-89",
      evidence: "payload: ' OR 1=1-- returned 200",
      remediation: "Use parameterized queries",
      attack: [{ id: "T1190", name: "Exploit Public-Facing Application", tactics: ["initial-access"] }],
      iocs: [{ type: "url", value: "https://example.com/api/users" }],
    }

    const cockpit = mapToCockpitFinding(raw, 0)
    expect(cockpit.shortId).toBe("FIND-001")
    expect(cockpit.severity).toBe("critical")
    expect(cockpit.cvss).toBeUndefined()
    expect(cockpit.mitre[0].id).toBe("T1190")
    expect(cockpit.iocs[0].value).toBe("https://example.com/api/users")
    expect(cockpit.curlCommand).toBeUndefined()
    expect(cockpit.persisted).toBe(false)

    // With explicit declared CVSS from agent or scanner
    const rawWithCvss: Finding = {
      ...raw,
      cvss: { score: 9.8, vectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", severity: "CRITICAL" },
    }
    const cockpitWithCvss = mapToCockpitFinding(rawWithCvss, 0)
    expect(cockpitWithCvss.cvss).toBe(9.8)
  })

  test("does not fabricate forensic details or scoring when source data is absent", () => {
    const cockpit = mapToCockpitFinding({ title: "Unscored", severity: "high", source: "memory" }, 0)
    expect(cockpit.cvss).toBeUndefined()
    expect(cockpit.vector).toBeUndefined()
    expect(cockpit.cwe).toBeUndefined()
    expect(cockpit.poc).toBeUndefined()
    expect(cockpit.httpRequest).toBeUndefined()
    expect(cockpit.httpResponse).toBeUndefined()
    expect(cockpit.remediation).toBeUndefined()
    expect(cockpit.curlCommand).toBeUndefined()
  })

  test("aggregateAttackTechniques dedupes techniques across findings", () => {
    const aggregated = aggregateAttackTechniques([
      {
        id: "finding-1",
        shortId: "FIND-001",
        severity: "high",
        severityLabel: "HIGH",
        status: "open",
        persisted: true,
        title: "Finding with linked techniques",
        mitre: [
          { id: "T1190", name: "Exploit Public-Facing Application" },
          { id: "T1190", name: "Exploit Public-Facing Application" },
        ],
        iocs: [],
      },
    ])
    const ids = aggregated.map((a) => a.id)
    expect(new Set(ids).size).toBe(ids.length)
    expect(ids).toEqual(["T1190"])
  })
})

describe("Compliance Normative Datasets", () => {
  test("NIST_DOMAINS contains 6 CSF 2.0 pillars in order", () => {
    const codes = NIST_DOMAINS.map((d) => d.code)
    expect(codes).toEqual(["GV", "ID", "PR", "DE", "RS", "RC"])
  })

  test("ISO_DOMAINS contains 4 Annex A pillars", () => {
    const codes = ISO_DOMAINS.map((d) => d.code)
    expect(codes).toEqual(["A.5", "A.6", "A.7", "A.8"])
  })

  test("framework catalogues contain no preassigned compliance results or demo findings", () => {
    for (const domain of [...NIST_DOMAINS, ...ISO_DOMAINS]) {
      expect(domain.status).toBe("Sin evaluar")
      expect(domain.score).toBe("Sin evaluar")
      for (const subcontrol of domain.subcontrols) {
        expect(subcontrol.status).toBe("Sin evaluar")
        expect(subcontrol.findings).toEqual([])
      }
    }
  })

  test("keeps controls unassessed until explicit compliance evidence exists", () => {
    const domain: NistDomain = {
      code: "PR",
      name: "Protección",
      status: "Sin evaluar",
      score: "Sin evaluar",
      subcontrols: [{ code: "PR.DS", name: "Seguridad de datos", status: "Sin evaluar", findings: [] }],
    }
    const unlinked: CockpitFinding = {
      id: "finding-1",
      shortId: "FIND-001",
      severity: "critical",
      severityLabel: "CRITICAL",
      status: "open",
      persisted: true,
      title: "Critical SQL injection",
      cwe: "CWE-89",
      target: "https://target.invalid",
      mitre: [],
      iocs: [],
    }

    const withoutEvidence = deriveComplianceDomains([domain], [unlinked])[0]
    expect(withoutEvidence.status).toBe("Sin evaluar")
    expect(withoutEvidence.subcontrols[0].status).toBe("Sin evaluar")
    expect(withoutEvidence.subcontrols[0].findings).toEqual([])

    const linked = deriveComplianceDomains([domain], [{ ...unlinked, nistLinks: ["PR.DS"] }])[0]
    expect(linked.status).toBe("Requiere revisión")
    expect(linked.subcontrols[0].status).toBe("Requiere revisión")
    expect(linked.subcontrols[0].findings).toEqual(["FIND-001"])
  })
})

describe("Contract Compatibility", () => {
  test("preserves the 6 official ledger lifecycle states", () => {
    expect(LEDGER_LIFECYCLE).toEqual([
      "open",
      "in-progress",
      "remediated",
      "verified",
      "false-positive",
      "accepted-risk",
    ])

    let status = "open"
    const traversed: string[] = []
    for (let i = 0; i < LEDGER_LIFECYCLE.length; i++) {
      traversed.push(status)
      status = nextLedgerStatus(status)
    }
    expect(traversed).toEqual([...LEDGER_LIFECYCLE])
    expect(status).toBe("open")
  })
})

describe("Cockpit Filtering & Search Ergonomics", () => {
  test("preserves triage feedback for report exports", () => {
    const feedback = { verdict: "false-positive" as const, reason: "No reproducible issue", actor: "human" as const }
    const finding = mapToCockpitFinding(
      { title: "Reviewed finding", severity: "high", source: "db", feedback },
      0,
    )
    expect(finding.feedback).toEqual(feedback)
  })

  test("MITRE ATT&CK techniques are searchable in finding haystack", () => {
    const finding = mapToCockpitFinding({
      title: "Public application endpoint",
      severity: "high",
      source: "memory",
      attack: [{ id: "T1190", name: "Exploit Public-Facing Application", tactics: ["initial-access"] }],
    }, 0)

    const mitreStr = finding.mitre.map((technique) => `${technique.id} ${technique.name}`).join(" ")
    const haystack = `${finding.title} ${finding.cwe ?? ""} ${finding.target ?? ""} ${finding.shortId} ${mitreStr}`.toLowerCase()

    expect(haystack.includes("t1190")).toBe(true)
    expect(haystack.includes("exploit public-facing application")).toBe(true)
  })

  test("Pipe characters in titles or metadata are safely escaped for Markdown tables", () => {
    const rawTitle = "Vulnerabilidad en header | X-Frame-Options | clickjacking"
    const escapeMd = (str: string) => str.replace(/\|/g, "\\|")
    const escaped = escapeMd(rawTitle)
    expect(escaped).toBe("Vulnerabilidad en header \\| X-Frame-Options \\| clickjacking")
    expect(escaped.split(/(?<!\\)\|/)).toHaveLength(1)
  })
})

describe("Dynamic Compliance Metric Counters", () => {
  test("does not manufacture a compliance percentage without control evidence", () => {
    const derived = deriveComplianceDomains(NIST_DOMAINS, [])
    expect(derived.every((domain) => domain.status === "Sin evaluar")).toBe(true)
    expect(derived.flatMap((domain) => domain.subcontrols).every((subcontrol) => subcontrol.status === "Sin evaluar")).toBe(true)
  })
})
