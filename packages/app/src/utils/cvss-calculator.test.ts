import { describe, expect, test } from "bun:test"
import {
  calculateCvssFromVector,
  parseCvssVector,
  resolveFindingCvss,
  cvssRoundup,
  scoreToSeverity,
} from "./cvss-calculator"

describe("cvss-calculator", () => {
  describe("cvssRoundup", () => {
    test("roundup precision matches FIRST.org spec", () => {
      expect(cvssRoundup(4.0)).toBe(4.0)
      expect(cvssRoundup(4.01)).toBe(4.1)
      expect(cvssRoundup(4.00001)).toBe(4.1)
      expect(cvssRoundup(9.71)).toBe(9.8)
    })
  })

  describe("calculateCvssFromVector with official FIRST.org vectors", () => {
    test("calculates Critical 9.8 for Unauthenticated Network RCE/SQLi", () => {
      const res = calculateCvssFromVector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
      expect(res).toBeDefined()
      expect(res!.baseScore).toBe(9.8)
      expect(res!.severity).toBe("CRITICAL")
      expect(res!.impactScore).toBe(5.9)
      expect(res!.exploitabilityScore).toBe(3.9)
    })

    test("calculates High 8.8 for Authenticated Low File Upload", () => {
      const res = calculateCvssFromVector("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H")
      expect(res).toBeDefined()
      expect(res!.baseScore).toBe(8.8)
      expect(res!.severity).toBe("HIGH")
    })

    test("calculates High 7.5 for Path Traversal", () => {
      const res = calculateCvssFromVector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")
      expect(res).toBeDefined()
      expect(res!.baseScore).toBe(7.5)
      expect(res!.severity).toBe("HIGH")
    })

    test("calculates Medium 6.1 for Scope Changed XSS Reflected", () => {
      const res = calculateCvssFromVector("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N")
      expect(res).toBeDefined()
      expect(res!.baseScore).toBe(6.1)
      expect(res!.severity).toBe("MEDIUM")
    })

    test("calculates Medium 6.5 for CSRF Integrity High", () => {
      const res = calculateCvssFromVector("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N")
      expect(res).toBeDefined()
      expect(res!.baseScore).toBe(6.5)
      expect(res!.severity).toBe("MEDIUM")
    })

    test("calculates Medium 5.3 for Information Exposure", () => {
      const res = calculateCvssFromVector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N")
      expect(res).toBeDefined()
      expect(res!.baseScore).toBe(5.3)
      expect(res!.severity).toBe("MEDIUM")
    })

    test("calculates Low 3.1 for Cleartext HTTP transmission", () => {
      const res = calculateCvssFromVector("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N")
      expect(res).toBeDefined()
      expect(res!.baseScore).toBe(3.1)
      expect(res!.severity).toBe("LOW")
    })

    test("calculates None 0.0 for Zero impact Info", () => {
      const res = calculateCvssFromVector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")
      expect(res).toBeDefined()
      expect(res!.baseScore).toBe(0.0)
      expect(res!.severity).toBe("NONE")
    })
  })

  describe("parseCvssVector", () => {
    test("returns undefined for invalid or empty vector string", () => {
      expect(parseCvssVector("")).toBeUndefined()
      expect(parseCvssVector("INVALID")).toBeUndefined()
      expect(parseCvssVector("CVSS:3.1/AV:N")).toBeUndefined()
    })

    test("parses metrics correctly regardless of casing", () => {
      const m = parseCvssVector("cvss:3.1/av:n/ac:l/pr:n/ui:n/s:u/c:h/i:h/a:h")
      expect(m).toBeDefined()
      expect(m!.av).toBe("N")
      expect(m!.c).toBe("H")
    })

    test("rejects unsupported versions and metric values", () => {
      expect(parseCvssVector("CVSS:4.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")).toBeUndefined()
      expect(parseCvssVector("CVSS:3.1/AV:Z/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")).toBeUndefined()
    })
  })

  describe("resolveFindingCvss", () => {
    test("prioritizes explicit cvssVector", () => {
      const res = resolveFindingCvss({
        cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
      })
      expect(res?.baseScore).toBe(7.5)
      expect(res?.severity).toBe("HIGH")
    })

    test("returns no score without an explicit vector", () => {
      const res = resolveFindingCvss({
        raw: JSON.stringify({ title: "SQL Injection", cwe: "CWE-89", severity: "critical" }),
      })
      expect(res).toBeUndefined()
    })

    test("calculates only a valid explicit vector", () => {
      const res = resolveFindingCvss({
        cvss: { vectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" },
      })
      expect(res?.baseScore).toBe(6.1)
      expect(res?.severity).toBe("MEDIUM")
    })

    test("does not score an invalid explicit vector", () => {
      const res = resolveFindingCvss({
        cvssVector: "CVSS:3.1/AV:Z/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      })
      expect(res).toBeUndefined()
    })
  })

  describe("scoreToSeverity", () => {
    test("maps scores to correct severity levels", () => {
      expect(scoreToSeverity(9.8)).toBe("CRITICAL")
      expect(scoreToSeverity(7.5)).toBe("HIGH")
      expect(scoreToSeverity(6.1)).toBe("MEDIUM")
      expect(scoreToSeverity(3.1)).toBe("LOW")
      expect(scoreToSeverity(0.0)).toBe("NONE")
    })
  })
})
