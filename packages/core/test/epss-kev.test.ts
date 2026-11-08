import { describe, expect, it } from "bun:test"
import { extractCves, enrichEpssAndKev, checkCisaKev, lookupEpss } from "../src/threat-intel/epss-kev"
import { Effect } from "effect"

describe("threat-intel: epss-kev", () => {
  it("extracts unique CVEs from text, json or tags", () => {
    const raw = "Vulnerabilidad detectada en CVE-2023-38606 y cve-2021-44228. Referencia duplicada: CVE-2023-38606."
    const extracted = extractCves(raw)
    expect(extracted).toEqual(["CVE-2023-38606", "CVE-2021-44228"])
  })

  it("handles empty or non-CVE input gracefully", () => {
    expect(extractCves("")).toEqual([])
    expect(extractCves(null)).toEqual([])
    expect(extractCves("No vulnerabilities found")).toEqual([])
    expect(extractCves({ text: "Clean target" })).toEqual([])
  })

  it("extracts CVEs embedded in objects or arrays", () => {
    const obj = {
      evidence: { detail: "Affected by CVE-2024-21413" },
      tags: ["cve-2020-1472", "remote-code-execution"],
    }
    const extracted = extractCves(obj)
    expect(extracted).toContain("CVE-2024-21413")
    expect(extracted).toContain("CVE-2020-1472")
  })

  it("handles EPSS and KEV enrichment for empty array", async () => {
    const result = await Effect.runPromise(enrichEpssAndKev([]))
    expect(result).toBeUndefined()
  })
})
