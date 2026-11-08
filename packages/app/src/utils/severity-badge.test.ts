import { describe, expect, test } from "bun:test"
import { SEV_BADGE } from "./severity"
import { severityBadgeTone } from "./severity-badge"
import { SEVERITY_ORDER } from "@/components/session/findings-data"

describe("severityBadgeTone", () => {
  test("cubre las 5 severidades con el mapa SEV_BADGE", () => {
    expect(SEVERITY_ORDER).toHaveLength(5)
    for (const sev of SEVERITY_ORDER) {
      expect(severityBadgeTone(sev)).toBe(SEV_BADGE[sev])
    }
  })

  test("cada tono referencia tokens --severity-* (bg + fg)", () => {
    for (const sev of SEVERITY_ORDER) {
      const tone = severityBadgeTone(sev)
      expect(tone).toContain(`bg-severity-bg-${sev}`)
      expect(tone).toContain(`text-severity-fg-${sev}`)
    }
  })
})
