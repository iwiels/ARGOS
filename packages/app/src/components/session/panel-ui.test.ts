import { describe, expect, test } from "bun:test"
import { MIN_SEGMENT_WIDTH, withVisibleSegments } from "./panel-ui"

const seg = (key: string, width: number) => ({ key, label: key, color: "red", width, display: String(width) })

describe("withVisibleSegments", () => {
  test("keeps a lone dominant category readable while the rare one stays visible", () => {
    // El caso real de NIST CSF: 1 control deficiente de 106 (0.94%), que sin
    // piso se dibujaba como una astilla invisible.
    const out = withVisibleSegments([seg("deficient", (1 / 106) * 100), seg("compliant", (105 / 106) * 100)])

    const deficient = out.find((s) => s.key === "deficient")!
    const compliant = out.find((s) => s.key === "compliant")!

    // Tras renormalizar, el piso queda algo por debajo de MIN_SEGMENT_WIDTH
    // (4 / (4 + 99.06) ≈ 3.88%). Lo que importa es que siga siendo visible:
    // ~3.9% de una barra de ~380px son ~15px.
    expect(deficient.width).toBeGreaterThan(3)
    expect(deficient.width).toBeLessThan(MIN_SEGMENT_WIDTH)
    expect(deficient.width * 106).toBeGreaterThan(seg("x", (1 / 106) * 100).width * 106 * 3)
    // El dominante debe seguir dominando claramente.
    expect(compliant.width).toBeGreaterThan(deficient.width * 10)
  })

  test("always sums to 100%", () => {
    for (const input of [
      [seg("a", (1 / 106) * 100), seg("b", (105 / 106) * 100)],
      [seg("a", 50), seg("b", 25), seg("c", 25)],
      [seg("a", 100)],
      [seg("a", 0.1), seg("b", 0.1), seg("c", 99.8)],
    ]) {
      const total = withVisibleSegments(input).reduce((sum, s) => sum + s.width, 0)
      expect(total).toBeCloseTo(100, 5)
    }
  })

  test("drops empty categories and handles an empty input", () => {
    expect(withVisibleSegments([seg("a", 0), seg("b", 100)]).map((s) => s.key)).toEqual(["b"])
    expect(withVisibleSegments([])).toEqual([])
    expect(withVisibleSegments([seg("a", 0)])).toEqual([])
  })

  test("leaves already-balanced distributions proportional", () => {
    const out = withVisibleSegments([seg("a", 50), seg("b", 50)])
    expect(out[0].width).toBeCloseTo(50, 5)
    expect(out[1].width).toBeCloseTo(50, 5)
  })
})
