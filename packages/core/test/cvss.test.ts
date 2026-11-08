import { describe, expect, it } from "bun:test"
import { calculateCvss, parseCvssShortForm, parseCvssVector, vectorToString, type CvssVector } from "../src/security/cvss"

/**
 * Vectores de referencia verificados a mano contra la fórmula oficial de
 * FIRST.org (ISS → Impact → Exploitability → roundup), no solo contra
 * memoria de valores "conocidos" — ver el cálculo en la PR que introdujo
 * este archivo si hace falta re-verificar.
 */
describe("calculateCvss — vectores de referencia", () => {
  it("SQLi/RCE crítico sin auth: 9.8 Critical", () => {
    const v: CvssVector = {
      attackVector: "N",
      attackComplexity: "L",
      privilegesRequired: "N",
      userInteraction: "N",
      scope: "U",
      confidentiality: "H",
      integrity: "H",
      availability: "H",
    }
    const result = calculateCvss(v)
    expect(result.score).toBe(9.8)
    expect(result.severity).toBe("critical")
    expect(result.vectorString).toBe("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
  })

  it("XSS reflejado con scope cambiado: 6.1 Medium", () => {
    const v: CvssVector = {
      attackVector: "N",
      attackComplexity: "L",
      privilegesRequired: "N",
      userInteraction: "R",
      scope: "C",
      confidentiality: "L",
      integrity: "L",
      availability: "N",
    }
    const result = calculateCvss(v)
    expect(result.score).toBe(6.1)
    expect(result.severity).toBe("medium")
  })

  it("acceso local con privilegios altos e interacción requerida: 1.8 Low", () => {
    const v: CvssVector = {
      attackVector: "L",
      attackComplexity: "H",
      privilegesRequired: "H",
      userInteraction: "R",
      scope: "U",
      confidentiality: "L",
      integrity: "N",
      availability: "N",
    }
    const result = calculateCvss(v)
    expect(result.score).toBe(1.8)
    expect(result.severity).toBe("low")
  })

  it("CSRF-like sin impacto en confidencialidad: 4.3 Medium", () => {
    const v: CvssVector = {
      attackVector: "N",
      attackComplexity: "L",
      privilegesRequired: "N",
      userInteraction: "R",
      scope: "U",
      confidentiality: "N",
      integrity: "L",
      availability: "N",
    }
    const result = calculateCvss(v)
    expect(result.score).toBe(4.3)
    expect(result.severity).toBe("medium")
  })

  it("sin impacto alguno: 0.0 None", () => {
    const v: CvssVector = {
      attackVector: "N",
      attackComplexity: "L",
      privilegesRequired: "N",
      userInteraction: "N",
      scope: "U",
      confidentiality: "N",
      integrity: "N",
      availability: "N",
    }
    const result = calculateCvss(v)
    expect(result.score).toBe(0)
    expect(result.severity).toBe("none")
  })

  it("nunca produce un score mayor a 10", () => {
    const v: CvssVector = {
      attackVector: "N",
      attackComplexity: "L",
      privilegesRequired: "N",
      userInteraction: "N",
      scope: "C",
      confidentiality: "H",
      integrity: "H",
      availability: "H",
    }
    const result = calculateCvss(v)
    expect(result.score).toBeLessThanOrEqual(10)
  })
})

describe("parseCvssVector — nunca confía en input no verificado", () => {
  it("acepta un objeto con los 8 campos válidos", () => {
    const parsed = parseCvssVector({
      attackVector: "N",
      attackComplexity: "L",
      privilegesRequired: "N",
      userInteraction: "N",
      scope: "U",
      confidentiality: "H",
      integrity: "H",
      availability: "H",
    })
    expect(parsed).toBeDefined()
    expect(parsed && calculateCvss(parsed).score).toBe(9.8)
  })

  it("rechaza un valor de enum inválido", () => {
    expect(
      parseCvssVector({
        attackVector: "NETWORK",
        attackComplexity: "L",
        privilegesRequired: "N",
        userInteraction: "N",
        scope: "U",
        confidentiality: "H",
        integrity: "H",
        availability: "H",
      }),
    ).toBeUndefined()
  })

  it("rechaza un objeto con campos faltantes", () => {
    expect(parseCvssVector({ attackVector: "N", scope: "U" })).toBeUndefined()
  })

  it("rechaza input que no es un objeto", () => {
    expect(parseCvssVector("CVSS:3.1/AV:N")).toBeUndefined()
    expect(parseCvssVector(null)).toBeUndefined()
    expect(parseCvssVector(undefined)).toBeUndefined()
  })
})

describe("parseCvssShortForm — notación av/ac/pr/ui/s/c/i/a que escribe un agente", () => {
  it("acepta la notación corta en mayúsculas o minúsculas", () => {
    const parsed = parseCvssShortForm({ av: "n", ac: "L", pr: "N", ui: "n", s: "U", c: "H", i: "h", a: "H" })
    expect(parsed).toBeDefined()
    expect(parsed && calculateCvss(parsed).score).toBe(9.8)
  })

  it("rechaza si falta cualquiera de los 8 campos", () => {
    expect(parseCvssShortForm({ av: "N", ac: "L", pr: "N", ui: "N", s: "U", c: "H", i: "H" })).toBeUndefined()
  })

  it("rechaza un valor fuera del enum", () => {
    expect(
      parseCvssShortForm({ av: "N", ac: "L", pr: "N", ui: "N", s: "X", c: "H", i: "H", a: "H" }),
    ).toBeUndefined()
  })
})

describe("vectorToString", () => {
  it("produce el formato canónico CVSS:3.1/...", () => {
    const v: CvssVector = {
      attackVector: "A",
      attackComplexity: "H",
      privilegesRequired: "L",
      userInteraction: "R",
      scope: "C",
      confidentiality: "L",
      integrity: "N",
      availability: "H",
    }
    expect(vectorToString(v)).toBe("CVSS:3.1/AV:A/AC:H/PR:L/UI:R/S:C/C:L/I:N/A:H")
  })
})
