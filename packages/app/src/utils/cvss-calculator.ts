/**
 * cvss-calculator.ts
 *
 * Implementación oficial del cálculo de métricas base CVSS v3.1 según
 * la especificación de FIRST.org (Common Vulnerability Scoring System v3.1: Specification).
 *
 * Provee cálculo CVSS v3.1 únicamente cuando existe un vector base explícito y válido.
 */

export type CvssSeverityRating = "NONE" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"

export interface CvssMetrics {
  av: "N" | "A" | "L" | "P" // Attack Vector
  ac: "L" | "H" // Attack Complexity
  pr: "N" | "L" | "H" // Privileges Required
  ui: "N" | "R" // User Interaction
  s: "U" | "C" // Scope
  c: "N" | "L" | "H" // Confidentiality
  i: "N" | "L" | "H" // Integrity
  a: "N" | "L" | "H" // Availability
}

export interface CvssCalculationResult {
  vector: string
  baseScore: number
  severity: CvssSeverityRating
  impactScore: number
  exploitabilityScore: number
  metrics: CvssMetrics
}

// ── Coeficientes y Pesos de Métrica (FIRST.org CVSS v3.1) ───────────────────

const WEIGHT_AV: Record<CvssMetrics["av"], number> = {
  N: 0.85,
  A: 0.62,
  L: 0.55,
  P: 0.2,
}

const WEIGHT_AC: Record<CvssMetrics["ac"], number> = {
  L: 0.77,
  H: 0.44,
}

const WEIGHT_PR_UNCHANGED: Record<CvssMetrics["pr"], number> = {
  N: 0.85,
  L: 0.62,
  H: 0.27,
}

const WEIGHT_PR_CHANGED: Record<CvssMetrics["pr"], number> = {
  N: 0.85,
  L: 0.68,
  H: 0.5,
}

const WEIGHT_UI: Record<CvssMetrics["ui"], number> = {
  N: 0.85,
  R: 0.62,
}

const WEIGHT_CIA: Record<"N" | "L" | "H", number> = {
  N: 0.0,
  L: 0.22,
  H: 0.56,
}

/**
 * Función oficial Roundup según la especificación CVSS v3.1 de FIRST.org:
 * Redondea al decimal superior más cercano en el primer decimal.
 */
export function cvssRoundup(input: number): number {
  const intInput = Math.round(input * 100000)
  if (intInput % 10000 === 0) {
    return intInput / 100000
  }
  return (Math.floor(intInput / 10000) + 1) / 10
}

/**
 * Determina el rating de severidad cualitativa a partir de la puntuación base.
 */
export function scoreToSeverity(score: number): CvssSeverityRating {
  if (score >= 9.0) return "CRITICAL"
  if (score >= 7.0) return "HIGH"
  if (score >= 4.0) return "MEDIUM"
  if (score >= 0.1) return "LOW"
  return "NONE"
}

/**
 * Calcula la puntuación Base CVSS v3.1 a partir de las métricas.
 */
export function calculateCvssFromMetrics(metrics: CvssMetrics): CvssCalculationResult {
  const avVal = WEIGHT_AV[metrics.av] ?? 0.85
  const acVal = WEIGHT_AC[metrics.ac] ?? 0.77
  const prVal = (metrics.s === "C" ? WEIGHT_PR_CHANGED : WEIGHT_PR_UNCHANGED)[metrics.pr] ?? 0.85
  const uiVal = WEIGHT_UI[metrics.ui] ?? 0.85
  const cVal = WEIGHT_CIA[metrics.c] ?? 0
  const iVal = WEIGHT_CIA[metrics.i] ?? 0
  const aVal = WEIGHT_CIA[metrics.a] ?? 0

  // ISS = 1 - [ (1 - ImpactConf) * (1 - ImpactInteg) * (1 - ImpactAvail) ]
  const iss = 1 - (1 - cVal) * (1 - iVal) * (1 - aVal)

  let impact: number
  if (metrics.s === "U") {
    impact = 6.42 * iss
  } else {
    impact = 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15)
  }

  const exploitability = 8.22 * avVal * acVal * prVal * uiVal

  let baseScore = 0
  if (impact > 0) {
    if (metrics.s === "U") {
      baseScore = cvssRoundup(Math.min(impact + exploitability, 10))
    } else {
      baseScore = cvssRoundup(Math.min(1.08 * (impact + exploitability), 10))
    }
  }

  // Redondear sub-scores a 1 decimal para visualización limpia
  const impactScore = Math.round(impact * 10) / 10
  const exploitabilityScore = Math.round(exploitability * 10) / 10

  const vector = `CVSS:3.1/AV:${metrics.av}/AC:${metrics.ac}/PR:${metrics.pr}/UI:${metrics.ui}/S:${metrics.s}/C:${metrics.c}/I:${metrics.i}/A:${metrics.a}`

  return {
    vector,
    baseScore,
    severity: scoreToSeverity(baseScore),
    impactScore,
    exploitabilityScore,
    metrics,
  }
}

/**
 * Parsea un vector base CVSS v3.1 y valida todas sus métricas.
 */
export function parseCvssVector(vectorStr: string): CvssMetrics | undefined {
  if (!vectorStr || typeof vectorStr !== "string") return undefined
  const parts = vectorStr.trim().split("/")
  if (parts.shift()?.toUpperCase() !== "CVSS:3.1") return undefined
  const metricMap: Record<string, string> = {}

  for (const part of parts) {
    const [k, v] = part.split(":")
    const key = k?.toUpperCase()
    const value = v?.toUpperCase()
    if (!key || !value || metricMap[key] !== undefined) return undefined
    metricMap[key] = value
  }

  const allowed: Record<string, readonly string[]> = {
    AV: ["N", "A", "L", "P"],
    AC: ["L", "H"],
    PR: ["N", "L", "H"],
    UI: ["N", "R"],
    S: ["U", "C"],
    C: ["N", "L", "H"],
    I: ["N", "L", "H"],
    A: ["N", "L", "H"],
  }
  if (Object.keys(metricMap).length !== Object.keys(allowed).length) return undefined
  for (const [key, value] of Object.entries(metricMap)) {
    if (!allowed[key]?.includes(value)) return undefined
  }

  const av = metricMap["AV"] as CvssMetrics["av"]
  const ac = metricMap["AC"] as CvssMetrics["ac"]
  const pr = metricMap["PR"] as CvssMetrics["pr"]
  const ui = metricMap["UI"] as CvssMetrics["ui"]
  const s = metricMap["S"] as CvssMetrics["s"]
  const c = metricMap["C"] as CvssMetrics["c"]
  const i = metricMap["I"] as CvssMetrics["i"]
  const a = metricMap["A"] as CvssMetrics["a"]

  if (!av || !ac || !pr || !ui || !s || !c || !i || !a) {
    return undefined
  }

  return { av, ac, pr, ui, s, c, i, a }
}

/**
 * Calcula el resultado CVSS a partir de una cadena de vector.
 */
export function calculateCvssFromVector(vectorStr: string): CvssCalculationResult | undefined {
  const metrics = parseCvssVector(vectorStr)
  if (!metrics) return undefined
  return calculateCvssFromMetrics(metrics)
}

/**
 * Calcula CVSS solo a partir de un vector v3.1 explícito y válido.
 */
export function resolveFindingCvss(finding: {
  cvss?: { vectorString?: string }
  cvssVector?: string
  raw?: string
}): CvssCalculationResult | undefined {
  const rawVector = finding.raw?.match(/CVSS:3\.[01](?:\/[A-Z]+:[A-Z]+)+/i)?.[0]
  const vector = finding.cvss?.vectorString ?? finding.cvssVector ?? rawVector
  return vector ? calculateCvssFromVector(vector) : undefined
}
