/**
 * Calculadora de CVSS v3.1 Base Score, implementada desde la especificación
 * pública de FIRST.org (https://www.first.org/cvss/v3.1/specification-document).
 * Sin dependencias de terceros — la fórmula es un estándar abierto, no código
 * de nadie. Constantes y algoritmo verificados contra vectores de referencia
 * publicados (ver cvss.test.ts).
 *
 * Patrón deliberado: quien llama (agente o auditor) elige los 8 valores
 * semánticos del vector — cada uno es una observación verificable ("¿requiere
 * autenticación?", "¿cambia el scope?") — y esta función calcula el número.
 * El LLM nunca decide el score directamente; eso es lo que evita puntajes
 * inventados o inconsistentes entre hallazgos similares.
 */

export type AttackVector = "N" | "A" | "L" | "P"
export type AttackComplexity = "L" | "H"
export type PrivilegesRequired = "N" | "L" | "H"
export type UserInteraction = "N" | "R"
export type Scope = "U" | "C"
export type ImpactMetric = "N" | "L" | "H"

export interface CvssVector {
  attackVector: AttackVector
  attackComplexity: AttackComplexity
  privilegesRequired: PrivilegesRequired
  userInteraction: UserInteraction
  scope: Scope
  confidentiality: ImpactMetric
  integrity: ImpactMetric
  availability: ImpactMetric
}

export type CvssSeverity = "none" | "low" | "medium" | "high" | "critical"

export interface CvssResult {
  score: number
  severity: CvssSeverity
  vectorString: string
}

const AV_WEIGHT: Record<AttackVector, number> = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 }
const AC_WEIGHT: Record<AttackComplexity, number> = { L: 0.77, H: 0.44 }
const PR_WEIGHT_UNCHANGED: Record<PrivilegesRequired, number> = { N: 0.85, L: 0.62, H: 0.27 }
const PR_WEIGHT_CHANGED: Record<PrivilegesRequired, number> = { N: 0.85, L: 0.68, H: 0.5 }
const UI_WEIGHT: Record<UserInteraction, number> = { N: 0.85, R: 0.62 }
const IMPACT_WEIGHT: Record<ImpactMetric, number> = { H: 0.56, L: 0.22, N: 0 }

/**
 * Redondeo definido por la especificación CVSS: "round up to the nearest
 * 0.1". Trabaja en enteros escalados por 100000 para evitar errores de punto
 * flotante — es el algoritmo textual del documento oficial, no una
 * aproximación.
 */
function roundUp(value: number): number {
  const intInput = Math.round(value * 100000)
  if (intInput % 10000 === 0) return intInput / 100000
  return (Math.floor(intInput / 10000) + 1) / 10
}

function severityFor(score: number): CvssSeverity {
  if (score === 0) return "none"
  if (score < 4) return "low"
  if (score < 7) return "medium"
  if (score < 9) return "high"
  return "critical"
}

export function vectorToString(v: CvssVector): string {
  return `CVSS:3.1/AV:${v.attackVector}/AC:${v.attackComplexity}/PR:${v.privilegesRequired}/UI:${v.userInteraction}/S:${v.scope}/C:${v.confidentiality}/I:${v.integrity}/A:${v.availability}`
}

/** Calcula el Base Score de CVSS v3.1. Nunca lanza — un vector válido por construcción de tipos siempre produce un resultado. */
export function calculateCvss(v: CvssVector): CvssResult {
  const iss = 1 - (1 - IMPACT_WEIGHT[v.confidentiality]) * (1 - IMPACT_WEIGHT[v.integrity]) * (1 - IMPACT_WEIGHT[v.availability])

  const impact =
    v.scope === "U"
      ? 6.42 * iss
      : 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15)

  const prWeight = v.scope === "U" ? PR_WEIGHT_UNCHANGED : PR_WEIGHT_CHANGED
  const exploitability = 8.22 * AV_WEIGHT[v.attackVector] * AC_WEIGHT[v.attackComplexity] * prWeight[v.privilegesRequired] * UI_WEIGHT[v.userInteraction]

  let score: number
  if (impact <= 0) {
    score = 0
  } else if (v.scope === "U") {
    score = roundUp(Math.min(impact + exploitability, 10))
  } else {
    score = roundUp(Math.min(1.08 * (impact + exploitability), 10))
  }

  return { score, severity: severityFor(score), vectorString: vectorToString(v) }
}

const ENUM_SETS = {
  attackVector: ["N", "A", "L", "P"],
  attackComplexity: ["L", "H"],
  privilegesRequired: ["N", "L", "H"],
  userInteraction: ["N", "R"],
  scope: ["U", "C"],
  confidentiality: ["N", "L", "H"],
  integrity: ["N", "L", "H"],
  availability: ["N", "L", "H"],
} as const satisfies Record<keyof CvssVector, readonly string[]>

/** Valida que un objeto arbitrario (p. ej. del payload de un agente) sea un CvssVector completo y bien formado. */
export function parseCvssVector(input: unknown): CvssVector | undefined {
  if (!input || typeof input !== "object") return undefined
  const record = input as Record<string, unknown>
  const result: Record<string, string> = {}
  for (const key of Object.keys(ENUM_SETS) as (keyof CvssVector)[]) {
    const value = record[key]
    if (typeof value !== "string" || !(ENUM_SETS[key] as readonly string[]).includes(value)) return undefined
    result[key] = value
  }
  return result as unknown as CvssVector
}

const SHORT_FORM_KEYS: Record<keyof CvssVector, string> = {
  attackVector: "av",
  attackComplexity: "ac",
  privilegesRequired: "pr",
  userInteraction: "ui",
  scope: "s",
  confidentiality: "c",
  integrity: "i",
  availability: "a",
}

/**
 * Igual que parseCvssVector, pero acepta la notación corta del vector oficial
 * (av/ac/pr/ui/s/c/i/a) — la forma en la que un agente que ya conoce CVSS
 * la va a escribir de forma más confiable que un nombre de campo inventado.
 */
export function parseCvssShortForm(input: unknown): CvssVector | undefined {
  if (!input || typeof input !== "object") return undefined
  const record = input as Record<string, unknown>
  const result: Record<string, string> = {}
  for (const key of Object.keys(ENUM_SETS) as (keyof CvssVector)[]) {
    const value = record[SHORT_FORM_KEYS[key]]
    if (typeof value !== "string") return undefined
    const upper = value.toUpperCase()
    if (!(ENUM_SETS[key] as readonly string[]).includes(upper)) return undefined
    result[key] = upper
  }
  return result as unknown as CvssVector
}
