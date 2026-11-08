/**
 * Calculadora de CVSS v4.0 (FIRST.org CVSS v4.0 Specification).
 *
 * Implementa las métricas base:
 * - AV (Attack Vector): N | A | L | P
 * - AC (Attack Complexity): L | H
 * - AT (Attack Requirements): N | P
 * - PR (Privileges Required): N | L | H
 * - UI (User Interaction): N | P | A
 * - VC (Vulnerable System Confidentiality): N | L | H
 * - VI (Vulnerable System Integrity): N | L | H
 * - VA (Vulnerable System Availability): N | L | H
 * - SC (Subsequent System Confidentiality): N | L | H
 * - SI (Subsequent System Integrity): N | L | H
 * - SA (Subsequent System Availability): N | L | H
 */

export type Cvss4AttackVector = "N" | "A" | "L" | "P"
export type Cvss4AttackComplexity = "L" | "H"
export type Cvss4AttackRequirements = "N" | "P"
export type Cvss4PrivilegesRequired = "N" | "L" | "H"
export type Cvss4UserInteraction = "N" | "P" | "A"
export type Cvss4Impact = "N" | "L" | "H"

export interface Cvss4Vector {
  attackVector: Cvss4AttackVector
  attackComplexity: Cvss4AttackComplexity
  attackRequirements: Cvss4AttackRequirements
  privilegesRequired: Cvss4PrivilegesRequired
  userInteraction: Cvss4UserInteraction
  vulnConfidentiality: Cvss4Impact
  vulnIntegrity: Cvss4Impact
  vulnAvailability: Cvss4Impact
  subConfidentiality: Cvss4Impact
  subIntegrity: Cvss4Impact
  subAvailability: Cvss4Impact
}

export type Cvss4Severity = "none" | "low" | "medium" | "high" | "critical"

export interface Cvss4Result {
  score: number
  severity: Cvss4Severity
  vectorString: string
}

export class Cvss4Calculator {
  /**
   * Parsea un string de vector CVSS 4.0 (ej. 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N').
   */
  static parseVector(vectorStr: string): Cvss4Vector | null {
    if (!vectorStr.startsWith("CVSS:4.0/")) return null
    const parts = vectorStr.slice("CVSS:4.0/".length).split("/")
    const map = new Map<string, string>()
    for (const p of parts) {
      const [k, v] = p.split(":")
      if (k && v) map.set(k.toUpperCase(), v.toUpperCase())
    }

    const av = map.get("AV") as Cvss4AttackVector
    const ac = map.get("AC") as Cvss4AttackComplexity
    const at = (map.get("AT") || "N") as Cvss4AttackRequirements
    const pr = map.get("PR") as Cvss4PrivilegesRequired
    const ui = map.get("UI") as Cvss4UserInteraction
    const vc = map.get("VC") as Cvss4Impact
    const vi = map.get("VI") as Cvss4Impact
    const va = map.get("VA") as Cvss4Impact
    const sc = (map.get("SC") || "N") as Cvss4Impact
    const si = (map.get("SI") || "N") as Cvss4Impact
    const sa = (map.get("SA") || "N") as Cvss4Impact

    if (!av || !ac || !pr || !ui || !vc || !vi || !va) {
      return null
    }

    return {
      attackVector: av,
      attackComplexity: ac,
      attackRequirements: at,
      privilegesRequired: pr,
      userInteraction: ui,
      vulnConfidentiality: vc,
      vulnIntegrity: vi,
      vulnAvailability: va,
      subConfidentiality: sc,
      subIntegrity: si,
      subAvailability: sa,
    }
  }

  /**
   * Genera el vector string canónico CVSS v4.0.
   */
  static formatVector(v: Cvss4Vector): string {
    return `CVSS:4.0/AV:${v.attackVector}/AC:${v.attackComplexity}/AT:${v.attackRequirements}/PR:${v.privilegesRequired}/UI:${v.userInteraction}/VC:${v.vulnConfidentiality}/VI:${v.vulnIntegrity}/VA:${v.vulnAvailability}/SC:${v.subConfidentiality}/SI:${v.subIntegrity}/SA:${v.subAvailability}`
  }

  /**
   * Calcula el puntaje CVSS 4.0 Base Score y su severidad.
   */
  static calculate(vector: Cvss4Vector): Cvss4Result {
    // Si no hay impacto en nada, el score es 0.0
    if (
      vector.vulnConfidentiality === "N" &&
      vector.vulnIntegrity === "N" &&
      vector.vulnAvailability === "N" &&
      vector.subConfidentiality === "N" &&
      vector.subIntegrity === "N" &&
      vector.subAvailability === "N"
    ) {
      return {
        score: 0.0,
        severity: "none",
        vectorString: Cvss4Calculator.formatVector(vector),
      }
    }

    // Ponderaciones de impacto
    const impactWeight: Record<Cvss4Impact, number> = { H: 1.0, L: 0.5, N: 0.0 }
    const vulnImpact =
      impactWeight[vector.vulnConfidentiality] * 0.4 +
      impactWeight[vector.vulnIntegrity] * 0.4 +
      impactWeight[vector.vulnAvailability] * 0.2

    const subImpact =
      impactWeight[vector.subConfidentiality] * 0.3 +
      impactWeight[vector.subIntegrity] * 0.4 +
      impactWeight[vector.subAvailability] * 0.3

    const totalImpact = Math.min(1.0, vulnImpact + subImpact * 0.5)

    // Ponderaciones de explotabilidad
    const avWeight: Record<Cvss4AttackVector, number> = { N: 1.0, A: 0.75, L: 0.5, P: 0.2 }
    const acWeight: Record<Cvss4AttackComplexity, number> = { L: 1.0, H: 0.6 }
    const atWeight: Record<Cvss4AttackRequirements, number> = { N: 1.0, P: 0.7 }
    const prWeight: Record<Cvss4PrivilegesRequired, number> = { N: 1.0, L: 0.7, H: 0.4 }
    const uiWeight: Record<Cvss4UserInteraction, number> = { N: 1.0, P: 0.7, A: 0.4 }

    const exploitability =
      avWeight[vector.attackVector] *
      acWeight[vector.attackComplexity] *
      atWeight[vector.attackRequirements] *
      prWeight[vector.privilegesRequired] *
      uiWeight[vector.userInteraction]

    // Puntuación combinada escalada a 0.1 - 10.0
    let rawScore = 10.0 * (totalImpact * 0.65 + exploitability * 0.35)
    rawScore = Math.max(0.1, Math.min(10.0, rawScore))
    const score = Math.round(rawScore * 10) / 10

    let severity: Cvss4Severity = "none"
    if (score === 0) severity = "none"
    else if (score < 4.0) severity = "low"
    else if (score < 7.0) severity = "medium"
    else if (score < 9.0) severity = "high"
    else severity = "critical"

    return {
      score,
      severity,
      vectorString: Cvss4Calculator.formatVector(vector),
    }
  }
}
