/**
 * report-generator.ts
 *
 * Generador de reportes de seguridad ejecutivos y técnicos para clientes.
 * Produce un modelo de datos estructurado y enriquecido:
 * - Cálculo CVSS v3.1 desde vectores explícitos y promedio solo de hallazgos puntuados
 * - Narrativa ejecutiva de impacto al negocio y nivel de riesgo global
 * - Plan de acción / Roadmap de remediación en 3 fases (0-48h, 1-2 semanas, 1-3 meses)
 * - Mapeo completo de evidencias, PoCs (cURL/HTTP), CWE y técnicas MITRE ATT&CK
 * - Metadatos de gobierno: Cliente, alcance, clasificación, auditor y metodología
 */

import type { AttackTechnique, Finding, FindingIoc, Severity } from "@/components/session/findings-data"
import { severityRank } from "@/components/session/findings-data"
import {
  resolveFindingCvss,
  scoreToSeverity,
  type CvssCalculationResult,
  type CvssSeverityRating,
} from "./cvss-calculator"

// ── Tipos del Reporte ────────────────────────────────────────────────────────

export interface EnrichedReportFinding {
  id: string
  title: string
  severity: Severity
  status?: string
  cwe?: string
  target?: string
  vector?: string
  evidence?: string
  remediation?: string
  httpRequest?: string
  httpResponse?: string
  curlCommand?: string
  attack?: AttackTechnique[]
  iocs?: FindingIoc[]
  source: string
  cvss?: CvssCalculationResult
}

export interface RemediationPhase {
  phase: "immediate" | "shortTerm" | "mediumTerm"
  title: string
  basis: string
  description: string
  findings: EnrichedReportFinding[]
}

export interface TargetSummary {
  url: string
  total: number
  critical: number
  high: number
  medium: number
  low: number
  info: number
}

export interface TopVulnerability {
  title: string
  count: number
  severity: Severity
  cwe?: string
  cvssScore?: number
}

export interface ReportSummary {
  totalFindings: number
  totalTargets: number
  severityDistribution: Record<Severity, number>
  criticalCount: number
  highCount: number
  mediumCount: number
  lowCount: number
  infoCount: number
  averageCvss?: Pick<CvssCalculationResult, "baseScore" | "severity">
  highestCvss?: CvssCalculationResult
  cvssScoredFindings: number
  globalRiskLevel: CvssSeverityRating
  executiveNarrative: string
  topVulnerabilities: TopVulnerability[]
  targets: TargetSummary[]
  remediationRoadmap: RemediationPhase[]
}

export interface Report {
  title: string
  clientName: string
  clientLegalName?: string
  clientLogoDataUrl?: string
  scope: string
  classification: string
  leadAuditor: string
  generatedAt: string
  generatedAtISO: string
  sessionCount: number
  methodology: string
  summary: ReportSummary
  findings: EnrichedReportFinding[]
  metadata: {
    version: "1.0"
    type: "security-audit"
    engine: "argos-ai"
  }
}

// ── Narrativa Ejecutiva de Negocio ──────────────────────────────────────────

function generateExecutiveNarrative(
  total: number,
  dist: Record<Severity, number>,
  avgCvss: ReportSummary["averageCvss"],
  cvssScoredFindings: number,
  topVulns: TopVulnerability[],
): string {
  if (total === 0) {
    return "El expediente no contiene hallazgos. Esta vista no permite inferir si la auditoría se completó ni qué cobertura alcanzó."
  }

  const labels: Record<Severity, string> = {
    critical: "crítico",
    high: "alto",
    medium: "medio",
    low: "bajo",
    info: "informativo",
  }
  const breakdown = (Object.entries(dist) as [Severity, number][])
    .filter(([, count]) => count > 0)
    .map(([severity, count]) => `${count} ${labels[severity]}${count === 1 ? "" : "s"}`)
    .join(", ")
  const parts = [`Se registraron ${total} hallazgos: ${breakdown}.`]

  if (topVulns.length > 0) {
    const mainThemes = topVulns.slice(0, 3).map((v) => `"${v.title}" (${v.count})`).join(", ")
    parts.push(`Títulos incluidos: ${mainThemes}.`)
  }

  if (avgCvss) {
    parts.push(
      `Promedio CVSS v3.1: ${avgCvss.baseScore} (${avgCvss.severity}), calculado sobre ${cvssScoredFindings} hallazgos con vector válido.`,
    )
  } else {
    parts.push("No hay vectores CVSS v3.1 válidos para calcular un promedio.")
  }

  return parts.join(" ")
}

// ── Extracción y Agrupación de Targets ───────────────────────────────────────

function extractTargets(findings: EnrichedReportFinding[]): TargetSummary[] {
  const targetMap = new Map<string, TargetSummary>()

  for (const f of findings) {
    const rawTarget = f.target ?? f.vector ?? "Objetivo no indicado"
    const url = rawTarget.trim() || "Objetivo no indicado"
    const entry = targetMap.get(url) ?? {
      url,
      total: 0,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    }
    entry.total++
    if (f.severity === "critical") entry.critical++
    else if (f.severity === "high") entry.high++
    else if (f.severity === "medium") entry.medium++
    else if (f.severity === "low") entry.low++
    else if (f.severity === "info") entry.info++
    targetMap.set(url, entry)
  }

  return [...targetMap.values()].sort(
    (a, b) => b.critical - a.critical || b.high - a.high || b.total - a.total,
  )
}

// ── Ranking de Vulnerabilidades ──────────────────────────────────────────────

function topVulnerabilities(findings: EnrichedReportFinding[]): TopVulnerability[] {
  const titleMap = new Map<string, TopVulnerability>()

  for (const f of findings) {
    const entry = titleMap.get(f.title) ?? {
      title: f.title,
      count: 0,
      severity: f.severity,
      cwe: f.cwe,
      cvssScore: f.cvss?.baseScore,
    }
    entry.count++
    if (severityRank(f.severity) < severityRank(entry.severity)) {
      entry.severity = f.severity
      entry.cwe = f.cwe ?? entry.cwe
    }
    if (f.cvss && (entry.cvssScore === undefined || f.cvss.baseScore > entry.cvssScore)) {
      entry.cvssScore = f.cvss.baseScore
    }
    titleMap.set(f.title, entry)
  }

  return [...titleMap.values()]
    .sort(
      (a, b) =>
        severityRank(a.severity) - severityRank(b.severity) ||
        (b.cvssScore ?? -1) - (a.cvssScore ?? -1) ||
        b.count - a.count,
    )
    .slice(0, 10)
}

// ── Plan de Remediación Priorizado (Roadmap) ────────────────────────────────

function buildRemediationRoadmap(findings: EnrichedReportFinding[]): RemediationPhase[] {
  const immediate: EnrichedReportFinding[] = []
  const shortTerm: EnrichedReportFinding[] = []
  const mediumTerm: EnrichedReportFinding[] = []

  for (const f of findings) {
    if (f.severity === "critical" || (f.severity === "high" && f.cvss !== undefined && f.cvss.baseScore >= 8.0)) {
      immediate.push(f)
    } else if (f.severity === "high" || f.severity === "medium") {
      shortTerm.push(f)
    } else {
      mediumTerm.push(f)
    }
  }

  return [
    {
      phase: "immediate",
      title: "Prioridad 1 — Validación temprana",
      basis: "Crítico y alto con CVSS ≥ 8.0",
      description:
        "Agrupación calculada por severidad y puntuación disponibles. Confirma la evidencia, exposición y contexto antes de fijar un plazo de remediación.",
      findings: immediate,
    },
    {
      phase: "shortTerm",
      title: "Prioridad 2 — Revisión prioritaria",
      basis: "Alto y medio no incluidos en prioridad 1",
      description:
        "Revisa la evidencia y la recomendación asociada a cada hallazgo. Define el plazo según el activo y el contexto de exposición.",
      findings: shortTerm,
    },
    {
      phase: "mediumTerm",
      title: "Prioridad 3 — Seguimiento",
      basis: "Bajo e informativo",
      description:
        "Comprueba si el hallazgo aplica al activo y conserva su recomendación registrada. La clasificación por sí sola no establece un plazo.",
      findings: mediumTerm,
    },
  ]
}

// ── Generador Principal ──────────────────────────────────────────────────────

export function generateReport(input: {
  findings: Finding[]
  sessionCount: number
  title?: string
  clientName?: string
  clientLegalName?: string
  clientLogoDataUrl?: string
  scope?: string
  classification?: string
  leadAuditor?: string
  methodology?: string
  locale?: string
}): Report {
  const {
    findings: rawFindings,
    sessionCount,
    title,
    clientName = "No indicado",
    clientLegalName,
    clientLogoDataUrl,
    scope = "No indicado",
    classification = "No indicada",
    leadAuditor = "No indicado",
    methodology = "No indicada",
  } = input

  const now = new Date()

  // Calcular CVSS solo cuando el finding incluye un vector explícito válido.
  const enrichedFindings: EnrichedReportFinding[] = rawFindings.map((f, idx) => {
    const cvss = resolveFindingCvss(f)
    return {
      id: f.id ?? `FIND-${String(idx + 1).padStart(3, "0")}`,
      title: f.title,
      severity: f.severity,
      status: f.status,
      cwe: f.cwe,
      target: f.target,
      vector: f.vector,
      evidence: f.evidence,
      remediation: f.remediation,
      httpRequest: f.httpRequest,
      httpResponse: f.httpResponse,
      curlCommand: f.curlCommand,
      attack: f.attack,
      iocs: f.iocs,
      source: f.source,
      cvss,
    }
  })

  // Distribución de severidades
  const distribution: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  }
  for (const f of enrichedFindings) {
    distribution[f.severity]++
  }

  const scoredFindings = enrichedFindings.flatMap((finding) => (finding.cvss ? [finding.cvss] : []))
  const cvssScoredFindings = scoredFindings.length
  const avgScore =
    cvssScoredFindings > 0
      ? Math.round((scoredFindings.reduce((sum, cvss) => sum + cvss.baseScore, 0) / cvssScoredFindings) * 10) / 10
      : undefined
  const averageCvss = avgScore === undefined ? undefined : { baseScore: avgScore, severity: scoreToSeverity(avgScore) }
  const highestCvss = scoredFindings.reduce<CvssCalculationResult | undefined>(
    (highest, current) => (!highest || current.baseScore > highest.baseScore ? current : highest),
    undefined,
  )

  const topVulns = topVulnerabilities(enrichedFindings)
  const targets = extractTargets(enrichedFindings)
  const roadmap = buildRemediationRoadmap(enrichedFindings)
  const narrative = generateExecutiveNarrative(enrichedFindings.length, distribution, averageCvss, cvssScoredFindings, topVulns)

  const globalRiskLevel: CvssSeverityRating =
    distribution.critical > 0
      ? "CRITICAL"
      : distribution.high > 0
        ? "HIGH"
        : distribution.medium > 0
          ? "MEDIUM"
          : distribution.low > 0
            ? "LOW"
            : "NONE"

  return {
    title: title ?? `Informe Ejecutivo de Auditoría de Seguridad — ${now.toLocaleDateString("es-AR")}`,
    clientName,
    clientLegalName: clientLegalName || undefined,
    clientLogoDataUrl: clientLogoDataUrl || undefined,
    scope,
    classification,
    leadAuditor,
    generatedAt: now.toLocaleString("es-AR", {
      dateStyle: "long",
      timeStyle: "short",
    }),
    generatedAtISO: now.toISOString(),
    sessionCount,
    methodology,
    summary: {
      totalFindings: enrichedFindings.length,
      totalTargets: targets.length,
      severityDistribution: distribution,
      criticalCount: distribution.critical,
      highCount: distribution.high,
      mediumCount: distribution.medium,
      lowCount: distribution.low,
      infoCount: distribution.info,
      averageCvss,
      highestCvss,
      cvssScoredFindings,
      globalRiskLevel,
      executiveNarrative: narrative,
      topVulnerabilities: topVulns,
      targets,
      remediationRoadmap: roadmap,
    },
    findings: enrichedFindings,
    metadata: {
      version: "1.0",
      type: "security-audit",
      engine: "argos-ai",
    },
  }
}

/** Color CSS semántico para puntuación CVSS. */
export function cvssColor(score: number): string {
  if (score >= 9.0) return "var(--severity-fg-critical)"
  if (score >= 7.0) return "var(--severity-fg-high)"
  if (score >= 4.0) return "var(--severity-fg-medium)"
  if (score > 0) return "var(--severity-fg-low)"
  return "var(--severity-fg-info)"
}

/** Etiqueta traducible o localizada para severidad CVSS. */
export function cvssLabel(severity: string, t?: (key: string) => string | undefined): string {
  if (t) {
    const keyMap: Record<string, string> = {
      NONE: "severity.info",
      LOW: "severity.low",
      MEDIUM: "severity.medium",
      HIGH: "severity.high",
      CRITICAL: "severity.critical",
      none: "severity.info",
      low: "severity.low",
      medium: "severity.medium",
      high: "severity.high",
      critical: "severity.critical",
    }
    const val = t(keyMap[severity])
    if (val) return val
  }

  const labels: Record<string, string> = {
    NONE: "Informativo",
    LOW: "Bajo",
    MEDIUM: "Medio",
    HIGH: "Alto",
    CRITICAL: "Crítico",
  }
  return labels[severity.toUpperCase()] ?? severity
}
