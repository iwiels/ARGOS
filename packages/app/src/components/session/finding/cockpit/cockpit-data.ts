import type { Finding, Severity } from "../../findings-data"
import type { CockpitFinding, NistDomain } from "./cockpit-types"

export const NIST_DOMAINS: NistDomain[] = [
  {
    code: "GV",
    name: "GOBERNANZA",
    status: "Sin evaluar",
    score: "Sin evaluar",
    subcontrols: [
      { code: "GV.OC", name: "Contexto Organizacional", status: "Sin evaluar", findings: [] },
      { code: "GV.RM", name: "Estrategia de Gestión de Riesgos", status: "Sin evaluar", findings: [] },
      { code: "GV.RR", name: "Roles, Responsabilidades y Autoridades", status: "Sin evaluar", findings: [] },
      { code: "GV.PO", name: "Políticas", status: "Sin evaluar", findings: [] },
      { code: "GV.OV", name: "Supervisión y Control", status: "Sin evaluar", findings: [] },
      { code: "GV.SC", name: "Gestión de Riesgos en Cadena de Suministro", status: "Sin evaluar", findings: [] },
    ],
  },
  {
    code: "ID",
    name: "IDENTIFICACIÓN",
    status: "Sin evaluar",
    score: "Sin evaluar",
    subcontrols: [
      { code: "ID.AM", name: "Gestión de Activos", status: "Sin evaluar", findings: [] },
      { code: "ID.RA", name: "Evaluación de Riesgos", status: "Sin evaluar", findings: [] },
      { code: "ID.IM", name: "Mejora Continua", status: "Sin evaluar", findings: [] },
    ],
  },
  {
    code: "PR",
    name: "PROTECCIÓN",
    status: "Sin evaluar",
    score: "Sin evaluar",
    subcontrols: [
      { code: "PR.AA", name: "Gestión de Identidad, Autenticación y Control de Acceso", status: "Sin evaluar", findings: [] },
      { code: "PR.AT", name: "Concienciación y Capacitación", status: "Sin evaluar", findings: [] },
      { code: "PR.DS", name: "Seguridad de los Datos", status: "Sin evaluar", findings: [] },
      { code: "PR.PS", name: "Seguridad de Plataformas y Servicios", status: "Sin evaluar", findings: [] },
      { code: "PR.IR", name: "Resiliencia de la Infraestructura Tecnológica", status: "Sin evaluar", findings: [] },
    ],
  },
  {
    code: "DE",
    name: "DETECCIÓN",
    status: "Sin evaluar",
    score: "Sin evaluar",
    subcontrols: [
      { code: "DE.AE", name: "Análisis de Eventos Adversos", status: "Sin evaluar", findings: [] },
      { code: "DE.CM", name: "Monitoreo Continuo de Seguridad", status: "Sin evaluar", findings: [] },
    ],
  },
  {
    code: "RS",
    name: "RESPUESTA",
    status: "Sin evaluar",
    score: "Sin evaluar",
    subcontrols: [
      { code: "RS.MA", name: "Gestión de Incidentes", status: "Sin evaluar", findings: [] },
      { code: "RS.AN", name: "Análisis de Incidentes", status: "Sin evaluar", findings: [] },
      { code: "RS.CO", name: "Reportes y Comunicación de Incidentes", status: "Sin evaluar", findings: [] },
      { code: "RS.MI", name: "Mitigación de Incidentes", status: "Sin evaluar", findings: [] },
    ],
  },
  {
    code: "RC",
    name: "RECUPERACIÓN",
    status: "Sin evaluar",
    score: "Sin evaluar",
    subcontrols: [
      { code: "RC.RP", name: "Ejecución del Plan de Recuperación", status: "Sin evaluar", findings: [] },
      { code: "RC.CO", name: "Comunicación de Recuperación", status: "Sin evaluar", findings: [] },
    ],
  },
]

export const ISO_DOMAINS: NistDomain[] = [
  {
    code: "A.5",
    name: "CONTROLES ORGANIZACIONALES",
    status: "Sin evaluar",
    score: "Sin evaluar",
    subcontrols: [
      { code: "A.5.1", name: "Políticas de Seguridad de la Información", status: "Sin evaluar", findings: [] },
      { code: "A.5.15", name: "Control de Acceso", status: "Sin evaluar", findings: [] },
      { code: "A.5.19", name: "Seguridad de la Información en Relaciones con Proveedores", status: "Sin evaluar", findings: [] },
      { code: "A.5.20", name: "Gestión de Seguridad en la Cadena de Suministro TIC", status: "Sin evaluar", findings: [] },
    ],
  },
  {
    code: "A.6",
    name: "CONTROLES DE PERSONAS",
    status: "Sin evaluar",
    score: "Sin evaluar",
    subcontrols: [
      { code: "A.6.1", name: "Selección de Personal", status: "Sin evaluar", findings: [] },
      { code: "A.6.3", name: "Toma de Conciencia en Seguridad", status: "Sin evaluar", findings: [] },
    ],
  },
  {
    code: "A.7",
    name: "CONTROLES FÍSICOS",
    status: "Sin evaluar",
    score: "Sin evaluar",
    subcontrols: [
      { code: "A.7.1", name: "Perímetros de Seguridad Física", status: "Sin evaluar", findings: [] },
      { code: "A.7.4", name: "Monitoreo de Seguridad Física", status: "Sin evaluar", findings: [] },
    ],
  },
  {
    code: "A.8",
    name: "CONTROLES TECNOLÓGICOS",
    status: "Sin evaluar",
    score: "Sin evaluar",
    subcontrols: [
      { code: "A.8.1", name: "Dispositivos de Usuario Final", status: "Sin evaluar", findings: [] },
      { code: "A.8.8", name: "Gestión de Vulnerabilidades Técnicas", status: "Sin evaluar", findings: [] },
      { code: "A.8.20", name: "Seguridad de Redes y Servicios de Red", status: "Sin evaluar", findings: [] },
      { code: "A.8.24", name: "Uso de Criptografía y Certificados", status: "Sin evaluar", findings: [] },
    ],
  },
]

export function mapToCockpitFinding(f: Finding, index: number): CockpitFinding {
  const shortId = `FIND-${String(index + 1).padStart(3, "0")}`
  const severity = f.severity ?? "info"
  const severityLabel = severity.toUpperCase()

  const mitre = (f.attack ?? []).map((t) => ({
    id: t.id,
    name: t.name,
    tool: t.reason,
  }))

  const iocs = (f.iocs ?? []).map((ioc) => ({
    type: ioc.type.toUpperCase(),
    value: ioc.value,
  }))

  return {
    id: f.id ?? f.observationID ?? `live_${index}_${f.title.slice(0, 16)}`,
    shortId,
    severity,
    severityLabel,
    cvss: f.cvss?.score,
    cvssImpactNote: f.cvss?.severity ? `Impacto: ${f.cvss.severity}` : undefined,
    vector: f.vector || f.cvss?.vectorString,
    cwe: f.cwe,
    status: f.status || "open",
    persisted: !!(f.id && f.session),
    title: f.title,
    target: f.target,
    orchestrator: f.agent || f.sourceTool,
    mitre,
    iocs,
    poc: f.evidence,
    remediation: f.remediation,
    nistLinks: [],
    httpRequest: f.httpRequest,
    httpResponse: f.httpResponse,
    curlCommand: f.curlCommand,
    cisaKev: f.epssKev?.cisaKev,
    epssScore: f.epssKev?.epssScore,
    session: f.session,
    raw: f.raw,
    feedback: f.feedback,
  }
}

export function reportableCockpitFindings(findings: readonly CockpitFinding[]): CockpitFinding[] {
  return findings.filter((finding) => finding.status !== "false-positive" && finding.feedback?.verdict !== "false-positive")
}

export function cockpitFindingMetrics(findings: readonly CockpitFinding[]) {
  const reportable = reportableCockpitFindings(findings)
  const severityCounts: Record<Severity | "all", number> = { all: reportable.length, critical: 0, high: 0, medium: 0, low: 0, info: 0 }
  for (const finding of reportable) severityCounts[finding.severity]++
  const scores = reportable.flatMap((finding) => finding.cvss === undefined ? [] : [finding.cvss])
  return {
    severityCounts,
    maxCvss: scores.length ? Math.max(...scores) : undefined,
    targetCount: new Set(reportable.map((finding) => finding.target).filter(Boolean)).size,
  }
}

export function aggregateAttackTechniques(findings: CockpitFinding[]): { id: string; name: string }[] {
  const map = new Map<string, string>()
  for (const f of findings) {
    for (const m of f.mitre) {
      if (!map.has(m.id)) {
        map.set(m.id, m.name)
      }
    }
  }
  return Array.from(map.entries()).map(([id, name]) => ({ id, name }))
}

export function deriveComplianceDomains(
  domains: readonly NistDomain[],
  findings: readonly CockpitFinding[],
): NistDomain[] {
  return domains.map((domain) => {
    const subcontrols = domain.subcontrols.map((subcontrol) => {
      const linkedFindings = findings.filter((finding) => finding.nistLinks?.includes(subcontrol.code))
      return {
        ...subcontrol,
        status: linkedFindings.length > 0 ? ("Requiere revisión" as const) : ("Sin evaluar" as const),
        findings: linkedFindings.map((finding) => finding.shortId),
      }
    })
    const linkedCount = subcontrols.filter((subcontrol) => subcontrol.status === "Requiere revisión").length
    return {
      ...domain,
      status: linkedCount > 0 ? ("Requiere revisión" as const) : ("Sin evaluar" as const),
      score: `${linkedCount} con hallazgos vinculados`,
      subcontrols,
    }
  })
}
