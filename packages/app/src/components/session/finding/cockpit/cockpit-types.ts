import type { FindingFeedback, Severity } from "../../findings-data"

export type CockpitTab = "findings" | "compliance" | "report"

export interface CockpitFinding {
  id: string
  shortId: string
  severity: Severity
  severityLabel: string
  cvss?: number
  cvssImpactNote?: string
  vector?: string
  cwe?: string
  status: string
  persisted: boolean
  title: string
  target?: string
  orchestrator?: string
  mitre: { id: string; name: string; tool?: string }[]
  iocs: { type: string; value: string }[]
  poc?: string
  remediation?: string
  nistLinks?: string[]
  httpRequest?: string
  httpResponse?: string
  curlCommand?: string
  cisaKev?: boolean
  epssScore?: number
  session?: string
  raw?: string
  feedback?: FindingFeedback
}

export interface NistSubcontrol {
  code: string
  name: string
  status: "Cumple" | "Parcial" | "Deficiente" | "Requiere revisión" | "Sin evaluar"
  findings: string[]
}

export interface NistDomain {
  code: string
  name: string
  status: "Cumple" | "Parcial" | "Deficiente" | "Requiere revisión" | "Sin evaluar"
  score: string
  subcontrols: NistSubcontrol[]
}

export type ComplianceFramework = "NIST" | "ISO"
export type ComplianceFilter = "all" | "Deficiente" | "Parcial" | "Cumple" | "Requiere revisión" | "Sin evaluar" | "issues"

export interface DossierMetadata {
  scope: string
  auditor: string
  client: string
  tlp: string
  signed: boolean
  signedAt?: string
}
