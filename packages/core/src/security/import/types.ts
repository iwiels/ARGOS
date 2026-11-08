import type { FindingContract, Severity } from "../contract"

export type ImportFormat =
  | "sarif"
  | "nuclei"
  | "semgrep"
  | "trivy"
  | "gitleaks"
  | "zap"
  | "burp"
  | "defectdojo"

export interface ImportSummary {
  total: number
  critical: number
  high: number
  medium: number
  low: number
  info: number
}

export interface ParsedImportResult {
  format: ImportFormat
  scanner: string
  version?: string
  target?: string
  isCompleteScan: boolean
  findings: FindingContract[]
  summary: ImportSummary
}

export interface ImportParserContract {
  readonly format: ImportFormat
  readonly version: string
  readonly maxSizeBytes: number
  readonly maxDepth: number
  parse(content: string, options?: { target?: string; isCompleteScan?: boolean }): ParsedImportResult
}

export function computeSummary(findings: FindingContract[]): ImportSummary {
  const summary: ImportSummary = { total: findings.length, critical: 0, high: 0, medium: 0, low: 0, info: 0 }
  for (const f of findings) {
    const s = f.severity?.toLowerCase()
    if (s === "critical") summary.critical++
    else if (s === "high") summary.high++
    else if (s === "medium") summary.medium++
    else if (s === "low") summary.low++
    else summary.info++
  }
  return summary
}
