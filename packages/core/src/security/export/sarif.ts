/**
 * Export SARIF 2.1.0.
 *
 * Reusa el generador canónico de `packages/core/src/security/sarif.ts` —que ya
 * emite `codeFlows`, `partialFingerprints` y `taxonomies`, las tres cosas que
 * el parser Go (`argos-bin/cmd/web/tools/sarif.go`) preserva al reingestar— y
 * sólo lo adapta al contrato de export (nombre de archivo + mime).
 */

import { generateSarifLog, type SarifFinding } from "../sarif"
import type { ReportDocument, ReportFinding } from "./model"

export function toSarifFindings(findings: ReportFinding[]): SarifFinding[] {
  return findings.map((finding) => ({
    id: finding.id,
    fingerprint: finding.fingerprint,
    title: finding.title,
    severity: finding.severity,
    status: finding.status,
    cwe: finding.cwe,
    owasp: finding.owasp,
    references: finding.references,
    vector: finding.vector,
    target: finding.target,
    remediation: finding.remediation,
    tags: finding.tags,
    attackTechniqueIds: finding.attackTechniqueIds,
    sourceTool: finding.sourceTool,
    epssScore: finding.epssScore,
    cisaKev: finding.cisaKev,
    cvssScore: finding.cvssScore,
    cvssVector: finding.cvssVector,
    dataflow: finding.dataflow,
    partialFingerprints: finding.partialFingerprints,
    suppressions: finding.suppressions,
    feedback: finding.feedback,
  }))
}

export function exportSarif(document: ReportDocument): string {
  const log = generateSarifLog(toSarifFindings(document.findings), {
    target: document.meta.target,
    runName: document.meta.engagement ?? document.meta.sessionID,
  })
  // El generador canónico conserva `taxonomies` porque el parser Go
  // (`argos-bin/cmd/web/tools/sarif.go`) lee esa clave. El export profesional
  // usa la forma que exige el JSON Schema oficial de SARIF 2.1.0 (`taxa`), y
  // el CWE/OWASP sigue viajando en `properties` — que es lo que el parser Go
  // lee primero — así que el round-trip no pierde señal.
  for (const run of log.runs) {
    for (const result of run.results) {
      delete (result as { taxonomies?: unknown }).taxonomies
    }
  }
  return JSON.stringify(log, null, 2)
}
