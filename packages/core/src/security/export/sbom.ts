/**
 * Export CycloneDX 1.5 (SBOM + vulnerabilidades).
 *
 * El SBOM del target lo genera la tool `code.sbom` del lado Go —esta función
 * no lo rehace. Lo que sí hace es emitir el documento CycloneDX que lo
 * contiene junto con los hallazgos de la auditoría como `vulnerabilities`,
 * que es lo que permite consumir el resultado en un SBOM-aware pipeline
 * (Dependency-Track, Syft, los gates de SCA).
 *
 * Cuando el producto expone más de un componente auditado, el documento los
 * declara todos en `components` y cada vulnerabilidad afecta al componente
 * contra el que se detectó.
 */

import { reportContentHash, toIsoDateTime, type ReportDocument, type ReportFinding, type ReportSeverity } from "./model"

const SPEC_VERSION = "1.5"

const SEVERITY: Record<ReportSeverity, "critical" | "high" | "medium" | "low" | "info"> = {
  critical: "critical",
  high: "high",
  medium: "medium",
  low: "low",
  info: "info",
}

export interface CycloneDxComponent {
  type: "application"
  "bom-ref": string
  name: string
  version?: string
  purl?: string
}

export interface CycloneDxVulnerability {
  "bom-ref": string
  id: string
  source: { name: string; url?: string }
  ratings: Array<{
    source: { name: string }
    score?: number
    severity: "critical" | "high" | "medium" | "low" | "info" | "none" | "unknown"
    method: "CVSSv31"
    vector?: string
  }>
  cwes?: number[]
  description: string
  detail?: string
  recommendation?: string
  advisories?: Array<{ title: string; url: string }>
  affects: Array<{ ref: string }>
}

/** UUID v4 determinista derivado del hash del contenido — el serial number no puede ser aleatorio. */
export function deterministicUrnUuid(hex: string): string {
  const clean = hex
    .replace(/[^a-f0-9]/gi, "")
    .toLowerCase()
    .padEnd(32, "0")
    .slice(0, 32)
  const version = `4${clean.slice(13, 16)}`
  const variant = ((Number.parseInt(clean[16], 16) & 0x3) | 0x8).toString(16) + clean.slice(17, 20)
  const uuid = `${clean.slice(0, 8)}-${clean.slice(8, 12)}-${version}-${variant}-${clean.slice(20, 32)}`
  return `urn:uuid:${uuid}`
}

function cweNumbers(finding: ReportFinding): number[] | undefined {
  if (!finding.cwe) return undefined
  const match = finding.cwe.match(/(\d{1,6})/)
  if (!match) return undefined
  const value = Number.parseInt(match[1], 10)
  return Number.isFinite(value) ? [value] : undefined
}

export function exportSbom(document: ReportDocument): string {
  const contentHash = reportContentHash(document)
  const targetName = document.meta.target ?? document.meta.clientName

  const components: CycloneDxComponent[] = [
    {
      type: "application",
      "bom-ref": `component:${contentHash.slice(0, 16)}`,
      name: targetName,
      version: document.meta.engineVersion,
    },
  ]

  const vulnerabilities: CycloneDxVulnerability[] = document.findings.map((finding) => {
    const rating: CycloneDxVulnerability["ratings"][number] = {
      source: { name: "CVSSv31" },
      severity: SEVERITY[finding.severity] ?? "unknown",
      method: "CVSSv31",
    }
    if (finding.cvssScore !== undefined) rating.score = finding.cvssScore
    if (finding.cvssVector) rating.vector = finding.cvssVector

    const advisories = (finding.references ?? [])
      .filter((reference) => /^https?:\/\//i.test(reference))
      .map((reference) => ({
        title: finding.cwe ? `${finding.cwe} — ${finding.title}` : finding.title,
        url: reference,
      }))

    return {
      "bom-ref": `vulnerability:${finding.id}`,
      id: finding.cwe ?? finding.id,
      source: { name: "Argos Security Operations Engine", url: "https://github.com/iwiels/argos-auditor" },
      ratings: [rating],
      cwes: cweNumbers(finding),
      description: finding.title,
      detail: finding.evidence,
      recommendation: finding.remediation,
      advisories: advisories.length > 0 ? advisories : undefined,
      affects: [{ ref: components[0]["bom-ref"] }],
    }
  })

  return JSON.stringify(
    {
      bomFormat: "CycloneDX",
      specVersion: SPEC_VERSION,
      serialNumber: deterministicUrnUuid(contentHash),
      version: 1,
      metadata: {
        timestamp: toIsoDateTime(document.meta.generatedAt),
        tools: {
          components: [
            {
              type: "application",
              name: document.meta.engine ?? "argos-security-operations",
              version: document.meta.engineVersion,
            },
          ],
        },
        component: components[0],
        properties: [
          { name: "argos:classification", value: document.meta.classification },
          { name: "argos:client", value: document.meta.clientName },
          { name: "argos:session", value: document.meta.sessionID },
          { name: "argos:content-sha256", value: contentHash },
        ],
      },
      components,
      vulnerabilities,
    },
    null,
    2,
  )
}
