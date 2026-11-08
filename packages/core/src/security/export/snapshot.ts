import { createHash } from "node:crypto"
import type { ReportDocument, ReportFinding, ReportSummary } from "./model"
import { redactReportDocument } from "./redact"

export interface CanonicalAuditSnapshot {
  version: "1.0.0"
  snapshotHash: string
  generatedAt: string
  sessionID: string
  meta: {
    title: string
    clientName: string
    target?: string
    leadAuditor: string
    classification: string
    methodology: string
  }
  summary: ReportSummary
  findings: ReportFinding[]
}

/**
 * Ordena recursivamente las claves de un objeto para serialización JSON canónica determinista.
 */
function sortObjectKeys<T>(obj: T): T {
  if (obj === null || typeof obj !== "object") {
    return obj
  }
  if (Array.isArray(obj)) {
    return obj.map(sortObjectKeys) as unknown as T
  }
  const sorted: Record<string, unknown> = {}
  for (const key of Object.keys(obj).sort()) {
    sorted[key] = sortObjectKeys((obj as Record<string, unknown>)[key])
  }
  return sorted as T
}

export class AuditSnapshotService {
  /**
   * Genera un snapshot canónico e inmutable del estado del informe de auditoría (Etapa 4).
   */
  static createSnapshot(reportDoc: ReportDocument): CanonicalAuditSnapshot {
    const doc = redactReportDocument(reportDoc)
    const sortedFindings = [...doc.findings].sort((a, b) => a.id.localeCompare(b.id))

    const payloadWithoutHash = {
      version: "1.0.0" as const,
      generatedAt: doc.meta.generatedAt.toISOString(),
      sessionID: doc.meta.sessionID,
      meta: {
        title: doc.meta.title,
        clientName: doc.meta.clientName,
        target: doc.meta.target,
        leadAuditor: doc.meta.leadAuditor,
        classification: doc.meta.classification,
        methodology: doc.meta.methodology,
      },
      summary: doc.summary,
      findings: sortedFindings,
    }

    const canonicalJson = JSON.stringify(sortObjectKeys(payloadWithoutHash))
    const snapshotHash = createHash("sha256").update(canonicalJson).digest("hex")

    return {
      ...payloadWithoutHash,
      snapshotHash,
    }
  }

  /**
   * Verifica la integridad criptográfica del snapshot canónico.
   */
  static verifySnapshot(snapshot: CanonicalAuditSnapshot): boolean {
    const { snapshotHash, ...rest } = snapshot
    const canonicalJson = JSON.stringify(sortObjectKeys(rest))
    const computedHash = createHash("sha256").update(canonicalJson).digest("hex")
    return computedHash === snapshotHash
  }
}
