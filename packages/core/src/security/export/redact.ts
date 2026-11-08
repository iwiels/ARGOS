import type { ReportDocument, ReportFinding } from "./model"

/**
 * Patrones universales de redacción uniforme de secretos para informes entregables (Etapa 4).
 */
const SECRET_PATTERNS: Array<[RegExp, string]> = [
  // Private keys PEM
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/gi, "[REDACTED PRIVATE KEY]"],
  // Authorization headers
  [/(bearer\s+)[A-Za-z0-9._~+/=-]{8,}/gi, "$1[REDACTED]"],
  [/(basic\s+)[A-Za-z0-9+/=]{8,}/gi, "$1[REDACTED]"],
  [/(authorization\s*[:=]\s*["']?)[^"'\s,}]+/gi, "$1[REDACTED]"],
  // Query parameters / API keys
  [/((?:auth_token|api[_-]?key|access_token|secret|password|token)=)[^&\s"')]+/gi, "$1[REDACTED]"],
  [/(x-api-key\s*[:=]\s*)[^\s,"'}\]]+/gi, "$1[REDACTED]"],
  // JSON key-value secrets
  [/("(?:password|api[_-]?key|secret|token|client_secret|access_token)"\s*:\s*")[^"]+/gi, "$1[REDACTED]"],
  // Basic-auth embedded in URLs
  [/(\w[\w.-]*:\/\/[^/\s:@"]+:)([^@\s/"]+@)/g, "$1[REDACTED]@"],
]

export function redactSecrets(input: string | undefined | null): string {
  if (!input) return ""
  let output = input
  for (const [pattern, replacement] of SECRET_PATTERNS) {
    output = output.replace(pattern, replacement)
  }
  return output
}

/**
 * Aplica redacción uniforme de secretos sobre un documento de informe de auditoría.
 */
export function redactReportDocument(doc: ReportDocument): ReportDocument {
  const redactedFindings: ReportFinding[] = doc.findings.map((f) => ({
    ...f,
    target: redactSecrets(f.target),
    vector: redactSecrets(f.vector),
    evidence: redactSecrets(f.evidence),
    remediation: redactSecrets(f.remediation),
  }))

  return {
    ...doc,
    meta: {
      ...doc.meta,
      target: doc.meta.target ? redactSecrets(doc.meta.target) : undefined,
      scope: redactSecrets(doc.meta.scope),
    },
    findings: redactedFindings,
  }
}
