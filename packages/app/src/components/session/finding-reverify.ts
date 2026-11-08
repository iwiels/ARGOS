import { cleanEvidence, type Finding } from "./findings-data"

/** Evita que una evidencia enorme (un dump, un JSON crudo) inunde el prompt. */
const MAX_EVIDENCE_CHARS = 1200

type Translate = (key: string, params?: Record<string, string | number>) => string

/**
 * Arma el mensaje que el botón "Re-verificar" inserta en el chat.
 *
 * El chequeo pasivo por HTTP solo resuelve cabeceras y TLS; para el resto de
 * los hallazgos (secretos en el historial de git, SQLi, IAM, puertos) devolvía
 * "requiere confirmación manual" sin investigar nada. Este prompt le pasa al
 * agente el contexto completo del hallazgo y le pide que cierre el ciclo
 * llamando a la tool `finding_status`, que es lo único que actualiza el panel.
 */
export function buildReverifyPrompt(finding: Finding, t: Translate): string {
  const evidence = cleanEvidence(finding.evidence) ?? finding.evidence
  const truncated =
    evidence && evidence.length > MAX_EVIDENCE_CHARS ? `${evidence.slice(0, MAX_EVIDENCE_CHARS)}…` : evidence

  const details = [
    t("findings.copy.finding", { title: finding.title }),
    `ID: ${finding.id}`,
    t("findings.reverify.severity", { value: finding.severityRaw ?? finding.severity }),
    finding.status ? t("findings.reverify.status", { value: finding.status }) : undefined,
    finding.target ? t("findings.reverify.target", { value: finding.target }) : undefined,
    finding.vector ? t("findings.copy.vector", { value: finding.vector }) : undefined,
    finding.cwe ? t("findings.copy.cwe", { value: finding.cwe }) : undefined,
    finding.agent ? t("findings.reverify.detectedBy", { value: finding.agent }) : undefined,
  ].filter((line): line is string => !!line)

  return [
    t("findings.reverify.intro"),
    "",
    details.join("\n"),
    ...(truncated ? ["", t("findings.reverify.evidenceLabel"), truncated] : []),
    "",
    t("findings.reverify.task", { id: finding.id ?? "" }),
    "",
    t("findings.reverify.honesty"),
  ].join("\n")
}
