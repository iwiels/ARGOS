/**
 * Export JUnit XML — el formato que los gates de CI leen.
 *
 * Cada hallazgo es un `<testcase>`; un hallazgo que sigue vigente es un
 * `<failure>` con la evidencia como cuerpo. El documento respeta el
 * `junit.xsd` de Jenkins (el que consumen GitLab CI, GitHub Actions y
 * Jenkins): el orden de los elementos es `sequence`, así que `properties` va
 * antes de los `testcase` y `system-out`/`system-err` al final.
 */

import { toIsoDateTime, type ReportDocument, type ReportFinding, type ReportSeverity } from "./model"

const XML_CONTROL_CHARS = /[\u0000-\u0008\u000B\u000C\u000E-\u001F]/g

export function escapeXml(value: string): string {
  return (
    value
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&apos;")
      // Los caracteres de control no son legales en XML 1.0.
      .replace(XML_CONTROL_CHARS, "")
  )
}

const SEVERITY_LABEL: Record<ReportSeverity, string> = {
  critical: "CRITICAL",
  high: "HIGH",
  medium: "MEDIUM",
  low: "LOW",
  info: "INFO",
}

/** Un hallazgo no verificado no es un fallo todavía: se reporta como `skipped`. */
function isFailure(finding: ReportFinding): boolean {
  return (
    finding.status !== "false-positive" &&
    finding.status !== "accepted-risk" &&
    finding.status !== "remediated" &&
    finding.feedback?.verdict !== "false-positive"
  )
}

function failureBody(finding: ReportFinding): string {
  const lines: string[] = []
  if (finding.evidence) lines.push(finding.evidence)
  if (finding.curlCommand) lines.push("", "curl:", finding.curlCommand)
  if (finding.httpRequest) lines.push("", "request:", finding.httpRequest)
  if (finding.httpResponse) lines.push("", "response:", finding.httpResponse)
  if (finding.remediation) lines.push("", "remediation:", finding.remediation)
  return lines.join("\n")
}

export function exportJunit(document: ReportDocument): string {
  const cases = document.findings.map((finding) => {
    const classname = `argos.security.${finding.cwe ?? "finding"}`
    const name = `[${SEVERITY_LABEL[finding.severity]}] ${finding.title}`
    const attrs = [`classname="${escapeXml(classname)}"`, `name="${escapeXml(name)}"`, `time="0"`]
    if (isFailure(finding)) {
      const message = escapeXml(
        [finding.title, finding.target].filter(Boolean).join(" — ") +
          (finding.cvssScore ? ` (CVSS ${finding.cvssScore})` : ""),
      )
      return `    <testcase ${attrs.join(" ")}>\n      <failure type="${escapeXml(finding.severity)}" message="${message}">${escapeXml(failureBody(finding))}</failure>\n    </testcase>`
    }
    return `    <testcase ${attrs.join(" ")}>\n      <skipped message="${escapeXml(finding.feedback?.verdict ?? finding.status)}"/>\n    </testcase>`
  })

  const failures = document.findings.filter(isFailure).length
  const skipped = document.findings.length - failures
  const timestamp = toIsoDateTime(document.meta.generatedAt)
  const suiteName = escapeXml(document.meta.engagement ?? document.meta.sessionID)

  return [
    `<?xml version="1.0" encoding="UTF-8"?>`,
    `<testsuites name="Argos Security Operations" tests="${document.findings.length}" failures="${failures}" errors="0" skipped="${skipped}" time="0" timestamp="${timestamp}">`,
    `  <testsuite name="${suiteName}" tests="${document.findings.length}" failures="${failures}" errors="0" skipped="${skipped}" time="0" timestamp="${timestamp}" hostname="argos" package="argos.security">`,
    `    <properties>`,
    `      <property name="client" value="${escapeXml(document.meta.clientName)}"/>`,
    `      <property name="classification" value="${escapeXml(document.meta.classification)}"/>`,
    `      <property name="scope" value="${escapeXml(document.meta.scope)}"/>`,
    `      <property name="leadAuditor" value="${escapeXml(document.meta.leadAuditor)}"/>`,
    `      <property name="globalRisk" value="${escapeXml(document.summary.globalRisk)}"/>`,
    `      <property name="averageCvss" value="${document.summary.averageCvss}"/>`,
    `    </properties>`,
    ...cases,
    `    <system-out>${escapeXml(`${document.meta.title} — ${document.summary.totalFindings} hallazgos`)}</system-out>`,
    `  </testsuite>`,
    `</testsuites>`,
    ``,
  ].join("\n")
}
