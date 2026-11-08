import { createHash } from "node:crypto"
import { and, eq } from "drizzle-orm"
import { Cause, Effect } from "effect"
import type { Database } from "../database/database"
import type { EventV2 } from "../event"
import type { Location } from "../location"
import { SessionSchema } from "../session/schema"
import { SessionTable } from "../session/sql"
import { normalizeContractSeverity } from "./contract"
import { FindingUpserted } from "./events"
import { ingestToolFindings } from "./ingest"
import { FindingObservationTable, FindingTable } from "./sql"
import { fromSarifLog, type SarifLog } from "./sarif"

export const FINDING_IMPORT_FORMATS = [
  "sarif-2.1",
  "nuclei-jsonl",
  "semgrep-json",
  "gitleaks-json",
  "trivy-json",
  "zap-json",
  "burp-xml",
  "defectdojo-generic-json",
] as const
export type FindingImportFormat = (typeof FINDING_IMPORT_FORMATS)[number]

export const FINDING_IMPORT_PARSER_VERSION = 1
export const MAX_FINDING_IMPORT_BYTES = 8 * 1024 * 1024
export const MAX_FINDING_IMPORT_FINDINGS = 50_000
const MAX_JSON_DEPTH = 64
const MAX_JSON_NODES = 250_000

export type FindingImportErrorCode =
  | "unsupported_format"
  | "size_limit"
  | "invalid_document"
  | "result_limit"
  | "empty_import"

export class FindingImportError extends Error {
  readonly code: FindingImportErrorCode
  readonly line?: number

  constructor(code: FindingImportErrorCode, message: string, line?: number) {
    super(message)
    this.name = "FindingImportError"
    this.code = code
    this.line = line
  }
}

export interface ImportedFinding {
  id: string
  source: "import"
  source_tool: string
  rule_id?: string
  title: string
  severity: string
  status: string
  confidence: "possible"
  cwe?: string
  owasp?: string[]
  target?: string
  vector?: string
  evidence: Record<string, unknown>
  remediation?: string
  tags: string[]
  references: string[]
}

export interface FindingImportPreview {
  format: FindingImportFormat
  parserVersion: number
  contentSha256: string
  findings: ImportedFinding[]
  warnings: string[]
}

export interface FindingImportInput {
  sessionID: string
  format: FindingImportFormat
  content: string
  importID?: string
}

export interface FindingImportResult extends FindingImportPreview {
  sourceEventID: string
  importedCount: number
}

type JsonRecord = Record<string, unknown>

const isRecord = (value: unknown): value is JsonRecord => !!value && typeof value === "object" && !Array.isArray(value)

const stringValue = (value: unknown, max = 4096) => {
  if (typeof value !== "string") return undefined
  const trimmed = value.trim()
  return trimmed ? trimmed.slice(0, max) : undefined
}

const strings = (value: unknown, maxItems = 16, maxChars = 512): string[] => {
  const values = typeof value === "string" ? value.split(",") : Array.isArray(value) ? value : []
  const seen = new Set<string>()
  const result: string[] = []
  for (const item of values) {
    const text = stringValue(item, maxChars)
    if (!text || seen.has(text)) continue
    seen.add(text)
    result.push(text)
    if (result.length === maxItems) break
  }
  return result
}

const errorMessage = (error: unknown) => (error instanceof Error ? error.message : String(error))

function parseJson(content: string): unknown {
  try {
    return JSON.parse(content)
  } catch (error) {
    throw new FindingImportError("invalid_document", `Invalid JSON document: ${errorMessage(error)}`)
  }
}

function assertBoundedJson(value: unknown) {
  const pending: Array<{ value: unknown; depth: number }> = [{ value, depth: 0 }]
  let nodes = 0
  while (pending.length > 0) {
    const current = pending.pop()!
    nodes++
    if (nodes > MAX_JSON_NODES) {
      throw new FindingImportError("size_limit", "Import document contains too many JSON values")
    }
    if (current.depth > MAX_JSON_DEPTH) {
      throw new FindingImportError("size_limit", `Import document exceeds the JSON depth limit of ${MAX_JSON_DEPTH}`)
    }
    if (Array.isArray(current.value)) {
      for (const child of current.value) pending.push({ value: child, depth: current.depth + 1 })
    } else if (isRecord(current.value)) {
      for (const child of Object.values(current.value)) pending.push({ value: child, depth: current.depth + 1 })
    }
  }
}

function cweValue(value: unknown) {
  const candidates = Array.isArray(value) ? value : [value]
  for (const candidate of candidates) {
    if (typeof candidate === "number" && Number.isSafeInteger(candidate) && candidate > 0 && candidate <= 999999) {
      return `CWE-${candidate}`
    }
    const text = stringValue(candidate, 128)
    if (!text) continue
    const match = text.match(/CWE[-_\s]?\d{1,6}/i) ?? text.match(/^\d{1,6}$/)
    if (match) return `CWE-${match[0].replace(/\D/g, "")}`
  }
}

function hasRecognizedSeverity(value: unknown) {
  const raw = stringValue(value, 64)?.toLowerCase()
  if (!raw) return false
  const normalized = normalizeContractSeverity(raw)
  return normalized !== "info" || ["info", "information", "informational", "informativo", "none"].includes(raw)
}

function stableId(parts: unknown[]) {
  return `imp_${createHash("sha256").update(JSON.stringify(parts)).digest("hex").slice(0, 32)}`
}

function makePreview(
  format: FindingImportFormat,
  content: string,
  findings: ImportedFinding[],
  warnings: string[],
): FindingImportPreview {
  const distinctWarnings = [...new Set(warnings)]
  const boundedWarnings = distinctWarnings.slice(0, 64)
  if (distinctWarnings.length > 64) boundedWarnings.push("Additional import warnings were omitted.")
  return {
    format,
    parserVersion: FINDING_IMPORT_PARSER_VERSION,
    contentSha256: createHash("sha256").update(content).digest("hex"),
    findings,
    warnings:
      findings.length === 0 ? [...boundedWarnings, `The ${format} document contains no findings.`] : boundedWarnings,
  }
}

function parseSarif(content: string): FindingImportPreview {
  const document = parseJson(content)
  assertBoundedJson(document)
  if (!isRecord(document) || document.version !== "2.1.0" || !Array.isArray(document.runs)) {
    throw new FindingImportError("invalid_document", "SARIF import must be a 2.1.0 log with a runs array")
  }

  let resultCount = 0
  const sourceResults: Array<{ run: JsonRecord; result: JsonRecord; index: number }> = []
  for (const runValue of document.runs) {
    if (!isRecord(runValue)) throw new FindingImportError("invalid_document", "SARIF runs must contain objects")
    const results = runValue.results ?? []
    if (!Array.isArray(results)) throw new FindingImportError("invalid_document", "SARIF run results must be an array")
    resultCount += results.length
    if (resultCount > MAX_FINDING_IMPORT_FINDINGS) {
      throw new FindingImportError("result_limit", `SARIF import exceeds ${MAX_FINDING_IMPORT_FINDINGS} results`)
    }
    results.forEach((result, index) => {
      if (!isRecord(result)) throw new FindingImportError("invalid_document", "SARIF results must contain objects")
      sourceResults.push({ run: runValue, result, index })
    })
  }

  let parsed: ReturnType<typeof fromSarifLog>
  try {
    parsed = fromSarifLog(document as unknown as SarifLog)
  } catch (error) {
    throw new FindingImportError("invalid_document", `Invalid SARIF result structure: ${errorMessage(error)}`)
  }

  const findings = parsed.map((finding, index): ImportedFinding => {
    const source = sourceResults[index]
    const result = source?.result ?? {}
    const run = source?.run ?? {}
    const tool = isRecord(run.tool) ? run.tool : {}
    const driver = isRecord(tool.driver) ? tool.driver : {}
    const rules = Array.isArray(driver.rules) ? driver.rules : []
    const ruleIndex = typeof result.ruleIndex === "number" ? result.ruleIndex : -1
    const rule = ruleIndex >= 0 && ruleIndex < rules.length && isRecord(rules[ruleIndex]) ? rules[ruleIndex] : {}
    const resultProperties = isRecord(result.properties) ? result.properties : {}
    const ruleProperties = isRecord(rule.properties) ? rule.properties : {}
    const sourceTool = stringValue(driver.name, 256) ?? finding.sourceTool ?? "sarif"
    const message = sourceTool.toLowerCase().includes("gitleaks")
      ? undefined
      : isRecord(result.message)
        ? stringValue(result.message.text, 4096)
        : undefined
    const locations = Array.isArray(result.locations) ? result.locations : []
    const firstLocation = isRecord(locations[0]) ? locations[0] : {}
    const physical = isRecord(firstLocation.physicalLocation) ? firstLocation.physicalLocation : {}
    const artifact = isRecord(physical.artifactLocation) ? physical.artifactLocation : {}
    const region = isRecord(physical.region) ? physical.region : {}
    const target = withoutUrlQuery(stringValue(artifact.uri, 2048)) ?? withoutUrlQuery(finding.target) ?? finding.target
    const line =
      typeof region.startLine === "number" && Number.isSafeInteger(region.startLine) ? region.startLine : undefined
    const endLine =
      typeof region.endLine === "number" && Number.isSafeInteger(region.endLine) ? region.endLine : undefined
    const resultRuleID = stringValue(result.ruleId, 512) ?? stringValue(rule.id, 512)
    const ruleHelp = stringValue(rule.helpUri, 512)
    const partialFingerprints = isRecord(result.partialFingerprints) ? result.partialFingerprints : {}
    const suppressionValues = Array.isArray(result.suppressions)
      ? result.suppressions.slice(0, 8).flatMap((value) => {
          if (!isRecord(value)) return []
          return [
            {
              kind: stringValue(value.kind, 64),
              status: stringValue(value.status, 64),
            },
          ]
        })
      : []
    const codeFlows = finding.dataflow?.slice(0, 12).map((step) => ({
      file: stringValue(step.file, 2048),
      line: step.line,
      endLine: step.endLine,
    }))
    const evidence = {
      format: "sarif-2.1",
      message,
      location: target ? { uri: target, startLine: line, endLine } : undefined,
      dataflow: codeFlows,
      partialFingerprints: Object.fromEntries(
        Object.entries(partialFingerprints)
          .slice(0, 16)
          .map(([key, value]) => [
            key.slice(0, 128),
            stringValue(value, 1024) ? createHash("sha256").update(stringValue(value, 1024)!).digest("hex") : undefined,
          ]),
      ),
      suppressions: suppressionValues,
      cvssScore: finding.cvssScore,
      cvssVector: finding.cvssVector,
      severity_reported: hasRecognizedSeverity(
        stringValue(resultProperties.severity, 64) ??
          stringValue(result.level, 64) ??
          stringValue(isRecord(rule.defaultConfiguration) ? rule.defaultConfiguration.level : undefined, 64),
      ),
      external_finding_id: stringValue(resultProperties.findingId, 128),
      external_status: stringValue(resultProperties.status, 64),
    }
    const severity = stringValue(resultProperties.severity, 64) ?? finding.severity
    const id = stableId([sourceTool, resultRuleID, target, line, finding.cwe])

    return {
      id,
      source: "import",
      source_tool: sourceTool,
      rule_id: resultRuleID,
      title: finding.title,
      severity,
      status: "observed",
      confidence: "possible",
      cwe: finding.cwe ?? cweValue(ruleProperties.cwe) ?? cweValue(ruleProperties.tags),
      owasp: finding.owasp,
      target,
      vector: line && target ? `${target}:L${line}` : (finding.vector ?? target),
      evidence,
      remediation: finding.remediation,
      tags: ["sarif", ...strings(ruleProperties.tags, 16, 64)],
      references: ruleHelp ? [ruleHelp] : [],
    }
  })

  return {
    format: "sarif-2.1",
    parserVersion: FINDING_IMPORT_PARSER_VERSION,
    contentSha256: createHash("sha256").update(content).digest("hex"),
    findings,
    warnings:
      findings.length === 0
        ? ["The SARIF document contains no results."]
        : findings.some((finding) => finding.evidence.severity_reported === false)
          ? ["One or more SARIF results do not declare a severity; the parser retained the SARIF-derived fallback."]
          : [],
  }
}

function parseNucleiJsonl(content: string): FindingImportPreview {
  const findings: ImportedFinding[] = []
  const warnings: string[] = []
  const lines = content.split(/\r?\n/)
  for (let index = 0; index < lines.length; index++) {
    const line = lines[index].trim()
    if (!line) continue
    if (findings.length >= MAX_FINDING_IMPORT_FINDINGS) {
      throw new FindingImportError(
        "result_limit",
        `Nuclei import exceeds ${MAX_FINDING_IMPORT_FINDINGS} results`,
        index + 1,
      )
    }

    let value: unknown
    try {
      value = JSON.parse(line)
    } catch (error) {
      throw new FindingImportError(
        "invalid_document",
        `Invalid Nuclei JSONL at line ${index + 1}: ${errorMessage(error)}`,
        index + 1,
      )
    }
    assertBoundedJson(value)
    if (!isRecord(value)) {
      throw new FindingImportError("invalid_document", `Nuclei line ${index + 1} must contain a JSON object`, index + 1)
    }
    const info = isRecord(value.info) ? value.info : undefined
    if (!info) {
      throw new FindingImportError("invalid_document", `Nuclei line ${index + 1} is missing its info object`, index + 1)
    }

    const templateID = stringValue(value["template-id"], 256) ?? "unknown-template"
    const matchedAt = withoutUrlQuery(stringValue(value["matched-at"], 2048))
    const target = matchedAt ?? withoutUrlQuery(stringValue(value.host, 2048))
    const title = stringValue(info.name, 512) ?? templateID
    const rawSeverity = stringValue(info.severity, 64)
    const severity = normalizeContractSeverity(rawSeverity)
    if (!hasRecognizedSeverity(rawSeverity)) {
      warnings.push(`Nuclei line ${index + 1} has no recognized severity; imported as info.`)
    }
    const classification = isRecord(info.classification) ? info.classification : {}
    const tags = strings(info.tags, 32, 64).map((tag) => tag.toLowerCase())
    const references = strings(info.reference)
    const cwe = cweValue(classification["cwe-id"])

    findings.push({
      id: stableId(["nuclei", templateID, matchedAt, title, cwe]),
      source: "import",
      source_tool: "nuclei",
      rule_id: `nuclei:${templateID}`,
      title,
      severity,
      status: "observed",
      confidence: "possible",
      cwe,
      target,
      vector: matchedAt ?? target,
      evidence: {
        format: "nuclei-jsonl",
        template_id: templateID,
        matched_at: matchedAt,
        matcher_name: stringValue(value["matcher-name"], 256),
        severity_reported: hasRecognizedSeverity(rawSeverity),
      },
      remediation: stringValue(info.remediation, 8000),
      tags,
      references,
    })
  }

  return makePreview("nuclei-jsonl", content, findings, warnings)
}

function parseSemgrep(content: string): FindingImportPreview {
  const document = parseJson(content)
  assertBoundedJson(document)
  if (!isRecord(document) || !Array.isArray(document.results)) {
    throw new FindingImportError("invalid_document", "Semgrep JSON must contain a results array")
  }
  if (document.results.length > MAX_FINDING_IMPORT_FINDINGS) {
    throw new FindingImportError("result_limit", `Semgrep import exceeds ${MAX_FINDING_IMPORT_FINDINGS} results`)
  }

  const findings: ImportedFinding[] = []
  const warnings: string[] = []
  for (const [index, item] of document.results.entries()) {
    if (!isRecord(item) || !isRecord(item.extra)) {
      throw new FindingImportError("invalid_document", `Semgrep result ${index + 1} must contain an extra object`)
    }
    const extra = item.extra
    const metadata = isRecord(extra.metadata) ? extra.metadata : {}
    const checkID = stringValue(item.check_id, 512)
    const path = stringValue(item.path, 2048)
    if (!checkID || !path) {
      throw new FindingImportError("invalid_document", `Semgrep result ${index + 1} is missing check_id or path`)
    }
    const start = isRecord(item.start) ? item.start : {}
    const end = isRecord(item.end) ? item.end : {}
    const startLine =
      typeof start.line === "number" && Number.isSafeInteger(start.line) && start.line > 0 ? start.line : undefined
    const endLine =
      typeof end.line === "number" && Number.isSafeInteger(end.line) && end.line > 0 ? end.line : undefined
    const rawSeverity = stringValue(extra.severity, 64)?.toLowerCase()
    const severityBySemgrep: Record<string, string> = { error: "high", warning: "medium", info: "info" }
    const severity = rawSeverity ? (severityBySemgrep[rawSeverity] ?? normalizeContractSeverity(rawSeverity)) : "info"
    const severityReported = Boolean(rawSeverity && (rawSeverity in severityBySemgrep || severity !== "info"))
    if (!severityReported) warnings.push(`Semgrep result ${index + 1} has no recognized severity; imported as info.`)
    const title = stringValue(metadata.shortDescription, 512) ?? stringValue(metadata.name, 512) ?? checkID
    const references = strings(metadata.references)
    const fingerprint = stringValue(extra.fingerprint, 512)
    const fingerprintHash = fingerprint ? createHash("sha256").update(fingerprint).digest("hex") : undefined
    const tags = strings(metadata.tags, 32, 64).map((tag) => tag.toLowerCase())
    const vector = startLine ? `${path}:L${startLine}` : path
    findings.push({
      id: stableId(["semgrep", checkID, path, startLine, fingerprintHash]),
      source: "import",
      source_tool: "semgrep",
      rule_id: `semgrep:${checkID}`,
      title,
      severity,
      status: "observed",
      confidence: "possible",
      cwe: cweValue(metadata.cwe),
      owasp: strings(metadata.owasp, 16, 64),
      target: path,
      vector,
      evidence: {
        format: "semgrep-json",
        message: stringValue(extra.message, 4096),
        startLine,
        endLine,
        fingerprint_sha256: fingerprintHash,
        severity_reported: severityReported,
      },
      remediation: stringValue(metadata.remediation, 8000),
      tags,
      references,
    })
  }
  return makePreview("semgrep-json", content, findings, warnings)
}

function parseGitleaks(content: string): FindingImportPreview {
  const document = parseJson(content)
  assertBoundedJson(document)
  if (!Array.isArray(document))
    throw new FindingImportError("invalid_document", "Gitleaks JSON must be an array of findings")
  if (document.length > MAX_FINDING_IMPORT_FINDINGS) {
    throw new FindingImportError("result_limit", `Gitleaks import exceeds ${MAX_FINDING_IMPORT_FINDINGS} results`)
  }

  const warnings: string[] = []
  const findings = document.map((item, index): ImportedFinding => {
    if (!isRecord(item))
      throw new FindingImportError("invalid_document", `Gitleaks finding ${index + 1} must be an object`)
    const ruleID = stringValue(item.RuleID, 256)
    const path = stringValue(item.File, 2048)
    if (!ruleID || !path) {
      throw new FindingImportError("invalid_document", `Gitleaks finding ${index + 1} is missing RuleID or File`)
    }
    const startLine =
      typeof item.StartLine === "number" && Number.isSafeInteger(item.StartLine) && item.StartLine > 0
        ? item.StartLine
        : undefined
    const endLine =
      typeof item.EndLine === "number" && Number.isSafeInteger(item.EndLine) && item.EndLine > 0
        ? item.EndLine
        : undefined
    const fingerprint = stringValue(item.Fingerprint, 1024)
    const fingerprintHash = fingerprint ? createHash("sha256").update(fingerprint).digest("hex") : undefined
    warnings.push(`Gitleaks finding ${index + 1} does not declare a severity; imported as info.`)
    return {
      id: stableId(["gitleaks", ruleID, path, startLine, fingerprintHash]),
      source: "import",
      source_tool: "gitleaks",
      rule_id: `gitleaks:${ruleID}`,
      title: stringValue(item.Description, 512) ?? ruleID,
      severity: "info",
      status: "observed",
      confidence: "possible",
      target: path,
      vector: startLine ? `${path}:L${startLine}` : path,
      evidence: {
        format: "gitleaks-json",
        file: path,
        startLine,
        endLine,
        commit: stringValue(item.Commit, 128),
        fingerprint_sha256: fingerprintHash,
        severity_reported: false,
      },
      tags: ["secret", ...strings(item.Tags, 16, 64)],
      references: [],
    }
  })
  return makePreview("gitleaks-json", content, findings, warnings)
}

function parseTrivy(content: string): FindingImportPreview {
  const document = parseJson(content)
  assertBoundedJson(document)
  if (!isRecord(document) || !Array.isArray(document.Results)) {
    throw new FindingImportError("invalid_document", "Trivy JSON must contain a Results array")
  }

  const findings: ImportedFinding[] = []
  const warnings: string[] = []
  const addResult = (rawSeverity: unknown, index: number) => {
    const value = stringValue(rawSeverity, 64)?.toLowerCase()
    if (!hasRecognizedSeverity(value) || value === "unknown") {
      warnings.push(`Trivy finding ${index} has no recognized severity; imported as info.`)
      return "info"
    }
    const mapped = normalizeContractSeverity(value)
    if (mapped === "info" && value !== "info")
      warnings.push(`Trivy finding ${index} has an unknown severity; imported as info.`)
    return mapped
  }
  const takeArray = (record: JsonRecord, key: string, resultIndex: number) => {
    const value = record[key]
    if (value === undefined || value === null) return []
    if (!Array.isArray(value))
      throw new FindingImportError("invalid_document", `Trivy result ${resultIndex} field ${key} must be an array`)
    return value
  }

  for (const [resultIndex, resultValue] of document.Results.entries()) {
    if (!isRecord(resultValue))
      throw new FindingImportError("invalid_document", `Trivy result ${resultIndex + 1} must be an object`)
    const result = resultValue
    const target = stringValue(result.Target, 2048) ?? stringValue(document.ArtifactName, 2048) ?? "unknown target"
    const categories: Array<[string, string]> = [
      ["Vulnerabilities", "vulnerability"],
      ["Misconfigurations", "misconfiguration"],
      ["Secrets", "secret"],
    ]
    for (const [field, category] of categories) {
      for (const itemValue of takeArray(result, field, resultIndex + 1)) {
        if (!isRecord(itemValue)) {
          throw new FindingImportError(
            "invalid_document",
            `Trivy ${field} entry in result ${resultIndex + 1} must be an object`,
          )
        }
        if (findings.length >= MAX_FINDING_IMPORT_FINDINGS) {
          throw new FindingImportError("result_limit", `Trivy import exceeds ${MAX_FINDING_IMPORT_FINDINGS} findings`)
        }
        const item = itemValue
        const identifier =
          stringValue(item.VulnerabilityID, 256) ?? stringValue(item.ID, 256) ?? stringValue(item.RuleID, 256)
        const title = stringValue(item.Title, 512) ?? identifier
        if (!identifier || !title) {
          throw new FindingImportError(
            "invalid_document",
            `Trivy ${field} entry in result ${resultIndex + 1} is missing its identifier or title`,
          )
        }
        const startLine =
          typeof item.StartLine === "number" && Number.isSafeInteger(item.StartLine) && item.StartLine > 0
            ? item.StartLine
            : undefined
        const endLine =
          typeof item.EndLine === "number" && Number.isSafeInteger(item.EndLine) && item.EndLine > 0
            ? item.EndLine
            : undefined
        const severityValue = stringValue(item.Severity, 64)
        const severity = addResult(severityValue, findings.length + 1)
        const packageName = stringValue(item.PkgName, 256)
        const installedVersion = stringValue(item.InstalledVersion, 128)
        const fixedVersion = stringValue(item.FixedVersion, 128)
        const vector = startLine ? `${target}:L${startLine}` : packageName ? `${target}:${packageName}` : target
        const ruleID = `trivy:${identifier}`
        const references = [stringValue(item.PrimaryURL, 512), ...strings(item.References, 16, 512)].filter(
          (value): value is string => Boolean(value),
        )
        findings.push({
          id: stableId(["trivy", category, identifier, target, packageName, installedVersion, startLine]),
          source: "import",
          source_tool: "trivy",
          rule_id: ruleID,
          title,
          severity,
          status: "observed",
          confidence: "possible",
          cwe: cweValue(item.CweIDs ?? item.CweID),
          target,
          vector,
          evidence: {
            format: "trivy-json",
            category,
            target,
            package: packageName,
            installed_version: installedVersion,
            fixed_version: fixedVersion,
            startLine,
            endLine,
            severity_reported: hasRecognizedSeverity(severityValue),
          },
          remediation: fixedVersion
            ? `Upgrade ${packageName ?? "the affected component"} to ${fixedVersion}.`
            : stringValue(item.Resolution, 8000),
          tags: [category, ...strings(item.Tags, 16, 64)],
          references,
        })
      }
    }
  }
  return makePreview("trivy-json", content, findings, warnings)
}

function withoutUrlQuery(value: string | undefined) {
  if (!value) return undefined
  try {
    const url = new URL(value)
    url.search = ""
    url.hash = ""
    url.username = ""
    url.password = ""
    return url.toString().replace(/\/$/, "") || "/"
  } catch {
    return value.split(/[?#]/, 1)[0]?.slice(0, 2048)
  }
}

function safeBurpLocation(value: string | undefined) {
  const location = stringValue(value, 2048)
  if (!location) return undefined
  return location
    .replace(/https?:\/\/[^\s()<>]+/gi, (url) => withoutUrlQuery(url) ?? "[redacted URL]")
    .replace(/\b(password|token|secret|authorization|cookie)\s*[:=]\s*[^,;\s)]+/gi, "$1=[redacted]")
    .slice(0, 2048)
}

function parseZap(content: string): FindingImportPreview {
  const document = parseJson(content)
  assertBoundedJson(document)
  if (!isRecord(document)) throw new FindingImportError("invalid_document", "ZAP JSON must be an object")
  const siteValue = document.site
  const sites: unknown[] = Array.isArray(siteValue) ? siteValue : isRecord(siteValue) ? [siteValue] : []
  const directAlerts = Array.isArray(document.alerts) ? [{ "@name": "unknown target", alerts: document.alerts }] : []
  if (!Array.isArray(siteValue) && !isRecord(siteValue) && directAlerts.length === 0) {
    throw new FindingImportError("invalid_document", "ZAP JSON must contain a site array or alerts array")
  }

  const findings: ImportedFinding[] = []
  const warnings: string[] = []
  for (const [siteIndex, siteValue] of [...sites, ...directAlerts].entries()) {
    if (!isRecord(siteValue))
      throw new FindingImportError("invalid_document", `ZAP site ${siteIndex + 1} must be an object`)
    const site = siteValue
    if (site.alerts === undefined) continue
    if (!Array.isArray(site.alerts))
      throw new FindingImportError("invalid_document", `ZAP site ${siteIndex + 1} alerts must be an array`)
    for (const alertValue of site.alerts) {
      if (!isRecord(alertValue))
        throw new FindingImportError("invalid_document", `ZAP alert in site ${siteIndex + 1} must be an object`)
      const alert = alertValue
      const pluginID = stringValue(alert.pluginid, 256) ?? stringValue(alert.alertRef, 256)
      const title = stringValue(alert.alert, 512) ?? stringValue(alert.name, 512)
      if (!title || !pluginID)
        throw new FindingImportError(
          "invalid_document",
          `ZAP alert in site ${siteIndex + 1} is missing alert/plugin ID`,
        )
      const riskCode =
        typeof alert.riskcode === "string"
          ? alert.riskcode.trim()
          : typeof alert.riskcode === "number" && Number.isSafeInteger(alert.riskcode)
            ? `${alert.riskcode}`
            : ""
      const severityByRisk: Record<string, string> = { "0": "info", "1": "low", "2": "medium", "3": "high" }
      const rawSeverity = severityByRisk[riskCode]
      if (!rawSeverity) warnings.push(`ZAP alert ${pluginID} has no recognized risk code; imported as info.`)
      const severity = rawSeverity ?? "info"
      const instances = Array.isArray(alert.instances) ? alert.instances : []
      if (alert.instances !== undefined && !Array.isArray(alert.instances)) {
        throw new FindingImportError("invalid_document", `ZAP alert ${pluginID} instances must be an array`)
      }
      const firstInstance = isRecord(instances[0]) ? instances[0] : {}
      const instanceURL = stringValue(firstInstance.uri, 2048)
      const target =
        withoutUrlQuery(instanceURL) ?? withoutUrlQuery(stringValue(site["@name"], 2048)) ?? "unknown target"
      const method = stringValue(firstInstance.method, 16)
      const parameter = stringValue(firstInstance.param, 128)
      const cwe = cweValue(alert.cweid)
      findings.push({
        id: stableId(["zap", pluginID, target, method, parameter]),
        source: "import",
        source_tool: "zap",
        rule_id: `zap:${pluginID}`,
        title,
        severity,
        status: "observed",
        confidence: "possible",
        cwe,
        target,
        vector: target,
        evidence: {
          format: "zap-json",
          instance_count: instances.length,
          method,
          parameter,
          risk_code: riskCode || undefined,
          severity_reported: Boolean(rawSeverity),
        },
        remediation: stringValue(alert.solution, 8000),
        tags: ["zap", ...strings(alert.tags && isRecord(alert.tags) ? Object.keys(alert.tags) : alert.tags, 24, 64)],
        references: strings(alert.reference),
      })
      if (findings.length > MAX_FINDING_IMPORT_FINDINGS) {
        throw new FindingImportError("result_limit", `ZAP import exceeds ${MAX_FINDING_IMPORT_FINDINGS} findings`)
      }
    }
  }
  return makePreview("zap-json", content, findings, warnings)
}

function decodeXmlText(value: string) {
  if (/&(?!(?:amp|lt|gt|quot|apos|#\d+|#x[\da-f]+);)/i.test(value)) {
    throw new FindingImportError("invalid_document", "Burp XML contains an unsupported or malformed entity")
  }
  const decodeCodepoint = (codepoint: number) => {
    if (
      !Number.isSafeInteger(codepoint) ||
      codepoint < 1 ||
      codepoint > 0x10ffff ||
      (codepoint >= 0xd800 && codepoint <= 0xdfff)
    ) {
      throw new FindingImportError("invalid_document", "Burp XML contains an invalid numeric entity")
    }
    return String.fromCodePoint(codepoint)
  }
  return value
    .replace(/&#(\d+);/g, (_match, digits: string) => decodeCodepoint(Number(digits)))
    .replace(/&#x([\da-f]+);/gi, (_match, digits: string) => decodeCodepoint(Number.parseInt(digits, 16)))
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&amp;/g, "&")
    .trim()
}

function xmlField(xml: string, name: string) {
  const match = xml.match(new RegExp(`<${name}\\b[^>]*>([\\s\\S]*?)</${name}\\s*>`, "i"))
  return match ? stringValue(decodeXmlText(match[1]), 8000) : undefined
}

function stripBurpDoctype(content: string) {
  const start = content.search(/<!DOCTYPE\b/i)
  if (start < 0) return content
  if (content.slice(start + 1).search(/<!DOCTYPE\b/i) >= 0) {
    throw new FindingImportError("invalid_document", "Burp XML must contain at most one document type declaration")
  }

  let bracketDepth = 0
  let quote: '"' | "'" | undefined
  let end = -1
  for (let index = start + "<!DOCTYPE".length; index < content.length; index++) {
    const character = content[index]
    if (quote) {
      if (character === quote) quote = undefined
      continue
    }
    if (character === '"' || character === "'") quote = character
    else if (character === "[") bracketDepth++
    else if (character === "]") bracketDepth--
    else if (character === ">" && bracketDepth === 0) {
      end = index
      break
    }
    if (bracketDepth < 0) break
  }
  if (end < 0 || quote || bracketDepth !== 0) {
    throw new FindingImportError("invalid_document", "Burp XML contains a malformed document type declaration")
  }

  const declaration = content.slice(start, end + 1)
  const header = declaration.match(/^<!DOCTYPE\s+([A-Za-z_:][\w:.-]*)([\s\S]*)>$/i)
  if (!header || header[1].toLowerCase() !== "issues") {
    throw new FindingImportError("invalid_document", "Burp XML document type must declare the issues root")
  }

  const remainder = header[2].trim()
  if (remainder) {
    if (!remainder.startsWith("[") || !remainder.endsWith("]")) {
      throw new FindingImportError("invalid_document", "External Burp XML document types are not accepted")
    }
    const subset = remainder.slice(1, -1)
    if (/%|<!\s*ENTITY\b/i.test(subset)) {
      throw new FindingImportError("invalid_document", "Burp XML parameter and entity declarations are not accepted")
    }

    let offset = 0
    while (offset < subset.length) {
      const rest = subset.slice(offset)
      const whitespace = rest.match(/^\s+/)?.[0]
      if (whitespace) {
        offset += whitespace.length
        continue
      }
      if (rest.startsWith("<!--")) {
        const close = subset.indexOf("-->", offset + 4)
        if (close < 0) {
          throw new FindingImportError("invalid_document", "Burp XML document type contains an incomplete comment")
        }
        offset = close + 3
        continue
      }
      if (!/^<!\s*(?:ELEMENT|ATTLIST)\b/i.test(rest)) {
        throw new FindingImportError("invalid_document", "Burp XML document type contains an unsupported declaration")
      }

      let declarationEnd = -1
      let declarationQuote: '"' | "'" | undefined
      for (let index = 2; index < rest.length; index++) {
        const character = rest[index]
        if (declarationQuote) {
          if (character === declarationQuote) declarationQuote = undefined
          continue
        }
        if (character === '"' || character === "'") declarationQuote = character
        else if (character === ">") {
          declarationEnd = index
          break
        }
      }
      if (declarationEnd < 0 || declarationQuote) {
        throw new FindingImportError("invalid_document", "Burp XML document type contains an incomplete declaration")
      }
      offset += declarationEnd + 1
    }
  }

  return content.slice(0, start) + content.slice(end + 1)
}

function parseBurpXml(content: string): FindingImportPreview {
  const xml = stripBurpDoctype(content)
  const opening = xml.match(/<issues\b[^>]*>/i)
  if (!opening || !/<\/issues\s*>/i.test(xml)) {
    throw new FindingImportError("invalid_document", "Burp XML must contain a complete issues root element")
  }
  const issueOpenCount = (xml.match(/<issue\b[^>]*>/gi) ?? []).length
  const issueCloseCount = (xml.match(/<\/issue\s*>/gi) ?? []).length
  if (issueOpenCount !== issueCloseCount)
    throw new FindingImportError("invalid_document", "Burp XML contains an incomplete issue element")
  if (issueOpenCount > MAX_FINDING_IMPORT_FINDINGS) {
    throw new FindingImportError("result_limit", `Burp XML import exceeds ${MAX_FINDING_IMPORT_FINDINGS} findings`)
  }

  const findings: ImportedFinding[] = []
  const warnings: string[] = []
  const issues = xml.matchAll(/<issue\b[^>]*>([\s\S]*?)<\/issue\s*>/gi)
  for (const [index, match] of [...issues].entries()) {
    const issue = match[1]
    const name = xmlField(issue, "name")
    const host = xmlField(issue, "host")
    const path = xmlField(issue, "path")
    const title = name ?? xmlField(issue, "type")
    const serialNumber = xmlField(issue, "serialNumber")
    const location = safeBurpLocation(xmlField(issue, "location"))
    if (!title) throw new FindingImportError("invalid_document", `Burp issue ${index + 1} is missing its name`)
    const severityRaw = xmlField(issue, "severity")?.toLowerCase()
    const severity = severityRaw ? normalizeContractSeverity(severityRaw) : "info"
    const severityReported = hasRecognizedSeverity(severityRaw)
    if (!severityReported) warnings.push(`Burp issue ${index + 1} has no recognized severity; imported as info.`)
    const base = withoutUrlQuery(host) ?? host
    const target = base && path ? withoutUrlQuery(`${base}${path}`) : (base ?? withoutUrlQuery(path))
    const referencesBlock = issue.match(/<references\b[^>]*>([\s\S]*?)<\/references\s*>/i)?.[1]
    const references = referencesBlock
      ? [...referencesBlock.matchAll(/<reference\b[^>]*>([\s\S]*?)<\/reference\s*>/gi)]
          .map((reference) => stringValue(decodeXmlText(reference[1]), 512))
          .filter((reference): reference is string => Boolean(reference))
          .slice(0, 16)
      : []
    const vector = location ?? target ?? serialNumber ?? title
    findings.push({
      id: stableId(["burp", title, target, location ?? serialNumber, severityRaw]),
      source: "import",
      source_tool: "burp",
      rule_id: `burp:${stableId([title]).slice(4, 20)}`,
      title,
      severity,
      status: "observed",
      confidence: "possible",
      target,
      vector,
      evidence: {
        format: "burp-xml",
        host: withoutUrlQuery(host),
        path: withoutUrlQuery(path),
        burp_serial_number: serialNumber,
        location,
        confidence: xmlField(issue, "confidence"),
        severity_reported: severityReported,
      },
      remediation: xmlField(issue, "remediationDetail") ?? xmlField(issue, "remediationBackground"),
      tags: ["burp"],
      references,
    })
  }
  return makePreview("burp-xml", content, findings, warnings)
}

function parseDefectDojo(content: string): FindingImportPreview {
  const document = parseJson(content)
  assertBoundedJson(document)
  const records = Array.isArray(document)
    ? document
    : isRecord(document) && Array.isArray(document.findings)
      ? document.findings
      : undefined
  if (!records)
    throw new FindingImportError(
      "invalid_document",
      "DefectDojo Generic JSON must be an array or contain a findings array",
    )
  if (records.length > MAX_FINDING_IMPORT_FINDINGS) {
    throw new FindingImportError("result_limit", `DefectDojo import exceeds ${MAX_FINDING_IMPORT_FINDINGS} findings`)
  }

  const findings: ImportedFinding[] = []
  const warnings: string[] = []
  for (const [index, value] of records.entries()) {
    if (!isRecord(value))
      throw new FindingImportError("invalid_document", `DefectDojo finding ${index + 1} must be an object`)
    const title = stringValue(value.title, 512)
    const rawSeverity = stringValue(value.severity, 64)
    if (!title) throw new FindingImportError("invalid_document", `DefectDojo finding ${index + 1} is missing title`)
    const severity = normalizeContractSeverity(rawSeverity)
    const severityReported = hasRecognizedSeverity(rawSeverity)
    if (!severityReported)
      warnings.push(`DefectDojo finding ${index + 1} has no recognized severity; imported as info.`)
    const rawCwe = value.cwe
    const cwe =
      typeof rawCwe === "number" && Number.isSafeInteger(rawCwe) && rawCwe > 0 ? `CWE-${rawCwe}` : cweValue(rawCwe)
    const endpoints = Array.isArray(value.endpoints) ? value.endpoints : []
    const target =
      withoutUrlQuery(stringValue(endpoints[0], 2048)) ??
      withoutUrlQuery(stringValue(value.url, 2048)) ??
      withoutUrlQuery(stringValue(value.host, 2048))
    const uniqueID = stringValue(value.unique_id_from_tool, 128) ?? stringValue(value.id, 128)
    const tags = strings(value.tags, 32, 64)
    const references = strings(value.references, 16, 512)
    const ruleID = uniqueID ?? stableId(["defectdojo", title, cwe, target])
    findings.push({
      id: stableId(["defectdojo", uniqueID ?? title, cwe, target]),
      source: "import",
      source_tool: "defectdojo",
      rule_id: `defectdojo:${ruleID}`,
      title,
      severity,
      status: "observed",
      confidence: "possible",
      cwe,
      target,
      vector: target,
      evidence: {
        format: "defectdojo-generic-json",
        external_id: uniqueID,
        active: typeof value.active === "boolean" ? value.active : undefined,
        verified: typeof value.verified === "boolean" ? value.verified : undefined,
        severity_reported: severityReported,
      },
      remediation: stringValue(value.mitigation, 8000),
      tags,
      references,
    })
  }
  return makePreview("defectdojo-generic-json", content, findings, warnings)
}

export function parseFindingImport(format: FindingImportFormat, content: string): FindingImportPreview {
  const contentBytes = new TextEncoder().encode(content).byteLength
  if (contentBytes > MAX_FINDING_IMPORT_BYTES) {
    throw new FindingImportError("size_limit", `Import exceeds the ${MAX_FINDING_IMPORT_BYTES}-byte limit`)
  }
  if (!content.trim()) throw new FindingImportError("invalid_document", "Import document is empty")

  switch (format) {
    case "sarif-2.1":
      return parseSarif(content)
    case "nuclei-jsonl":
      return parseNucleiJsonl(content)
    case "semgrep-json":
      return parseSemgrep(content)
    case "gitleaks-json":
      return parseGitleaks(content)
    case "trivy-json":
      return parseTrivy(content)
    case "zap-json":
      return parseZap(content)
    case "burp-xml":
      return parseBurpXml(content)
    case "defectdojo-generic-json":
      return parseDefectDojo(content)
    default:
      throw new FindingImportError(
        "unsupported_format",
        `No finding parser is registered for format: ${String(format)}`,
      )
  }
}

export function importFindingDocument(
  db: Database.Interface["db"],
  input: FindingImportInput,
  options?: { events?: EventV2.Interface; location?: Location.Ref },
) {
  return Effect.gen(function* () {
    const preview = yield* Effect.try({
      try: () => parseFindingImport(input.format, input.content),
      catch: (error) => (error instanceof Error ? error : new Error(String(error))),
    })
    if (preview.findings.length === 0) {
      return yield* Effect.fail(new FindingImportError("empty_import", "The report contains no findings to persist"))
    }
    const requestedImportID = input.importID?.trim()
    if (
      input.importID !== undefined &&
      (!requestedImportID || requestedImportID.length > 128 || /[\u0000-\u001f]/.test(requestedImportID))
    ) {
      return yield* Effect.fail(
        new FindingImportError("invalid_document", "Import ID must be 1–128 printable characters"),
      )
    }
    const batchID = requestedImportID ?? `${preview.format}-v${preview.parserVersion}`
    const sourceEventID = `import:${batchID}:${preview.contentSha256}`
    const sessionID = SessionSchema.ID.make(input.sessionID)
    const session = yield* db
      .select({ id: SessionTable.id })
      .from(SessionTable)
      .where(eq(SessionTable.id, sessionID))
      .get()
      .pipe(Effect.orDie)
    if (!session) return yield* Effect.fail(new Error(`Session not found: ${input.sessionID}`))

    yield* db.transaction(() =>
      ingestToolFindings(
        db,
        {
          sessionID,
          callID: `${batchID}:${preview.contentSha256}`,
          type: "tool",
          tool: `import.${preview.format}`,
          state: { status: "completed", output: JSON.stringify({ findings: preview.findings }) },
        },
        { source: "import" },
      ),
    )

    if (options?.events) {
      const rows = yield* db
        .select({ findingID: FindingTable.id, fingerprint: FindingTable.fingerprint })
        .from(FindingObservationTable)
        .innerJoin(FindingTable, eq(FindingTable.id, FindingObservationTable.finding_id))
        .where(
          and(
            eq(FindingObservationTable.session_id, sessionID),
            eq(FindingObservationTable.source_event_id, sourceEventID),
          ),
        )
        .all()
        .pipe(Effect.orDie)
      const unique = new Map(rows.map((row) => [row.findingID, row]))
      yield* Effect.forEach(
        [...unique.values()],
        (row) =>
          options.events!.publish(
            FindingUpserted,
            {
              sessionID,
              findingID: row.findingID,
              fingerprint: row.fingerprint,
            },
            { location: options.location },
          ).pipe(
            Effect.catchCauseIf(
              (cause) => !Cause.hasInterrupts(cause),
              (cause) =>
              Effect.logWarning("failed to publish finding import notification").pipe(
                Effect.annotateLogs({ findingID: row.findingID, cause }),
              ),
            ),
          ),
        { discard: true },
      )
    }

    return { ...preview, sourceEventID, importedCount: preview.findings.length } satisfies FindingImportResult
  })
}
