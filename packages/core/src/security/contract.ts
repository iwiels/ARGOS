/**
 * Canonical contract for security findings.
 *
 * This module is the single source of truth for the shape a finding has when
 * it crosses the boundary between the scanners (the Go tools in
 * `argos-bin/cmd/web/tools/contract.go`) and the Argos backend. The Go struct
 * and the interfaces below must stay in sync — the ARG-053 contract test
 * compares both sides field by field.
 *
 * The fields that drive the deterministic engines are `source_tool`, `tags`,
 * `cwe` and `vector`: compliance
 * (`packages/core/src/compliance/derive.ts`) and MITRE ATT&CK
 * (`packages/core/src/threat-intel/attack.ts`) match on those. A finding
 * without them is invisible to the scoring pipeline, which is why the tools
 * fill them in instead of leaving the transcription step to guess.
 */

import { parseCvssShortForm, type CvssVector } from "./cvss"
import { normalizePocRecord, type PocRecord } from "./poc"
import registryData from "./rules/registry.json"

export const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const
export type Severity = (typeof SEVERITIES)[number]

export const CONFIDENCES = ["confirmed", "probable", "possible"] as const
export type Confidence = (typeof CONFIDENCES)[number]

/** Canonical length limits for every free-text field of a finding. */
export const MAX_TITLE_CHARS = 512
export const MAX_AGENT_CHARS = 128
export const MAX_TARGET_CHARS = 2048
export const MAX_VECTOR_CHARS = 2048
export const MAX_CWE_CHARS = 64
// Evidence/raw allow more headroom than prose findings need because a
// "topology" finding (tags includes "topology-snapshot") carries a full
// argos-lan build_topology/host_discovery JSON dump as its evidence —
// see packages/app/src/components/session/topology-data.ts, which parses it
// back out. A large internal network easily exceeds the old 8k/16k caps.
export const MAX_EVIDENCE_CHARS = 32_000
export const MAX_REMEDIATION_CHARS = 8000
export const MAX_TAGS = 32
export const MAX_TAG_CHARS = 64
export const MAX_RAW_CHARS = 48_000
export const MAX_SOURCE_TOOL_CHARS = 128
export const MAX_RULE_ID_CHARS = 256
export const MAX_OWASP_ITEMS = 16
export const MAX_REFERENCES = 16
export const MAX_REFERENCE_CHARS = 512
export const MAX_ID_CHARS = 128

/**
 * The eight CVSS v3.1 base metrics, in the short form the scanners emit.
 * The backend stores the long form (see {@link CvssVector}) and computes the
 * score from it — a tool never declares a score.
 */
export interface CvssVectorContract {
  AV: CvssVector["attackVector"]
  AC: CvssVector["attackComplexity"]
  PR: CvssVector["privilegesRequired"]
  UI: CvssVector["userInteraction"]
  S: CvssVector["scope"]
  C: CvssVector["confidentiality"]
  I: CvssVector["integrity"]
  A: CvssVector["availability"]
}

/** Wire shape of a finding, mirrored by the Go `Finding` struct. */
export interface FindingContract {
  id?: string
  source: string
  source_tool?: string
  rule_id?: string
  title: string
  severity: string
  confidence?: string
  cwe?: string
  owasp?: string[]
  target: string
  vector?: string
  evidence?: Record<string, unknown>
  /**
   * Proof of concept reproducible del hallazgo.
   *
   * Las tools lo escriben dentro de `evidence["poc"]` (el struct Go canónico
   * no tiene campo propio para esto); el normalizador lo levanta a su
   * columna para que el motor de re-test pueda re-ejecutarlo.
   */
  poc?: PocRecord
  remediation?: string
  cvss?: CvssVectorContract
  tags?: string[]
  references?: string[]
}

/**
 * Wire fields of {@link FindingContract}, in declaration order.
 *
 * TypeScript erases the interface at runtime, so the contract test cannot
 * reflect over it the way the Go test reflects over the struct. This list is
 * that runtime mirror: `packages/core/test/contract.test.ts` compares it
 * against the shared golden file
 * (`packages/core/test/fixtures/finding-contract.json`), and the Go test does
 * the same with `reflect` over the struct. Adding a field on one side only
 * fails one of the two.
 */
export const CONTRACT_WIRE_FIELDS = [
  "id",
  "source",
  "source_tool",
  "rule_id",
  "title",
  "severity",
  "confidence",
  "cwe",
  "owasp",
  "target",
  "vector",
  "evidence",
  "poc",
  "remediation",
  "cvss",
  "tags",
  "references",
] as const

/** A finding after normalization: every field has a known shape and length. */
export interface NormalizedFinding {
  id?: string
  source: string
  sourceTool?: string
  ruleId?: string
  title: string
  severity: Severity
  confidence: Confidence
  cwe?: string
  owasp: string[]
  target?: string
  vector?: string
  evidence: Record<string, unknown>
  poc?: PocRecord
  remediation?: string
  cvss?: CvssVectorContract
  tags: string[]
  references: string[]
}

const CVSS_LONG_TO_SHORT = {
  attackVector: "AV",
  attackComplexity: "AC",
  privilegesRequired: "PR",
  userInteraction: "UI",
  scope: "S",
  confidentiality: "C",
  integrity: "I",
  availability: "A",
} as const satisfies Record<keyof CvssVector, keyof CvssVectorContract>

const SEVERITY_ALIASES: Record<string, Severity> = {
  critical: "critical",
  crit: "critical",
  critico: "critical",
  "crítico": "critical",
  high: "high",
  alto: "high",
  alta: "high",
  medium: "medium",
  medio: "medium",
  media: "medium",
  moderate: "medium",
  low: "low",
  bajo: "low",
  baja: "low",
  info: "info",
  informational: "info",
  informativo: "info",
  none: "info",
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === "object" && !Array.isArray(value)
}

function stringValue(value: unknown, maxChars?: number): string | undefined {
  if (typeof value !== "string") return undefined
  const normalized = value.trim()
  if (!normalized) return undefined
  return maxChars === undefined ? normalized : normalized.slice(0, maxChars)
}

/**
 * A rule of the canonical finding taxonomy registry.
 *
 * The registry (packages/core/src/security/rules/registry.json) is the source
 * of truth for the taxonomy of every scanner rule Argos knows: the CWE and
 * the OWASP category it maps to, the canonical tags the compliance and
 * ATT&CK engines match on, and the minimum severity the rule guarantees.
 */
export interface FindingRule {
  id: string
  cwe: string[]
  owasp: string[]
  severityFloor: Severity | undefined
  tags: string[]
  references: string[]
}

type RegistryRuleFile = {
  id: string
  cwe?: string[]
  owasp?: string[]
  severity_floor?: string
  tags?: string[]
  references?: string[]
  matcher?: string
}

type RegistryFile = {
  version: string
  vocabulary: string[]
  cwe_by_tag: Record<string, string>
  rules: RegistryRuleFile[]
}

const REGISTRY = registryData as unknown as RegistryFile

const RULE_INDEX = new Map<string, FindingRule>()
for (const rule of REGISTRY.rules ?? []) {
  const floor = rule.severity_floor
  RULE_INDEX.set(rule.id, {
    id: rule.id,
    cwe: [...(rule.cwe ?? [])],
    owasp: [...(rule.owasp ?? [])],
    severityFloor: floor && (SEVERITIES as readonly string[]).includes(floor) ? (floor as Severity) : undefined,
    tags: [...(rule.tags ?? [])],
    references: [...(rule.references ?? [])],
  })
}

const CANONICAL_TAGS = new Set(REGISTRY.vocabulary ?? [])

/**
 * Returns the registry entry of a rule id ("nuclei:exposed-env-file",
 * "semgrep:javascript.lang.security.audit.eval-detected"), or undefined when
 * the registry does not know the rule.
 */
export function lookupRule(id: string): FindingRule | undefined {
  const rule = RULE_INDEX.get(id.trim())
  return rule ? { ...rule, cwe: [...rule.cwe], owasp: [...rule.owasp], tags: [...rule.tags], references: [...rule.references] } : undefined
}

/**
 * Returns the minimum severity a rule guarantees, or undefined when the rule
 * is unknown. A floor never lowers the severity a tool reports.
 */
export function severityFloor(id: string): Severity | undefined {
  return lookupRule(id)?.severityFloor
}

/** Returns the canonical tags of a rule, or an empty list when unknown. */
export function tagsForRule(id: string): string[] {
  return lookupRule(id)?.tags ?? []
}

/**
 * Returns the CWE a canonical tag implies, or undefined when the tag carries
 * no CWE of its own. Used as the last resort of the CWE resolution chain:
 * an empty result is preferred over an invented identifier.
 */
export function cweForTag(tag: string): string | undefined {
  const cwe = REGISTRY.cwe_by_tag?.[tag.trim().toLowerCase()]
  return cwe ? normalizeContractCwe(cwe) : undefined
}

/** Reports whether a tag belongs to the canonical vocabulary. */
export function isCanonicalTag(tag: string): boolean {
  return CANONICAL_TAGS.has(tag.trim().toLowerCase())
}

/** Returns the canonical tag vocabulary the compliance and ATT&CK engines match on. */
export function canonicalVocabulary(): string[] {
  return [...CANONICAL_TAGS]
}

/**
 * Normalizes a severity onto the canonical closed set. Unknown values degrade
 * to "info" instead of guessing a level.
 */
export function normalizeContractSeverity(value: unknown): Severity {
  const normalized = typeof value === "string" ? value.trim().toLowerCase() : ""
  return SEVERITY_ALIASES[normalized] ?? "info"
}

/**
 * Normalizes a confidence onto the canonical closed set. Anything outside the
 * vocabulary degrades to "possible" — the least committal value.
 */
export function normalizeContractConfidence(value: unknown): Confidence {
  const normalized = typeof value === "string" ? value.trim().toLowerCase() : ""
  return (CONFIDENCES as readonly string[]).includes(normalized) ? (normalized as Confidence) : "possible"
}

/**
 * Normalizes a CWE identifier to the canonical "CWE-NNN" form. Accepts
 * "CWE-89", "cwe 89" and the bare "89". Returns undefined when the value
 * does not parse: an invented CWE is worse than a missing one.
 */
export function normalizeContractCwe(value: unknown): string | undefined {
  const raw = stringValue(value)
  if (!raw) return undefined
  const upper = raw.toUpperCase()
  const digits = upper.startsWith("CWE") ? upper.slice(3).replace(/^[-_\s]+/, "") : upper
  // No published CWE id has more than four digits; anything longer is noise.
  if (!digits || digits.length > 6 || !/^\d+$/.test(digits)) return undefined
  return `CWE-${digits}`
}

/**
 * Normalizes the evidence into a plain object. A string becomes
 * `{ text }`; anything that is not an object is dropped.
 */
export function normalizeContractEvidence(value: unknown): Record<string, unknown> {
  if (!value) return {}
  if (typeof value === "string") {
    const trimmed = value.trim()
    return trimmed ? { text: trimmed.slice(0, MAX_EVIDENCE_CHARS) } : {}
  }
  if (isRecord(value)) return value
  return {}
}

/**
 * Normalizes a list of strings: trimmed, deduplicated and capped both in item
 * length and in item count. Tags are lowercased because they come from a
 * controlled vocabulary; references and OWASP ids keep their case (URLs are
 * case-sensitive, "A03:2021" is canonical).
 */
function stringList(value: unknown, maxItems: number, maxChars: number, lowercase = false): string[] {
  if (!Array.isArray(value)) return []
  const seen = new Set<string>()
  const out: string[] = []
  for (const item of value) {
    const trimmed = stringValue(item, maxChars)
    if (!trimmed) continue
    const normalized = lowercase ? trimmed.toLowerCase() : trimmed
    if (seen.has(normalized)) continue
    seen.add(normalized)
    out.push(normalized)
    if (out.length >= maxItems) break
  }
  return out
}

/**
 * Normalizes the CVSS base metrics. The canonical short form ("AV", "AC", …)
 * is accepted, as is the long form the backend stores. The vector is dropped
 * unless every base metric is present and valid — a partial vector would
 * force the scorer to invent the missing ones.
 */
export function normalizeContractCvss(value: unknown): CvssVectorContract | undefined {
  if (!isRecord(value)) return undefined
  const short: Record<string, unknown> = {}
  for (const [longKey, shortKey] of Object.entries(CVSS_LONG_TO_SHORT)) {
    short[shortKey.toLowerCase()] = value[longKey] ?? value[shortKey] ?? value[shortKey.toLowerCase()]
  }
  const parsed = parseCvssShortForm(short)
  if (!parsed) return undefined
  return {
    AV: parsed.attackVector,
    AC: parsed.attackComplexity,
    PR: parsed.privilegesRequired,
    UI: parsed.userInteraction,
    S: parsed.scope,
    C: parsed.confidentiality,
    I: parsed.integrity,
    A: parsed.availability,
  }
}

/**
 * Normaliza el proof of concept del hallazgo.
 *
 * Se acepta en dos lugares: como campo propio del contrato (`poc`) y dentro
 * de la evidencia (`evidence["poc"]`), que es donde lo escriben las tools Go
 * — el struct canónico del hallazgo no tiene campo para el PoC.
 */
export function normalizeContractPoc(raw: unknown, evidence?: Record<string, unknown>): PocRecord | undefined {
  const candidate = raw ?? (evidence && typeof evidence === "object" ? evidence.poc : undefined)
  return normalizePocRecord(candidate)
}

/**
 * Normalizes an arbitrary payload into the canonical finding shape. This is
 * the single entry point both ingestion paths use: the tool output and the
 * `argos_memory_save` payload of the LLM.
 */
export function normalizeContract(raw: unknown): NormalizedFinding {
  const record = isRecord(raw) ? raw : {}
  const evidence = normalizeContractEvidence(record.evidence)
  return {
    id: stringValue(record.id, MAX_ID_CHARS),
    source: stringValue(record.source, MAX_SOURCE_TOOL_CHARS) ?? "",
    sourceTool: stringValue(record.source_tool, MAX_SOURCE_TOOL_CHARS),
    ruleId: stringValue(record.rule_id, MAX_RULE_ID_CHARS),
    title: stringValue(record.title, MAX_TITLE_CHARS) ?? "",
    severity: normalizeContractSeverity(record.severity),
    confidence: normalizeContractConfidence(record.confidence),
    cwe: normalizeContractCwe(record.cwe),
    owasp: stringList(record.owasp, MAX_OWASP_ITEMS, MAX_TAG_CHARS),
    target: stringValue(record.target, MAX_TARGET_CHARS),
    vector: stringValue(record.vector, MAX_VECTOR_CHARS),
    evidence,
    poc: normalizeContractPoc(record.poc, evidence),
    remediation: stringValue(record.remediation, MAX_REMEDIATION_CHARS),
    cvss: normalizeContractCvss(record.cvss),
    tags: stringList(record.tags, MAX_TAGS, MAX_TAG_CHARS, true),
    references: stringList(record.references, MAX_REFERENCES, MAX_REFERENCE_CHARS),
  }
}

/**
 * Maps a normalized finding onto the columns of the `security_finding` table
 * (see `packages/core/src/security/sql.ts`).
 */
export function contractToDbRow(finding: NormalizedFinding): {
  title: string
  severity: Severity
  source: string
  source_tool: string | undefined
  target: string | undefined
  cwe: string | undefined
  vector: string | undefined
  evidence: Record<string, unknown>
  poc: PocRecord | undefined
  remediation: string | undefined
  tags: string[]
  cvss_input: CvssVector | undefined
  confidence: Confidence
  rule_id: string | undefined
  owasp: string[]
  references: string[]
} {
  return {
    title: finding.title,
    severity: finding.severity,
    source: finding.source,
    source_tool: finding.sourceTool,
    target: finding.target,
    cwe: finding.cwe,
    vector: finding.vector,
    evidence: finding.evidence,
    poc: finding.poc,
    remediation: finding.remediation,
    tags: finding.tags,
    cvss_input: finding.cvss ? contractCvssToVector(finding.cvss) : undefined,
    confidence: finding.confidence,
    rule_id: finding.ruleId,
    owasp: finding.owasp,
    references: finding.references,
  }
}

/** Converts the short contract vector into the long form the database stores. */
export function contractCvssToVector(contract: CvssVectorContract): CvssVector {
  return {
    attackVector: contract.AV,
    attackComplexity: contract.AC,
    privilegesRequired: contract.PR,
    userInteraction: contract.UI,
    scope: contract.S,
    confidentiality: contract.C,
    integrity: contract.I,
    availability: contract.A,
  }
}
