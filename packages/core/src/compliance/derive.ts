/** Derivación del estado de controles a partir de hallazgos.
 *
 *  El matching usa dos capas:
 *  1. Señales de keywords (datos de saasfort, MIT) cacheados en el catálogo —
 *     checks externos ("HSTS", "CAA record", …) contra título/vector/tags/tool.
 *  2. Heurísticas semánticas de la aplicación (como attack.ts): tags/CWE/tool/
 *     técnicas ATT&CK conocidos → controles concretos del catálogo cargado.
 *  El conector Elasticsearch (`es.*`) mapea a controles de logging/monitoring.
 *
 *  Regla de estado (derivado de findings, jerárquico):
 *  - subcategoría/control con hallazgo crítico/alto abierto  → deficient
 *  - subcategoría/control con hallazgos (sin crítico/alto)    → partial
 *  - sin hallazgos                                            → compliant
 *  - función/categoría/tema = peor de sus hijos
 *
 *  Cada match además deja **rastro auditable**: la regla que lo disparó
 *  (`derivedFrom`) y la confianza de la derivación (no la del hallazgo). Un
 *  auditor tiene que poder responder "¿por qué este control falla?" sin
 *  volver a correr el motor.
 */

import {
  FRAMEWORKS,
  type ControlEvidence,
  type ControlEvidenceFinding,
  type ControlStatus,
  type ControlStatusRow,
  type EvidenceConfidence,
  type EvidenceEntry,
  type FindingLike,
  type Framework,
} from "./types"
import { buildSignalIndex, type SignalIndex, type SignalKind } from "./parse"
import type { ComplianceCatalogRow } from "./sql"

export type SemTarget = [Framework, string]

export type SemanticRule = {
  reason: string
  tags?: string[]
  cwes?: string[]
  /**
   * Herramientas de la regla. Si la regla **no** declara `cwes`, la
   * herramienta es la señal primaria (dispara la regla sola). Si la regla
   * **sí** declara `cwes`, la herramienta corrobora: sube la confianza de
   * `medium` a `high` pero no dispara la regla por sí sola (un hallazgo sin
   * CWE no es una vulnerabilidad web solo por venir del escáner web).
   */
  tools?: string[]
  techniques?: string[]
  targets: SemTarget[]
}

/**
 * Los targets de SOC 2 / NIS2 / DORA de cada regla NO son inventados: son los
 * que el crosswalk de ISO 27001:2022 declara para los mismos controles ISO
 * que la regla ya apunta (`soc2[]`, `nis2[]`, `dora[]` de cada fila ISO). El
 * test `compliance-frameworks.test.ts` valida que todo target existe en el
 * catálogo generado y que está justificado por el crosswalk.
 *
 * Los targets de PCI-DSS sí son una decisión de mapeo propia (PCI-DSS no está
 * en ese crosswalk). Cada regla apunta al sub-requisito de la norma (X.Y) y al
 * control hoja que la describe (X.Y.Z): el sub-requisito es el nivel que un
 * auditor cita en el informe y la hoja es el nivel que computa el score. Los
 * ancestros de la hoja heredan el estado por el rollup, así que ambos niveles
 * quedan deficientes con el mismo hallazgo.
 */
export const SEMANTIC: SemanticRule[] = [
  {
    reason: "vuln:web-app",
    tags: ["xss", "sqli", "command-injection", "rce", "code-injection", "path-traversal", "ssrf", "xxe", "deserialization", "idor", "broken-access-control", "upload", "open-redirect"],
    targets: [
      ["nist_csf_v2", "PR.PS-06"],
      ["iso27001_2022", "A.8.28"],
      ["iso27001_2022", "A.8.26"],
      ["soc2", "CC8"],
      ["soc2", "PI1"],
      ["nis2", "21.2.e"],
      ["dora", "Art.7"],
      ["pci_dss_v4", "6.2"],
      ["pci_dss_v4", "6.2.4"],
      ["pci_dss_v4", "6.3"],
      ["pci_dss_v4", "6.3.1"],
      ["pci_dss_v4", "6.4"],
      ["pci_dss_v4", "6.4.3"],
      ["pci_dss_v4", "11.3"],
      ["pci_dss_v4", "11.3.2"],
    ],
  },
  {
    reason: "cwe:web-vuln",
    cwes: ["89", "78", "79", "22", "94", "918", "502", "434", "611", "77", "95"],
    // La herramienta corrobora el CWE (el escáner web/fuzzer es quien lo
    // verificó): sube la confianza de la derivación a `high`.
    tools: ["web.scan", "web.fuzz", "web.probe"],
    targets: [
      ["nist_csf_v2", "PR.PS-06"],
      ["iso27001_2022", "A.8.28"],
      ["soc2", "CC8"],
      ["nis2", "21.2.e"],
      ["dora", "Art.7"],
      ["pci_dss_v4", "6.2.4"],
      ["pci_dss_v4", "6.3.1"],
      ["pci_dss_v4", "11.3.2"],
    ],
  },
  {
    reason: "vuln:access-control",
    // Access control roto (IDOR) es su propia familia: PCI-DSS la trata en
    // Req.7 (acceso por necesidad de conocer / mínimo privilegio) y Req.6.4
    // (aplicaciones públicas protegidas). Se separa de `vuln:web-app` para no
    // declarar conformes controles de acceso por un XSS o un SQLi.
    tags: ["idor", "broken-access-control"],
    cwes: ["639", "862", "863", "284"],
    targets: [
      ["pci_dss_v4", "6.4"],
      ["pci_dss_v4", "6.4.1"],
      ["pci_dss_v4", "7.2"],
      ["pci_dss_v4", "7.2.1"],
      ["pci_dss_v4", "7.3"],
      ["pci_dss_v4", "7.3.1"],
    ],
  },
  {
    reason: "vuln:auth",
    tags: ["auth", "weak-auth", "default-credentials", "hardcoded-credentials", "brute-force", "mfa-bypass", "password-spray", "default-account"],
    cwes: ["287", "306", "307", "521", "640", "798", "862", "863"],
    targets: [
      ["nist_csf_v2", "PR.AA-01"],
      ["nist_csf_v2", "PR.AA-03"],
      ["nist_csf_v2", "PR.AA-05"],
      ["iso27001_2022", "A.8.5"],
      ["iso27001_2022", "A.5.17"],
      ["iso27001_2022", "A.8.2"],
      ["soc2", "CC6"],
      ["nis2", "21.2.i"],
      ["nis2", "21.2.j"],
      ["dora", "Art.9"],
      ["pci_dss_v4", "8.3"],
      ["pci_dss_v4", "8.3.2"],
      ["pci_dss_v4", "8.3.4"],
      ["pci_dss_v4", "8.3.6"],
      ["pci_dss_v4", "8.4"],
      ["pci_dss_v4", "8.4.2"],
      ["pci_dss_v4", "8.6"],
      ["pci_dss_v4", "8.6.2"],
    ],
  },
  {
    reason: "crypto-tls",
    tags: ["tls", "weak-crypto", "self-signed", "invalid-cert", "missing-hsts", "hsts", "cleartext", "plaintext", "missing-tls", "weak-cipher"],
    cwes: ["319", "311", "326", "327", "295"],
    // El escáner web es quien verifica la configuración TLS: corrobora el CWE.
    tools: ["web.scan", "web.probe"],
    targets: [
      ["nist_csf_v2", "PR.DS-02"],
      ["iso27001_2022", "A.8.24"],
      ["iso27001_2022", "A.8.20"],
      ["soc2", "CC6"],
      ["soc2", "C1"],
      ["nis2", "21.2.e"],
      ["nis2", "21.2.h"],
      ["dora", "Art.7"],
      ["dora", "Art.9"],
      ["pci_dss_v4", "3.4"],
      ["pci_dss_v4", "3.4.1"],
      ["pci_dss_v4", "4.2"],
      ["pci_dss_v4", "4.2.1"],
    ],
  },
  {
    reason: "secrets",
    tags: ["secret-exposure", "hardcoded-secret", "api-key", "token", ".env", "credentials", "password-store"],
    cwes: ["200", "522", "256"],
    targets: [
      ["nist_csf_v2", "PR.DS-01"],
      ["iso27001_2022", "A.8.3"],
      ["iso27001_2022", "A.8.10"],
      ["soc2", "CC6"],
      ["soc2", "C1"],
      ["soc2", "PI1"],
      ["nis2", "21.2.a"],
      ["nis2", "21.2.i"],
      ["dora", "Art.6"],
      ["dora", "Art.9"],
      ["pci_dss_v4", "3.5"],
      ["pci_dss_v4", "3.5.1"],
      ["pci_dss_v4", "8.3"],
      ["pci_dss_v4", "8.3.2"],
    ],
  },
  {
    reason: "network-exposure",
    tags: ["open-ports", "port-scan", "service-discovery", "exposed-service", "open-share", "smb-share", "rdp", "vpn"],
    tools: ["lan.port_scan", "lan.host_discovery", "web.probe"],
    targets: [
      ["nist_csf_v2", "ID.AM-01"],
      ["nist_csf_v2", "PR.IR-01"],
      ["iso27001_2022", "A.8.20"],
      ["iso27001_2022", "A.8.22"],
      ["soc2", "CC6"],
      ["nis2", "21.2.e"],
      ["dora", "Art.7"],
      ["dora", "Art.9"],
      ["pci_dss_v4", "1.2"],
      ["pci_dss_v4", "1.2.7"],
      ["pci_dss_v4", "1.3"],
      ["pci_dss_v4", "1.3.1"],
      ["pci_dss_v4", "1.4"],
      ["pci_dss_v4", "1.4.1"],
    ],
  },
  {
    reason: "cloud-exposure",
    tags: ["open-bucket", "cloud-misconfig", "s3-exposure", "cloud-storage", "aws", "azure", "gcp"],
    targets: [
      ["nist_csf_v2", "ID.AM-05"],
      ["iso27001_2022", "A.8.3"],
      ["iso27001_2022", "A.5.23"],
      ["soc2", "CC6"],
      ["soc2", "CC9"],
      ["nis2", "21.2.d"],
      ["nis2", "21.2.e"],
      ["nis2", "21.2.i"],
      ["dora", "Art.9"],
      ["dora", "Art.28"],
      ["pci_dss_v4", "2.2"],
      ["pci_dss_v4", "2.2.4"],
      ["pci_dss_v4", "3.5"],
      ["pci_dss_v4", "3.5.1"],
    ],
  },
  {
    reason: "dos",
    tags: ["dos", "resource-exhaustion", "rate-limit"],
    cwes: ["400", "770", "799"],
    targets: [
      ["nist_csf_v2", "PR.IR-04"],
      ["iso27001_2022", "A.8.6"],
      ["soc2", "A1"],
      ["nis2", "21.2.c"],
      ["dora", "Art.7"],
      ["pci_dss_v4", "6.2.4"],
      ["pci_dss_v4", "6.4"],
      ["pci_dss_v4", "6.4.1"],
    ],
  },
  {
    reason: "backup-ransomware",
    tags: ["backup", "ransomware", "backup-deletion", "backup-exposed", "shadow-copy"],
    techniques: ["T1486", "T1490"],
    targets: [
      ["nist_csf_v2", "PR.DS-11"],
      ["iso27001_2022", "A.8.13"],
      ["iso27001_2022", "A.5.29"],
      ["soc2", "A1"],
      ["soc2", "CC7"],
      ["nis2", "21.2.c"],
      ["dora", "Art.11"],
      ["dora", "Art.12"],
      ["pci_dss_v4", "9.5"],
      ["pci_dss_v4", "9.5.1"],
      ["pci_dss_v4", "12.10"],
      ["pci_dss_v4", "12.10.2"],
    ],
  },
  {
    reason: "supply-chain",
    tags: ["supply-chain", "dependency", "malicious-package", "typosquatting", "dependency-confusion"],
    targets: [
      ["nist_csf_v2", "GV.SC-05"],
      ["nist_csf_v2", "PR.PS-06"],
      ["iso27001_2022", "A.5.19"],
      ["iso27001_2022", "A.5.21"],
      ["soc2", "CC9"],
      ["nis2", "21.2.d"],
      ["dora", "Art.28"],
      ["pci_dss_v4", "6.3"],
      ["pci_dss_v4", "6.3.3"],
      ["pci_dss_v4", "6.4"],
      ["pci_dss_v4", "6.4.2"],
      ["pci_dss_v4", "11.3"],
      ["pci_dss_v4", "11.3.2"],
    ],
  },
  {
    reason: "phishing",
    tags: ["phishing", "spoof", "dmarc"],
    targets: [
      ["nist_csf_v2", "PR.AT-01"],
      ["iso27001_2022", "A.6.3"],
      ["iso27001_2022", "A.5.14"],
      ["soc2", "CC1"],
      ["soc2", "CC6"],
      ["soc2", "C1"],
      ["nis2", "21.2.g"],
      ["nis2", "21.2.h"],
      ["dora", "Art.9"],
      ["dora", "Art.13"],
      ["pci_dss_v4", "5.4"],
      ["pci_dss_v4", "5.4.1"],
    ],
  },
  {
    reason: "logging-monitoring",
    tags: ["log", "logging", "audit", "tampering", "log-injection"],
    techniques: ["T1070", "T1562.001"],
    targets: [
      ["nist_csf_v2", "PR.PS-04"],
      ["nist_csf_v2", "DE.CM-01"],
      ["iso27001_2022", "A.8.15"],
      ["iso27001_2022", "A.8.16"],
      ["soc2", "CC7"],
      ["soc2", "CC4"],
      ["nis2", "21.2.b"],
      ["dora", "Art.10"],
      ["pci_dss_v4", "10.2"],
      ["pci_dss_v4", "10.2.1"],
      ["pci_dss_v4", "10.4"],
      ["pci_dss_v4", "10.4.1"],
    ],
  },
  {
    reason: "information-disclosure",
    tags: ["information-disclosure", "pii", "data-exposure", "git-exposure", "data-exfiltration"],
    techniques: ["T1213", "T1530", "T1005", "T1041"],
    targets: [
      ["nist_csf_v2", "PR.DS-01"],
      ["nist_csf_v2", "ID.AM-07"],
      ["iso27001_2022", "A.8.3"],
      ["iso27001_2022", "A.8.10"],
      ["soc2", "CC6"],
      ["soc2", "C1"],
      ["soc2", "PI1"],
      ["nis2", "21.2.a"],
      ["nis2", "21.2.i"],
      ["dora", "Art.6"],
      ["dora", "Art.9"],
      ["pci_dss_v4", "3.3"],
      ["pci_dss_v4", "3.3.1"],
      ["pci_dss_v4", "6.2.4"],
    ],
  },
]

/** Findings originados en el conector Elasticsearch apuntan a logging/monitoring. */
const ELASTICSEARCH_TARGETS: SemTarget[] = [
  ["nist_csf_v2", "PR.PS-04"],
  ["nist_csf_v2", "DE.CM-01"],
  ["nist_csf_v2", "DE.AE-02"],
  ["iso27001_2022", "A.8.15"],
  ["iso27001_2022", "A.8.16"],
  ["soc2", "CC7"],
  ["soc2", "CC4"],
  ["nis2", "21.2.b"],
  ["dora", "Art.10"],
  ["pci_dss_v4", "10.2"],
  ["pci_dss_v4", "10.2.1"],
  ["pci_dss_v4", "10.4"],
  ["pci_dss_v4", "10.4.1"],
]

const isOpen = (status?: string | null) => {
  const closed = new Set(["closed", "fixed", "resolved", "mitigated", "accepted", "remediated"])
  return !(status && closed.has(status.trim().toLowerCase()))
}

const CRITICAL_HIGH = new Set(["critical", "high"])

const escapeRegex = (value: string) => value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")

const matchesKeyword = (haystack: string, keyword: string) => {
  const key = keyword.trim().toLowerCase()
  if (!key) return false
  if (key.includes(" ")) return haystack.includes(key)
  return new RegExp(`\\b${escapeRegex(key)}\\b`).test(haystack)
}

export interface ControlMatch {
  framework: Framework
  controlId: string
  reason: string
  /** Confianza de esta derivación (vínculo finding ↔ control). */
  confidence: EvidenceConfidence
}

/** Orden de confianza: la mayor gana. */
const CONFIDENCE_RANK: Record<EvidenceConfidence, number> = { low: 1, medium: 2, high: 3 }

export const maxConfidence = (a: EvidenceConfidence, b: EvidenceConfidence): EvidenceConfidence =>
  CONFIDENCE_RANK[a] >= CONFIDENCE_RANK[b] ? a : b

/** La menor gana: el eslabón más débil de la cadena. */
export const minConfidence = (a: EvidenceConfidence, b: EvidenceConfidence): EvidenceConfidence =>
  CONFIDENCE_RANK[a] <= CONFIDENCE_RANK[b] ? a : b

function normalizeFinding(finding: FindingLike) {
  const tags = Array.isArray(finding.tags) ? finding.tags.map((tag) => String(tag).toLowerCase()) : []
  const cwe = String(finding.cwe ?? "")
    .toUpperCase()
    .replace(/^CWE-?/, "")
  const techniques = Array.isArray(finding.attackTechniques)
    ? finding.attackTechniques.map((t) => {
        if (typeof t === "string") return t
        if (t && typeof t === "object") return String((t as { id?: unknown }).id ?? "")
        return ""
      })
    : []
  return {
    tags,
    cwe,
    techniques,
    tool: (finding.sourceTool ?? "").toLowerCase(),
    title: (finding.title ?? "").toLowerCase(),
  }
}

/**
 * Confianza de un check externo del catálogo.
 *
 * - `header` + match en el **título**: el escáner verificó esa cabecera de
 *   seguridad (`high`).
 * - `header` matcheado fuera del título: la señal existe pero no es el objeto
 *   del hallazgo (`medium`).
 * - `check` completo (frase del catálogo externo) en el título: `medium` — es
 *   un check de un catálogo de terceros, verificado por keywords.
 * - `word` (fragmento) o match fuera del título: `low` — coincidencia léxica.
 */
const signalConfidence = (kind: SignalKind, matchedInTitle: boolean): EvidenceConfidence => {
  if (kind === "header") return matchedInTitle ? "high" : "medium"
  if (kind === "check") return matchedInTitle ? "medium" : "low"
  return "low"
}

/**
 * Mapea un hallazgo a controles del catálogo cargado. Devuelve un match por
 * (control, regla): un hallazgo puede activar el mismo control por reglas
 * distintas y cada una queda registrada por separado — el auditor tiene que
 * poder ver todas las reglas que sobbingran.
 *
 * La validación usa claves compuestas `framework:control_id` para que un target
 * semántico o keyword nunca mapee un control del framework equivocado si los IDs
 * llegaran a colisionar entre catálogos.
 */
export function matchFindingToControls(
  finding: FindingLike,
  signalIndex: SignalIndex,
  catalogIds: Set<string>,
): ControlMatch[] {
  const { tags, cwe, techniques, tool, title } = normalizeFinding(finding)
  const haystack = [finding.title, finding.vector, tags.join(" "), tool]
    .filter((value): value is string => !!value && typeof value === "string")
    .join(" ")
    .toLowerCase()

  const matched = new Map<string, ControlMatch>()
  const add = (framework: Framework, controlId: string, reason: string, confidence: EvidenceConfidence) => {
    const key = `${framework}:${controlId}`
    if (!catalogIds.has(key)) return
    const matchKey = `${key}:${reason}`
    const existing = matched.get(matchKey)
    if (existing) {
      existing.confidence = maxConfidence(existing.confidence, confidence)
      return
    }
    matched.set(matchKey, { framework, controlId, reason, confidence })
  }

  // Capa 1: señales de keywords (checks externos del catálogo).
  for (const [keyword, targets] of signalIndex) {
    if (!matchesKeyword(haystack, keyword)) continue
    const matchedInTitle = matchesKeyword(title, keyword)
    for (const target of targets) {
      add(target.framework, target.controlId, `check:${keyword}`, signalConfidence(target.kind, matchedInTitle))
    }
  }

  // Capa 2: heurísticas semánticas (tags / CWE / tool / técnica ATT&CK).
  for (const rule of SEMANTIC) {
    const tagHit = rule.tags?.some((tag) => tags.includes(tag)) ?? false
    const cweHit = rule.cwes?.includes(cwe) ?? false
    const toolHit = rule.tools?.some((name) => tool === name || tool.startsWith(name)) ?? false
    const techHit = rule.techniques?.some((id) => techniques.includes(id)) ?? false
    // Una regla que declara CWE no se dispara por la herramienta: la
    // herramienta corrobora (sube la confianza), no decide.
    const declaresCwes = (rule.cwes?.length ?? 0) > 0
    const toolTriggers = toolHit && !declaresCwes
    if (!tagHit && !cweHit && !techHit && !toolTriggers) continue
    // high: dos señales independientes (CWE exacto + herramienta corroborante).
    // medium: una señal canónica (CWE exacto o tag exacto de la regla).
    // low: heurística (solo tool, solo técnica ATT&CK).
    const confidence: EvidenceConfidence = cweHit && toolHit ? "high" : cweHit || tagHit ? "medium" : "low"
    for (const [framework, controlId] of rule.targets) {
      add(framework, controlId, rule.reason, confidence)
    }
  }

  // Capa 3: evidencia del conector Elasticsearch (tools `es.*`).
  // Match por origen de herramienta, sin CWE ni tag canónico: mismo nivel que
  // un match por tool en las reglas semánticas.
  if (tool.startsWith("es.")) {
    for (const [framework, controlId] of ELASTICSEARCH_TARGETS) {
      add(framework, controlId, "evidence:elasticsearch", "low")
    }
  }

  return Array.from(matched.values())
}

const STATUS_RANK: Record<ControlStatus, number> = {
  deficient: 4,
  partial: 3,
  compliant: 2,
  unassessed: 1,
}

const worst = (a: ControlStatus, b: ControlStatus): ControlStatus =>
  STATUS_RANK[a] >= STATUS_RANK[b] ? a : b

const toEvidence = (finding: FindingLike, fromElasticsearch: boolean): EvidenceEntry => ({
  findingID: finding.id ?? "",
  title: finding.title ?? "",
  severity: finding.severity ?? "info",
  status: finding.status ?? "open",
  tool: finding.sourceTool ?? undefined,
  fromElasticsearch,
  timeUpdated: finding.timeUpdated ?? 0,
  cwe: finding.cwe ? String(finding.cwe) : undefined,
})

const toEvidenceFinding = (finding: FindingLike): ControlEvidenceFinding => ({
  id: finding.id ?? "",
  title: finding.title ?? "",
  severity: finding.severity ?? "info",
  cwe: finding.cwe ? String(finding.cwe) : undefined,
  sourceTool: finding.sourceTool ?? undefined,
  confidence: finding.confidence ?? undefined,
})

const MAX_EVIDENCE_PER_CONTROL = 20
const MAX_FINDINGS_PER_RULE = 20
const MAX_DERIVATION_PER_CONTROL = 50

export function deriveProjectStatuses(input: {
  projectID: string
  findings: FindingLike[]
  catalog: ComplianceCatalogRow[]
  now?: number
}): ControlStatusRow[] {
  const { projectID, findings, catalog, now = Date.now() } = input
  if (catalog.length === 0) return []

  const nistChecks = new Map<string, string[]>()
  const isoChecks = new Map<string, string[]>()
  for (const row of catalog) {
    const checks = Array.isArray(row.attributes["checks"]) ? (row.attributes["checks"] as string[]) : []
    if (checks.length === 0) continue
    if (row.framework === FRAMEWORKS.nistCsfV2) nistChecks.set(row.control_id, checks)
    else if (row.framework === FRAMEWORKS.iso27001) isoChecks.set(row.control_id, checks)
  }
  const signalIndex = buildSignalIndex(nistChecks, isoChecks)
  const catalogIds = new Set(catalog.map((row) => `${row.framework}:${row.control_id}`))

  // Controles que el motor no puede verificar: ningún hallazgo de Argos puede
  // activarlos (p. ej. el control físico de la Requirement 9 de PCI-DSS). Se
  // reportan como `unassessed`, nunca como `compliant`: afirmar conformidad
  // sobre algo que nadie midió es una mentira en el informe.
  const notEvaluable = new Set<string>()
  for (const row of catalog) {
    const coverage = row.attributes?.["coverage"]
    if (coverage === "not-evaluable") notEvaluable.add(`${row.framework}:${row.control_id}`)
  }

  // Hijos por framework para expandir matches de categoría y agregar estados.
  // La clave es `framework:control_id`: los ids de control pueden colisionar
  // entre frameworks (y el estado/evidencia de uno no puede filtrarse al otro).
  const childrenByParent = new Map<string, string[]>()
  for (const row of catalog) {
    if (!row.parent_id) continue
    const parentKey = `${row.framework}:${row.parent_id}`
    const siblings = childrenByParent.get(parentKey) ?? []
    siblings.push(`${row.framework}:${row.control_id}`)
    childrenByParent.set(parentKey, siblings)
  }

  // Acumulación de evidencia por control.
  //  - `rules`: regla → hallazgos que la activaron (la vista auditable).
  //  - `flat`: lista plana de hallazgos (la que consumen UI y exports), con la
  //    regla y la confianza del match más fuerte de cada hallazgo.
  type RuleAcc = { findings: ControlEvidenceFinding[]; confidence: EvidenceConfidence }
  const rules = new Map<string, Map<string, RuleAcc>>()
  const flat = new Map<string, Map<string, EvidenceEntry>>()

  const accumulate = (
    controlKey: string,
    findingKey: string,
    finding: FindingLike,
    match: ControlMatch,
  ) => {
    const ruleMap = rules.get(controlKey) ?? new Map<string, RuleAcc>()
    const rule = ruleMap.get(match.reason) ?? { findings: [], confidence: "low" as EvidenceConfidence }
    rule.findings.push(toEvidenceFinding(finding))
    rule.confidence = maxConfidence(rule.confidence, match.confidence)
    ruleMap.set(match.reason, rule)
    rules.set(controlKey, ruleMap)

    const flatMap = flat.get(controlKey) ?? new Map<string, EvidenceEntry>()
    const existing = flatMap.get(findingKey)
    if (!existing) {
      flatMap.set(findingKey, {
        ...toEvidence(finding, String(finding.sourceTool ?? "").toLowerCase().startsWith("es.")),
        derivedFrom: match.reason,
        confidence: match.confidence,
      })
    } else if (CONFIDENCE_RANK[match.confidence] > CONFIDENCE_RANK[existing.confidence ?? "low"]) {
      existing.derivedFrom = match.reason
      existing.confidence = match.confidence
    }
    flat.set(controlKey, flatMap)
  }

  findings.forEach((finding, index) => {
    const matches = matchFindingToControls(finding, signalIndex, catalogIds)
    // La clave del hallazgo dentro del control: findings sin id siguen siendo
    // hallazgos distintos.
    const findingKey = finding.id ? finding.id : `#${index}`
    for (const match of matches) {
      accumulate(`${match.framework}:${match.controlId}`, findingKey, finding, match)
    }
  })

  // Estado por control (todos los niveles). Los padres = peor de sus hijos.
  const statusFor = (key: string): { status: ControlStatus; evidence: EvidenceEntry[]; derivation: ControlEvidence[] } => {
    const ruleMap = rules.get(key)
    const flatMap = flat.get(key)
    const derivation = ruleMap
      ? Array.from(ruleMap, ([derivedFrom, acc]) => ({
          derivedFrom,
          findings: acc.findings.slice(0, MAX_FINDINGS_PER_RULE),
          confidence: acc.confidence,
        }))
      : []
    if (!flatMap || flatMap.size === 0) {
      // Sin hallazgos: el default del motor es "sin hallazgos mapeados". Pero si
      // el control no es evaluable por Argos, `unassessed` es la única respuesta
      // honesta.
      return { status: notEvaluable.has(key) ? "unassessed" : "compliant", evidence: [], derivation: [] }
    }
    const findings = Array.from(flatMap.values())
    const openCriticalHigh = findings.some(
      (f) => isOpen(f.status) && CRITICAL_HIGH.has(String(f.severity ?? "").toLowerCase()),
    )
    return {
      status: openCriticalHigh ? "deficient" : "partial",
      evidence: findings.slice(0, MAX_EVIDENCE_PER_CONTROL),
      derivation: derivation.slice(0, MAX_DERIVATION_PER_CONTROL),
    }
  }

  const computed = new Map<string, { status: ControlStatus; evidence: EvidenceEntry[]; derivation: ControlEvidence[] }>()
  const compute = (key: string): { status: ControlStatus; evidence: EvidenceEntry[]; derivation: ControlEvidence[] } => {
    const cached = computed.get(key)
    if (cached) return cached
    const own = statusFor(key)
    const children = childrenByParent.get(key) ?? []
    let status = own.status
    const evidence: EvidenceEntry[] = own.status !== "compliant" ? [...own.evidence] : []
    const derivation: ControlEvidence[] = [...own.derivation]
    // Un padre con hijos que el motor no evaluó no puede declararse conforme:
    // `unassessed` es el peor estado conocido para un nodo agregado.
    let hasUnassessed = notEvaluable.has(key)
    for (const childKey of children) {
      const child = compute(childKey)
      if (child.status === "unassessed") hasUnassessed = true
      status = worst(status, child.status)
      if (child.evidence.length > 0 && evidence.length < MAX_EVIDENCE_PER_CONTROL) {
        evidence.push(...child.evidence.slice(0, MAX_EVIDENCE_PER_CONTROL - evidence.length))
      }
      if (child.derivation.length > 0 && derivation.length < MAX_DERIVATION_PER_CONTROL) {
        derivation.push(...child.derivation.slice(0, MAX_DERIVATION_PER_CONTROL - derivation.length))
      }
    }
    if (hasUnassessed && status === "compliant") status = "unassessed"
    const result = { status, evidence, derivation }
    computed.set(key, result)
    return result
  }

  const rows: ControlStatusRow[] = []
  for (const row of catalog) {
    const { status, evidence, derivation } = compute(`${row.framework}:${row.control_id}`)
    rows.push({
      projectID,
      framework: row.framework,
      controlId: row.control_id,
      status,
      evidence,
      derivation,
      // Sin evidencia no hay derivación que auditar: el estado es el default
      // del motor ("sin hallazgos mapeados") y no se afirma nada más.
      confidence: derivation.length === 0 ? "high" : derivation.reduce((acc, entry) => maxConfidence(acc, entry.confidence), "low" as EvidenceConfidence),
      timeUpdated: now,
    })
  }
  return rows
}
