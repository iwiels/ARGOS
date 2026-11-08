/** Compliance engine types.
 *
 * NIST CSF 2.0 and the ISO 27001:2022 crosswalk are fetched from public
 * sources and cached in the database (`compliance_catalog` / `compliance_mapping`).
 *
 * SOC 2, NIS2 and DORA catalogs are derived from the ISO crosswalk and bundled.
 * PCI DSS contains reference identifiers and heuristic finding mappings only;
 * it is not a compliance assessment and includes no standard text.
 *
 */

export const FRAMEWORKS = {
  nistCsfV2: "nist_csf_v2",
  iso27001: "iso27001_2022",
  soc2: "soc2",
  nis2: "nis2",
  dora: "dora",
  pciDssV4: "pci_dss_v4",
} as const

export type Framework = (typeof FRAMEWORKS)[keyof typeof FRAMEWORKS]

/** Frameworks cuyo catálogo se deriva del crosswalk ISO 27001:2022. */
export type DerivedFramework = typeof FRAMEWORKS.soc2 | typeof FRAMEWORKS.nis2 | typeof FRAMEWORKS.dora

/** Frameworks cuyo catálogo es propio (no derivado del crosswalk). */
export type OwnCatalogFramework = typeof FRAMEWORKS.pciDssV4

/** Claves de las fuentes del catálogo de compliance. */
export type SourceKey =
  | "nist_csf_v2"
  | "iso27001_crosswalk"
  | "checks_nist"
  | "checks_iso"
  | "soc2"
  | "nis2"
  | "dora"
  | "pci_dss_v4"

/**
 * Cobertura de un control frente a los hallazgos de Argos.
 *
 * - `evaluable`: algún hallazgo del catálogo de reglas puede activar el
 *   control, así que su estado (conforme/deficiente) es una afirmación
 *   sustentada.
 * - `not-evaluable`: ningún finding de Argos puede llegar al control (p. ej.
 *   control físico de la Requirement 9). El motor lo reporta como
 *   `unassessed` — **nunca** como conforme, porque no verificó nada.
 */
export type ControlCoverage = "evaluable" | "not-evaluable"

export type ControlLevel = "function" | "category" | "subcategory" | "theme" | "control"

/** Nodo del catálogo: función/categoría/subcategoría (NIST) o tema/control (ISO). */
export interface ControlNode {
  id: string
  title: string
  parentId: string | null
  level: ControlLevel
  sortId?: string
  framework: Framework
  /** Atributos auxiliares persistidos (checks externos, metadata de fuente…). */
  attributes: Record<string, unknown>
  source: string
}

/** Fila del crosswalk: ISO 27001:2022 ↔ NIST CSF 2.0 (un par por dirección). */
export interface ControlMapping {
  sourceFramework: Framework
  sourceControlId: string
  targetFramework: Framework
  targetControlId: string
}

/** Estado derivado de los hallazgos para un control de un proyecto. */
export type ControlStatus = "deficient" | "partial" | "compliant" | "unassessed"

/**
 * Confianza de una **derivación** de compliance: qué tan fuerte es el vínculo
 * entre el hallazgo y el control. No es la confianza del hallazgo en sí (esa
 * vive en `security_finding.confidence`).
 *
 * - `high`: la regla declara `cwes` y `tools`, y el finding coincide con el
 *   CWE exacto y con una de las herramientas declaradas.
 * - `medium`: coincidencia por CWE exacto o por tag exacto de la regla, o
 *   check externo completo de un catálogo público.
 * - `low`: coincidencia heurística (título, tag genérico, fragmento de
 *   keyword, técnica ATT&CK, o solo herramienta).
 */
export type EvidenceConfidence = "high" | "medium" | "low"

/** Hallazgo resumido que sustenta una derivación de control. */
export interface ControlEvidenceFinding {
  id: string
  title: string
  severity: string
  cwe?: string
  sourceTool?: string
  /** Confianza del propio hallazgo (`possible`/`probable`/`confirmed`). */
  confidence?: string
}

/**
 * Regla que derivó el control + los hallazgos que la activaron. Una entrada
 * por regla: un control con dos reglas distintas expone dos entradas.
 */
export interface ControlEvidence {
  /** Regla que disparó la derivación (el `reason` de la SemanticRule). */
  derivedFrom: string
  findings: ControlEvidenceFinding[]
  /** Confianza de la derivación, no del finding. */
  confidence: EvidenceConfidence
}

export interface EvidenceEntry {
  findingID: string
  title: string
  severity: string
  status: string
  tool?: string
  /** Hallazgo originado en el conector Elasticsearch (tools `es.*`). */
  fromElasticsearch: boolean
  timeUpdated: number
  /** CWE del hallazgo: el auditor necesita verlo junto al control. */
  cwe?: string
  /** Regla que derivó el control a partir de este hallazgo. */
  derivedFrom?: string
  /** Confianza de esa derivación (no la del hallazgo). */
  confidence?: EvidenceConfidence
}

export interface ControlStatusRow {
  projectID: string
  framework: Framework
  controlId: string
  status: ControlStatus
  /** Hallazgos que sustentan el estado (lista plana; la consumen UI y export). */
  evidence: EvidenceEntry[]
  /** Evidencia auditable agrupada por regla: qué regla derivó el control. */
  derivation: ControlEvidence[]
  /**
   * Confianza agregada del control: la **mayor** entre sus entradas de
   * evidencia (un finding de confianza alta no se degrada porque otro fue
   * heurístico).
   *
   * Un control **sin** hallazgos tiene confianza `high`: no hubo derivación que
   * auditar y su estado es el default del motor ("sin hallazgos mapeados").
   * Esto no significa que el control esté verificado, significa que no se
   * afirma nada sobre él más allá del default.
   */
  confidence: EvidenceConfidence
  timeUpdated: number
}

export interface SourceRefresh {
  key: SourceKey
  url: string
  license: string
  ok: boolean
  error?: string
  controls?: number
  mappings?: number
  /** La fuente es un snapshot bundled (no se descarga de la red). */
  bundled?: boolean
}

export interface RefreshSummary {
  refreshedAt: number
  sources: SourceRefresh[]
  catalogControlCount: number
  mappingCount: number
}

/** Evento de drift: un control cambió de estado entre dos recomputes. */
export interface DriftEvent {
  id: number
  projectID: string
  framework: Framework
  controlId: string
  statusFrom: ControlStatus
  statusTo: ControlStatus
  timeRecorded: number
}

/** Conteos agregados de estado para un framework (todos los proyectos). */
export interface FrameworkCompliance {
  framework: Framework
  title: string
  version: string
  totalControls: number
  counts: Record<ControlStatus, number>
  /** Porcentaje de controles sin deficiencias (0-100). */
  score: number
  /**
   * Confianza agregada del framework: la **menor** entre las hojas con
   * evidencia (el eslabón más débil). Se usa `high` cuando ningún control
   * tiene hallazgos mapeados — no hay nada que sustente ni que dudar.
   */
  confidence: EvidenceConfidence
}

/** Resumen global del monitoreo continuo (CCM). */
export interface GlobalComplianceSummary {
  generatedAt: number
  projectCount: number
  frameworks: FrameworkCompliance[]
  lastUpdated: number | null
}

/** Nodo del árbol de compliance para un Session/proyecto concreto — el catálogo
 *  (jerárquico) fusionado con el estado derivado de sus findings. Un solo nodo
 *  raíz sintético por framework agrupa las funciones/temas de nivel superior. */
export interface SessionComplianceNode {
  id: string
  title: string
  level: ControlLevel | "root"
  status: ControlStatus
  findingCount: number
  evidence: EvidenceEntry[]
  /** Evidencia auditable del control (regla → hallazgos → confianza). */
  derivation: ControlEvidence[]
  /** Confianza agregada del control. */
  confidence: EvidenceConfidence
  children: SessionComplianceNode[]
}

export interface SessionComplianceFramework {
  framework: Framework
  title: string
  version: string
  refreshedAt?: number
  tree: SessionComplianceNode
}

export interface SessionComplianceStatus {
  frameworks: SessionComplianceFramework[]
  catalogCount: number
  mappingCount: number
  lastRefreshed?: number
}

/** Forma mínima de un finding para el mapeo a controles. */
export interface FindingLike {
  id?: string | null
  title?: string | null
  tags?: unknown
  cwe?: string | number | null
  vector?: string | null
  sourceTool?: string | null
  severity?: string | null
  status?: string | null
  attackTechniques?: unknown
  /** Confianza del hallazgo (`possible`/`probable`/`confirmed`). */
  confidence?: string | null
  timeUpdated?: number
}
