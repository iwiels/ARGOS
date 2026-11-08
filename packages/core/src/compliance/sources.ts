/**
 * Public URLs used to fetch NIST CSF and the ISO crosswalk at runtime. The
 * derived framework catalogs are bundled snapshots listed below.
 *
 * Licencias verificadas:
 * - NIST CSF 2.0 (OSCAL): obra del gobierno de EE. UU., dominio público / CC0.
 * - workmcg/control-crosswalk: MIT — ISO 27001:2022 (93/93) ↔ NIST CSF 2.0.
 * - saasfort/nis2-controls: MIT — keywords de señales externas por control.
 *
 * Cada URL es sobreescribible por env (`ARGOS_COMPLIANCE_*_URL`) para que cada
 * despliegue pueda apuntar a un espejo o a un entorno sin internet.
 *
 * SOC 2, NIS2 y DORA no tienen fuente de red propia: sus catálogos se derivan
 * del crosswalk ISO 27001:2022 (fuente única) y se commitean como snapshots
 * bundled generados por `scripts/gen-compliance-catalogs.ts`.
 *
 * Argos retains PCI DSS reference IDs and heuristic finding mappings only;
 * this is not a compliance assessment and does not include the standard text.
 */

import type { Framework, SourceKey } from "./types"

export interface ComplianceSourceConfig {
  key: SourceKey
  url: string
  license: string
  description: string
  /** Snapshot bundled: se lee del repo, no se descarga de la red. */
  bundled?: boolean
}


export const complianceSources = (): ComplianceSourceConfig[] => [
  {
    key: "nist_csf_v2",
    url:
      process.env.ARGOS_COMPLIANCE_NIST_CATALOG_URL ??
      "https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/CSF/v2.0/json/NIST_CSF_v2.0_catalog-min.json",
    license: "Public Domain (CC0) — NIST",
    description: "NIST CSF 2.0 full catalog (functions, categories, subcategories) in OSCAL.",
  },
  {
    key: "iso27001_crosswalk",
    url:
      process.env.ARGOS_COMPLIANCE_CROSSWALK_URL ??
      "https://raw.githubusercontent.com/workmcg/control-crosswalk/main/data/crosswalk.json",
    license: "MIT — workmcg/control-crosswalk",
    description: "ISO/IEC 27001:2022 Annex A (93/93) mapped to NIST CSF 2.0 subcategories.",
  },
  {
    key: "checks_nist",
    url:
      process.env.ARGOS_COMPLIANCE_CHECKS_NIST_URL ??
      "https://raw.githubusercontent.com/saasfort/nis2-controls/main/data/nist-csf-v2-mapping.json",
    license: "MIT — saasfort/nis2-controls",
    description: "Externally-observable check keywords per NIST CSF 2.0 category.",
  },
  {
    key: "checks_iso",
    url:
      process.env.ARGOS_COMPLIANCE_CHECKS_ISO_URL ??
      "https://raw.githubusercontent.com/saasfort/nis2-controls/main/data/iso27001-mapping.json",
    license: "MIT — saasfort/nis2-controls",
    description: "Externally-observable check keywords per ISO 27001:2022 control.",
  },
]

/**
 * Catálogos derivados del crosswalk ISO 27001:2022 (SOC 2, NIS2, DORA).
 * Son snapshots bundled: no se descargan, se commitean y se regeneran con
 * `scripts/gen-compliance-catalogs.ts` (el test de sync falla si divergen).
 */
export const bundledCatalogSources = (): ComplianceSourceConfig[] => [
  {
    key: "soc2",
    url: "bundled://iso27001_crosswalk.json",
    license: "Derivado de workmcg/control-crosswalk (MIT) — AICPA TSC 2017 (rev. 2022)",
    description: "SOC 2 Trust Services Criteria derivadas del mapeo ISO 27001:2022 del crosswalk.",
    bundled: true,
  },
  {
    key: "nis2",
    url: "bundled://iso27001_crosswalk.json",
    license: "Derivado de workmcg/control-crosswalk (MIT) — Directive (EU) 2022/2555",
    description: "Medidas del Art. 21(2) de NIS2 derivadas del mapeo ISO 27001:2022 del crosswalk.",
    bundled: true,
  },
  {
    key: "dora",
    url: "bundled://iso27001_crosswalk.json",
    license: "Derivado de workmcg/control-crosswalk (MIT) — Regulation (EU) 2022/2554",
    description: "Artículos de ICT risk management de DORA derivados del mapeo ISO 27001:2022 del crosswalk.",
    bundled: true,
  },
  {
    key: "pci_dss_v4",
    url: "bundled://pci_dss_v4.json",
    license: "PCI Security Standards Council; reference identifiers only, no standard text bundled",
    description: "PCI DSS reference IDs with heuristic finding mappings; not a compliance assessment.",
    bundled: true,
  },
]

/** El conector Elasticsearch (binario `argos-es`) expone tools con este prefijo. */
export const ELASTICSEARCH_TOOL_PREFIX = "es."

/** Fuente legible para el UI. */
export const FRAMEWORK_META: Record<Framework, { title: string; version: string }> = {
  nist_csf_v2: { title: "NIST CSF 2.0", version: "CSF 2.0" },
  iso27001_2022: { title: "ISO 27001:2022", version: "ISO/IEC 27001:2022" },
  soc2: { title: "SOC 2 Trust Services Criteria", version: "TSC 2017 (rev. 2022)" },
  nis2: { title: "NIS2 (EU 2022/2555)", version: "Art. 21(2) (a)–(j)" },
  dora: { title: "DORA (EU 2022/2554)", version: "ICT risk management articles" },
  pci_dss_v4: { title: "PCI DSS reference IDs (not an assessment)", version: "v4.0.1" },
}
