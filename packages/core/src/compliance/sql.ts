import { index, integer, sqliteTable, text } from "drizzle-orm/sqlite-core"
import { ProjectTable } from "../project/sql"
import type {
  ControlEvidence,
  ControlNode,
  ControlStatus,
  ControlStatusRow,
  EvidenceConfidence,
  EvidenceEntry,
  Framework,
} from "./types"

/** Catálogo cacheado: nodos de NIST CSF 2.0 e ISO 27001:2022. */
export const ComplianceCatalogTable = sqliteTable(
  "compliance_catalog",
  {
    framework: text().$type<Framework>().notNull(),
    control_id: text().notNull(),
    title: text().notNull(),
    parent_id: text(),
    level: text().notNull(),
    sort_id: text(),
    attributes: text({ mode: "json" }).notNull().$type<Record<string, unknown>>().default({}),
    source: text(),
    time_updated: integer().notNull(),
  },
  (table) => [
    index("compliance_catalog_parent_idx").on(table.framework, table.parent_id),
    index("compliance_catalog_level_idx").on(table.framework, table.level),
  ],
)

/** Cross-framework mapping (ISO 27001 ↔ NIST CSF 2.0), en ambas direcciones. */
export const ComplianceMappingTable = sqliteTable(
  "compliance_mapping",
  {
    source_framework: text().$type<Framework>().notNull(),
    source_control_id: text().notNull(),
    target_framework: text().$type<Framework>().notNull(),
    target_control_id: text().notNull(),
  },
  (table) => [
    index("compliance_mapping_source_idx").on(table.source_framework, table.source_control_id),
  ],
)

/** Estado derivado de hallazgos por proyecto y control. */
export const ComplianceStatusTable = sqliteTable(
  "compliance_control_status",
  {
    project_id: text()
      .notNull()
      .references(() => ProjectTable.id, { onDelete: "cascade" }),
    framework: text().$type<Framework>().notNull(),
    control_id: text().notNull(),
    status: text().notNull(),
    evidence: text({ mode: "json" })
      .notNull()
      .$type<EvidenceEntry[]>()
      .default([]),
    /** Evidencia auditable por regla: qué regla derivó el control y con qué
     *  confianza (ARG-042). */
    derivation: text({ mode: "json" })
      .notNull()
      .$type<ControlEvidence[]>()
      .default([]),
    /** Confianza agregada del control. */
    confidence: text().notNull().$type<EvidenceConfidence>().default("high"),
    time_updated: integer().notNull(),
  },
  (table) => [index("compliance_status_project_idx").on(table.project_id)],
)

/** Historial de transiciones de estado por control: base del monitoreo continuo
 *  (CCM). Cada vez que un recompute detecta un cambio de estado (drift), se
 *  registra una fila con el estado anterior y el nuevo. */
export const ComplianceHistoryTable = sqliteTable(
  "compliance_control_history",
  {
    id: integer().primaryKey({ autoIncrement: true }),
    project_id: text()
      .notNull()
      .references(() => ProjectTable.id, { onDelete: "cascade" }),
    framework: text().$type<Framework>().notNull(),
    control_id: text().notNull(),
    status_from: text().notNull(),
    status_to: text().notNull(),
    time_recorded: integer().notNull(),
  },
  (table) => [index("compliance_history_project_idx").on(table.project_id, table.framework, table.control_id)],
)

export interface ControlHistoryRow {
  id: number
  projectID: string
  framework: Framework
  controlId: string
  statusFrom: ControlStatus
  statusTo: ControlStatus
  timeRecorded: number
}

export type ComplianceCatalogRow = typeof ComplianceCatalogTable.$inferSelect
export type ComplianceStatusRow = ControlStatusRow
export type ComplianceHistoryRow = typeof ComplianceHistoryTable.$inferSelect

export const catalogRowToNode = (row: ComplianceCatalogRow): ControlNode => ({
  id: row.control_id,
  title: row.title,
  parentId: row.parent_id ?? null,
  level: row.level as ControlNode["level"],
  sortId: row.sort_id ?? undefined,
  framework: row.framework,
  attributes: row.attributes,
  source: row.source ?? "",
})
