import { index, integer, sqliteTable, text, uniqueIndex, type AnySQLiteColumn } from "drizzle-orm/sqlite-core"
import { ProjectTable } from "../project/sql"
import { SessionTable } from "../session/sql"
import type { AttackTechniqueRow, EnrichmentInfo, IocRow } from "../threat-intel/enrichment"
import type { CvssVector } from "./cvss"
import type { PocRecord } from "./poc"

export const FindingCaseTable = sqliteTable(
  "security_finding_case",
  {
    id: text().primaryKey(),
    project_id: text()
      .notNull()
      .references(() => ProjectTable.id, { onDelete: "cascade" }),
    identity_key: text(),
    merged_into_id: text().references((): AnySQLiteColumn => FindingCaseTable.id, { onDelete: "set null" }),
    status: text().notNull().default("open"),
    status_reason: text(),
    owner: text(),
    due_at: integer(),
    accepted_risk_until: integer(),
    time_created: integer().notNull(),
    time_updated: integer().notNull(),
  },
  (table) => [
    uniqueIndex("security_finding_case_project_identity_idx").on(table.project_id, table.identity_key),
    index("security_finding_case_project_status_idx").on(table.project_id, table.status, table.time_updated),
  ],
)

export const FindingCaseTransitionTable = sqliteTable(
  "security_finding_case_transition",
  {
    id: text().primaryKey(),
    case_id: text()
      .notNull()
      .references(() => FindingCaseTable.id, { onDelete: "cascade" }),
    from_status: text(),
    to_status: text().notNull(),
    reason: text(),
    actor: text().notNull(),
    session_id: text().references(() => SessionTable.id, { onDelete: "set null" }),
    time_created: integer().notNull(),
  },
  (table) => [
    index("security_finding_case_transition_case_time_idx").on(table.case_id, table.time_created),
    index("security_finding_case_transition_session_idx").on(table.session_id, table.time_created),
  ],
)

export const FindingCaseOperationTable = sqliteTable(
  "security_finding_case_operation",
  {
    id: text().primaryKey(),
    project_id: text()
      .notNull()
      .references(() => ProjectTable.id, { onDelete: "cascade" }),
    kind: text().notNull(),
    source_case_id: text()
      .notNull()
      .references(() => FindingCaseTable.id, { onDelete: "cascade" }),
    target_case_id: text()
      .notNull()
      .references(() => FindingCaseTable.id, { onDelete: "cascade" }),
    reason: text().notNull(),
    actor: text().notNull(),
    session_id: text().references(() => SessionTable.id, { onDelete: "set null" }),
    finding_ids: text({ mode: "json" }).notNull().$type<string[]>(),
    time_created: integer().notNull(),
    reversed_at: integer(),
    reversed_reason: text(),
    reversed_by: text(),
  },
  (table) => [
    index("security_finding_case_operation_project_time_idx").on(table.project_id, table.time_created),
    index("security_finding_case_operation_source_idx").on(table.source_case_id, table.time_created),
    index("security_finding_case_operation_target_idx").on(table.target_case_id, table.time_created),
  ],
)

export const FindingTable = sqliteTable(
  "security_finding",
  {
    id: text().primaryKey(),
    session_id: text()
      .notNull()
      .references(() => SessionTable.id, { onDelete: "cascade" }),
    project_id: text()
      .notNull()
      .references(() => ProjectTable.id, { onDelete: "cascade" }),
    case_id: text().references(() => FindingCaseTable.id, { onDelete: "set null" }),
    fingerprint: text().notNull(),
    title: text().notNull(),
    severity: text().notNull(),
    status: text().notNull().default("open"),
    source: text().notNull(),
    source_tool: text(),
    agent: text(),
    target: text(),
    cwe: text(),
    vector: text(),
    evidence: text({ mode: "json" }).notNull().$type<Record<string, unknown>>(),
    // Proof of concept reproducible del hallazgo: la petición que lo
    // reproduce y el matcher que decide si dejó de reproducirse. Lo escribe
    // la tool que confirmó el vector (en `Evidence["poc"]`) y lo re-ejecuta
    // el motor de re-test (ver security/retest.ts).
    poc: text({ mode: "json" }).$type<PocRecord>(),
    remediation: text(),
    tags: text({ mode: "json" }).notNull().$type<string[]>(),
    // Confianza de la detección en el vocabulario cerrado
    // confirmed|probable|possible. La tools Go la declara; los hallazgos
    // transcritos por el LLM quedan en "possible" salvo que lo declaren.
    confidence: text().notNull().default("possible"),
    // Identificador estable de la regla que produjo el hallazgo
    // ("nuclei:exposed-env-file", "sqlmap", …).
    rule_id: text(),
    owasp: text({ mode: "json" }).$type<string[]>(),
    references: text({ mode: "json" }).$type<string[]>(),
    raw: text(),
    attack_techniques: text({ mode: "json" }).$type<AttackTechniqueRow[]>(),
    iocs: text({ mode: "json" }).$type<IocRow[]>(),
    // Vector CVSS v3.1 crudo, provisto explícitamente por el agente o el
    // auditor humano — nunca inferido de tags/CWE. El score se computa
    // determinísticamente en el enrichment (ver cvss.ts) a partir de este.
    cvss_input: text({ mode: "json" }).$type<CvssVector>(),
    enrichment: text({ mode: "json" }).$type<EnrichmentInfo>(),
    enriched_at: integer(),
    validation_status: text().default("detected"),
    validation_evidence: text({ mode: "json" }).$type<Record<string, unknown>>(),
    validated_at: integer(),
    time_created: integer().notNull(),
    time_updated: integer().notNull(),
  },
  (table) => [
    uniqueIndex("security_finding_session_fingerprint_idx").on(table.session_id, table.fingerprint),
    index("security_finding_project_idx").on(table.project_id),
    index("security_finding_case_idx").on(table.case_id),
    index("security_finding_session_severity_idx").on(table.session_id, table.severity),
    index("security_finding_session_updated_idx").on(table.session_id, table.time_updated),
    index("security_finding_session_cwe_idx").on(table.session_id, table.cwe),
    // Búsqueda por taxonomía: es el acceso caliente del ingest y de la
    // reconciliación (el fingerprint v2 es cwe + target + vector).
    index("security_finding_session_cwe_target_idx").on(table.session_id, table.cwe, table.target),
  ],
)

/**
 * Triage humano (o del agente) sobre un hallazgo: falso positivo, verdadero
 * positivo o riesgo aceptado.
 *
 * Es feedback **por engagement**: la fila cuelga de `session_id`, no de la
 * regla. Un FP marcado en un engagement no suprime el mismo hallazgo en otro
 * — solo alimenta la precisión histórica de la regla, que se muestra como
 * contexto y nunca se aplica como supresión automática.
 *
 * Un veredicto por hallazgo (índice único): cambiar de opinión es un upsert,
 * no una fila nueva, para que la precisión de la regla no cuente dos veces el
 * mismo hallazgo.
 */
export const FindingFeedbackTable = sqliteTable(
  "security_finding_feedback",
  {
    id: text().primaryKey(),
    project_id: text()
      .notNull()
      .references(() => ProjectTable.id, { onDelete: "cascade" }),
    session_id: text()
      .notNull()
      .references(() => SessionTable.id, { onDelete: "cascade" }),
    finding_id: text()
      .notNull()
      .references(() => FindingTable.id, { onDelete: "cascade" }),
    // Identidad del hallazgo (fingerprint v2): permite correlacionar el mismo
    // bug entre sesiones sin volver a resolver la taxonomía.
    fingerprint: text().notNull(),
    rule_id: text(),
    source_tool: text(),
    cwe: text(),
    // false-positive | true-positive | accepted-risk
    verdict: text().notNull(),
    reason: text(),
    // human | agent. El agente puede proponer, pero el veredicto humano se
    // registra con su propio actor para que la cadena de auditoría lo distinga.
    actor: text().notNull().default("human"),
    time_created: integer().notNull(),
    time_updated: integer().notNull(),
  },
  (table) => [
    uniqueIndex("security_feedback_finding_idx").on(table.finding_id),
    index("security_feedback_session_verdict_idx").on(table.session_id, table.verdict),
    index("security_feedback_project_rule_idx").on(table.project_id, table.rule_id),
  ],
)

export const FindingObservationTable = sqliteTable(
  "security_finding_observation",
  {
    id: text().primaryKey(),
    project_id: text()
      .notNull()
      .references(() => ProjectTable.id, { onDelete: "cascade" }),
    session_id: text()
      .notNull()
      .references(() => SessionTable.id, { onDelete: "cascade" }),
    finding_id: text().notNull(),
    source_event_id: text().notNull(),
    fingerprint: text().notNull(),
    source: text().notNull(),
    source_tool: text(),
    rule_id: text(),
    observed_at: integer().notNull(),
    snapshot: text().notNull(),
  },
  (table) => [
    uniqueIndex("security_finding_observation_source_identity_idx").on(
      table.session_id,
      table.source_event_id,
      table.source_tool,
      table.fingerprint,
    ),
    index("security_finding_observation_finding_time_idx").on(table.finding_id, table.observed_at),
    index("security_finding_observation_project_time_idx").on(table.project_id, table.observed_at),
  ],
)

/**
 * Índice del tráfico HTTP de la sesión (`traffic_exchange`).
 *
 * NO es la fuente de verdad: el store en disco
 * (`<memoryDir>/traffic/<sessionID>/*.json`) lo escribe el binario Go
 * (`argos-bin/internal/traffic`) y esta tabla es el caché que la UI lee.
 * El reconciliador de `security/traffic.ts` la puebla desde el store.
 */
export const TrafficExchangeTable = sqliteTable(
  "traffic_exchange",
  {
    id: text().primaryKey(),
    session_id: text()
      .notNull()
      .references(() => SessionTable.id, { onDelete: "cascade" }),
    project_id: text()
      .notNull()
      .references(() => ProjectTable.id, { onDelete: "cascade" }),
    /** Momento de la request, en epoch ms. */
    timestamp: integer().notNull(),
    method: text().notNull(),
    url: text().notNull(),
    host: text(),
    status: integer().notNull(),
    duration_ms: integer().notNull().default(0),
    source_tool: text(),
    target: text(),
    /** El target estaba dentro del alcance autorizado cuando se capturó. */
    scope_allowed: integer({ mode: "boolean" }).notNull().default(false),
    request_headers: text({ mode: "json" }).$type<Record<string, string[]>>(),
    response_headers: text({ mode: "json" }).$type<Record<string, string[]>>(),
    request_body: text(),
    response_body: text(),
    request_body_sha256: text(),
    response_body_sha256: text(),
    request_body_size: integer().notNull().default(0),
    response_body_size: integer().notNull().default(0),
    time_created: integer().notNull(),
  },
  (table) => [
    index("traffic_exchange_session_idx").on(table.session_id),
    index("traffic_exchange_session_time_idx").on(table.session_id, table.timestamp),
    index("traffic_exchange_session_status_idx").on(table.session_id, table.status),
  ],
)

/**
 * Casos de vulnerabilidad a nivel de proyecto (Etapa 2 - DefectDojo/PentAGI).
 *
 * Almacena la identidad canónica del hallazgo y su ciclo de vida longitudinal
 * a través de múltiples sesiones y auditorías.
 */
export const SecurityCaseTable = sqliteTable(
  "security_case",
  {
    id: text().primaryKey(),
    project_id: text()
      .notNull()
      .references(() => ProjectTable.id, { onDelete: "cascade" }),
    fingerprint: text().notNull(),
    context_type: text().notNull().default("endpoint_param"), // endpoint_param | code_location | component_dep | asset_infra
    title: text().notNull(),
    severity: text().notNull(),
    status: text().notNull().default("open"), // open | in_progress | remediated | verified | accepted_risk | false_positive | closed
    cwe: text(),
    target: text(),
    vector: text(),
    first_seen_at: integer().notNull(),
    last_seen_at: integer().notNull(),
    remediated_at: integer(),
    merged_into_id: text(),
    merge_reason: text(),
    sla_due_at: integer(),
    sla_status: text(), // within_sla | breached | warning
    accepted_risk_expires_at: integer(),
    accepted_risk_reason: text(),
    time_created: integer().notNull(),
    time_updated: integer().notNull(),
  },
  (table) => [
    uniqueIndex("security_case_project_fingerprint_idx").on(table.project_id, table.fingerprint),
    index("security_case_project_status_idx").on(table.project_id, table.status),
    index("security_case_project_severity_idx").on(table.project_id, table.severity),
  ],
)

/**
 * Observaciones individuales registradas en cada ejecución/sesión (Etapa 2).
 * Reingerir un resultado no destruye la evidencia anterior: agrega una observación.
 */
export const CaseObservationTable = sqliteTable(
  "security_case_observation",
  {
    id: text().primaryKey(),
    case_id: text()
      .notNull()
      .references(() => SecurityCaseTable.id, { onDelete: "cascade" }),
    finding_id: text().references(() => FindingTable.id, { onDelete: "set null" }),
    session_id: text()
      .notNull()
      .references(() => SessionTable.id, { onDelete: "cascade" }),
    project_id: text()
      .notNull()
      .references(() => ProjectTable.id, { onDelete: "cascade" }),
    run_id: text(),
    source: text().notNull(), // scanner | agent | import | manual
    source_tool: text(),
    rule_id: text(),
    observed_at: integer().notNull(),
    evidence: text({ mode: "json" }).notNull().$type<Record<string, unknown>>(),
    raw: text(),
    confidence: text().notNull().default("possible"),
  },
  (table) => [
    index("security_observation_case_idx").on(table.case_id),
    index("security_observation_session_idx").on(table.session_id),
    index("security_observation_project_idx").on(table.project_id),
  ],
)

/**
 * Historial reversible de transiciones, fusiones y remediaciones de casos (Etapa 2).
 */
export const CaseTransitionHistoryTable = sqliteTable(
  "security_case_history",
  {
    id: text().primaryKey(),
    case_id: text()
      .notNull()
      .references(() => SecurityCaseTable.id, { onDelete: "cascade" }),
    project_id: text()
      .notNull()
      .references(() => ProjectTable.id, { onDelete: "cascade" }),
    previous_status: text(),
    new_status: text().notNull(),
    action: text().notNull(), // status_change | merge | split | observation_added
    reason: text(),
    actor: text().notNull().default("human"),
    time_created: integer().notNull(),
  },
  (table) => [
    index("security_case_history_case_idx").on(table.case_id),
    index("security_case_history_project_idx").on(table.project_id),
  ],
)

/**
 * Tareas autónomas de auditoría con soporte de estados y checkpoints (Etapa 3).
 */
export const AuditTaskExecutionTable = sqliteTable(
  "audit_task_execution",
  {
    id: text().primaryKey(),
    session_id: text()
      .notNull()
      .references(() => SessionTable.id, { onDelete: "cascade" }),
    project_id: text()
      .notNull()
      .references(() => ProjectTable.id, { onDelete: "cascade" }),
    type: text().notNull(), // web_scan | api_audit | code_audit | lan_scan | full_audit
    status: text().notNull().default("queued"), // queued | running | paused | interrupted | cancelled | completed
    target: text(),
    progress: integer().default(0),
    current_step: text(),
    checkpoint_id: text(),
    error: text(),
    metadata: text({ mode: "json" }).$type<Record<string, unknown>>(),
    time_created: integer().notNull(),
    time_updated: integer().notNull(),
  },
  (table) => [
    index("audit_task_session_idx").on(table.session_id),
    index("audit_task_status_idx").on(table.status),
  ],
)

/**
 * Checkpoints de auditoría para reanudar sin repetir pasos completados (Etapa 3).
 */
export const AuditCheckpointTable = sqliteTable(
  "audit_checkpoint",
  {
    id: text().primaryKey(),
    task_id: text()
      .notNull()
      .references(() => AuditTaskExecutionTable.id, { onDelete: "cascade" }),
    session_id: text()
      .notNull()
      .references(() => SessionTable.id, { onDelete: "cascade" }),
    step_name: text().notNull(),
    step_index: integer().notNull(),
    completed_steps: text({ mode: "json" }).notNull().$type<string[]>(),
    state_snapshot: text({ mode: "json" }).notNull().$type<Record<string, unknown>>(),
    time_created: integer().notNull(),
  },
  (table) => [
    index("audit_checkpoint_task_idx").on(table.task_id),
  ],
)

/**
 * Presupuesto durable acumulativo por sesión (Etapa 3).
 */
export const AuditDurableBudgetTable = sqliteTable(
  "audit_durable_budget",
  {
    id: text().primaryKey(),
    session_id: text()
      .notNull()
      .references(() => SessionTable.id, { onDelete: "cascade" }),
    project_id: text()
      .notNull()
      .references(() => ProjectTable.id, { onDelete: "cascade" }),
    turns_count: integer().notNull().default(0),
    tokens_input: integer().notNull().default(0),
    tokens_output: integer().notNull().default(0),
    total_cost_usd: text().notNull().default("0.00"),
    external_api_calls: integer().notNull().default(0),
    tool_calls: integer().notNull().default(0),
    time_updated: integer().notNull(),
  },
  (table) => [
    uniqueIndex("audit_durable_budget_session_idx").on(table.session_id),
  ],
)

/**
 * Perfiles de autenticación basados en roles con pre-flight (Etapa 3).
 */
export const AuthProfileTable = sqliteTable(
  "security_auth_profile",
  {
    id: text().primaryKey(),
    project_id: text()
      .notNull()
      .references(() => ProjectTable.id, { onDelete: "cascade" }),
    role_name: text().notNull(),
    auth_type: text().notNull(), // bearer | cookie | header | basic | oauth2
    credentials: text({ mode: "json" }).notNull().$type<Record<string, string>>(),
    preflight_url: text(),
    preflight_status: text().default("untested"), // valid | invalid | untested
    last_preflight_at: integer(),
    time_created: integer().notNull(),
    time_updated: integer().notNull(),
  },
  (table) => [
    index("security_auth_profile_project_idx").on(table.project_id),
  ],
)

/**
 * Ledger de cobertura de superficie de ataque por endpoint/rol (Etapa 3).
 */
export const SurfaceCoverageTable = sqliteTable(
  "security_surface_coverage",
  {
    id: text().primaryKey(),
    session_id: text()
      .notNull()
      .references(() => SessionTable.id, { onDelete: "cascade" }),
    project_id: text()
      .notNull()
      .references(() => ProjectTable.id, { onDelete: "cascade" }),
    target_url: text().notNull(),
    method: text().notNull(),
    role: text().notNull().default("anonymous"),
    status: text().notNull(), // executed | no_findings | blocked | omitted | inconclusive
    tools_executed: text({ mode: "json" }).$type<string[]>(),
    findings_count: integer().notNull().default(0),
    reason: text(),
    time_updated: integer().notNull(),
  },
  (table) => [
    index("security_surface_coverage_session_idx").on(table.session_id),
  ],
)

/**
 * Outbox durable para conectores externos con backoff y deduplicación (Etapa 4).
 */
export const ConnectorOutboxTable = sqliteTable(
  "connector_outbox",
  {
    id: text().primaryKey(),
    project_id: text()
      .notNull()
      .references(() => ProjectTable.id, { onDelete: "cascade" }),
    session_id: text().references(() => SessionTable.id, { onDelete: "cascade" }),
    target_system: text().notNull(), // jira | linear | slack | teams | defectdojo | github
    event_type: text().notNull(), // finding.created | finding.remediated | report.ready
    idempotency_key: text().notNull().unique(),
    payload: text({ mode: "json" }).notNull().$type<Record<string, unknown>>(),
    status: text().notNull().default("pending"), // pending | delivered | failed
    attempts: integer().notNull().default(0),
    max_attempts: integer().notNull().default(5),
    next_retry_at: integer(),
    last_error: text(),
    time_created: integer().notNull(),
    time_delivered: integer(),
  },
  (table) => [
    index("connector_outbox_status_retry_idx").on(table.status, table.next_retry_at),
  ],
)

/**
 * Horarios persistidos de auditoría con zona horaria y control de ocurrencias omitidas (Etapa 4).
 */
export const AuditScheduleTable = sqliteTable(
  "audit_schedule",
  {
    id: text().primaryKey(),
    project_id: text()
      .notNull()
      .references(() => ProjectTable.id, { onDelete: "cascade" }),
    name: text().notNull(),
    target: text().notNull(),
    scan_type: text().notNull().default("web_scan"), // web_scan | api_audit | code_audit | lan_scan | full_audit
    cron_expression: text().notNull().default("0 0 * * *"),
    timezone: text().notNull().default("UTC"),
    next_run_at: integer().notNull(),
    last_run_at: integer(),
    last_status: text().default("pending"), // pending | completed | missed | running
    missed_occurrences: integer().notNull().default(0),
    enabled: integer({ mode: "boolean" }).notNull().default(true),
    time_created: integer().notNull(),
    time_updated: integer().notNull(),
  },
  (table) => [
    index("audit_schedule_project_idx").on(table.project_id),
    index("audit_schedule_next_run_idx").on(table.next_run_at, table.enabled),
  ],
)
