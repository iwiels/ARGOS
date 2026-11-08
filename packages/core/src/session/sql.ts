import { sql } from "drizzle-orm"
import { sqliteTable, text, integer, index, primaryKey, real, uniqueIndex } from "drizzle-orm/sqlite-core"
import * as DatabasePath from "../database/path"
import { ProjectTable } from "../project/sql"
import type { SessionMessage } from "./message"
import type { Prompt } from "./prompt"
import type { SessionInput } from "./input"
import type { Snapshot } from "../snapshot"
import { PermissionV1 } from "../v1/permission"
import { ProjectV2 } from "../project"
import type { SessionSchema } from "./schema"
import type { MessageID, PartID, SessionV1 } from "../v1/session"
import { WorkspaceV2 } from "../workspace"
import { Timestamps } from "../database/schema.sql"
import type { SystemContext } from "../system-context/index"
import { AgentV2 } from "../agent"

type SessionMessageData = Omit<(typeof SessionMessage.Message)["Encoded"], "type" | "id">
type V1MessageData = Omit<SessionV1.Info, "id" | "sessionID">
type V1PartData = Omit<SessionV1.Part, "id" | "sessionID" | "messageID">

export const SessionTable = sqliteTable(
  "session",
  {
    id: text().$type<SessionSchema.ID>().primaryKey(),
    project_id: text()
      .$type<ProjectV2.ID>()
      .notNull()
      .references(() => ProjectTable.id, { onDelete: "cascade" }),
    workspace_id: text().$type<WorkspaceV2.ID>(),
    parent_id: text().$type<SessionSchema.ID>(),
    slug: text().notNull(),
    directory: DatabasePath.directoryColumn().notNull(),
    path: DatabasePath.pathColumn(),
    title: text().notNull(),
    version: text().notNull(),
    share_url: text(),
    summary_additions: integer(),
    summary_deletions: integer(),
    summary_files: integer(),
    summary_diffs: text({ mode: "json" }).$type<Snapshot.FileDiff[]>(),
    metadata: text({ mode: "json" }).$type<Record<string, unknown>>(),
    cost: real().notNull().default(0),
    tokens_input: integer().notNull().default(0),
    tokens_output: integer().notNull().default(0),
    tokens_reasoning: integer().notNull().default(0),
    tokens_cache_read: integer().notNull().default(0),
    tokens_cache_write: integer().notNull().default(0),
    revert: text({ mode: "json" }).$type<{ messageID: MessageID; partID?: PartID; snapshot?: string; diff?: string }>(),
    permission: text({ mode: "json" }).$type<PermissionV1.Ruleset>(),
    agent: text(),
    model: text({ mode: "json" }).$type<{
      id: string
      providerID: string
      variant?: string
    }>(),
    scope_cidrs: text({ mode: "json" }).$type<string[]>(),
    scope_domains: text({ mode: "json" }).$type<string[]>(),
    scope_excluded: text({ mode: "json" }).$type<string[]>(),
    scope_max_rps: integer(),
    scope_safe_mode: integer({ mode: "boolean" }),
    ...Timestamps,
    time_compacting: integer(),
    time_archived: integer(),
  },
  (table) => [
    index("session_project_idx").on(table.project_id),
    index("session_workspace_idx").on(table.workspace_id),
    index("session_parent_idx").on(table.parent_id),
  ],
)

export const EngagementBudgetTable = sqliteTable("session_engagement_budget", {
  session_id: text()
    .$type<SessionSchema.ID>()
    .primaryKey()
    .references(() => SessionTable.id, { onDelete: "cascade" }),
  tool_calls: integer().notNull().default(0),
  tokens: integer().notNull().default(0),
  findings: integer().notNull().default(0),
  started_at: integer().notNull(),
  budget: text({ mode: "json" })
    .$type<{
      maxToolCalls: number
      maxTokens: number
      maxWallClockMs: number
      maxFindings: number
      maxConcurrentAgents: number
    }>()
    .notNull(),
  time_updated: integer().notNull(),
})

export const SessionRunTable = sqliteTable(
  "session_run",
  {
    id: text().primaryKey(),
    session_id: text()
      .$type<SessionSchema.ID>()
      .notNull()
      .references(() => SessionTable.id, { onDelete: "cascade" }),
    runtime_id: text().notNull(),
    process_id: integer().notNull(),
    hostname: text().notNull(),
    status: text().$type<SessionSchema.RunStatus>().notNull(),
    resume_claim: integer({ mode: "boolean" }).notNull().default(false),
    resume_count: integer().notNull().default(0),
    started_at: integer().notNull(),
    updated_at: integer().notNull(),
    ended_at: integer(),
    last_event_seq: integer(),
    error: text(),
  },
  (table) => [
    index("session_run_session_started_idx").on(table.session_id, table.started_at, table.id),
    index("session_run_status_runtime_idx").on(table.status, table.runtime_id),
    uniqueIndex("session_run_active_session_unique")
      .on(table.session_id)
      .where(sql`${table.status} = 'running'`),
  ],
)

export const SessionRunCoverageTable = sqliteTable(
  "session_run_coverage",
  {
    id: text().primaryKey(),
    session_id: text()
      .$type<SessionSchema.ID>()
      .notNull()
      .references(() => SessionTable.id, { onDelete: "cascade" }),
    run_id: text()
      .notNull()
      .references(() => SessionRunTable.id, { onDelete: "cascade" }),
    surface: text().notNull(),
    role: text().notNull(),
    test_key: text().notNull(),
    status: text().notNull(),
    finding_count: integer().notNull().default(0),
    attestation: text().notNull(),
    runtime_tool: text(),
    evidence_hash: text(),
    evidence_ref: text(),
    summary: text(),
    idempotency_key: text(),
    created_at: integer().notNull(),
  },
  (table) => [
    index("session_run_coverage_owner_idx").on(table.session_id, table.run_id, table.created_at, table.id),
    uniqueIndex("session_run_coverage_idempotency_idx")
      .on(table.run_id, table.idempotency_key)
      .where(sql`${table.idempotency_key} IS NOT NULL`),
  ],
)

export const SessionRunCoveragePlanTable = sqliteTable("session_run_coverage_plan", {
  session_id: text()
    .$type<SessionSchema.ID>()
    .notNull()
    .references(() => SessionTable.id, { onDelete: "cascade" }),
  run_id: text()
    .primaryKey()
    .references(() => SessionRunTable.id, { onDelete: "cascade" }),
  version: integer().notNull(),
  source: text().$type<"controller">().notNull(),
  requirements: text({ mode: "json" }).notNull().$type<
    Array<{
      surface: "web" | "api" | "repository"
      role: string
      testKey: string
      runtimeTool: string
    }>
  >(),
  created_at: integer().notNull(),
})

export const MessageTable = sqliteTable(
  "message",
  {
    id: text().$type<MessageID>().primaryKey(),
    session_id: text()
      .$type<SessionSchema.ID>()
      .notNull()
      .references(() => SessionTable.id, { onDelete: "cascade" }),
    ...Timestamps,
    data: text({ mode: "json" }).notNull().$type<V1MessageData>(),
  },
  (table) => [index("message_session_time_created_id_idx").on(table.session_id, table.time_created, table.id)],
)

export const PartTable = sqliteTable(
  "part",
  {
    id: text().$type<PartID>().primaryKey(),
    message_id: text()
      .$type<MessageID>()
      .notNull()
      .references(() => MessageTable.id, { onDelete: "cascade" }),
    session_id: text().$type<SessionSchema.ID>().notNull(),
    ...Timestamps,
    data: text({ mode: "json" }).notNull().$type<V1PartData>(),
  },
  (table) => [
    index("part_message_id_id_idx").on(table.message_id, table.id),
    index("part_session_idx").on(table.session_id),
  ],
)

export const TodoTable = sqliteTable(
  "todo",
  {
    session_id: text()
      .$type<SessionSchema.ID>()
      .notNull()
      .references(() => SessionTable.id, { onDelete: "cascade" }),
    content: text().notNull(),
    status: text().notNull(),
    priority: text().notNull(),
    position: integer().notNull(),
    ...Timestamps,
  },
  (table) => [
    primaryKey({ columns: [table.session_id, table.position] }),
    index("todo_session_idx").on(table.session_id),
  ],
)

export const SessionMessageTable = sqliteTable(
  "session_message",
  {
    id: text().$type<SessionMessage.ID>().primaryKey(),
    session_id: text()
      .$type<SessionSchema.ID>()
      .notNull()
      .references(() => SessionTable.id, { onDelete: "cascade" }),
    type: text().$type<SessionMessage.Type>().notNull(),
    seq: integer().notNull(),
    ...Timestamps,
    data: text({ mode: "json" }).notNull().$type<SessionMessageData>(),
  },
  (table) => [
    uniqueIndex("session_message_session_seq_idx").on(table.session_id, table.seq),
    index("session_message_session_type_seq_idx").on(table.session_id, table.type, table.seq),
    index("session_message_session_time_created_id_idx").on(table.session_id, table.time_created, table.id),
    index("session_message_time_created_idx").on(table.time_created),
  ],
)

export const SessionInputTable = sqliteTable(
  "session_input",
  {
    id: text().$type<SessionMessage.ID>().primaryKey(),
    session_id: text()
      .$type<SessionSchema.ID>()
      .notNull()
      .references(() => SessionTable.id, { onDelete: "cascade" }),
    prompt: text({ mode: "json" }).notNull().$type<Prompt>(),
    delivery: text().$type<SessionInput.Delivery>().notNull(),
    admitted_seq: integer().notNull(),
    promoted_seq: integer(),
    time_created: integer()
      .notNull()
      .$default(() => Date.now()),
  },
  (table) => [
    index("session_input_session_pending_delivery_seq_idx").on(
      table.session_id,
      table.promoted_seq,
      table.delivery,
      table.admitted_seq,
    ),
    uniqueIndex("session_input_session_admitted_seq_idx").on(table.session_id, table.admitted_seq),
    uniqueIndex("session_input_session_promoted_seq_idx").on(table.session_id, table.promoted_seq),
  ],
)

export const SessionContextEpochTable = sqliteTable("session_context_epoch", {
  session_id: text()
    .$type<SessionSchema.ID>()
    .primaryKey()
    .references(() => SessionTable.id, { onDelete: "cascade" }),
  baseline: text().notNull(),
  agent: text().$type<AgentV2.ID>().notNull().default(AgentV2.defaultID),
  snapshot: text({ mode: "json" }).notNull().$type<SystemContext.Snapshot>(),
  baseline_seq: integer().notNull(),
  replacement_seq: integer(),
  revision: integer().notNull().default(0),
})
