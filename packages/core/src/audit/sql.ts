import { index, integer, sqliteTable, text } from "drizzle-orm/sqlite-core"

export const AuditLogTable = sqliteTable(
  "audit_log",
  {
    id: text().primaryKey(),
    seq: integer().notNull().unique(),
    project_id: text(),
    session_id: text(),
    event_type: text().notNull(),
    action: text().notNull(),
    agent: text(),
    target: text(),
    summary: text().notNull(),
    payload: text().notNull().default("{}"),
    prev_hash: text().notNull(),
    hash: text().notNull(),
    time_created: integer().notNull(),
  },
  (table) => [
    index("audit_log_session_idx").on(table.session_id),
    index("audit_log_time_idx").on(table.time_created),
  ],
)
