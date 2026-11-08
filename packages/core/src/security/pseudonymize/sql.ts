import { index, integer, sqliteTable, text, uniqueIndex } from "drizzle-orm/sqlite-core"
import { SessionTable } from "../../session/sql"

export const EngagementPseudonymTable = sqliteTable(
  "engagement_pseudonym",
  {
    id: text().primaryKey(),
    engagement_id: text().notNull(),
    entity_type: text().notNull(), // "ip" | "cidr" | "domain" | "email" | "username"
    token: text().notNull(), // "ZXDOM001", "ZXIP001", etc.
    real_value: text().notNull(),
    time_created: integer().notNull(),
  },
  (table) => [
    uniqueIndex("engagement_pseudonym_token_idx").on(table.engagement_id, table.token),
    uniqueIndex("engagement_pseudonym_real_idx").on(table.engagement_id, table.entity_type, table.real_value),
    index("engagement_pseudonym_engagement_idx").on(table.engagement_id),
  ],
)

// Backward compatibility alias
export const PseudonymTable = EngagementPseudonymTable
