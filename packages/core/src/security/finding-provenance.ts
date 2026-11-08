import { inArray, sql } from "drizzle-orm"
import { FindingTable } from "./sql"

export const TRUSTED_FINDING_SOURCES = ["agent-reviewed", "import"] as const

export const trustedFindingSourceCondition = () =>
  inArray(FindingTable.source, [...TRUSTED_FINDING_SOURCES])

export const trustedFindingSourceSqlList = sql.join(
  TRUSTED_FINDING_SOURCES.map((source) => sql`${source}`),
  sql`, `,
)
