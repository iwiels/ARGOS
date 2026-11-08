import { Effect } from "effect"
import type { DatabaseMigration } from "../migration"

export default {
  id: "20260812000000_compliance",
  up(tx) {
    return Effect.gen(function* () {
      yield* tx.run(`
        CREATE TABLE \`compliance_catalog\` (
          \`framework\` text NOT NULL,
          \`control_id\` text NOT NULL,
          \`title\` text NOT NULL,
          \`parent_id\` text,
          \`level\` text NOT NULL,
          \`sort_id\` text,
          \`attributes\` text NOT NULL DEFAULT '{}',
          \`source\` text,
          \`time_updated\` integer NOT NULL,
          PRIMARY KEY (\`framework\`, \`control_id\`)
        )
      `)
      yield* tx.run("CREATE INDEX `compliance_catalog_parent_idx` ON `compliance_catalog` (`framework`, `parent_id`)")
      yield* tx.run("CREATE INDEX `compliance_catalog_level_idx` ON `compliance_catalog` (`framework`, `level`)")
      yield* tx.run(`
        CREATE TABLE \`compliance_mapping\` (
          \`source_framework\` text NOT NULL,
          \`source_control_id\` text NOT NULL,
          \`target_framework\` text NOT NULL,
          \`target_control_id\` text NOT NULL,
          PRIMARY KEY (\`source_framework\`, \`source_control_id\`, \`target_framework\`, \`target_control_id\`)
        )
      `)
      yield* tx.run("CREATE INDEX `compliance_mapping_source_idx` ON `compliance_mapping` (`source_framework`, `source_control_id`)")
      yield* tx.run(`
        CREATE TABLE \`compliance_control_status\` (
          \`project_id\` text NOT NULL REFERENCES \`project\`(\`id\`) ON DELETE CASCADE,
          \`framework\` text NOT NULL,
          \`control_id\` text NOT NULL,
          \`status\` text NOT NULL,
          \`evidence\` text NOT NULL DEFAULT '[]',
          \`time_updated\` integer NOT NULL,
          PRIMARY KEY (\`project_id\`, \`framework\`, \`control_id\`)
        )
      `)
      yield* tx.run("CREATE INDEX `compliance_status_project_idx` ON `compliance_control_status` (`project_id`)")
    })
  },
} satisfies DatabaseMigration.Migration
