import { Effect } from "effect"
import type { DatabaseMigration } from "../migration"

export default {
  id: "20260814000000_session_scope",
  up(tx) {
    return Effect.gen(function* () {
      yield* tx.run("ALTER TABLE `session` ADD COLUMN `scope_cidrs` text")
      yield* tx.run("ALTER TABLE `session` ADD COLUMN `scope_domains` text")
      yield* tx.run("ALTER TABLE `session` ADD COLUMN `scope_excluded` text")
      yield* tx.run("ALTER TABLE `session` ADD COLUMN `scope_max_rps` integer")
      yield* tx.run("ALTER TABLE `session` ADD COLUMN `scope_safe_mode` integer")
    })
  },
} satisfies DatabaseMigration.Migration
